from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

from . import coverage as coverage_mod
from . import externals as externals_mod
from . import introspect as introspect_mod
from . import optimize as optimize_mod
from .analyze import analyze_repo
from .build import auto_stub_and_rebuild, build, probe, resolve_sources
from .campaign import campaign as run_campaign
from .config import DEFAULT_CONFIG, Workspace, deep_merge, default_workspace_path
from .detect import doctor, toolchain_for_config
from .generate import generate_artifacts, write_corpus_seeds
from .mocks import (
    constraint_summary,
    constraints_prompt_section,
    default_constraints,
    merge_constraints,
    merge_defaults,
    questions as mock_questions,
    set_constraint_status,
    set_symbol,
    summary as mocks_summary,
)
from .report import generate_report
from .runfuzz import run_fuzz
from .util import DtfuzzError, format_hex, now_iso, parse_hex, print_json, read_json, resolve, write_json


def _emit(args, data: dict, text: str = "") -> None:
    if getattr(args, "json", False):
        print_json(data)
    elif text:
        print(text)
    else:
        print_json(data)


def _workspace(args) -> Workspace:
    path = args.workdir
    if not path:
        raise DtfuzzError("--workdir is required for this command")
    return Workspace(path)


def _load(args) -> tuple[Workspace, dict, dict]:
    ws = _workspace(args)
    config = ws.load_config()
    analysis = ws.load_analysis()
    return ws, config, analysis


def _safe_module(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")
    return cleaned or "module"


def _report_path(args, ws: Workspace, config: dict) -> Path | None:
    if getattr(args, "no_introspector", False):
        return None
    explicit = getattr(args, "introspector", None) or (config.get("introspector", {}) or {}).get("report")
    repo = config.get("repo") or (getattr(args, "repo", None) or os.getcwd())
    if explicit:
        return Path(resolve(explicit, repo))
    return introspect_mod.discover_report(repo, ws.root if ws else None)


def _try_load_reachability(
    path: Path | None,
    entry_name: str,
    entry_file: str,
    repo: str,
    toolchain: dict,
) -> tuple[dict | None, str]:
    if not path:
        return None, ""
    try:
        return introspect_mod.load_report(path, entry_name, entry_file, repo, toolchain), ""
    except DtfuzzError as exc:
        return None, f"Fuzz Introspector 报告解析失败，回退到 AST 扫描：{exc}"


def _mock_resolved_keys(probe_result: dict, mocks: dict) -> set[str]:
    resolved = {item.get("symbol") for item in probe_result.get("resolved", []) if item.get("symbol")}
    defined = set(probe_result.get("defined_symbols", []) or [])
    normalize = lambda value: value[1:] if value.startswith("_") else value
    for key, entry in (mocks.get("symbols") or {}).items():
        names = {key.split("@", 1)[0], entry.get("name", ""), entry.get("mangled_name", "")}
        if any(name and normalize(str(name)) in defined for name in names):
            resolved.add(key)
    return resolved


def cmd_doctor(args) -> dict:
    info = doctor(args.repo or os.getcwd())
    text = "\n".join(
        [
            f"platform: {info['platform']}",
            f"clang: {info.get('clang') or 'MISSING'}  ({info.get('clang_version', '')})",
            f"libFuzzer runtime: {info.get('fuzzer_runtime') or 'MISSING'}",
            f"llvm-cov: {info.get('llvm_cov') or 'MISSING'}",
            f"llvm-profdata: {info.get('llvm_profdata') or 'MISSING'}",
            f"build system: {info.get('build_system', 'unknown')}",
        ]
        + [f"warning: {item}" for item in info.get("warnings", [])]
        + [f"hint: {item}" for item in info.get("hints", [])]
    )
    _emit(args, {"ok": info.get("ok", False), **info}, text)
    return info


def _entry_from_analysis(analysis: dict) -> dict:
    signature = analysis.get("entry", {}).get("signature", {}) or {}
    model = analysis.get("input_model", {}) or {}
    roles = model.get("roles", {}) or {}
    params = []
    for param in signature.get("params", []) or []:
        params.append({**param, "role": roles.get(param.get("name", ""), "constant")})
    return {
        "name": analysis.get("entry", {}).get("name", ""),
        "file": analysis.get("entry", {}).get("file", ""),
        "header": analysis.get("entry", {}).get("header", ""),
        "qualified_name": analysis.get("entry", {}).get("qualified_name", ""),
        "return_type": signature.get("return_type", "int"),
        "params": params,
        "input_model": model.get("input_model", "buffer"),
        "type_bytes": int(model.get("type_bytes") or 0),
        "type_endian": model.get("type_endian", "big"),
        "type_offset": 0,
        "is_method": bool(analysis.get("entry", {}).get("is_method")),
    }


def cmd_init(args) -> dict:
    repo = resolve(args.repo or os.getcwd())
    if not Path(repo).is_dir():
        raise DtfuzzError(f"repo not found: {repo}")
    if not args.entry:
        raise DtfuzzError("--entry is required")
    module = _safe_module(args.module or args.entry)
    workdir = Path(args.workdir) if args.workdir else default_workspace_path(repo, module)
    ws = Workspace(workdir)
    existing_config = None
    if ws.config_path.is_file() and not args.force:
        raise DtfuzzError(f"workspace already initialized: {ws.root}; use --force to re-run analysis")
    if ws.config_path.is_file():
        existing_config = ws.load_config()
    ws.ensure()
    toolchain = toolchain_for_config(repo, resolve(args.source, repo) if args.source else None)
    include_dirs = list(dict.fromkeys(list(args.include or []) + list(toolchain.get("include_dirs", []))))
    defines = list(dict.fromkeys(list(args.define or []) + list(toolchain.get("defines", []))))
    std = args.std or toolchain.get("std", "")
    external_temp: dict = {"external_sources": [], "sources": {}}
    for external_path in getattr(args, "external_source", None) or []:
        externals_mod.add_source(external_temp, external_path)
    include_dirs = list(dict.fromkeys([*include_dirs, *external_temp["sources"].get("include_dirs", [])]))
    defines = list(dict.fromkeys([*defines, *external_temp["sources"].get("defines", [])]))
    entry_file = str(resolve(args.source, repo)) if args.source else ""
    preflight_questions = externals_mod.missing_include_questions(
        repo,
        [entry_file] if entry_file else [],
        include_dirs,
        external_temp["external_sources"],
        command_hint=(
            f"dtfuzz init --repo {repo} --entry {args.entry}"
            + (f" --source {args.source}" if args.source else "")
            + f" --workdir {workdir} --external-source <DIR> [--include <DIR>] --force"
        ),
    )
    report_path = _report_path(args, ws, existing_config or {})
    reachability, reachability_warning = _try_load_reachability(
        report_path, args.entry, entry_file, str(repo), toolchain
    )
    try:
        analysis = analyze_repo(
            repo=repo,
            entry_name=args.entry,
            entry_file=args.source,
            clang=toolchain["clang"],
            include_dirs=include_dirs,
            defines=defines,
            std=std,
            exclude_dirs=set((existing_config or {}).get("sources", {}).get("exclude_dirs", []) or []),
            max_files=1 if getattr(args, "no_real_scan", False) else 200,
            reachability=reachability,
        )
    except DtfuzzError as exc:
        if not preflight_questions:
            raise
        data = {
            "ok": False,
            "stage": "analyze",
            "error": str(exc),
            "external_source_questions": preflight_questions,
            "next": [
                "这些头文件看起来来自外部库/平台组件。请提供源码或 include 目录，然后重跑 init（加 --external-source / --include）。",
                "如果不需要外部源码，也可以把它们补进仓库的 include 路径或用 --define 处理。",
            ],
        }
        _emit(
            args,
            data,
            "analysis failed before a workspace was created; external source inquiry:\n"
            + externals_mod.format_questions(preflight_questions),
        )
        raise SystemExit(1)
    if reachability_warning:
        analysis.setdefault("warnings", []).append(reachability_warning)
    if reachability:
        introspect_mod.attach(analysis, reachability, repo)
        analysis.setdefault("warnings", []).extend(reachability.get("warnings", []))
        introspect_mod.write_reachability(ws, reachability)
    config = deep_merge(DEFAULT_CONFIG, existing_config or {})
    config.update(
        {
            "module": module,
            "repo": str(Path(repo).resolve()),
            "language": args.language or ("cpp" if Path(analysis["entry"]["file"]).suffix.lower() in {".cc", ".cpp", ".cxx"} else "c"),
            "build_system": args.build_system or toolchain.get("build_system", "unknown"),
        }
    )
    if external_temp["external_sources"]:
        config.setdefault("external_sources", [])
        known_paths = {item.get("path") for item in config["external_sources"]}
        for item in external_temp["external_sources"]:
            if item["path"] not in known_paths:
                config["external_sources"].append(item)
        config["sources"]["include_dirs"] = list(
            dict.fromkeys([*config["sources"].get("include_dirs", []), *external_temp["sources"].get("include_dirs", [])])
        )
        config["sources"]["defines"] = list(
            dict.fromkeys([*config["sources"].get("defines", []), *external_temp["sources"].get("defines", [])])
        )
    config["entry"] = _entry_from_analysis(analysis)
    repo_resolved = Path(repo).resolve()

    def rel_items(items: list[str]) -> list[str]:
        result = []
        for item in items:
            try:
                result.append(str(Path(item).resolve().relative_to(repo_resolved)))
            except ValueError:
                result.append(str(item))
        return result

    config["sources"]["target"] = rel_items(analysis.get("module_files", analysis.get("internal_files", [])))
    existing_real = list((existing_config or {}).get("sources", {}).get("real") or [])
    config["sources"]["real"] = rel_items(
        list(dict.fromkeys([*(analysis.get("real_files", []) or []), *existing_real]))
    )
    config["sources"]["include_dirs"] = include_dirs
    config["sources"]["defines"] = defines
    config["sources"]["std"] = std
    config["coverage"]["target_files"] = analysis.get("target_files", [])
    config["toolchain"] = {
        "clang": toolchain["clang"],
        "llvm_cov": toolchain["llvm_cov"],
        "llvm_profdata": toolchain["llvm_profdata"],
        "llvm_symbolizer": toolchain.get("llvm_symbolizer") or "",
        "llvm_cxxfilt": toolchain.get("llvm_cxxfilt") or "",
    }
    ws.save_config(config)
    mocks_path = ws.mocks_config_path(config)
    existing_mocks = ws.load_mocks(config) if mocks_path.is_file() else None
    mocks = merge_defaults(analysis, existing_mocks)
    ws.save_mocks(mocks, config)
    probe_result = probe(ws, config, analysis)
    if probe_result.get("ok"):
        resolved = _mock_resolved_keys(probe_result, mocks)
        for key in list(mocks.get("symbols", {})):
            entry = mocks["symbols"][key]
            if key not in resolved:
                continue
            if entry.get("confirmed", False):
                entry["stub"] = False
                entry["confirmed"] = False
                entry["status"] = "resolved_real"
                entry["note"] = "disabled: a linked real implementation was found; mock rule kept for reference"
            else:
                del mocks["symbols"][key]
        ws.save_mocks(mocks, config)
        analysis["probe"] = {
            "unresolved": probe_result.get("unresolved", []),
            "resolved": probe_result.get("resolved", []),
            "unclassified_symbols": probe_result.get("unclassified_symbols", []),
        }
    else:
        analysis["probe"] = {"error": probe_result.get("log", "probe failed")}
        analysis.setdefault("warnings", []).append("链接探测失败；mock 候选基于全仓定义扫描，需在构建时复核。")
    externals_mod.attach(analysis, config)
    write_json(ws.analysis_path, analysis)
    questions = mock_questions(mocks)
    data = {
        "ok": True,
        "workdir": str(ws.root),
        "module": module,
        "entry": config["entry"],
        "input_model": analysis.get("input_model"),
        "target_files": analysis.get("target_files"),
        "real_files": analysis.get("real_files"),
        "external_symbols": analysis.get("external_symbols"),
        "probe": analysis.get("probe"),
        "mocks_path": str(mocks_path),
        "pending_mocks": [
            {
                "symbol": key,
                "signature": symbol.get("signature", ""),
                "status": symbol.get("status", "pending"),
                "reachable": symbol.get("reachable", True),
            }
            for key, symbol in sorted((mocks.get("symbols") or {}).items())
            if not symbol.get("confirmed", False) and symbol.get("reachable", True)
        ],
        "reachability": analysis.get("reachability"),
        "external_source_summary": analysis.get("external_source_summary", {}),
        "external_source_questions": analysis.get("external_source_questions", []),
        "mock_questions": questions,
        "analysis_questions": analysis.get("questions", []),
        "warnings": analysis.get("warnings", []),
        "next": [
            "Ask the human for mock rules for pending_mocks (return 0/random error code, random fixed-length bytes, ...).",
            "Import the rules into the mocks config (dtfuzz mocks import).",
            "Run `dtfuzz gen`.",
            "Run `dtfuzz build`.",
            "Run `dtfuzz round --seconds 60`.",
        ],
    }
    text_lines = [
        f"workspace: {ws.root}",
        f"entry: {config['entry']['qualified_name']} ({config['entry']['file']})",
        f"input model: {config['entry']['input_model']} (type_bytes={config['entry']['type_bytes']}, {config['entry']['type_endian']}-endian)",
        "target files:",
    ]
    for item in analysis.get("target_files", []):
        text_lines.append(f"  {item}")
    if analysis.get("real_files"):
        text_lines.append("linked real sources (cross-module):")
        for item in analysis.get("real_files", []):
            text_lines.append(f"  {item}")
    reachability = analysis.get("reachability") or {}
    if reachability:
        text_lines.append(
            "reachability (Fuzz Introspector): "
            f"{reachability.get('reachable_count', 0)} reachable, "
            f"{reachability.get('module_count', 0)} in-module, "
            f"{reachability.get('external_count', 0)} external"
        )
        text_lines.append(f"  report: {reachability.get('report')}")
        if reachability.get("stub_scope"):
            text_lines.append("  stub scope (reachable external symbols):")
            for item in reachability["stub_scope"][:20]:
                text_lines.append(
                    f"    {item.get('symbol')} [{item.get('status')}] {item.get('signature', '')}"
                )
    external_questions = analysis.get("external_source_questions") or []
    if external_questions:
        text_lines.append(
            "external source inquiry (ask the user for a mounted library/SDK source directory):"
        )
        for item in external_questions[:20]:
            if item.get("kind") == "include":
                text_lines.append(f"  header {item.get('header')} (used by {item.get('file')})")
            else:
                text_lines.append(f"  {item.get('symbol')}: {item.get('signature', '')}")
    text_lines.append(f"mocks config: {mocks_path}")
    text_lines.append("pending mocks (no linked implementation; human rules required):")
    for item in sorted((mocks.get("symbols") or {}).items()):
        key, symbol = item
        if not symbol.get("confirmed", False) and symbol.get("reachable", True):
            text_lines.append(
                f"  {key}: {symbol.get('signature', '')} "
                f"[{symbol.get('status', 'pending')}; scope={symbol.get('scope', 'unknown')}]"
            )
    if analysis.get("probe", {}).get("unclassified_symbols"):
        text_lines.append("unclassified undefined symbols (review if project code):")
        for item in analysis["probe"]["unclassified_symbols"][:20]:
            text_lines.append(f"  {item}")
    if questions:
        text_lines.append("questions:")
        for item in questions:
            text_lines.append(f"  [{item['symbol']}] {item['question']}")
    if analysis.get("warnings"):
        text_lines.append("warnings:")
        for item in analysis["warnings"]:
            text_lines.append(f"  {item}")
    _emit(args, data, "\n".join(text_lines))
    return data


def _reanalyze(ws: Workspace, config: dict, reachability: dict | None = None, extra_warnings: list[str] | None = None) -> tuple[dict, dict, dict]:
    toolchain = config.get("toolchain", {})
    entry = config.get("entry", {})
    analysis = analyze_repo(
        repo=config["repo"],
        entry_name=entry.get("name", ""),
        entry_file=entry.get("file") or None,
        clang=toolchain.get("clang") or "clang",
        include_dirs=list(config.get("sources", {}).get("include_dirs", [])) + list(toolchain.get("include_dirs", []) or []),
        defines=list(config.get("sources", {}).get("defines", [])),
        std=config.get("sources", {}).get("std", ""),
        exclude_dirs=set(config.get("sources", {}).get("exclude_dirs", []) or []),
        reachability=reachability,
    )
    if extra_warnings:
        analysis.setdefault("warnings", []).extend(extra_warnings)
    if reachability:
        introspect_mod.attach(analysis, reachability, config["repo"])
        analysis.setdefault("warnings", []).extend(reachability.get("warnings", []))
        introspect_mod.write_reachability(ws, reachability)
    config["entry"] = _entry_from_analysis(analysis)
    config["sources"]["target"] = analysis.get("module_files", analysis.get("internal_files", []))
    existing_real = list(config.get("sources", {}).get("real") or [])
    config["sources"]["real"] = list(
        dict.fromkeys([*(analysis.get("real_files", []) or []), *existing_real])
    )
    config["coverage"]["target_files"] = analysis.get("target_files", [])
    ws.save_config(config)
    mocks = merge_defaults(analysis, ws.load_mocks(config))
    ws.save_mocks(mocks, config)
    probe_result = probe(ws, config, analysis)
    if probe_result.get("ok"):
        resolved = _mock_resolved_keys(probe_result, mocks)
        for key in list(mocks.get("symbols", {})):
            entry_mock = mocks["symbols"][key]
            if key not in resolved:
                continue
            if entry_mock.get("confirmed", False):
                entry_mock["stub"] = False
                entry_mock["confirmed"] = False
                entry_mock["status"] = "resolved_real"
                entry_mock["note"] = "disabled: a linked real implementation was found; mock rule kept for reference"
            else:
                del mocks["symbols"][key]
        ws.save_mocks(mocks, config)
        analysis["probe"] = {
            "unresolved": probe_result.get("unresolved", []),
            "resolved": probe_result.get("resolved", []),
            "unclassified_symbols": probe_result.get("unclassified_symbols", []),
        }
    else:
        analysis["probe"] = {"error": probe_result.get("log", "probe failed")}
    externals_mod.attach(analysis, config)
    write_json(ws.analysis_path, analysis)
    return analysis, mocks, probe_result


def cmd_analyze(args) -> dict:
    ws, config, _ = _load(args)
    report = _report_path(args, ws, config)
    reachability, warning = _try_load_reachability(
        report,
        config.get("entry", {}).get("name", ""),
        config.get("entry", {}).get("file", ""),
        config.get("repo", ""),
        config.get("toolchain", {}),
    )
    analysis, mocks, _ = _reanalyze(ws, config, reachability, [warning] if warning else None)
    data = {
        "ok": True,
        "entry": config["entry"],
        "external_symbols": analysis.get("external_symbols"),
        "real_files": analysis.get("real_files"),
        "probe": analysis.get("probe"),
        "reachability": analysis.get("reachability"),
        "mocks_path": str(ws.mocks_config_path(config)),
        "pending_mocks": [
            {"symbol": key, "signature": symbol.get("signature", ""), "reachable": symbol.get("reachable", True)}
            for key, symbol in sorted((mocks.get("symbols") or {}).items())
            if not symbol.get("confirmed", False) and symbol.get("reachable", True)
        ],
        "warnings": analysis.get("warnings", []),
        "mock_questions": mock_questions(mocks),
    }
    _emit(args, data, "\n".join(f"{item['signature']}" for item in analysis.get("external_symbols", [])))
    return data


def cmd_introspect(args) -> dict:
    ws, config, analysis = _load(args)
    repo = config["repo"]
    entry = config.get("entry", {})
    report_path: Path | None = None
    run_info: dict = {}
    if args.run_light:
        fi_src = args.fi_src or (config.get("introspector", {}) or {}).get("fi_src") or os.environ.get("FI_SRC")
        if not fi_src:
            raise DtfuzzError("--run-light requires --fi-src or config.introspector.fi_src (or FI_SRC)")
        python = (config.get("introspector", {}) or {}).get("python") or "python3"
        report_path = introspect_mod.run_light(repo, ws.introspector_dir / "light", fi_src, python)
        run_info["run"] = "light"
    elif args.run_lto:
        fi_clang = args.fi_clang or (config.get("introspector", {}) or {}).get("fi_clang") or os.environ.get("FI_CLANG")
        if not fi_clang:
            raise DtfuzzError("--run-lto requires --fi-clang or config.introspector.fi_clang (or FI_CLANG)")
        harness = next(
            (item for item in (ws.harness_dir / "fuzz_target.cc", ws.harness_dir / "fuzz_target.c") if item.is_file()),
            None,
        )
        if harness is None:
            raise DtfuzzError("harness missing; run `dtfuzz gen` before `dtfuzz introspect --run-lto`")
        fi_src = args.fi_src or (config.get("introspector", {}) or {}).get("fi_src") or os.environ.get("FI_SRC")
        python = (config.get("introspector", {}) or {}).get("python") or "python3"
        report_path = introspect_mod.run_lto(
            repo,
            ws.introspector_dir / "lto",
            fi_clang,
            resolve_sources(config, analysis),
            str(harness),
            python=python,
            fi_src=fi_src,
        )
        run_info["run"] = "lto"
    else:
        explicit = args.report or (config.get("introspector", {}) or {}).get("report")
        report_path = Path(resolve(explicit, repo)) if explicit else introspect_mod.discover_report(repo, ws.root)
    if not report_path or not Path(report_path).exists():
        raise DtfuzzError(
            "no Fuzz Introspector report found; pass --report, or use --run-light / --run-lto"
        )
    reachability, warning = _try_load_reachability(
        report_path,
        entry.get("name", ""),
        entry.get("file", ""),
        repo,
        config.get("toolchain", {}),
    )
    if not reachability or not reachability.get("matched"):
        raise DtfuzzError(warning or f"entry {entry.get('name')!r} was not found in {report_path}")
    analysis, mocks, _ = _reanalyze(ws, config, reachability, [warning] if warning else None)
    data = {
        "ok": True,
        "report": str(report_path),
        "run": run_info.get("run", "parse"),
        "reachability": analysis.get("reachability"),
        "pending_mocks": [
            {"symbol": key, "signature": symbol.get("signature", ""), "reachable": symbol.get("reachable", True)}
            for key, symbol in sorted((mocks.get("symbols") or {}).items())
            if not symbol.get("confirmed", False) and symbol.get("reachable", True)
        ],
        "warnings": analysis.get("warnings", []),
    }
    reach = analysis.get("reachability") or {}
    text_lines = [
        f"report: {report_path}",
        f"entry match: {reach.get('entry', {}).get('matched')}",
        f"reachable: {reach.get('reachable_count', 0)} "
        f"(module {reach.get('module_count', 0)}, external {reach.get('external_count', 0)})",
    ]
    if reach.get("stub_scope"):
        text_lines.append("stub scope:")
        for item in reach["stub_scope"][:30]:
            text_lines.append(f"  {item.get('symbol')} [{item.get('status')}] {item.get('signature', '')}")
    if reach.get("warnings"):
        text_lines.extend(f"warning: {item}" for item in reach["warnings"])
    _emit(args, data, "\n".join(text_lines))
    return data


def cmd_constraints_list(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    mocks = ws.load_mocks(config)
    rows = constraint_summary(mocks)
    if args.category:
        rows = [item for item in rows if item["category"] == args.category]
    if not args.all:
        rows = [item for item in rows if item.get("status") != "rejected"]
    data = {"ok": True, "constraints": rows, "mocks_path": str(ws.mocks_config_path(config))}
    lines = []
    for item in rows:
        marker = "[REVIEW]" if item.get("highlight") else "[OK]"
        lines.append(
            f"{marker} {item['id']} [{item['category_label']}] {item['subject']}: "
            f"{item['requirement']}"
            + (f"  原因: {item['reason']}" if item.get("reason") else "")
            + (f"  证据: {item['evidence']}" if item.get("evidence") else "")
        )
    _emit(args, data, "\n".join(lines) or "no constraints")
    return data


def cmd_constraints_confirm(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    mocks = ws.load_mocks(config)
    changed = [item for item in args.id if set_constraint_status(mocks, item, confirmed=True, status="active")]
    ws.save_mocks(mocks, config)
    data = {"ok": True, "confirmed": changed, "mocks_path": str(ws.mocks_config_path(config))}
    _emit(args, data, "confirmed: " + ", ".join(changed) if changed else "no matching constraints")
    return data


def cmd_constraints_reject(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    mocks = ws.load_mocks(config)
    changed = [item for item in args.id if set_constraint_status(mocks, item, confirmed=False, status="rejected", note=args.note or "rejected by user")]
    ws.save_mocks(mocks, config)
    data = {"ok": True, "rejected": changed, "mocks_path": str(ws.mocks_config_path(config))}
    _emit(args, data, "rejected: " + ", ".join(changed) if changed else "no matching constraints")
    return data


def cmd_constraints_import(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    incoming = read_json(args.file)
    if incoming is None:
        raise DtfuzzError(f"file not found: {args.file}")
    mocks = ws.load_mocks(config)
    added = merge_constraints(mocks, incoming, source=args.source, confirmed=bool(args.confirm))
    ws.save_mocks(mocks, config)
    data = {"ok": True, "constraints_added": added, "mocks_path": str(ws.mocks_config_path(config))}
    _emit(args, data, f"imported {len(added)} constraint drafts into {ws.mocks_config_path(config)}")
    return data


def cmd_constraints_draft(args) -> dict:
    ws, config, analysis = _load(args)
    mocks = ws.load_mocks(config)
    if args.file:
        incoming = read_json(args.file)
        if incoming is None:
            raise DtfuzzError(f"file not found: {args.file}")
        added = merge_constraints(mocks, incoming, source="llm", confirmed=False)
        ws.save_mocks(mocks, config)
        data = {"ok": True, "constraints_added": added, "mocks_path": str(ws.mocks_config_path(config))}
        _emit(args, data, f"constraints added: {len(added)}")
        return data
    result = optimize_mod.draft_constraints(ws, config, analysis, mocks, mode=args.mode)
    data = {"ok": True, **result}
    if result.get("prompt"):
        text = f"prompt: {result['prompt']}\nnext: {result.get('next', '')}"
    else:
        text = f"constraints added: {len(result.get('constraints_added', []))}"
    _emit(args, data, text)
    return data


def _external_attach(ws: Workspace, config: dict, analysis: dict) -> dict:
    externals_mod.attach(analysis, config)
    write_json(ws.analysis_path, analysis)
    return analysis


def cmd_externals_add(args) -> dict:
    ws, config, analysis = _load(args)
    entry = externals_mod.add_source(
        config,
        args.path,
        name=args.name or "",
        link=bool(args.link),
        include_dirs=list(args.include_dir or []),
        defines=list(args.define or []),
        std=args.std or "",
    )
    ws.save_config(config)
    if args.link:
        reachability = read_json(ws.reachability_path, default=None)
        analysis, _, _ = _reanalyze(ws, config, reachability)
    else:
        _external_attach(ws, config, analysis)
    data = {
        "ok": True,
        "source": entry,
        "external_source_summary": analysis.get("external_source_summary", {}),
        "external_source_questions": analysis.get("external_source_questions", []),
        "warnings": analysis.get("warnings", []),
    }
    text_lines = [
        f"registered external source: {entry['name']} -> {entry['path']} (link={entry['link']})",
        "matched: " + json.dumps(data["external_source_summary"], ensure_ascii=False),
    ]
    if data["external_source_questions"]:
        text_lines.append("questions:")
        for item in data["external_source_questions"][:20]:
            text_lines.append(f"  {item.get('symbol') or item.get('header')}: {item.get('question', '')}")
    _emit(args, data, "\n".join(text_lines))
    return data


def cmd_externals_list(args) -> dict:
    ws, config, analysis = _load(args)
    entries = config.get("external_sources", []) or []
    data = {
        "ok": True,
        "external_sources": entries,
        "external_source_summary": analysis.get("external_source_summary", {}),
        "external_source_questions": analysis.get("external_source_questions", []),
        "matched_functions": [
            {
                "symbol": item.get("qualified_name") or item.get("name"),
                "source": (item.get("external_source") or {}).get("file"),
                "line": (item.get("external_source") or {}).get("line"),
            }
            for item in analysis.get("external_symbols", [])
            if item.get("external_source")
        ],
        "matched_macros": analysis.get("external_macros", []),
        "matched_types": analysis.get("external_types", []),
    }
    lines = [f"- {item['name']}: {item['path']} (link={item.get('link', False)})" for item in entries]
    if analysis.get("external_source_summary"):
        lines.append("summary: " + json.dumps(analysis["external_source_summary"], ensure_ascii=False))
    if data["matched_functions"]:
        lines.append("matched functions:")
        for item in data["matched_functions"][:30]:
            lines.append(f"  {item['symbol']} -> {item['source']}:{item['line']}")
    if data["external_source_questions"]:
        lines.append("questions:")
        for item in data["external_source_questions"][:20]:
            lines.append(f"  {item.get('symbol') or item.get('header')}: {item.get('question', '')}")
    _emit(args, data, "\n".join(lines) or "no external sources")
    return data


def cmd_externals_remove(args) -> dict:
    ws, config, analysis = _load(args)
    removed = externals_mod.remove_source(config, args.path, unlink=not args.keep_linked)
    ws.save_config(config)
    if removed and not args.keep_linked:
        reachability = read_json(ws.reachability_path, default=None)
        analysis, _, _ = _reanalyze(ws, config, reachability)
    else:
        _external_attach(ws, config, analysis)
    data = {"ok": removed, "removed": removed, "external_sources": config.get("external_sources", [])}
    _emit(args, data, f"removed {args.path}" if removed else f"not registered: {args.path}")
    return data


def cmd_externals_scan(args) -> dict:
    ws, config, analysis = _load(args)
    _external_attach(ws, config, analysis)
    data = {
        "ok": True,
        "external_source_summary": analysis.get("external_source_summary", {}),
        "external_source_questions": analysis.get("external_source_questions", []),
        "matched_functions": [
            item.get("qualified_name") or item.get("name")
            for item in analysis.get("external_symbols", [])
            if item.get("external_source")
        ],
    }
    _emit(args, data, json.dumps(data["external_source_summary"], ensure_ascii=False))
    return data


def cmd_externals_inquire(args) -> dict:
    ws, config, analysis = _load(args)
    _external_attach(ws, config, analysis)
    questions = analysis.get("external_source_questions", [])
    data = {"ok": True, "questions": questions}
    _emit(args, data, externals_mod.format_questions(questions) or "no external source questions")
    return data


def cmd_probe(args) -> dict:
    ws, config, analysis = _load(args)
    result = probe(ws, config, analysis)
    analysis["probe"] = {
        "unresolved": result.get("unresolved", []),
        "resolved": result.get("resolved", []),
        "unclassified_symbols": result.get("unclassified_symbols", []),
        "ok": result.get("ok", False),
    }
    externals_mod.attach(analysis, config)
    write_json(ws.analysis_path, analysis)
    data = {"ok": bool(result.get("ok")), **result}
    if result.get("ok"):
        text = (
            f"resolved: {len(result.get('resolved', []))}\n"
            f"unresolved: {len(result.get('unresolved', []))}\n"
            + "\n".join(f"  {item['signature']}" for item in result.get("unresolved", []))
        )
    else:
        text = f"probe failed at {result.get('stage')}: {result.get('log')}"
    _emit(args, data, text)
    return data


def cmd_config_show(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    _emit(args, {"ok": True, "config": config}, json.dumps(config, indent=2, ensure_ascii=False))
    return config


def cmd_config_set(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    import json

    if args.file:
        patch = read_json(args.file)
        if patch is None:
            raise DtfuzzError(f"file not found: {args.file}")
    elif args.patch_json:
        patch = json.loads(args.patch_json)
    else:
        raise DtfuzzError("pass --patch-json or --file")
    if not isinstance(patch, dict):
        raise DtfuzzError("config patch must be a JSON object")
    config = deep_merge(config, patch)
    ws.save_config(config)
    _emit(args, {"ok": True, "config": config}, f"updated {ws.config_path}")
    return config


def cmd_mocks_list(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    mocks = ws.load_mocks(config)
    analysis = read_json(ws.analysis_path, default={}) or {}
    data = {
        "ok": True,
        "mocks_path": str(ws.mocks_config_path(config)),
        "symbols": mocks_summary(mocks),
        "constraints": constraint_summary(mocks),
        "questions": mock_questions(mocks),
        "external_sources": config.get("external_sources", []),
        "external_source_summary": analysis.get("external_source_summary", {}),
        "external_source_questions": analysis.get("external_source_questions", []),
        "variables": mocks.get("variables", {}),
    }
    lines = []
    for item in data["symbols"]:
        lines.append(
            f"{item['symbol']}: confirmed={item['confirmed']} status={item['status']} "
            f"reachable={item.get('reachable', True)} scope={item.get('scope', 'unknown')} "
            f"return={item['return']!r} sequence={item['return_sequence']} out={item['out_params']} "
            f"source={item['source']} stub={item['stub']}"
        )
    if data["constraints"]:
        lines.append("constraints:")
        for item in data["constraints"]:
            marker = "[REVIEW]" if item.get("highlight") else "[OK]"
            lines.append(
                f"  {marker} {item['id']} {item['category_label']} {item['subject']}: {item['requirement']}"
            )
    if data["external_source_questions"]:
        lines.append("external source inquiry (ask the user for a mounted library/SDK directory):")
        for item in data["external_source_questions"][:20]:
            if item.get("kind") == "include":
                lines.append(f"  header {item.get('header')} (used by {item.get('file')})")
            else:
                lines.append(f"  {item.get('symbol')}: {item.get('signature', '')}")
    _emit(args, data, "\n".join(lines) or "no mocks")
    return data


def cmd_mocks_set(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    mocks = ws.load_mocks(config)
    patch: dict = {}
    if args.return_value is not None:
        patch["return"] = args.return_value
    if args.return_sequence is not None:
        patch["return_sequence"] = [item.strip() for item in args.return_sequence.split(",") if item.strip()]
    if args.out_param:
        payload = read_json(args.out_param) if Path(args.out_param).is_file() else None
        if payload is None:
            import json

            payload = json.loads(args.out_param)
        patch.setdefault("out_params", {}).update(payload)
    if args.out_param_json:
        import json

        patch.setdefault("out_params", {}).update(json.loads(args.out_param_json))
    if args.body_file:
        patch["body"] = Path(args.body_file).read_text(encoding="utf-8")
    if args.body:
        patch["body"] = args.body
    if args.no_stub:
        patch["stub"] = False
    if args.stub:
        patch["stub"] = True
    if args.note is not None:
        patch["note"] = args.note
    if not patch:
        raise DtfuzzError("nothing to update; pass --return, --return-sequence, --out-param-json, --body, --no-stub, ...")
    if "out_params" in patch:
        current = (mocks.get("symbols", {}).get(args.symbol, {}) or {}).get("out_params", {})
        patch["out_params"] = {**current, **patch["out_params"]}
    set_symbol(mocks, args.symbol, patch)
    ws.save_mocks(mocks, config)
    data = {"ok": True, "symbol": args.symbol, "entry": mocks["symbols"].get(args.symbol)}
    _emit(args, data, f"updated {args.symbol}")
    return data


def cmd_mocks_clear(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    existing = ws.load_mocks(config)
    # Constraints describe the entry's input contract, not mock code; keep them
    # unless the user explicitly clears the whole file.
    ws.save_mocks(
        {"version": 1, "symbols": {}, "variables": {}, "constraints": existing.get("constraints") or default_constraints()},
        config,
    )
    data = {"ok": True, "mocks_path": str(ws.mocks_config_path(config))}
    _emit(args, data, f"cleared {ws.mocks_config_path(config)}")
    return data


def cmd_mocks_import(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    incoming = read_json(args.file)
    if incoming is None:
        raise DtfuzzError(f"file not found: {args.file}")
    mocks = ws.load_mocks(config)
    imported = []
    if "symbols" in incoming:
        items = incoming["symbols"].items()
    else:
        items = (
            (key, value)
            for key, value in incoming.items()
            if key not in {"variables", "version", "constraints"}
        )
    for key, value in items:
        existing = mocks.get("symbols", {}).get(key, {})
        merged = deep_merge(existing, {k: v for k, v in value.items() if k != "out_params"})
        if "out_params" in value and isinstance(value["out_params"], dict):
            merged["out_params"] = {**existing.get("out_params", {}), **value["out_params"]}
        merged["source"] = value.get("source", "user")
        merged["confirmed"] = bool(value.get("confirmed", True))
        merged.pop("status", None)
        mocks.setdefault("symbols", {})[key] = merged
        imported.append(key)
    if "variables" in incoming:
        mocks.setdefault("variables", {}).update(incoming["variables"])
    constraints_added = []
    if "constraints" in incoming:
        constraints_added = merge_constraints(
            mocks, incoming["constraints"], source="user", confirmed=bool(getattr(args, "confirm_constraints", False))
        )
    ws.save_mocks(mocks, config)
    data = {
        "ok": True,
        "symbols": len(mocks.get("symbols", {})),
        "imported": imported,
        "constraints_added": constraints_added,
        "mocks_path": str(ws.mocks_config_path(config)),
    }
    _emit(args, data, f"imported {len(imported)} symbols into {ws.mocks_config_path(config)}")
    return data


def cmd_gen(args) -> dict:
    ws, config, analysis = _load(args)
    mocks = ws.load_mocks(config)
    result = generate_artifacts(config, analysis, ws, mocks)
    data = {"ok": True, **result}
    _emit(
        args,
        data,
        "\n".join(
            [
                f"harness: {result['harness']}",
                f"mocks dir: {result['mocks_dir']}",
                f"generated mocks: {result['generated_mocks']}",
                f"dict: {result['dict']} ({result['tokens']} tokens)",
                f"new seeds: {len(result['seeds_created'])}",
            ]
        ),
    )
    return data


def cmd_build(args) -> dict:
    ws, config, analysis = _load(args)
    mocks = ws.load_mocks(config)
    result = build(ws, config, analysis)
    if not result.get("ok") and args.auto_stub:
        result = auto_stub_and_rebuild(ws, config, analysis, mocks, result)
    data = {"ok": bool(result.get("ok")), **result}
    if result.get("ok"):
        text = f"built: {result['binary']}"
    else:
        text = f"build failed at {result.get('stage')}: {result.get('log')}"
        if result.get("undefined_symbols"):
            text += "\nundefined: " + ", ".join(result["undefined_symbols"])
            text += "\n" + result.get("suggestion", "")
    _emit(args, data, text)
    if not result.get("ok"):
        raise SystemExit(1)
    return data


def _print_round(ws: Workspace, run_result: dict, cov: dict) -> str:
    stats = run_result.get("stats", {})
    lines = [
        f"runs={stats.get('runs', '?')} execs={stats.get('number_of_executed_units', '?')} corpus={run_result.get('corpus_files')} crashes={len(run_result.get('crashes', []))}",
        coverage_mod.format_summary(cov),
        f"log: {run_result.get('log')}",
    ]
    return "\n".join(lines)


def cmd_run(args) -> dict:
    ws, config, analysis = _load(args)
    result = run_fuzz(ws, config, analysis, seconds=args.seconds, runs=args.runs, fork=args.fork)
    data = {"ok": True, **result}
    stats = result.get("stats", {})
    text = (
        f"runs={stats.get('runs', '?')} execs={stats.get('number_of_executed_units', '?')} "
        f"corpus={result.get('corpus_files')} crashes={len(result.get('crashes', []))}\n"
        f"log: {result.get('log')}"
    )
    _emit(args, data, text)
    return data


def cmd_coverage(args) -> dict:
    ws, config, analysis = _load(args)
    summary = coverage_mod.collect(ws, config, analysis)
    data = {"ok": True, **summary}
    _emit(args, data, coverage_mod.format_summary(summary))
    return data


def cmd_round(args) -> dict:
    ws, config, analysis = _load(args)
    run_result = run_fuzz(ws, config, analysis, seconds=args.seconds, runs=args.runs, fork=args.fork)
    try:
        summary = coverage_mod.collect(ws, config, analysis)
    except DtfuzzError as exc:
        data = {"ok": True, "run": run_result, "coverage": None, "coverage_error": str(exc)}
        text = (
            f"runs={run_result.get('stats', {}).get('runs', '?')} "
            f"corpus={run_result.get('corpus_files')} crashes={len(run_result.get('crashes', []))}\n"
            f"coverage unavailable: {exc}\n"
            f"log: {run_result.get('log')}"
        )
        _emit(args, data, text)
        return data
    data = {"ok": True, "run": run_result, "coverage": summary}
    _emit(args, data, _print_round(ws, run_result, summary))
    return data


def _regenerate_and_build(ws: Workspace, config: dict, analysis: dict) -> dict:
    mocks = ws.load_mocks(config)
    gen = generate_artifacts(config, analysis, ws, mocks)
    result = build(ws, config, analysis)
    return {"gen": gen, "build": result}


def cmd_optimize(args) -> dict:
    ws, config, analysis = _load(args)
    if args.mode == "import":
        if not args.file:
            raise DtfuzzError("--file is required for import mode")
        result = optimize_mod.import_seeds(ws, config, args.file)
        data = {"ok": True, "mode": "import", **result}
        if result.get("mocks_changed"):
            data["rebuild"] = _regenerate_and_build(ws, config, analysis)
        text = f"seeds added: {len(result['seeds_added'])}, dict added: {result['dict_added']}"
        if result.get("mocks_changed"):
            text += f", mocks patched: {result.get('mock_patches')}"
        _emit(args, data, text)
        return data
    summary = read_json(ws.coverage_dir / "summary.json")
    if summary is None:
        raise DtfuzzError("coverage missing; run `dtfuzz round` or `dtfuzz coverage` first")
    result = optimize_mod.optimize(ws, config, analysis, summary, args.mode)
    data = {"ok": True, **result}
    if result.get("mocks_changed"):
        data["rebuild"] = _regenerate_and_build(ws, config, analysis)
    if result.get("next"):
        text = f"prompt: {result['prompt']}\nnext: {result['next']}"
    else:
        text = f"seeds added: {len(result.get('seeds_added', []))}, dict added: {result.get('dict_added', 0)}"
        if result.get("mocks_changed"):
            text += f", mocks patched: {result.get('mock_patches')}"
    _emit(args, data, text)
    return data


def cmd_seed_add(args) -> dict:
    ws = _workspace(args)
    config = ws.load_config()
    seeds = []
    for value in args.hex or []:
        seeds.append(parse_hex(value))
    for file_name in args.file or []:
        seeds.append(Path(file_name).read_bytes())
    if args.json_file:
        payload = read_json(args.json_file)
        if isinstance(payload, list):
            for item in payload:
                seeds.append(parse_hex(item if isinstance(item, str) else item.get("hex", "")))
        elif isinstance(payload, dict):
            for item in payload.get("seeds", []):
                seeds.append(parse_hex(item if isinstance(item, str) else item.get("hex", "")))
    if not seeds:
        raise DtfuzzError("no seeds; pass --hex or --file")
    created = write_corpus_seeds(ws.corpus_dir, seeds, {"source": args.source})
    data = {"ok": True, "created": created}
    _emit(args, data, "\n".join(f"{item['hex']}  ({item['size']} bytes)" for item in created) or "no new seeds")
    return data


def cmd_campaign(args) -> dict:
    ws, config, analysis = _load(args)
    mocks = ws.load_mocks(config)
    result = run_campaign(ws, config, analysis, mocks, seconds=args.seconds, max_rounds=args.max_rounds)
    data = result
    if result.get("ok"):
        text = f"rounds={result.get('rounds')} stop={result.get('stop_reason')}"
        if result.get("final_coverage"):
            text += "\n" + coverage_mod.format_summary(result["final_coverage"])
    else:
        text = f"campaign failed: {result.get('reason')}"
    _emit(args, data, text)
    return data


def cmd_report(args) -> dict:
    ws, config, analysis = _load(args)
    mocks = ws.load_mocks(config)
    text = generate_report(ws, config, analysis, mocks)
    data = {"ok": True, "report": str(ws.root / "report.md"), "markdown": text}
    _emit(args, data, f"report: {ws.root / 'report.md'}")
    return data


def cmd_repro(args) -> dict:
    ws, config, analysis = _load(args)
    binary = ws.binary_path
    if not binary.is_file():
        raise DtfuzzError("fuzz binary missing; run `dtfuzz build` first")
    input_path = Path(args.input)
    if not input_path.is_file():
        raise DtfuzzError(f"input not found: {input_path}")
    from .util import run

    proc = run([str(binary), str(input_path), "-runs=1"], cwd=config.get("repo") or None, timeout=120)
    text = (proc.stderr or "") + "\n" + (proc.stdout or "")
    data = {"ok": True, "returncode": proc.returncode, "output": text[-12000:]}
    _emit(args, data, text[-6000:])
    return data


def cmd_clean(args) -> dict:
    ws = _workspace(args)
    removed = []
    targets = []
    if args.all or args.build:
        targets.append(ws.build_dir)
    if args.all or args.coverage:
        targets.append(ws.coverage_dir)
    if args.all or args.corpus:
        targets.append(ws.corpus_dir)
    if args.all or args.artifacts:
        targets.append(ws.artifacts_dir)
    for target in targets:
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            removed.append(str(target))
    ws.ensure()
    data = {"ok": True, "removed": removed}
    _emit(args, data, "\n".join(removed) or "nothing removed")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dtfuzz", description="Coverage-guided libFuzzer campaigns for message-entry modules.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_json(p):
        p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("doctor", help="check clang/libFuzzer/llvm-cov toolchain")
    p.add_argument("--repo")
    add_json(p)
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("init", help="analyze a module and create a workspace")
    p.add_argument("--repo")
    p.add_argument("--module")
    p.add_argument("--entry", required=True)
    p.add_argument("--source")
    p.add_argument("--include", action="append")
    p.add_argument("--define", action="append")
    p.add_argument("--std")
    p.add_argument("--language", choices=["c", "cpp"])
    p.add_argument("--build-system")
    p.add_argument("--workdir")
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-real-scan", action="store_true", help="analyze only the entry; use for prebuilt libraries")
    p.add_argument("--introspector", help="Fuzz Introspector fuzzerLogFile-*.data.yaml or calltree report")
    p.add_argument("--no-introspector", action="store_true", help="ignore Fuzz Introspector and use AST reachability only")
    p.add_argument(
        "--external-source",
        action="append",
        help="user-provided library/SDK source directory (read-only context; repeatable)",
    )
    add_json(p)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("analyze", help="re-run clang analysis")
    p.add_argument("--workdir", required=True)
    p.add_argument("--introspector", help="Fuzz Introspector report to use for reachability")
    p.add_argument("--no-introspector", action="store_true")
    add_json(p)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("introspect", help="apply Fuzz Introspector reachability and recompute the stub scope")
    p.add_argument("--workdir", required=True)
    p.add_argument("--report", help="Fuzz Introspector fuzzerLogFile-*.data.yaml / calltree / JSON")
    p.add_argument("--run-light", action="store_true", help="run fuzz-introspector's source-only frontend (needs --fi-src)")
    p.add_argument("--run-lto", action="store_true", help="compile with the Fuzz Introspector LTO pass (needs --fi-clang)")
    p.add_argument("--fi-clang", help="clang built with the Fuzz Introspector LLVM pass")
    p.add_argument("--fi-src", help="path to the fuzz-introspector checkout")
    add_json(p)
    p.set_defaults(func=cmd_introspect)

    p = sub.add_parser("probe", help="compile target+real sources and list unlinkable symbols")
    p.add_argument("--workdir", required=True)
    add_json(p)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("config", help="show or patch config.json")
    csub = p.add_subparsers(dest="config_command", required=True)
    c = csub.add_parser("show")
    c.add_argument("--workdir", required=True)
    add_json(c)
    c.set_defaults(func=cmd_config_show)
    c = csub.add_parser("set")
    c.add_argument("--workdir", required=True)
    c.add_argument("--patch-json")
    c.add_argument("--file")
    add_json(c)
    c.set_defaults(func=cmd_config_set)

    p = sub.add_parser("mocks", help="inspect or edit mock config")
    msub = p.add_subparsers(dest="mocks_command", required=True)
    m = msub.add_parser("list")
    m.add_argument("--workdir", required=True)
    add_json(m)
    m.set_defaults(func=cmd_mocks_list)
    m = msub.add_parser("set")
    m.add_argument("--workdir", required=True)
    m.add_argument("--symbol", required=True)
    m.add_argument("--return", dest="return_value")
    m.add_argument("--return-sequence")
    m.add_argument("--out-param")
    m.add_argument("--out-param-json")
    m.add_argument("--body")
    m.add_argument("--body-file")
    m.add_argument("--no-stub", action="store_true")
    m.add_argument("--stub", action="store_true")
    m.add_argument("--note")
    add_json(m)
    m.set_defaults(func=cmd_mocks_set)
    m = msub.add_parser("import")
    m.add_argument("--workdir", required=True)
    m.add_argument("--file", required=True)
    m.add_argument("--confirm-constraints", action="store_true", help="mark imported input constraints as human-confirmed")
    add_json(m)
    m.set_defaults(func=cmd_mocks_import)
    m = msub.add_parser("clear")
    m.add_argument("--workdir", required=True)
    add_json(m)
    m.set_defaults(func=cmd_mocks_clear)

    p = sub.add_parser("constraints", help="manage the four classes of input constraints")
    csub = p.add_subparsers(dest="constraints_command", required=True)
    c = csub.add_parser("list")
    c.add_argument("--workdir", required=True)
    c.add_argument("--category", choices=["input_construction", "variable_constraints", "input_relations", "setup_teardown"])
    c.add_argument("--all", action="store_true", help="include rejected entries")
    add_json(c)
    c.set_defaults(func=cmd_constraints_list)
    c = csub.add_parser("confirm")
    c.add_argument("--workdir", required=True)
    c.add_argument("--id", action="append", required=True)
    add_json(c)
    c.set_defaults(func=cmd_constraints_confirm)
    c = csub.add_parser("reject")
    c.add_argument("--workdir", required=True)
    c.add_argument("--id", action="append", required=True)
    c.add_argument("--note")
    add_json(c)
    c.set_defaults(func=cmd_constraints_reject)
    c = csub.add_parser("import")
    c.add_argument("--workdir", required=True)
    c.add_argument("--file", required=True)
    c.add_argument("--source", default="user")
    c.add_argument("--confirm", action="store_true")
    add_json(c)
    c.set_defaults(func=cmd_constraints_import)
    c = csub.add_parser("draft")
    c.add_argument("--workdir", required=True)
    c.add_argument("--mode", choices=["prompt", "claude-cli", "anthropic-api", "api"], default="prompt")
    c.add_argument("--file")
    add_json(c)
    c.set_defaults(func=cmd_constraints_draft)

    p = sub.add_parser("externals", help="register user-provided library/SDK source directories")
    esub = p.add_subparsers(dest="externals_command", required=True)
    e = esub.add_parser("add")
    e.add_argument("--workdir", required=True)
    e.add_argument("--path", required=True)
    e.add_argument("--name")
    e.add_argument("--link", action="store_true", help="treat the source as production code and add it to sources.real")
    e.add_argument("--include-dir", action="append")
    e.add_argument("--define", action="append")
    e.add_argument("--std")
    add_json(e)
    e.set_defaults(func=cmd_externals_add)
    e = esub.add_parser("list")
    e.add_argument("--workdir", required=True)
    add_json(e)
    e.set_defaults(func=cmd_externals_list)
    e = esub.add_parser("remove")
    e.add_argument("--workdir", required=True)
    e.add_argument("--path", required=True)
    e.add_argument("--keep-linked", action="store_true")
    add_json(e)
    e.set_defaults(func=cmd_externals_remove)
    e = esub.add_parser("scan")
    e.add_argument("--workdir", required=True)
    add_json(e)
    e.set_defaults(func=cmd_externals_scan)
    e = esub.add_parser("inquire")
    e.add_argument("--workdir", required=True)
    add_json(e)
    e.set_defaults(func=cmd_externals_inquire)

    p = sub.add_parser("gen", help="generate harness, stubs, dict and seeds")
    p.add_argument("--workdir", required=True)
    add_json(p)
    p.set_defaults(func=cmd_gen)

    p = sub.add_parser("build", help="compile the fuzz target")
    p.add_argument("--workdir", required=True)
    p.add_argument("--auto-stub", action="store_true", help="unsafe fallback: generate default mocks for unlinkable symbols without human rules")
    p.set_defaults(auto_stub=False)
    add_json(p)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("run", help="run the fuzzer")
    p.add_argument("--workdir", required=True)
    p.add_argument("--seconds", type=int)
    p.add_argument("--runs", type=int)
    p.add_argument("--fork", action="store_true", default=None)
    add_json(p)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("coverage", help="collect coverage from the last run")
    p.add_argument("--workdir", required=True)
    add_json(p)
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("round", help="run + collect coverage")
    p.add_argument("--workdir", required=True)
    p.add_argument("--seconds", type=int)
    p.add_argument("--runs", type=int)
    p.add_argument("--fork", action="store_true", default=None)
    add_json(p)
    p.set_defaults(func=cmd_round)

    p = sub.add_parser("optimize", help="produce a seed-optimization prompt or call an LLM optimizer")
    p.add_argument("--workdir", required=True)
    p.add_argument("--mode", choices=["none", "prompt", "claude-cli", "anthropic-api", "api", "import"], default=None)
    p.add_argument("--file")
    add_json(p)
    p.set_defaults(func=cmd_optimize)

    p = sub.add_parser("seed", help="manage corpus seeds")
    ssub = p.add_subparsers(dest="seed_command", required=True)
    s = ssub.add_parser("add")
    s.add_argument("--workdir", required=True)
    s.add_argument("--hex", action="append")
    s.add_argument("--file", action="append")
    s.add_argument("--json-file")
    s.add_argument("--source", default="agent")
    add_json(s)
    s.set_defaults(func=cmd_seed_add)

    p = sub.add_parser("campaign", help="build + run + coverage + optimize loop")
    p.add_argument("--workdir", required=True)
    p.add_argument("--seconds", type=int)
    p.add_argument("--max-rounds", type=int)
    add_json(p)
    p.set_defaults(func=cmd_campaign)

    p = sub.add_parser("report", help="write report.md")
    p.add_argument("--workdir", required=True)
    add_json(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("repro", help="reproduce a crash input")
    p.add_argument("--workdir", required=True)
    p.add_argument("--input", required=True)
    add_json(p)
    p.set_defaults(func=cmd_repro)

    p = sub.add_parser("clean", help="remove generated build/coverage/corpus artifacts")
    p.add_argument("--workdir", required=True)
    p.add_argument("--all", action="store_true")
    p.add_argument("--build", action="store_true")
    p.add_argument("--coverage", action="store_true")
    p.add_argument("--corpus", action="store_true")
    p.add_argument("--artifacts", action="store_true")
    add_json(p)
    p.set_defaults(func=cmd_clean)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except DtfuzzError as exc:
        if getattr(args, "json", False):
            print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        if getattr(args, "json", False):
            print_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        else:
            raise
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
