from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .util import DtfuzzError, now_iso, read_json, rel_to, sha256_file, write_json, run

REGION_CODE = 0
REGION_EXPANSION = 1
REGION_BRANCH = 4
REGION_SKIP = {2, 3, 5, 6}


def _norm(path: str) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(path)


def _split_mangled(name: str) -> tuple[str, str]:
    index = name.rfind(":")
    if index >= 0:
        tail = name[index + 1 :]
        if tail.startswith("_Z") or tail.startswith("?"):
            return name[: index + 1], tail
    if name.startswith("_Z") or name.startswith("?"):
        return "", name
    return "", name


def demangle_names(names: list[str], toolchain: dict) -> dict[str, str]:
    demangler = toolchain.get("llvm_cxxfilt") or ""
    if not demangler or not names:
        return {name: name for name in names}
    unique = list(dict.fromkeys(names))
    prefixes: dict[str, str] = {}
    tails: list[str] = []
    for name in unique:
        prefix, tail = _split_mangled(name)
        prefixes[name] = prefix
        tails.append(tail or name)
    proc = run([demangler], input_text="\n".join(tails), timeout=60)
    if proc.returncode != 0:
        return {name: name for name in names}
    lines = proc.stdout.splitlines()
    if len(lines) != len(unique):
        return {name: name for name in names}
    return {name: prefixes[name] + lines[index] for index, name in enumerate(unique)}


def _target_set(config: dict, analysis: dict) -> set[str]:
    values = list((config.get("coverage", {}) or {}).get("target_files") or [])
    if not values:
        values = list(analysis.get("target_files") or [])
    repo = config.get("repo", "")
    result = set()
    for item in values:
        path = Path(item)
        if not path.is_absolute() and repo:
            path = Path(repo) / path
        result.add(_norm(str(path)))
    return result


def _summary(entry: dict) -> dict:
    return {
        "count": int(entry.get("count", 0)),
        "covered": int(entry.get("covered", 0)),
        "percent": round(float(entry.get("percent", 0.0)), 2),
    }


def _aggregate(items: list[dict], key: str) -> dict:
    count = sum(int(item.get(key, {}).get("count", 0)) for item in items)
    covered = sum(int(item.get(key, {}).get("covered", 0)) for item in items)
    percent = round((covered * 100.0 / count) if count else 0.0, 2)
    return {"count": count, "covered": covered, "percent": percent}


def _region_lines(function: dict) -> set[int]:
    lines: set[int] = set()
    for region in function.get("regions", []) or []:
        if not isinstance(region, list) or len(region) < 8:
            continue
        start_line, _, end_line, _, count, _, _, kind = region[:8]
        # Only real code regions describe source lines. Expansion, skipped,
        # gap, and branch regions have synthetic ranges and zero counts.
        if int(kind) != REGION_CODE:
            continue
        if count == 0:
            for line in range(int(start_line), int(end_line) + 1):
                lines.add(line)
    return lines


def _code_lines(function: dict) -> set[int]:
    """All source lines described by code regions (not expansion/branch/gap)."""
    lines: set[int] = set()
    for region in function.get("regions", []) or []:
        if not isinstance(region, list) or len(region) < 8:
            continue
        start_line, _, end_line, _, _, _, _, kind = region[:8]
        if int(kind) != REGION_CODE:
            continue
        lines.update(range(int(start_line), int(end_line) + 1))
    return lines


def _segment_uncovered_lines(file_entry: dict) -> set[int]:
    lines: set[int] = set()
    for segment in file_entry.get("segments", []) or []:
        if not isinstance(segment, list) or len(segment) < 6:
            continue
        line, _, count, has_count, _, is_gap = segment[:6]
        if has_count and count == 0 and not is_gap:
            lines.add(int(line))
    return lines


def collect(workspace, config: dict, analysis: dict) -> dict:
    toolchain = config.get("toolchain", {}) or {}
    llvm_profdata = toolchain.get("llvm_profdata") or "llvm-profdata"
    llvm_cov = toolchain.get("llvm_cov") or "llvm-cov"
    binary = workspace.binary_path
    if not binary.is_file():
        raise DtfuzzError("fuzz binary missing; run `dtfuzz build` first")
    raw_dir = workspace.coverage_dir / "raw"
    raw_profiles = sorted(raw_dir.glob("*.profraw"))
    if not raw_profiles:
        raise DtfuzzError("no .profraw files found; run the fuzzer first (dtfuzz run/round)")
    merged = workspace.coverage_dir / "merged.profdata"
    merge_cmd = [llvm_profdata, "merge", "-sparse", *[str(item) for item in raw_profiles], "-o", str(merged)]
    proc = run(merge_cmd, timeout=300)
    if proc.returncode != 0:
        raise DtfuzzError(f"llvm-profdata merge failed:\n{proc.stderr or proc.stdout}")
    export_cmd = [llvm_cov, "export", f"-instr-profile={merged}", str(binary)]
    proc = run(export_cmd, timeout=300)
    if proc.returncode != 0:
        raise DtfuzzError(f"llvm-cov export failed:\n{proc.stderr or proc.stdout}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise DtfuzzError(f"llvm-cov returned invalid JSON: {exc}") from exc
    blocks = data.get("data") or []
    if not blocks:
        raise DtfuzzError("llvm-cov returned no coverage data")
    block = blocks[0]
    targets = _target_set(config, analysis)
    repo = config.get("repo", "")
    files_out: dict[str, dict] = {}
    file_entries = []
    for file_entry in block.get("files", []) or []:
        filename = _norm(file_entry.get("filename", ""))
        if targets and filename not in targets:
            continue
        file_entries.append(file_entry)
        files_out[rel_to(filename, repo) if repo else filename] = {
            "lines": _summary(file_entry.get("summary", {}).get("lines", {})),
            "functions": _summary(file_entry.get("summary", {}).get("functions", {})),
            "branches": _summary(file_entry.get("summary", {}).get("branches", {})),
            "uncovered_lines": sorted(_segment_uncovered_lines(file_entry)),
        }
    if not file_entries and targets:
        for file_entry in block.get("files", []) or []:
            filename = _norm(file_entry.get("filename", ""))
            if any(filename.endswith(Path(target).name) for target in targets):
                file_entries.append(file_entry)
                files_out[rel_to(filename, repo) if repo else filename] = {
                    "lines": _summary(file_entry.get("summary", {}).get("lines", {})),
                    "functions": _summary(file_entry.get("summary", {}).get("functions", {})),
                    "branches": _summary(file_entry.get("summary", {}).get("branches", {})),
                    "uncovered_lines": sorted(_segment_uncovered_lines(file_entry)),
                }
    functions_out = []
    uncovered_functions = []
    partial_functions = []
    raw_names = [function.get("name", "") for function in block.get("functions", []) or []]
    demangled = demangle_names(raw_names, toolchain)
    for function in block.get("functions", []) or []:
        filenames = [_norm(item) for item in function.get("filenames", []) or []]
        matched = [item for item in filenames if item in targets] if targets else filenames
        if targets and not matched:
            continue
        filename = matched[0] if matched else (filenames[0] if filenames else "")
        raw_name = function.get("name", "")
        uncovered = _region_lines(function)
        code_lines = _code_lines(function)
        covered_lines = code_lines - uncovered
        record = {
            "name": demangled.get(raw_name, raw_name),
            "raw_name": raw_name,
            "file": rel_to(filename, repo) if repo else filename,
            "count": int(function.get("count", 0)),
            "regions": len(function.get("regions", []) or []),
            "total_lines": len(code_lines),
            "covered_lines": len(covered_lines),
            "percent": round(len(covered_lines) * 100.0 / len(code_lines), 2) if code_lines else 0.0,
            "uncovered_lines": sorted(uncovered),
        }
        functions_out.append(record)
        if record["count"] == 0:
            uncovered_functions.append(record)
        elif record["uncovered_lines"]:
            partial_functions.append(record)
    uncovered_lines: dict[str, list[int]] = {}
    for key, item in files_out.items():
        lines = set(item.get("uncovered_lines", []))
        for function in uncovered_functions + partial_functions:
            if function["file"] == key:
                lines.update(function.get("uncovered_lines", []))
        if lines:
            uncovered_lines[key] = sorted(lines)
            files_out[key]["uncovered_lines"] = sorted(lines)
    file_summaries = [entry.get("summary", {}) for entry in file_entries]
    summary = {
        "version": 1,
        "time": now_iso(),
        "line": _aggregate(file_summaries, "lines"),
        "function": _aggregate(file_summaries, "functions"),
        "branch": _aggregate(file_summaries, "branches"),
        "files": files_out,
        "functions": functions_out,
        "uncovered_functions": uncovered_functions,
        "partial_functions": partial_functions,
        "uncovered_lines": uncovered_lines,
        "raw_profiles": len(raw_profiles),
        "profdata": str(merged),
        "profdata_sha256": sha256_file(merged),
        "target_files": sorted(rel_to(item, repo) if repo else item for item in targets),
        "source_hash": {
            rel_to(item, repo) if repo else item: sha256_file(item)
            for item in targets
            if Path(item).is_file()
        },
    }
    runs = read_json(workspace.runs_dir / "history.json", default=[]) or []
    last_run = runs[-1] if runs else {}
    run_stats = last_run.get("stats", {}) or {}
    summary["libfuzzer"] = {
        "cov": run_stats.get("cov"),
        "ft": run_stats.get("ft"),
        "corp": run_stats.get("corp"),
        "execs": run_stats.get("number_of_executed_units"),
        "round_seconds": last_run.get("seconds"),
    }
    if targets and not files_out:
        summary["warning"] = "coverage JSON did not contain any configured target file; check instrumentation and file paths."
    history_path = workspace.coverage_dir / "history.json"
    history = read_json(history_path, default=[]) or []
    profile_hash = summary["profdata_sha256"]
    previous = history[-1] if history else None
    same_profile = bool(previous and previous.get("profdata_sha256") == profile_hash)
    round_no = int(previous.get("round", 0)) if same_profile else len(history) + 1
    summary["round"] = round_no
    write_json(workspace.coverage_dir / "summary.json", summary)
    entry = {
        "round": round_no,
        "time": summary["time"],
        "line_percent": summary["line"]["percent"],
        "function_percent": summary["function"]["percent"],
        "branch_percent": summary["branch"]["percent"],
        "uncovered_functions": len(uncovered_functions),
        "partial_functions": len(partial_functions),
        "raw_profiles": len(raw_profiles),
        "profdata_sha256": profile_hash,
        "libfuzzer_cov": summary["libfuzzer"].get("cov"),
        "libfuzzer_ft": summary["libfuzzer"].get("ft"),
        "corpus_files": summary["libfuzzer"].get("corp"),
    }
    if same_profile:
        history[-1] = entry
    else:
        history.append(entry)
    write_json(history_path, history)
    return summary


def format_summary(summary: dict) -> str:
    libfuzzer = summary.get("libfuzzer") or {}
    lines = [
        f"round {summary.get('round', '?')}  "
        f"lines {summary['line']['percent']}% ({summary['line']['covered']}/{summary['line']['count']})  "
        f"functions {summary['function']['percent']}% ({summary['function']['covered']}/{summary['function']['count']})  "
        f"branches {summary['branch']['percent']}%  "
        f"libFuzzer cov={libfuzzer.get('cov')} ft={libfuzzer.get('ft')} corp={libfuzzer.get('corp')}",
    ]
    for name, item in summary.get("files", {}).items():
        lines.append(f"  {name}: lines {item['lines']['percent']}% ({item['lines']['covered']}/{item['lines']['count']})")
    if summary.get("uncovered_functions"):
        lines.append("uncovered functions:")
        for function in summary["uncovered_functions"][:15]:
            lines.append(f"  - {function['name']} ({function['file']})")
    return "\n".join(lines)
