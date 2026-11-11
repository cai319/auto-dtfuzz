from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Any

from . import makefile as makefile_mod
from .util import DtfuzzError, now_iso, read_json, rel_to, resolve, run, sha256_text, write_json, write_text

CPP_EXTS = {".cc", ".cpp", ".cxx", ".c++", ".mm"}
C_EXTS = {".c", ".m"}


def _abs(path: str | Path, repo: str | Path) -> str:
    return str(resolve(path, repo))


def resolve_sources(config: dict, analysis: dict) -> list[str]:
    repo = config.get("repo", "")
    sources: list[str] = []
    configured = config.get("sources", {}).get("target") or []
    if configured:
        sources.extend(_abs(item, repo) for item in configured)
    else:
        sources.extend(analysis.get("internal_files", []))
    sources.extend(_abs(item, repo) for item in (config.get("sources", {}).get("real") or []))
    excluded = {_abs(item, repo) for item in (config.get("sources", {}).get("exclude") or [])}
    result: list[str] = []
    for item in sources:
        if item in excluded or not Path(item).is_file():
            continue
        if item not in result:
            result.append(item)
    libraries = list((config.get("sources", {}) or {}).get("libraries") or [])
    if not result and not libraries:
        raise DtfuzzError("no target sources; set sources.target or sources.libraries, or let dtfuzz init discover them")
    return result


def _compiler_for(path: str, clang: str, clangxx: str) -> str:
    suffix = Path(path).suffix.lower()
    return clangxx if suffix in CPP_EXTS else clang


def _std_flags(config: dict, path: str) -> list[str]:
    std = (config.get("sources", {}).get("std") or "").strip()
    if std:
        return [f"-std={std}"]
    suffix = Path(path).suffix.lower()
    if suffix in CPP_EXTS:
        return ["-std=c++17"]
    return ["-std=gnu11"]


def _compile_flags(
    config: dict,
    toolchain: dict,
    source: str,
    extra_include_dirs: list[str] | None = None,
    extra_flags: list[str] | None = None,
) -> list[str]:
    sources = config.get("sources", {})
    include_dirs = []
    repo = config.get("repo", "")
    for directory in list(sources.get("include_dirs", [])) + list(toolchain.get("include_dirs", [])) + list(extra_include_dirs or []):
        include_dirs.append(_abs(directory, repo))
    if repo:
        include_dirs.append(str(Path(repo).resolve()))
    include_dirs = list(dict.fromkeys(include_dirs))
    flags = ["-g", "-O1", "-fno-omit-frame-pointer", "-fno-common"]
    sanitizers = (config.get("fuzz", {}) or {}).get("sanitizers", "address")
    fuzzer_flags = "fuzzer-no-link" + (f",{sanitizers}" if sanitizers else "")
    flags.append(f"-fsanitize={fuzzer_flags}")
    flags.extend(["-fprofile-instr-generate", "-fcoverage-mapping"])
    flags.extend(_std_flags(config, source))
    for directory in include_dirs:
        flags.extend(["-I", directory])
    for define in sources.get("defines", []) or []:
        flags.append("-D" + str(define))
    flags.extend([str(item) for item in sources.get("extra_cflags", []) or []])
    flags.extend(extra_flags or [])
    return flags


def _link_flags(config: dict, clangxx: str, repo: str = "") -> list[str]:
    sanitizers = (config.get("fuzz", {}) or {}).get("sanitizers", "address")
    flags = [f"-fsanitize=fuzzer,{sanitizers}" if sanitizers else "-fsanitize=fuzzer", "-fprofile-instr-generate"]
    flags.extend([str(item) for item in (config.get("sources", {}).get("extra_ldflags") or [])])
    for library in (config.get("sources", {}) or {}).get("libraries") or []:
        value = str(library)
        if value.startswith("-"):
            flags.append(value)
        else:
            flags.append(str(resolve(value, repo)) if repo else value)
    return flags


def _compile_one(compiler: str, source: str, obj: str, flags: list[str], cwd: str) -> dict:
    cmd = [compiler] + flags + ["-c", source, "-o", obj]
    proc = run(cmd, cwd=cwd, timeout=600)
    return {
        "command": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "source": source,
        "object": obj,
    }


def _undefined_symbols(text: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r'Undefined symbols for architecture[^:]*:\s*\n(.*?)(?:\nld:|\Z)', text, re.S):
        block = match.group(1)
        for item in re.findall(r'"([^"]+)"', block):
            names.append(item)
    for match in re.finditer(r"undefined reference to [`'\"]([^`'\"]+)[`'\"]", text):
        names.append(match.group(1))
    for match in re.finditer(r"undefined symbol:\s*([^\s]+)", text):
        names.append(match.group(1))
    return list(dict.fromkeys(names))


def _find_symbol(analysis: dict, raw: str) -> dict | None:
    candidates = analysis.get("external_symbols", [])
    names = {raw, raw.lstrip("_")}
    for symbol in candidates:
        if symbol.get("name") in names or symbol.get("mangled_name") in names:
            return symbol
    return None


def build(workspace, config: dict, analysis: dict, auto_stub: bool = False, jobs: int = 1) -> dict:
    workspace.ensure()
    repo = config.get("repo", "")
    toolchain = config.get("toolchain", {})
    build_cfg = config.get("build", {}) or {}
    make_intro = analysis.get("makefile")
    make_host = None
    if build_cfg.get("mode") == "make-host":
        if not make_intro:
            make_intro = makefile_mod.introspect(
                repo,
                build_cfg.get("makefile") or "Makefile",
                build_cfg.get("make_target") or "",
            )
            analysis["makefile"] = make_intro
        sources_cfg = config.setdefault("sources", {})
        sources_cfg["include_dirs"] = list(dict.fromkeys(
            [*(sources_cfg.get("include_dirs") or []), *(make_intro.get("include_dirs") or [])]
        ))
        sources_cfg["defines"] = list(dict.fromkeys(
            [*(sources_cfg.get("defines") or []), *(make_intro.get("defines") or [])]
        ))
        if not sources_cfg.get("std") and make_intro.get("std"):
            sources_cfg["std"] = make_intro["std"]
        if build_cfg.get("run_make", True):
            make_host = makefile_mod.run_host_make(workspace, config, analysis, make_intro)
    clang = toolchain.get("clang") or "clang"
    clangxx = str(Path(clang).with_name("clang++")) if Path(clang).with_name("clang++").is_file() else "clang++"
    harness_candidates = [
        workspace.harness_dir / "fuzz_target.cc",
        workspace.harness_dir / "fuzz_target.c",
    ]
    harness = next((item for item in harness_candidates if item.is_file()), None)
    if harness is None:
        raise DtfuzzError("harness missing; run `dtfuzz gen` first")
    mocks_dir = workspace.mocks_dir(config)
    generated_mocks = workspace.generated_mocks_path(config)
    if not generated_mocks.is_file():
        raise DtfuzzError("generated mocks missing; run `dtfuzz gen` first")

    sources = resolve_sources(config, analysis)
    compile_units = list(sources)
    if harness not in compile_units:
        compile_units.append(str(harness))
    if generated_mocks not in compile_units:
        compile_units.append(str(generated_mocks))
    for custom_name in (config.get("mocks", {}) or {}).get("custom_files", []) or []:
        custom = mocks_dir / str(custom_name)
        if custom.is_file() and str(custom) not in compile_units:
            compile_units.append(str(custom))
    for variables_name in ("generated_variables.cc", "generated_variables.c"):
        variables = mocks_dir / variables_name
        if variables.is_file() and str(variables) not in compile_units:
            compile_units.append(str(variables))

    obj_dir = workspace.build_dir / "obj"
    obj_dir.mkdir(parents=True, exist_ok=True)
    commands: list[list[str]] = []
    compile_results: list[dict] = []
    objects: list[str] = []
    has_cpp = any(Path(item).suffix.lower() in CPP_EXTS for item in compile_units)
    for source in compile_units:
        compiler = _compiler_for(source, clang, clangxx)
        if Path(source).suffix.lower() in CPP_EXTS:
            has_cpp = True
        obj = obj_dir / (sha256_text(source)[:16] + ".o")
        extra_flags = (make_intro or {}).get("flags_by_source", {}).get(str(Path(source).resolve()), [])
        flags = _compile_flags(
            config, toolchain, source, [str(workspace.harness_dir), str(mocks_dir)], extra_flags
        )
        result = _compile_one(compiler, source, str(obj), flags, repo or str(workspace.root))
        compile_results.append(result)
        commands.append(result["command"])
        if result["returncode"] == 0:
            objects.append(str(obj))

    log_parts = []
    for item in compile_results:
        if item["returncode"] != 0:
            log_parts.append(f"$ {' '.join(shlex.quote(part) for part in item['command'])}")
            log_parts.append(item["stderr"] or item["stdout"])
    build_log = workspace.build_dir / "build.log"
    write_text(build_log, "\n\n".join(log_parts))
    if any(item["returncode"] != 0 for item in compile_results):
        write_text(workspace.build_dir / "build.sh", "#!/bin/sh\n" + "\n".join(shlex.join(cmd) for cmd in commands) + "\n")
        result = {
            "ok": False,
            "stage": "compile",
            "build_mode": build_cfg.get("mode", "direct"),
            "make_host": make_host,
            "makefile": (make_intro or {}).get("makefile", ""),
            "binary": "",
            "log": str(build_log),
            "commands": commands,
            "failed": [item for item in compile_results if item["returncode"] != 0],
        }
        write_json(workspace.build_dir / "build.json", result)
        return result

    link_compiler = clangxx if has_cpp else clang
    binary = workspace.binary_path
    link_cmd = [link_compiler] + objects + ["-o", str(binary)] + _link_flags(config, clangxx, repo)
    commands.append(link_cmd)
    link = run(link_cmd, cwd=repo or str(workspace.root), timeout=600)
    if link.returncode != 0:
        missing = _undefined_symbols((link.stderr or "") + "\n" + (link.stdout or ""))
        known = []
        for raw in missing:
            symbol = _find_symbol(analysis, raw)
            if symbol:
                known.append(
                    {
                        "raw": raw,
                        "symbol": symbol.get("name"),
                        "signature": symbol.get("signature", ""),
                        "reachable": symbol.get("reachable", True),
                        "scope": symbol.get("scope", "unknown"),
                        "must_link": bool(symbol.get("must_link")),
                    }
                )
        log_text = f"$ {shlex.join(link_cmd)}\n{link.stderr}{link.stdout}"
        existing = build_log.read_text(encoding="utf-8", errors="replace") if build_log.exists() else ""
        write_text(build_log, existing + "\n\n" + log_text)
        write_text(workspace.build_dir / "build.sh", "#!/bin/sh\n" + "\n".join(shlex.join(cmd) for cmd in commands) + "\n")
        mocks = workspace.load_mocks(config)
        must_link = [
            {
                "symbol": item.get("qualified_name") or item.get("name", ""),
                "signature": item.get("signature", ""),
                "status": item.get("status", ""),
                "definition_files": item.get("definition_files", []),
                "external_source": (item.get("external_source") or {}).get("file", ""),
            }
            for item in analysis.get("external_symbols", [])
            if item.get("must_link")
        ]
        pending = [
            {
                "symbol": key,
                "signature": symbol.get("signature", ""),
                "status": symbol.get("status", "pending"),
                "confirmed": bool(symbol.get("confirmed", False)),
            }
            for key, symbol in sorted((mocks.get("symbols") or {}).items())
            if not symbol.get("confirmed", False)
            and symbol.get("stub", True)
            and symbol.get("reachable", True)
            and not symbol.get("must_link")
        ]
        result = {
            "ok": False,
            "stage": "link",
            "build_mode": build_cfg.get("mode", "direct"),
            "make_host": make_host,
            "makefile": (make_intro or {}).get("makefile", ""),
            "binary": "",
            "log": str(build_log),
            "commands": commands,
            "undefined_symbols": missing,
            "known_symbols": known,
            "must_link": must_link,
            "pending_mocks": pending,
            "mocks_path": str(workspace.mocks_config_path(config)),
            "suggestion": (
                "These symbols have definitions in project/external code. Link them "
                "(sources.real, resolve sources.exclude, or externals add --link); do not mock "
                "them. Only symbols with no definition anywhere, or only in excluded dt/test "
                "dirs, may be mocked."
                if must_link
                else (
                    "These symbols have no linked implementation. Ask the human for mock rules "
                    "(for example random fixed-length bytes or a 0/random-error return), import them "
                    "into the mocks config, then run gen/build. Do not link dt/ or other excluded fakes."
                )
            ),
        }
        write_json(workspace.build_dir / "build.json", result)
        return result

    write_text(workspace.build_dir / "build.sh", "#!/bin/sh\n" + "\n".join(shlex.join(cmd) for cmd in commands) + "\n")
    result = {
        "ok": True,
        "stage": "link",
        "build_mode": build_cfg.get("mode", "direct"),
        "make_host": make_host,
        "makefile": (make_intro or {}).get("makefile", ""),
        "binary": str(binary),
        "log": str(build_log),
        "commands": commands,
        "objects": objects,
        "sources": sources,
        "libraries": list((config.get("sources", {}) or {}).get("libraries") or []),
    }
    write_json(workspace.build_dir / "build.json", result)
    return result


def _nm_tool(toolchain: dict) -> str:
    clang = toolchain.get("clang") or ""
    if clang:
        candidate = Path(clang).parent / "llvm-nm"
        if candidate.is_file():
            return str(candidate)
    import shutil

    return shutil.which("nm") or "nm"


def _normalize_symbol(symbol: str) -> str:
    return symbol[1:] if symbol.startswith("_") else symbol


def _nm_symbols(obj: str, tool: str, defined: bool) -> set[str]:
    cmd = [tool, "-g", "--defined-only" if defined else "-u", obj]
    proc = run(cmd, timeout=120)
    if proc.returncode != 0:
        return set()
    result = set()
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        result.add(parts[-1])
    return result


def probe(workspace, config: dict, analysis: dict) -> dict:
    """Compile target+real sources and list symbols with no linked definition."""
    workspace.ensure()
    repo = config.get("repo", "")
    toolchain = config.get("toolchain", {})
    clang = toolchain.get("clang") or "clang"
    sources = resolve_sources(config, analysis)
    obj_dir = workspace.build_dir / "probe_obj"
    obj_dir.mkdir(parents=True, exist_ok=True)
    results = []
    objects: list[str] = []
    make_intro = analysis.get("makefile") or {}
    for source in sources:
        obj = obj_dir / (sha256_text(source)[:16] + ".o")
        extra_flags = (make_intro.get("flags_by_source") or {}).get(str(Path(source).resolve()), [])
        flags = _compile_flags(
            config, toolchain, source,
            [str(workspace.harness_dir), str(workspace.mocks_dir(config))],
            extra_flags,
        )
        result = _compile_one(clang if Path(source).suffix.lower() not in CPP_EXTS else str(Path(clang).with_name("clang++")), source, str(obj), flags, repo or str(workspace.root))
        results.append(result)
        if result["returncode"] == 0:
            objects.append(str(obj))
    log_path = workspace.build_dir / "probe.log"
    write_text(log_path, "\n\n".join(
        f"$ {shlex.join(item['command'])}\n{item['stderr'] or item['stdout']}"
        for item in results
        if item["returncode"] != 0
    ))
    if any(item["returncode"] != 0 for item in results):
        result = {
            "ok": False,
            "stage": "compile",
            "log": str(log_path),
            "failed": [item for item in results if item["returncode"] != 0],
        }
        write_json(workspace.build_dir / "probe.json", result)
        return result

    nm = _nm_tool(toolchain)
    undefined: set[str] = set()
    defined: set[str] = set()
    for obj in objects:
        undefined |= _nm_symbols(obj, nm, defined=False)
        defined |= _nm_symbols(obj, nm, defined=True)
    undefined_norm = {_normalize_symbol(item) for item in undefined}
    defined_norm = {_normalize_symbol(item) for item in defined}

    unresolved = []
    resolved = []
    matched_norm: set[str] = set()
    for symbol in analysis.get("external_symbols", []):
        raw_names = {symbol.get("mangled_name", ""), symbol.get("name", "")}
        matched = {name for name in raw_names if name and (_normalize_symbol(name) in undefined_norm or _normalize_symbol(name) in defined_norm)}
        matched_norm |= {_normalize_symbol(name) for name in matched}
        # A symbol can be undefined in the object that references it and defined
        # in another object; the linker resolves the pair.  Presence in
        # ``defined_norm`` wins over ``undefined_norm``.
        if matched and any(_normalize_symbol(name) in defined_norm for name in matched):
            resolved.append(
                {
                    "symbol": symbol.get("qualified_name") or symbol.get("name"),
                    "signature": symbol.get("signature", ""),
                    "reachable": symbol.get("reachable", True),
                }
            )
        else:
            unresolved.append(
                {
                    "symbol": symbol.get("qualified_name") or symbol.get("name"),
                    "name": symbol.get("name"),
                    "signature": symbol.get("signature", ""),
                    "status": symbol.get("status", "missing"),
                    "reachable": symbol.get("reachable", True),
                    "scope": symbol.get("scope", "unknown"),
                    "must_link": bool(symbol.get("must_link")),
                    "external_source": (symbol.get("external_source") or {}).get("file", ""),
                    "definition_files": symbol.get("definition_files", []),
                    "excluded_definition_files": symbol.get("excluded_definition_files", []),
                }
            )
    libc_names = {
        "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "memcmp",
        "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strchr", "strstr",
        "printf", "fprintf", "sprintf", "snprintf", "puts", "abort", "exit", "_exit",
        "read", "write", "open", "close", "mmap", "munmap", "pthread_create", "pthread_join",
    }
    unclassified = sorted(
        item
        for item in undefined_norm
        if item not in matched_norm
        and item not in defined_norm
        and item not in libc_names
        and not item.startswith(("__", "dyld_", "section$", "ltmp"))
    )[:50]
    result = {
        "ok": True,
        "stage": "probe",
        "nm": nm,
        "sources": sources,
        "unresolved": unresolved,
        "resolved": resolved,
        "unclassified_symbols": unclassified,
        "defined_symbols": sorted(defined_norm)[:5000],
        "log": str(log_path),
    }
    write_json(workspace.build_dir / "probe.json", result)
    return result


def auto_stub_and_rebuild(workspace, config: dict, analysis: dict, mocks: dict, result: dict) -> dict:
    missing = result.get("undefined_symbols") or []
    if not missing:
        return result
    from .mocks import default_symbol

    added = []
    for raw in missing:
        symbol = _find_symbol(analysis, raw)
        if not symbol:
            continue
        if symbol.get("must_link"):
            # A real definition exists; --auto-stub must never override it.
            continue
        key = symbol.get("qualified_name") or symbol.get("name")
        if key in mocks.get("symbols", {}):
            continue
        entry = default_symbol(symbol)
        entry["source"] = "auto"
        entry["note"] = "added after link error; this bypasses human mock rules"
        entry["confirmed"] = True
        mocks.setdefault("symbols", {})[key] = entry
        added.append(key)
    if not added:
        return result
    workspace.save_mocks(mocks, config)
    from .generate import generate_artifacts

    generate_artifacts(config, analysis, workspace, mocks)
    return build(workspace, config, analysis, auto_stub=False)
