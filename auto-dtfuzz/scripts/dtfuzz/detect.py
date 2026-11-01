from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
from pathlib import Path

from .util import DtfuzzError, read_json, resolve, run, which

BREW_BIN_DIRS = (
    "/opt/homebrew/opt/llvm/bin",
    "/usr/local/opt/llvm/bin",
)

CLANG_NAMES = ("clang", "clang-22", "clang-21", "clang-20", "clang-19", "clang-18")


def _version(clang: str) -> str:
    try:
        proc = run([clang, "--version"], timeout=20)
        return (proc.stdout or proc.stderr).splitlines()[0].strip()
    except DtfuzzError:
        return ""


def _resource_dir(clang: str) -> str:
    try:
        proc = run([clang, "-print-resource-dir"], timeout=20)
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except DtfuzzError:
        return ""


def _fuzzer_runtime(clang: str) -> str:
    resource = _resource_dir(clang)
    if not resource:
        return ""
    root = Path(resource)
    matches = sorted(root.glob("**/libclang_rt.fuzzer*.a"))
    return str(matches[0]) if matches else ""


def _clang_candidates() -> list[str]:
    candidates: list[str] = []
    for env_name in ("DTFUZZ_CLANG", "CLANG"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(value)
    for directory in BREW_BIN_DIRS:
        for name in CLANG_NAMES:
            candidate = Path(directory) / name
            if candidate.is_file():
                candidates.append(str(candidate))
    found = which("clang")
    if found:
        candidates.append(found)
    seen: set[str] = set()
    unique: list[str] = []
    for item in candidates:
        real = str(Path(item).resolve())
        if real not in seen:
            seen.add(real)
            unique.append(item)
    return unique


def find_clang() -> dict:
    candidates = []
    chosen = None
    fallback = None
    for clang in _clang_candidates():
        runtime = _fuzzer_runtime(clang)
        info = {
            "path": clang,
            "version": _version(clang),
            "resource_dir": _resource_dir(clang),
            "fuzzer_runtime": runtime,
        }
        candidates.append(info)
        if fallback is None:
            fallback = info
        if runtime:
            chosen = info
            break
    return {"chosen": chosen or fallback, "candidates": candidates}


def _find_tool(name: str, clang_path: str | None) -> str | None:
    if clang_path:
        sibling = Path(clang_path).parent / name
        if sibling.is_file() and os.access(sibling, os.X_OK):
            return str(sibling)
    found = which(name)
    if found:
        return found
    if sys.platform == "darwin":
        try:
            proc = run(["xcrun", "--find", name], timeout=20)
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except DtfuzzError:
            pass
    return None


def detect_build_system(repo: str | Path) -> str:
    root = Path(repo)
    if (root / "compile_commands.json").is_file():
        return "compile-db"
    for name in ("Makefile", "makefile", "GNUmakefile"):
        if (root / name).is_file():
            return "make"
    if (root / "CMakeLists.txt").is_file():
        return "cmake"
    if (root / "meson.build").is_file():
        return "meson"
    if (root / "BUILD") .is_file() or (root / "BUILD.bazel").is_file() or (root / "WORKSPACE").is_file():
        return "bazel"
    return "unknown"


def find_compile_db(repo: str | Path) -> Path | None:
    root = Path(repo)
    candidates = [root / "compile_commands.json"]
    candidates += sorted(root.glob("build*/compile_commands.json"))
    candidates += sorted(root.glob("cmake-build*/compile_commands.json"))
    candidates += sorted(root.glob("out/**/compile_commands.json"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _strip_compiler(command: list[str]) -> list[str]:
    if not command:
        return command
    # Drop the compiler driver; keep flags and inputs.
    return command[1:]


def flags_from_compile_db(db_path: str | Path, source_file: str | Path) -> dict:
    entries = read_json(db_path, default=[])
    target = str(Path(source_file).resolve())
    chosen = None
    for entry in entries:
        file_name = entry.get("file", "")
        directory = entry.get("directory", "")
        if not file_name:
            continue
        candidate = Path(file_name)
        if not candidate.is_absolute():
            candidate = Path(directory) / candidate
        if str(candidate.resolve()) == target:
            chosen = entry
            break
    if chosen is None:
        return {}
    raw = chosen.get("command")
    if isinstance(raw, list):
        argv = list(raw)
    elif isinstance(raw, str):
        argv = shlex.split(raw)
    else:
        argv = list(chosen.get("arguments", []))
    argv = _strip_compiler(argv)
    directory = Path(chosen.get("directory", "."))
    includes: list[str] = []
    defines: list[str] = []
    std = ""
    extra: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-I", "-isystem", "-iquote") and i + 1 < len(argv):
            value = argv[i + 1]
            if arg != "-iquote":
                includes.append(str((directory / value).resolve() if not Path(value).is_absolute() else Path(value)))
            i += 2
            continue
        if arg.startswith("-I") and len(arg) > 2:
            value = arg[2:]
            includes.append(str((directory / value).resolve() if not Path(value).is_absolute() else Path(value)))
            i += 1
            continue
        if arg.startswith("-D") and len(arg) > 2:
            defines.append(arg[2:])
            i += 1
            continue
        if arg == "-D" and i + 1 < len(argv):
            defines.append(argv[i + 1])
            i += 2
            continue
        if arg.startswith("-std="):
            std = arg.split("=", 1)[1]
            i += 1
            continue
        if arg in ("-include", "-imacros") and i + 1 < len(argv):
            extra.append(arg)
            extra.append(argv[i + 1])
            i += 2
            continue
        i += 1
    dedup = lambda items: list(dict.fromkeys(items))
    return {
        "include_dirs": dedup(includes),
        "defines": dedup(defines),
        "std": std,
        "extra_cflags": dedup(extra),
        "source": str(db_path),
    }


def discover_include_dirs(repo: str | Path) -> list[str]:
    root = Path(repo)
    names = ("include", "inc", "src", "source", "lib", "api", "common")
    dirs: list[str] = []
    for name in names:
        candidate = root / name
        if candidate.is_dir():
            dirs.append(str(candidate))
    if (root / "include").is_dir():
        for child in sorted((root / "include").iterdir()):
            if child.is_dir() and child.name not in {"internal", "private"}:
                dirs.append(str(child))
    dirs.append(str(root))
    seen: set[str] = set()
    unique: list[str] = []
    for directory in dirs:
        real = str(Path(directory).resolve())
        if real not in seen:
            seen.add(real)
            unique.append(real)
    return unique


def doctor(repo: str | Path | None = None) -> dict:
    clang_info = find_clang()
    chosen = clang_info.get("chosen") or {}
    clang_path = chosen.get("path")
    llvm_cov = _find_tool("llvm-cov", clang_path)
    llvm_profdata = _find_tool("llvm-profdata", clang_path)
    llvm_symbolizer = _find_tool("llvm-symbolizer", clang_path)
    llvm_cxxfilt = _find_tool("llvm-cxxfilt", clang_path) or _find_tool("c++filt", clang_path)
    make = which("make")
    cmake = which("cmake")
    ninja = which("ninja")
    fuzz_ok = bool(clang_path and chosen.get("fuzzer_runtime"))
    coverage_ok = bool(llvm_cov and llvm_profdata)
    result = {
        "ok": bool(fuzz_ok and coverage_ok),
        "fuzz_ok": fuzz_ok,
        "coverage_ok": coverage_ok,
        "platform": sys.platform,
        "clang": clang_path,
        "clang_version": chosen.get("version", ""),
        "clang_resource_dir": chosen.get("resource_dir", ""),
        "fuzzer_runtime": chosen.get("fuzzer_runtime", ""),
        "llvm_cov": llvm_cov,
        "llvm_profdata": llvm_profdata,
        "llvm_symbolizer": llvm_symbolizer,
        "llvm_cxxfilt": llvm_cxxfilt,
        "make": make,
        "cmake": cmake,
        "ninja": ninja,
        "clang_candidates": clang_info.get("candidates", []),
        "warnings": [],
        "hints": [],
    }
    if not chosen.get("fuzzer_runtime"):
        result["warnings"].append("选中编译器缺少 libFuzzer 运行时。")
        if sys.platform == "darwin":
            result["hints"].append("macOS 请安装 Homebrew LLVM：brew install llvm")
        elif sys.platform.startswith("linux"):
            result["hints"].append("Linux 请安装 clang 与 compiler-rt（如 apt install clang libclang-rt-dev）")
        result["hints"].append("也可用 DTFUZZ_CLANG=/path/to/clang 指定带 libFuzzer 的编译器。")
    if not llvm_cov or not llvm_profdata:
        result["warnings"].append("缺少 llvm-cov / llvm-profdata，覆盖率闭环不可用。")
        result["hints"].append("优先使用与 clang 同一 LLVM 发行版的 llvm-cov / llvm-profdata。")
    if repo:
        repo_path = Path(repo)
        result["repo"] = str(repo_path.resolve())
        result["build_system"] = detect_build_system(repo_path)
        db = find_compile_db(repo_path)
        result["compile_commands"] = str(db) if db else None
        result["include_dirs"] = discover_include_dirs(repo_path)
    return result


def toolchain_for_config(repo: str | Path, source_file: str | Path | None = None) -> dict:
    info = doctor(repo)
    if not info.get("fuzz_ok"):
        warnings = "；".join(info["warnings"]) or "工具链不完整"
        hints = " ".join(info["hints"])
        raise DtfuzzError(f"{warnings}\n{hints}")
    flags: dict = {}
    db = info.get("compile_commands")
    if db and source_file:
        flags = flags_from_compile_db(db, source_file)
    include_dirs = list(flags.get("include_dirs", [])) or list(info.get("include_dirs", []))
    return {
        "clang": info["clang"],
        "llvm_cov": info.get("llvm_cov") or "",
        "llvm_profdata": info.get("llvm_profdata") or "",
        "llvm_symbolizer": info.get("llvm_symbolizer"),
        "llvm_cxxfilt": info.get("llvm_cxxfilt"),
        "coverage_ok": bool(info.get("coverage_ok")),
        "include_dirs": list(dict.fromkeys(include_dirs)),
        "defines": list(dict.fromkeys(flags.get("defines", []))),
        "std": flags.get("std", ""),
        "extra_cflags": flags.get("extra_cflags", []),
        "compile_commands": db,
        "build_system": info.get("build_system", "unknown"),
    }
