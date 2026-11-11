"""Makefile-aware host builds for cross-compiled projects.

The project's production Makefile may target ARM/MIPS/etc.  libFuzzer must run
on the host, so we keep the Makefile's source/include/define knowledge but
replace the cross compiler with host clang through per-compiler shims.

This module intentionally does not edit the repository.  It:

1. introspects ``make -Bn <target>`` to recover compile commands;
2. extracts source files, include dirs, defines, std and target-only flags;
3. generates executable shims in the dtfuzz workspace that forward to
   clang/clang++ while dropping target flags;
4. optionally runs ``make -k`` with the shim PATH to validate host portability
   and collect objects/libraries.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from pathlib import Path
from typing import Any

from .util import DtfuzzError, now_iso, run, sha256_file, write_json, write_text

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"}
HEADER_EXTS = {".h", ".hh", ".hpp", ".hxx"}

# Flags that only make sense for the cross target.  They are removed before
# host clang sees the command.
TARGET_FLAG_PREFIXES = (
    "-march=",
    "-mcpu=",
    "-mtune=",
    "-mfpu=",
    "-mfloat-abi=",
    "-mabi=",
    "-mthumb",
    "-marm",
    "-mlittle-endian",
    "-mbig-endian",
    "--sysroot=",
    "-specs=",
)
TARGET_FLAG_PAIRS = {"-target", "-mabi", "--sysroot"}

SKIP_COMMAND_PREFIXES = (
    "make[",
    "make:",
    "touch ",
    "mkdir ",
    "rm ",
    "echo ",
    "printf ",
    "cp ",
    "install ",
)


def find_makefile(repo: str | Path, name: str = "Makefile") -> Path:
    root = Path(repo).expanduser().resolve()
    candidate = Path(name)
    if not candidate.is_absolute():
        candidate = root / candidate
    if not candidate.is_file():
        for fallback in ("Makefile", "makefile", "GNUmakefile"):
            path = root / fallback
            if path.is_file():
                return path
        raise DtfuzzError(f"Makefile not found under {root}")
    return candidate


def _strip_target_flags(args: list[str]) -> tuple[list[str], list[str]]:
    kept: list[str] = []
    stripped: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in TARGET_FLAG_PAIRS:
            stripped.append(arg)
            if index + 1 < len(args):
                stripped.append(args[index + 1])
                index += 2
            else:
                index += 1
            continue
        if arg.startswith(TARGET_FLAG_PREFIXES):
            stripped.append(arg)
            index += 1
            continue
        kept.append(arg)
        index += 1
    return kept, stripped


def _join_continuations(text: str) -> list[str]:
    lines = text.splitlines()
    joined: list[str] = []
    buffer = ""
    for line in lines:
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        if buffer:
            buffer += line
            joined.append(buffer)
            buffer = ""
        else:
            joined.append(line)
    if buffer:
        joined.append(buffer)
    return joined


def parse_commands(output: str, repo: str | Path) -> dict[str, Any]:
    root = Path(repo).expanduser().resolve()
    commands: list[dict] = []
    include_dirs: list[str] = []
    defines: list[str] = []
    std = ""
    compilers: list[str] = []
    target_flags: list[str] = []
    flags_by_source: dict[str, list[str]] = {}

    for raw_line in _join_continuations(output):
        line = raw_line.strip()
        if not line or line.startswith(SKIP_COMMAND_PREFIXES):
            continue
        cwd = root
        if "&&" in line:
            prefix, rest = line.split("&&", 1)
            match = re.match(r"\s*cd\s+(.+?)\s*$", prefix)
            if match:
                cwd = (root / match.group(1).strip()).resolve()
                line = rest.strip()
        if " -c " not in f" {line} ":
            continue
        try:
            argv = shlex.split(line)
        except ValueError:
            continue
        source_index = None
        for index, token in enumerate(argv):
            if Path(token).suffix.lower() in SOURCE_EXTS:
                source_index = index
                break
        if source_index is None:
            continue
        source = argv[source_index]
        source_abs = (cwd / source).resolve() if not Path(source).is_absolute() else Path(source).resolve()
        compiler = argv[0]
        compilers.append(compiler)

        flags: list[str] = []
        includes_here: list[str] = []
        defines_here: list[str] = []
        index = 0
        skip_next = False
        while index < len(argv):
            token = argv[index]
            if skip_next:
                skip_next = False
                index += 1
                continue
            if index in {0, source_index} or token == "-c":
                index += 1
                continue
            if token in {"-o"}:
                skip_next = True
                index += 1
                continue
            if token == "-MF":
                skip_next = True
                index += 1
                continue
            if token in {"-I", "-isystem", "-iquote"} and index + 1 < len(argv):
                value = argv[index + 1]
                path = Path(value)
                if not path.is_absolute():
                    path = cwd / path
                includes_here.append(str(path.resolve()))
                flags.extend([token, str(path.resolve())])
                index += 2
                continue
            if token.startswith("-I") and len(token) > 2:
                path = Path(token[2:])
                if not path.is_absolute():
                    path = cwd / path
                includes_here.append(str(path.resolve()))
                flags.append("-I" + str(path.resolve()))
                index += 1
                continue
            if token == "-D" and index + 1 < len(argv):
                defines_here.append(argv[index + 1])
                flags.extend(["-D", argv[index + 1]])
                index += 2
                continue
            if token.startswith("-D") and len(token) > 2:
                defines_here.append(token[2:])
                flags.append(token)
                index += 1
                continue
            if token.startswith("-std="):
                std = token.split("=", 1)[1]
                flags.append(token)
                index += 1
                continue
            flags.append(token)
            index += 1

        kept, stripped = _strip_target_flags(flags)
        target_flags.extend(stripped)
        include_dirs.extend(includes_here)
        defines.extend(defines_here)
        flags_by_source[str(source_abs)] = kept
        commands.append(
            {
                "compiler": compiler,
                "source": str(source_abs),
                "cwd": str(cwd),
                "command": line,
                "flags": kept,
                "stripped_flags": stripped,
            }
        )

    def dedupe(items: list[str]) -> list[str]:
        return list(dict.fromkeys(item for item in items if item))

    return {
        "commands": commands,
        "sources": sorted(flags_by_source),
        "compilers": dedupe(compilers),
        "include_dirs": dedupe(include_dirs),
        "defines": dedupe(defines),
        "std": std,
        "target_flags": dedupe(target_flags),
        "flags_by_source": flags_by_source,
    }


def _parse_variables(output: str) -> dict[str, str]:
    variables: dict[str, str] = {}
    for line in output.splitlines():
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:?+]?=\s*(.*)$", line)
        if match:
            variables[match.group(1)] = match.group(2).strip()
    return variables


def introspect(
    repo: str | Path,
    makefile: str = "Makefile",
    target: str = "",
    timeout: int = 180,
) -> dict[str, Any]:
    root = Path(repo).expanduser().resolve()
    makefile_path = find_makefile(root, makefile)
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}

    attempts: list[tuple[list[str], str]] = []
    base = ["make", "-f", str(makefile_path), "-Bn"]
    if target:
        attempts.append(([*base, target], target))
    else:
        attempts.extend([([*base, "all"], "all"), (base, "default")])

    output = ""
    used_target = ""
    errors: list[str] = []
    for cmd, label in attempts:
        proc = run(cmd, cwd=root, env=env, timeout=timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        used_target = label
        if proc.returncode == 0 and " -c " in output:
            break
        errors.append(f"$ {' '.join(cmd)}\n{(proc.stderr or proc.stdout)[-2000:]}")
    parsed = parse_commands(output, root)
    variables: dict[str, str] = {}
    if not parsed["commands"]:
        proc = run(["make", "-f", str(makefile_path), "-pn"], cwd=root, env=env, timeout=timeout)
        variables = _parse_variables((proc.stdout or "") + "\n" + (proc.stderr or ""))
        if parsed["compilers"] == [] and variables.get("CC"):
            parsed["compilers"] = [variables["CC"]]
    return {
        "makefile": str(makefile_path),
        "makefile_sha256": sha256_file(makefile_path),
        "target": used_target,
        "generated_at": now_iso(),
        "commands": parsed["commands"],
        "sources": parsed["sources"],
        "compilers": parsed["compilers"],
        "include_dirs": parsed["include_dirs"],
        "defines": parsed["defines"],
        "std": parsed["std"],
        "target_flags": parsed["target_flags"],
        "flags_by_source": parsed["flags_by_source"],
        "variables": {key: variables[key] for key in ("CC", "CXX", "AR", "CFLAGS", "CXXFLAGS", "SRCS", "SOURCES", "CROSS_COMPILE") if key in variables},
        "errors": errors,
    }


def _compiler_is_cxx(name: str) -> bool:
    lower = name.lower()
    return "++" in lower or lower.endswith(("g++", "c++", "clang++"))


SHIM_TEMPLATE = '''#!/usr/bin/env python3
"""Generated by dtfuzz: host {kind} shim for a cross toolchain."""
import os
import sys

DROP_PREFIXES = {drop_prefixes!r}
DROP_PAIRS = {drop_pairs!r}
args = []
index = 0
while index < len(sys.argv[1:]):
    arg = sys.argv[index + 1]
    if arg in DROP_PAIRS:
        index += 2
        continue
    if arg.startswith(DROP_PREFIXES):
        index += 1
        continue
    args.append(arg)
    index += 1
extra = os.environ.get("DTFUZZ_EXTRA_CFLAGS", "")
if "-c" in args and extra:
    args.extend(extra.split())
os.execvp({compiler!r}, [{compiler!r}, *args])
'''


def generate_shims(workspace, compilers: list[str], toolchain: dict | None = None) -> dict[str, Any]:
    """Create compiler shims in <workspace>/shims and return PATH metadata."""
    shims_dir = Path(workspace.root) / "shims"
    shims_dir.mkdir(parents=True, exist_ok=True)
    toolchain = toolchain or {}
    clang = toolchain.get("clang") or shutil.which("clang") or "clang"
    clangxx = toolchain.get("clangxx") or str(Path(clang).with_name("clang++"))
    if not Path(clangxx).is_file():
        clangxx = shutil.which("clang++") or "clang++"
    created: dict[str, str] = {}
    for compiler in sorted(set(compilers)):
        name = Path(compiler).name
        if not name:
            continue
        kind = "c++" if _compiler_is_cxx(name) else "c"
        target = clangxx if kind == "c++" else clang
        path = shims_dir / name
        write_text(
            path,
            SHIM_TEMPLATE.format(
                kind=kind,
                drop_prefixes=TARGET_FLAG_PREFIXES,
                drop_pairs=tuple(TARGET_FLAG_PAIRS),
                compiler=target,
            ),
        )
        path.chmod(0o755)
        created[name] = str(path)
    # Archive tools are safe to forward to LLVM.
    for name, tool in (("ar", "llvm-ar"), ("ranlib", "llvm-ranlib")):
        found = shutil.which(tool)
        if found:
            path = shims_dir / name
            write_text(path, f'#!/bin/sh\nexec "{found}" "$@"\n')
            path.chmod(0o755)
            created.setdefault(name, str(path))
    return {"path": str(shims_dir), "created": created}


def run_host_make(
    workspace,
    config: dict,
    analysis: dict,
    intro: dict[str, Any],
    timeout: int = 1800,
) -> dict[str, Any]:
    """Run the project Makefile with shims; tolerate link/firmware failures."""
    repo = Path(config.get("repo", "")).expanduser().resolve()
    makefile = intro.get("makefile") or str(find_makefile(repo, (config.get("build", {}) or {}).get("makefile", "Makefile")))
    target = (config.get("build", {}) or {}).get("make_target") or intro.get("target") or "all"
    jobs = int((config.get("build", {}) or {}).get("make_jobs") or 0) or (os.cpu_count() or 1)
    shims = generate_shims(workspace, intro.get("compilers", []), config.get("toolchain", {}))
    env = {**os.environ, "PATH": shims["path"] + os.pathsep + os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C"}
    env.setdefault("CC", shims["created"].get("cc", shims["created"].get("gcc", "clang")))
    env.setdefault("CXX", shims["created"].get("c++", shims["created"].get("g++", "clang++")))
    env.setdefault("AR", shims["created"].get("ar", "llvm-ar"))
    env["DTFUZZ_EXTRA_CFLAGS"] = "-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address -fprofile-instr-generate -fcoverage-mapping"
    command = ["make", "-f", makefile, "-k", f"-j{jobs}", target]
    started = __import__("time").time()
    proc = run(command, cwd=repo, env=env, timeout=timeout)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    log_path = Path(workspace.build_dir) / "make-host.log"
    write_text(log_path, f"$ {' '.join(command)}\n\n{output}")
    objects: list[str] = []
    libraries: list[str] = []
    for path in repo.rglob("*"):
        if not path.is_file() or ".dtfuzz" in path.parts:
            continue
        try:
            if path.stat().st_mtime < started - 2:
                continue
        except OSError:
            continue
        if path.suffix == ".o":
            objects.append(str(path))
        elif path.suffix == ".a":
            libraries.append(str(path))
    result = {
        "ok": bool(objects or libraries),
        "returncode": proc.returncode,
        "command": command,
        "log": str(log_path),
        "objects": objects[:500],
        "libraries": libraries[:200],
        "shims": shims,
        "target": target,
    }
    write_json(Path(workspace.build_dir) / "make-host.json", result)
    return result
