"""User-provided external source directories (mounted libraries/SDKs).

The target repository often references functions that live in a secure C
library, a platform component, or an SDK that is not checked in.  Those
functions are legitimate mock candidates, but the mock semantics are much
better when we can read their definitions.

This module implements a small inquiry mechanism:

* register a directory the user mounted/provided (``config.external_sources``)
* scan it read-only for function definitions
* attach file/line/snippet/doc-comment context to external symbols
* emit questions for symbols that still have no source
* optionally add the sources to ``sources.real`` when the user explicitly says
  they are production code (``--link``)

Nothing here executes the external code.  Scanning is plain text parsing, and
linking only happens through the normal compile/link path after an explicit
``--link``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from .introspect import is_system_function
from .util import DtfuzzError, now_iso, rel_to, resolve, snippet

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
HEADER_EXTS = {".h", ".hh", ".hpp", ".hxx"}
SKIP_DIRS = {
    ".git", ".hg", ".svn", "build", "out", "dist", "target", "node_modules",
    "__pycache__", ".venv", "venv", "tests", "test", "mock", "mocks", "stub",
    "stubs", "fake", "fakes",
}

DEF_RE = re.compile(
    r"(?m)^[ \t]*(?:static[ \t]+)?(?:inline[ \t]+)?(?:extern[ \t]+)?"
    r"[A-Za-z_][\w:<>,*& \t]*?[\s*&]([A-Za-z_]\w*)\s*\([^;{}]*\)\s*"
    r"(?:const\s*)?(?:noexcept\s*)?\{"
)
MACRO_RE = re.compile(r"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\([^)]*\))?[ \t]*(.*)$")
TYPEDEF_RE = re.compile(r"(?m)^[ \t]*typedef\s+[^;{}]+?\b([A-Za-z_]\w*)\s*;")
TYPEDEF_BLOCK_RE = re.compile(
    r"(?ms)^[ \t]*typedef\s+(?:struct|union|enum|class)\b.*?\}\s*([A-Za-z_]\w*)\s*;"
)
TYPE_RE = re.compile(r"(?m)^[ \t]*(?:typedef\s+)?(?:struct|union|class|enum)\s+([A-Za-z_]\w*)\s*(?:\{|;)")
USING_RE = re.compile(r"(?m)^[ \t]*using\s+([A-Za-z_]\w*)\s*=")
INCLUDE_RE = re.compile(r'(?m)^[ \t]*#[ \t]*include[ \t]*[<"]([^">]+)[">]')
MACRO_USE_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")

PENDING_STATUSES = {"missing", "excluded_only", "conflict", "main_only", "over_cap"}


def _iter_sources(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in root.walk() if hasattr(root, "walk") else _walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".")]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() in SOURCE_EXTS:
                try:
                    if path.stat().st_size <= 4 * 1024 * 1024:
                        yield path
                except OSError:
                    continue


def _walk(root: Path):
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        yield Path(dirpath), dirnames, filenames


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _comment_block(lines: list[str], line_no: int) -> str:
    """Collect a short comment block immediately above a definition."""
    index = max(0, line_no - 2)
    collected: list[str] = []
    while index >= 0 and len(collected) < 12:
        text = lines[index].strip()
        if not text:
            if collected:
                break
            index -= 1
            continue
        if text.startswith(("//", "/*", "*", "*/")):
            collected.append(text)
            index -= 1
            continue
        break
    return "\n".join(reversed(collected))


def _extract_block(text: str, start: int) -> str:
    """Return the balanced ``{...}`` block starting at ``start`` (best effort)."""
    depth = 0
    index = start
    in_string = False
    quote = ""
    in_line_comment = False
    in_block_comment = False
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
        elif in_block_comment:
            if char == "*" and nxt == "/":
                in_block_comment = False
                index += 2
                continue
        elif in_string:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                in_string = False
        else:
            if char == "/" and nxt == "/":
                in_line_comment = True
                index += 2
                continue
            if char == "/" and nxt == "*":
                in_block_comment = True
                index += 2
                continue
            if char in {'"', "'"}:
                in_string = True
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start : index + 1]
        index += 1
    return text[start : start + 5000]


def _scan_file(path: Path, functions: dict, macros: dict, types: dict) -> None:
    text = _read_text(path)
    if not text:
        return
    lines = text.splitlines()

    def add(bucket: dict, name: str, line_no: int, snippet_text: str = "", **extra: Any) -> None:
        record = {
            "name": name,
            "file": str(path.resolve()),
            "line": line_no,
            "comment": _comment_block(lines, line_no),
            "snippet": snippet_text[:5000],
            **extra,
        }
        bucket.setdefault(name, []).append(record)

    for match in DEF_RE.finditer(text):
        body = _extract_block(text, match.end() - 1)
        signature = text[match.start() : match.end() - 1]
        add(
            functions,
            match.group(1),
            text.count("\n", 0, match.start()) + 1,
            snippet_text=(signature + "\n" + body) if body else signature,
        )
    for match in MACRO_RE.finditer(text):
        name = match.group(1)
        params = (match.group(2) or "").strip()
        value = (match.group(3) or "").strip()
        line_no = text.count("\n", 0, match.start()) + 1
        add(macros, name, line_no, snippet(text, line_no, radius=2, limit=800), params=params, value=value)
    for regex in (TYPEDEF_RE, TYPEDEF_BLOCK_RE, TYPE_RE, USING_RE):
        for match in regex.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            add(types, match.group(1), line_no, snippet(text, line_no, radius=6, limit=1500))


def scan_external(root: str | Path) -> dict[str, dict]:
    """Scan a directory for functions, macros and types.  Read-only."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise DtfuzzError(f"external source directory not found: {root_path}")
    result: dict[str, dict] = {"functions": {}, "macros": {}, "types": {}}
    for path in _iter_sources(root_path):
        _scan_file(path, result["functions"], result["macros"], result["types"])
    # Headers are not in SOURCE_EXTS but contain most macro/type definitions.
    for path in root_path.rglob("*"):
        if path.is_file() and path.suffix.lower() in HEADER_EXTS:
            try:
                if path.stat().st_size <= 4 * 1024 * 1024:
                    _scan_file(path, result["functions"], result["macros"], result["types"])
            except OSError:
                continue
    return result


def scan_definitions(root: str | Path) -> dict[str, list[dict]]:
    """Backward-compatible function-only scan."""
    return scan_external(root)["functions"]


def _external_entry(config: dict, path: str | Path, name: str = "", link: bool = False,
                    include_dirs: list[str] | None = None, defines: list[str] | None = None,
                    std: str = "", reference_only: bool = False) -> dict:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise DtfuzzError(f"external source directory not found: {root}")
    if link and reference_only:
        raise DtfuzzError("--link and --reference-only are mutually exclusive")
    return {
        "name": name or root.name,
        "path": str(root),
        "link": bool(link),
        "reference_only": bool(reference_only),
        "include_dirs": [str(Path(item).expanduser().resolve()) for item in (include_dirs or [])],
        "defines": list(defines or []),
        "std": std,
        "added_at": now_iso(),
    }


def _source_files(root: str | Path) -> list[str]:
    return [str(path.resolve()) for path in _iter_sources(Path(root).expanduser().resolve())]


def _apply_include_dirs(config: dict, entry: dict) -> None:
    """Make external headers visible to clang parsing (context, not linking)."""
    sources = config.setdefault("sources", {})
    include_dirs = list(sources.get("include_dirs") or [])
    for directory in [entry["path"], *entry.get("include_dirs", [])]:
        if directory not in include_dirs:
            include_dirs.append(directory)
    sources["include_dirs"] = include_dirs
    defines = list(sources.get("defines") or [])
    for item in entry.get("defines", []):
        if item not in defines:
            defines.append(item)
    sources["defines"] = defines
    if entry.get("std") and not sources.get("std"):
        sources["std"] = entry["std"]


def add_source(config: dict, path: str | Path, name: str = "", link: bool = False,
               include_dirs: list[str] | None = None, defines: list[str] | None = None,
               std: str = "", reference_only: bool = False) -> dict:
    entries = config.setdefault("external_sources", [])
    entry = _external_entry(config, path, name, link, include_dirs, defines, std, reference_only)
    for existing in entries:
        if existing.get("path") == entry["path"]:
            existing.update(entry)
            _apply_include_dirs(config, existing)
            if link:
                _apply_link(config, existing)
            return existing
    entries.append(entry)
    _apply_include_dirs(config, entry)
    if link:
        _apply_link(config, entry)
    return entry


def remove_source(config: dict, path: str | Path, unlink: bool = True) -> bool:
    root = str(Path(path).expanduser().resolve())
    entries = config.setdefault("external_sources", [])
    before = len(entries)
    config["external_sources"] = [item for item in entries if item.get("path") != root]
    if unlink:
        sources = config.setdefault("sources", {})
        real = [item for item in (sources.get("real") or []) if not str(item).startswith(root)]
        sources["real"] = real
        include_dirs = [
            item for item in (sources.get("include_dirs") or [])
            if not str(item).startswith(root)
        ]
        sources["include_dirs"] = include_dirs
    return len(config["external_sources"]) != before


def _apply_link(config: dict, entry: dict) -> None:
    sources = config.setdefault("sources", {})
    real = list(sources.get("real") or [])
    for file_name in _source_files(entry["path"]):
        if file_name not in real:
            real.append(file_name)
    sources["real"] = real
    include_dirs = list(sources.get("include_dirs") or [])
    for directory in [entry["path"], *entry.get("include_dirs", [])]:
        if directory not in include_dirs:
            include_dirs.append(directory)
    sources["include_dirs"] = include_dirs
    defines = list(sources.get("defines") or [])
    for item in entry.get("defines", []):
        if item not in defines:
            defines.append(item)
    sources["defines"] = defines
    if entry.get("std") and not sources.get("std"):
        sources["std"] = entry["std"]


def link_registered_sources(config: dict) -> list[str]:
    linked = []
    for entry in config.get("external_sources", []) or []:
        if entry.get("link"):
            _apply_link(config, entry)
            linked.append(entry.get("name", entry.get("path", "")))
    return linked


def _symbol_names(symbol: dict) -> set[str]:
    values = {
        symbol.get("name", ""),
        symbol.get("qualified_name", ""),
        symbol.get("mangled_name", ""),
    }
    # A library may define `verify_frame` while the caller uses
    # `netproto::verify_frame`; match the short name as a fallback.
    for value in list(values):
        if value and "::" in value:
            values.add(value.split("::")[-1])
    return {value for value in values if value}


def _pick_definition(index: dict[str, list[dict]], symbol: dict) -> dict | None:
    for name in _symbol_names(symbol):
        candidates = index.get(name) or []
        if candidates:
            return candidates[0]
    return None


SYSTEM_HEADERS = {
    "stdio.h", "stdlib.h", "string.h", "stdint.h", "stddef.h", "stdbool.h",
    "stdarg.h", "math.h", "time.h", "assert.h", "errno.h", "unistd.h",
    "pthread.h", "fcntl.h", "signal.h", "ctype.h", "limits.h", "inttypes.h",
    "setjmp.h", "malloc.h", "alloca.h", "dlfcn.h", "sys/types.h", "sys/socket.h",
    "sys/stat.h", "sys/time.h", "sys/mman.h", "netinet/in.h", "arpa/inet.h",
}


def _module_files(analysis: dict) -> list[Path]:
    values = []
    for item in (analysis.get("module_files") or []) + (analysis.get("target_files") or []) + [analysis.get("entry", {}).get("file", "")]:
        if item:
            values.append(Path(str(item)))
    return list(dict.fromkeys(values))


def _file_roots(config: dict, entries: list[dict]) -> list[Path]:
    roots = []
    repo = config.get("repo")
    if repo:
        roots.append(Path(repo))
    for directory in (config.get("sources", {}) or {}).get("include_dirs", []) or []:
        roots.append(Path(directory))
    for entry in entries:
        roots.append(Path(entry.get("path", "")))
        for directory in entry.get("include_dirs", []) or []:
            roots.append(Path(directory))
    return [root for root in roots if root and root.is_dir()]


def _resolve_include(include: str, roots: list[Path]) -> Path | None:
    name = Path(include).name
    for root in roots:
        direct = root / include
        if direct.is_file():
            return direct.resolve()
        try:
            found = next((item for item in root.rglob(name) if item.is_file()), None)
        except OSError:
            found = None
        if found:
            return found.resolve()
    return None


def _collect_module_uses(files: list[Path]) -> tuple[list[tuple[str, str]], set[str]]:
    includes: list[tuple[str, str]] = []
    macros: set[str] = set()
    for path in files:
        text = _read_text(path)
        if not text:
            continue
        for match in INCLUDE_RE.finditer(text):
            includes.append((str(path), match.group(1)))
        macros.update(MACRO_USE_RE.findall(text))
    return includes, macros


def missing_include_questions(
    repo: str | Path,
    files: list[str | Path],
    include_dirs: list[str] | None = None,
    external_sources: list[dict] | None = None,
    command_hint: str = "",
) -> list[dict]:
    """Check source files for non-system includes that cannot be resolved.

    This is also used before clang analysis: a missing external header makes
    the AST parse fail, so the inquiry must be surfaced even when no workspace
    exists yet.
    """
    roots = [Path(repo)]
    roots.extend(Path(item) for item in (include_dirs or []) if item)
    for entry in external_sources or []:
        roots.append(Path(entry.get("path", "")))
        roots.extend(Path(item) for item in entry.get("include_dirs", []) or [])
    roots = [root for root in roots if root and root.is_dir()]
    includes, _ = _collect_module_uses([Path(item) for item in files if Path(item).is_file()])
    questions = []
    for module_file, include in includes:
        if include in SYSTEM_HEADERS or include.split("/")[0] in {"sys", "netinet", "arpa", "linux"}:
            continue
        if _resolve_include(include, roots) is not None:
            continue
        questions.append(
            {
                "kind": "include",
                "header": include,
                "file": module_file,
                "question": (
                    f"{module_file} 引用了 {include}，但当前仓库和已登记的外挂目录中都没有找到。"
                    "如果它来自安全 C 库/平台组件，请提供包含该头文件的源码或 include 目录。"
                ),
                "action": (
                    command_hint
                    or "dtfuzz externals add --workdir <WORK> --path <DIR> [--include-dir <DIR>]"
                ),
            }
        )
    return questions


def attach(analysis: dict, config: dict) -> dict:
    """Attach external-source context to analysis and build inquiry questions."""
    entries = config.get("external_sources", []) or []
    analysis["external_sources"] = entries
    index: dict[str, dict] = {"functions": {}, "macros": {}, "types": {}}
    warnings: list[str] = []
    for entry in entries:
        try:
            scanned = scan_external(entry["path"])
        except DtfuzzError as exc:
            warnings.append(str(exc))
            continue
        for category, records in scanned.items():
            for name, items in records.items():
                index[category].setdefault(name, []).extend(items)

    def source_name(path: str) -> str:
        return next(
            (entry.get("name") for entry in entries if str(path).startswith(entry.get("path", ""))),
            "",
        )

    resolved = {
        item.get("symbol", "")
        for item in (analysis.get("probe") or {}).get("resolved", [])
        if item.get("symbol")
    }
    reference_only = []
    for symbol in analysis.get("external_symbols", []):
        names = {
            symbol.get("name", ""),
            symbol.get("qualified_name", ""),
            symbol.get("mangled_name", ""),
        }
        if names & resolved:
            symbol["status"] = "linked_real"
            symbol["must_link"] = False
            symbol.pop("must_link_source", None)
        definition = _pick_definition(index["functions"], symbol)
        if definition:
            source_entry = next(
                (entry for entry in entries if str(definition["file"]).startswith(entry.get("path", ""))),
                {},
            )
            is_reference = bool(source_entry.get("reference_only"))
            symbol["external_source"] = {
                **definition,
                "source_name": source_entry.get("name", source_name(definition["file"])),
                "reference_only": is_reference,
            }
            symbol["reference_only"] = is_reference
            if is_reference:
                reference_only.append(symbol.get("qualified_name") or symbol.get("name", ""))
            elif symbol.get("status") not in {"linked_real", "system"}:
                # A real definition exists in the user-provided component repo:
                # it must be linked, never mocked.
                symbol["must_link"] = True
                symbol["must_link_source"] = "external"
                symbol["status"] = "external_definition"
        else:
            symbol.pop("external_source", None)
            symbol.pop("reference_only", None)
            if symbol.get("must_link_source") == "external":
                symbol.pop("must_link", None)
                symbol.pop("must_link_source", None)
    if reference_only:
        warnings.append(
            "以下外部函数定义被用户标记为 reference-only（非生产实现），允许人工 mock，但报告中会注明："
            + ", ".join(reference_only[:12])
        )

    files = [path for path in _module_files(analysis) if path.is_file()]
    includes, used_macros = _collect_module_uses(files)
    roots = _file_roots(config, entries)
    external_includes = []
    include_questions = []
    for module_file, include in includes:
        if include in SYSTEM_HEADERS or include.split("/")[0] in {"sys", "netinet", "arpa", "linux"}:
            continue
        resolved = _resolve_include(include, roots)
        if resolved is None:
            include_questions.append(
                {
                    "kind": "include",
                    "header": include,
                    "file": module_file,
                    "question": (
                        f"{module_file} 引用了 {include}，但当前仓库和已登记的外挂目录中都没有找到。"
                        "如果它来自安全 C 库/平台组件，请提供包含该头文件的源码或 include 目录。"
                    ),
                    "action": "dtfuzz externals add --workdir <WORK> --path <DIR> [--include-dir <DIR>]",
                }
            )
        else:
            external_includes.append({"header": include, "resolved": str(resolved), "used_by": module_file})

    external_macros = []
    for name, records in index["macros"].items():
        if name in used_macros:
            for record in records:
                external_macros.append({**record, "source_name": source_name(record["file"])})
    module_text = "\n".join(_read_text(path) for path in files)
    external_types = []
    for name, records in index["types"].items():
        if re.search(r"\b" + re.escape(name) + r"\b", module_text):
            for record in records:
                external_types.append({**record, "source_name": source_name(record["file"])})

    questions = []
    for symbol in analysis.get("external_symbols", []):
        if symbol.get("external_source"):
            continue
        if symbol.get("reachable") is False:
            continue
        if symbol.get("status") not in PENDING_STATUSES and symbol.get("status") != "confirmed":
            continue
        if symbol.get("stub") is False and symbol.get("confirmed") is False:
            continue
        if is_system_function({"name": symbol.get("name", ""), "source_file": symbol.get("decl_file", "")}):
            continue
        questions.append(
            {
                "kind": "function",
                "symbol": symbol.get("qualified_name") or symbol.get("name", ""),
                "name": symbol.get("name", ""),
                "signature": symbol.get("signature", ""),
                "decl_file": symbol.get("decl_file", ""),
                "status": symbol.get("status", "missing"),
                "question": (
                    f"{symbol.get('name', '?')} 在当前仓库没有可用实现。它是否来自某个安全 C 库、"
                    "平台组件或 SDK？如果有源码目录（外挂/挂载目录），请提供路径；我会只读扫描并"
                    "用于 mock 语义和输入约束分析，不会自动链接。"
                ),
                "action": "dtfuzz externals add --workdir <WORK> --path <DIR> [--name <NAME>]",
            }
        )
    all_questions = questions + include_questions
    analysis["external_source_questions"] = all_questions
    analysis["external_include_questions"] = include_questions
    analysis["external_includes"] = external_includes
    analysis["external_macros"] = external_macros[:80]
    analysis["external_types"] = external_types[:80]
    if warnings:
        analysis.setdefault("warnings", []).extend(warnings)
    analysis["external_source_summary"] = {
        "registered": len(entries),
        "matched_functions": sum(1 for item in analysis.get("external_symbols", []) if item.get("external_source")),
        "matched_macros": len(external_macros),
        "matched_types": len(external_types),
        "resolved_includes": len(external_includes),
        "must_link": sum(1 for item in analysis.get("external_symbols", []) if item.get("must_link")),
        "reference_only": sum(1 for item in analysis.get("external_symbols", []) if item.get("reference_only")),
        "questions": len(all_questions),
    }
    return analysis


def source_context(analysis: dict, limit: int = 24000) -> str:
    """Format external function/macro/type snippets for LLM prompts."""
    parts = []
    used = 0

    def add(header: str, definition: dict) -> bool:
        nonlocal used
        block = definition.get("comment") or ""
        snippet_text = definition.get("snippet") or ""
        text = header + ("\n" + block if block else "") + ("\n" + snippet_text if snippet_text else "")
        if used + len(text) > limit:
            return False
        parts.append(text)
        used += len(text)
        return True

    for symbol in analysis.get("external_symbols", []):
        definition = symbol.get("external_source")
        if not definition:
            continue
        if not add(
            f"- 函数 {symbol.get('qualified_name') or symbol.get('name')} "
            f"({definition.get('file')}:{definition.get('line')})",
            definition,
        ):
            break
    for macro in analysis.get("external_macros", []) or []:
        if not add(f"- 宏 {macro.get('name')} = {macro.get('value', '')} ({macro.get('file')}:{macro.get('line')})", macro):
            break
    for item in analysis.get("external_types", []) or []:
        if not add(f"- 类型 {item.get('name')} ({item.get('file')}:{item.get('line')})", item):
            break
    if analysis.get("external_includes"):
        parts.append(
            "- 已解析的外部头文件："
            + ", ".join(item.get("header", "") for item in analysis["external_includes"][:20])
        )
    return "\n\n".join(parts) if parts else "(没有用户提供的外部库源码/宏/类型)"


def format_questions(questions: list[dict]) -> str:
    lines = []
    for item in questions:
        if item.get("kind") == "include":
            lines.append(f"- 头文件 {item.get('header')}（{item.get('file')}）：{item.get('question')}")
        else:
            lines.append(
                f"- {item.get('symbol', item.get('name', '?'))}: "
                f"{item.get('signature') or item.get('name', '')} "
                f"[{item.get('status', '')}] {item.get('question', '')}"
            )
    return "\n".join(lines)
