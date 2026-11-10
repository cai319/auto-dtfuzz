"""Fuzz Introspector reachability support.

The goal is to make the mock scope deterministic: instead of asking an LLM
which functions the entry calls, read Fuzz Introspector's static map and take
the transitive closure from the entry.  Only reachable functions that are not
defined in the target module are legitimate external symbols.

Two report formats are understood:

* ``fuzzerLogFile-*.data.yaml`` (merged Fuzz Introspector report, preferred)
* ``fuzzerLogFile-*.data`` (calltree text, used when only raw frontend output
  is available)

The parser is deliberately narrow.  auto-dtfuzz has no third-party Python
dependencies, so we do not import PyYAML.  Fuzz Introspector's function list is
a stable, indentation-based subset that we can read with a small state machine.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .util import DtfuzzError, read_json, rel_to, resolve, run, write_json

REPORT_GLOBS = (
    "out/introspector/*.data.yaml",
    "build/out/introspector/*.data.yaml",
    "build/out/*/introspector/*.data.yaml",
    "introspector/*.data.yaml",
    ".dtfuzz/*/introspector/*.data.yaml",
    "*.data.yaml",
)

CALLTREE_GLOBS = (
    "out/introspector/*.data",
    "build/out/introspector/*.data",
    "build/out/*/introspector/*.data",
    "introspector/*.data",
    ".dtfuzz/*/introspector/*.data",
)

BUILTIN_PREFIXES = (
    "<builtin>",
    "__",
    "llvm.",
    "std::",
    "operator new",
    "operator delete",
)

# Common libc/system symbols that show up in a Fuzz Introspector report but are
# not project functions.  This mirrors build.py's libc filter and is used only
# when synthesizing a mock candidate that the AST never saw.
SYSTEM_NAMES = {
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "memcmp",
    "memchr", "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat",
    "strchr", "strrchr", "strstr", "strdup", "strndup", "strspn", "strcspn", "strpbrk",
    "strtok", "strerror", "strcasecmp", "strncasecmp",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf",
    "vsnprintf", "scanf", "sscanf", "puts", "fputs", "putchar", "getchar", "fputc",
    "fgetc", "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "fgets", "feof",
    "fflush", "perror",
    "abort", "exit", "_exit", "atexit", "read", "write", "open", "close", "mmap",
    "munmap", "pthread_create", "pthread_join", "assert", "qsort", "bsearch",
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "strtod",
    "strtof", "strtold", "abs", "labs", "llabs", "div", "ldiv", "isalpha", "isdigit",
    "isspace", "islower", "isupper", "tolower", "toupper",
    "rand", "srand", "time", "getenv", "setenv", "signal", "raise", "longjmp", "setjmp",
    "alloca", "gettimeofday", "clock_gettime", "sleep", "usleep",
}

SYSTEM_PATH_PREFIXES = ("<builtin>", "/usr/", "/opt/", "/Library/Developer/", "/System/")


def is_system_function(item: dict) -> bool:
    name = item.get("name") or item.get("raw_name") or ""
    if name in SYSTEM_NAMES or name.startswith(BUILTIN_PREFIXES):
        return True
    source = item.get("source_file") or ""
    if source.startswith(SYSTEM_PATH_PREFIXES):
        return True
    return False

ENTRY_START = re.compile(r"^  - ([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")
FIELD = re.compile(r"^    ([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")
LIST_ITEM = re.compile(r"^    - (.*)$")

WANTED_LIST_FIELDS = {"functionsReached", "argNames", "argTypes", "constantsTouched"}
WANTED_SCALAR_FIELDS = {
    "functionName",
    "functionSourceFile",
    "linkageType",
    "functionLinenumber",
    "functionLinenumberEnd",
    "functionDepth",
    "returnType",
    "signature",
    "CyclomaticComplexity",
    "BBCount",
    "ICount",
    "EdgeCount",
}


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        inner = value[1:-1]
        if value[0] == '"':
            inner = (
                inner.replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace('\\"', '"')
                .replace("\\\\", "\\")
            )
        else:
            inner = inner.replace("''", "'")
        return inner
    return value


def _coerce(value: str) -> Any:
    text = value.strip()
    if text in {"", "~", "null", "Null", "NULL"}:
        return None
    if text == "[]":
        return []
    if text == "{}":
        return {}
    if text.startswith(("'", '"')) and text.endswith(text[0]) and len(text) >= 2:
        return _unquote(text)
    low = text.lower()
    if low in {"true", "yes"}:
        return True
    if low in {"false", "no"}:
        return False
    try:
        return int(text, 0)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def parse_data_yaml(path: str | Path) -> dict:
    """Parse the ``All functions`` list from a Fuzz Introspector YAML report."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise DtfuzzError(f"cannot read Fuzz Introspector report {path}: {exc}") from exc

    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip().startswith("All functions:"):
            start = index + 1
            break
    if start is None:
        raise DtfuzzError(
            f"{path}: no 'All functions:' section; expected a Fuzz Introspector "
            "fuzzerLogFile-*.data.yaml report"
        )

    functions: list[dict] = []
    current: dict | None = None
    current_list_field: str | None = None

    def finish() -> None:
        nonlocal current
        if current is not None:
            functions.append(current)
            current = None

    for line in lines[start:]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("Function list name:") or stripped.startswith("Fuzzer filename:"):
            finish()
            break
        entry = ENTRY_START.match(line)
        if entry:
            finish()
            current = {}
            current_list_field = None
            key, raw_value = entry.groups()
            if key in WANTED_SCALAR_FIELDS:
                current[key] = _coerce(raw_value)
            elif raw_value.strip() not in {"", "[]"}:
                current[key] = _coerce(raw_value)
            continue
        if current is None:
            continue
        field = FIELD.match(line)
        if field:
            key, raw_value = field.groups()
            value = _coerce(raw_value)
            if key in WANTED_LIST_FIELDS:
                current.setdefault(key, [] if value in (None, []) else [value])
                current_list_field = key if value in (None, []) else None
            elif key in WANTED_SCALAR_FIELDS:
                current[key] = value
                current_list_field = None
            else:
                if value not in (None, [], {}):
                    current[key] = value
                current_list_field = None
            continue
        if current_list_field:
            item = LIST_ITEM.match(line)
            if item:
                current.setdefault(current_list_field, []).append(_unquote(item.group(1)))

    finish()
    if not functions:
        raise DtfuzzError(f"{path}: Fuzz Introspector report has no functions")

    fuzzer_filename = ""
    for line in lines:
        if line.startswith("Fuzzer filename:"):
            fuzzer_filename = line.split(":", 1)[1].strip()
            break
    return {
        "path": str(path.resolve()),
        "format": "data.yaml",
        "fuzzer_filename": fuzzer_filename,
        "functions": functions,
    }


def _split_calltree_line(content: str) -> tuple[str, str, int | None]:
    """Split ``name [source] [line]`` from the right, keeping names with spaces."""
    parts = content.rsplit(" ", 2)
    if len(parts) == 3 and parts[2].lstrip("-").isdigit():
        name, source, line = parts
        return name.strip(), source.strip(), int(line)
    parts = content.rsplit(" ", 1)
    if len(parts) == 2 and parts[1].lstrip("-").isdigit():
        return parts[0].strip(), "", int(parts[1])
    return content.strip(), "", None


def parse_calltree(path: str | Path) -> dict:
    """Parse a Fuzz Introspector calltree text file into an edge list."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise DtfuzzError(f"cannot read calltree {path}: {exc}") from exc

    edges: list[tuple[str, str]] = []
    records: dict[str, dict] = {}
    stack: list[tuple[int, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped in {"Call tree", "============"} or set(stripped) == {"="}:
            continue
        if stripped.startswith("Call tree"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        name, source, line_no = _split_calltree_line(stripped)
        if not name:
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if stack:
            edges.append((stack[-1][1], name))
        stack.append((indent, name))
        records.setdefault(
            name,
            {
                "functionName": name,
                "functionSourceFile": source,
                "functionLinenumber": line_no,
                "linkageType": "",
                "functionsReached": [],
                "CyclomaticComplexity": 0,
            },
        )
    for src, dst in edges:
        records.setdefault(src, {"functionName": src, "functionsReached": []})
        records[src].setdefault("functionsReached", []).append(dst)
    return {
        "path": str(path.resolve()),
        "format": "calltree",
        "fuzzer_filename": "",
        "functions": list(records.values()),
    }


def discover_report(repo: str | Path, workdir: str | Path | None = None) -> Path | None:
    """Find a Fuzz Introspector report in common OSS-Fuzz/local locations."""
    roots = [Path(repo).expanduser().resolve()]
    if workdir:
        roots.insert(0, Path(workdir).expanduser().resolve())
    found: list[Path] = []
    for root in roots:
        for pattern in REPORT_GLOBS:
            found.extend(sorted(root.glob(pattern)))
        for pattern in CALLTREE_GLOBS:
            found.extend(sorted(root.glob(pattern)))
    # Prefer merged YAML over raw calltrees, and newer files first.
    found = [item for item in found if item.is_file()]
    if not found:
        return None
    found.sort(key=lambda item: (not item.name.endswith((".yaml", ".yml")), -item.stat().st_mtime))
    return found[0]


def _load_any(path: str | Path) -> dict:
    path = Path(path)
    if path.suffix in {".json"}:
        payload = read_json(path)
        if isinstance(payload, dict) and "All functions" in payload:
            payload = payload["All functions"]
        if isinstance(payload, dict) and isinstance(payload.get("Elements"), list):
            return {
                "path": str(path.resolve()),
                "format": "json",
                "fuzzer_filename": "",
                "functions": payload["Elements"],
            }
        if isinstance(payload, list):
            return {
                "path": str(path.resolve()),
                "format": "json",
                "fuzzer_filename": "",
                "functions": payload,
            }
        raise DtfuzzError(f"{path}: JSON is not a Fuzz Introspector function list")
    if path.suffix in {".data"} and path.name.startswith("fuzzerLogFile"):
        return parse_calltree(path)
    if path.suffix in {".yaml", ".yml"} or path.name.endswith(".data.yaml"):
        return parse_data_yaml(path)
    return parse_calltree(path)


def _demangle(raw_names: Iterable[str], toolchain: dict) -> dict[str, str]:
    demangler = (toolchain or {}).get("llvm_cxxfilt") or ""
    names = list(dict.fromkeys(str(item) for item in raw_names if item))
    if not demangler or not names:
        return {name: name for name in names}
    try:
        proc = run([demangler], input_text="\n".join(names), timeout=60)
    except DtfuzzError:
        return {name: name for name in names}
    if proc.returncode != 0:
        return {name: name for name in names}
    lines = proc.stdout.splitlines()
    if len(lines) != len(names):
        return {name: name for name in names}
    return {name: line.strip() for name, line in zip(names, lines)}


def _short_name(name: str) -> str:
    clean = re.sub(r"\(.*\)$", "", name or "")
    return clean.split("::")[-1].split("@")[0].strip()


def _variants(name: str) -> set[str]:
    clean = (name or "").strip()
    if not clean:
        return set()
    values = {clean, clean.lstrip("_")}
    short = _short_name(clean)
    if short:
        values.add(short)
    return {item for item in values if item}


def _function_record(raw: dict, displayed: str) -> dict:
    raw_name = str(raw.get("functionName") or raw.get("name") or "").strip()
    source = str(raw.get("functionSourceFile") or raw.get("file") or "").strip()
    reached = raw.get("functionsReached") or raw.get("reached") or []
    if isinstance(reached, str):
        reached = [reached]
    return {
        "raw_name": raw_name,
        "name": displayed or raw_name,
        "source_file": source,
        "line": raw.get("functionLinenumber") if raw.get("functionLinenumber") not in (None, -1) else raw.get("line"),
        "linkage": str(raw.get("linkageType") or ""),
        "depth": raw.get("functionDepth"),
        "complexity": int(raw.get("CyclomaticComplexity") or 0),
        "bb_count": int(raw.get("BBCount") or 0),
        "return_type": str(raw.get("returnType") or ""),
        "signature": str(raw.get("signature") or ""),
        "arg_names": list(raw.get("argNames") or []),
        "arg_types": list(raw.get("argTypes") or []),
        "functions_reached": [str(item) for item in reached if item],
        "known": True,
        "reachable": False,
        "in_module": False,
    }


def _build_index(functions: list[dict]) -> tuple[dict[str, dict], dict[str, dict], dict[str, list[dict]], dict[str, str]]:
    by_raw: dict[str, dict] = {}
    by_name: dict[str, dict] = {}
    by_short: dict[str, list[dict]] = defaultdict(list)
    raw_to_name: dict[str, str] = {}
    for item in functions:
        raw = item["raw_name"]
        name = item["name"]
        if raw:
            by_raw.setdefault(raw, item)
            raw_to_name[raw] = name
        if name:
            by_name.setdefault(name, item)
            short = _short_name(name)
            if short:
                by_short[short].append(item)
    return by_raw, by_name, by_short, raw_to_name


def _lookup(
    name: str,
    by_raw: dict[str, dict],
    by_name: dict[str, dict],
    by_short: dict[str, list[dict]],
) -> dict | None:
    if not name:
        return None
    if name in by_raw:
        return by_raw[name]
    if name in by_name:
        return by_name[name]
    short = _short_name(name)
    candidates = by_short.get(short) or []
    if len(candidates) == 1:
        return candidates[0]
    return None


def _entry_matches(record: dict, entry_names: set[str], entry_file: str) -> bool:
    # Match by function name only.  The source file is used later to choose
    # between same-named overloads; using it here would make every function in
    # the entry translation unit look like an entry point.
    names = _variants(record.get("name", "")) | _variants(record.get("raw_name", ""))
    return bool(names & entry_names)


def _find_entries(records: list[dict], entry_name: str, entry_file: str) -> list[dict]:
    entry_names = _variants(entry_name)
    if Path(entry_name).suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}:
        entry_names |= _variants(Path(entry_name).stem)
    matches = [item for item in records if _entry_matches(item, entry_names, entry_file)]
    if not matches:
        short = _short_name(entry_name)
        matches = [
            item
            for item in records
            if short and (_short_name(item.get("name", "")) == short or _short_name(item.get("raw_name", "")) == short)
        ]
    # Prefer the record whose source file matches the requested source file.
    if entry_file and len(matches) > 1:
        entry_base = Path(entry_file).name
        preferred = [item for item in matches if Path(item.get("source_file", "")).name == entry_base]
        if preferred:
            matches = preferred
    return matches


def _closure(entries: list[dict], functions: list[dict]) -> tuple[list[dict], list[dict], list[str]]:
    by_raw, by_name, by_short, raw_to_name = _build_index(functions)
    reachable: list[dict] = []
    synthetic: list[dict] = []
    warnings: list[str] = []
    seen: set[str] = set()
    queue: list[str] = []

    def enqueue(item: dict) -> None:
        for key in {item.get("raw_name", ""), item.get("name", "")}:
            if key and key not in seen:
                seen.add(key)
                queue.append(key)

    for entry in entries:
        entry["reachable"] = True
        reachable.append(entry)
        enqueue(entry)

    while queue:
        current = queue.pop(0)
        record = _lookup(current, by_raw, by_name, by_short)
        if record is None:
            if current and not current.startswith(BUILTIN_PREFIXES):
                synthetic.append(
                    {
                        "raw_name": current,
                        "name": current,
                        "source_file": "",
                        "line": None,
                        "linkage": "",
                        "depth": None,
                        "complexity": 0,
                        "bb_count": 0,
                        "return_type": "",
                        "signature": "",
                        "arg_names": [],
                        "arg_types": [],
                        "functions_reached": [],
                        "known": False,
                        "reachable": True,
                        "in_module": False,
                    }
                )
            continue
        if not record.get("reachable"):
            record["reachable"] = True
            reachable.append(record)
        for callee in record.get("functions_reached", []):
            display = raw_to_name.get(callee, callee)
            for key in {callee, display}:
                if key and key not in seen:
                    seen.add(key)
                    queue.append(key)
    if not reachable:
        warnings.append("no reachable function found from the requested entry")
    return reachable, synthetic, warnings


def _resolve_source(source: str, repo: str | Path) -> str:
    if not source or source.startswith("<"):
        return source
    path = Path(source)
    if path.is_absolute():
        return str(path)
    root = Path(repo).expanduser().resolve()
    for candidate in (root / source, root / "src" / source, root / ".." / source):
        if candidate.exists():
            return str(candidate.resolve())
    return str((root / source).resolve())


def _source_matches(source: str, module_files: set[str]) -> bool:
    if not source or source.startswith("<"):
        return False
    normalized = str(Path(source))
    if normalized in module_files:
        return True
    source_name = Path(normalized).name
    for module in module_files:
        if module.endswith(normalized) or normalized.endswith(module):
            return True
        if Path(module).name == source_name:
            return True
    return False


def annotate_module(reachability: dict, analysis: dict, repo: str | Path) -> dict:
    """Mark reachable functions as in-module or external using analysis files."""
    module_files = set()
    for item in (analysis.get("module_files") or []) + (analysis.get("target_files") or []) + [analysis.get("entry", {}).get("file", "")]:
        if not item:
            continue
        path = Path(str(item))
        if not path.is_absolute():
            path = Path(repo) / str(item)
        try:
            module_files.add(str(path.resolve()))
        except OSError:
            module_files.add(str(path))
    for item in reachability.get("functions", []):
        item["in_module"] = _source_matches(item.get("source_file", ""), module_files)
    reachable = [item for item in reachability.get("functions", []) if item.get("reachable")]
    external = [item for item in reachable if not item.get("in_module")]
    reachability["module_functions"] = [item for item in reachable if item.get("in_module")]
    reachability["external_functions"] = external
    reachability["reachable_count"] = len(reachable)
    reachability["module_count"] = len(reachability["module_functions"])
    reachability["external_count"] = len(external)
    return reachability


def load_report(
    path: str | Path,
    entry_name: str,
    entry_file: str = "",
    repo: str | Path = ".",
    toolchain: dict | None = None,
) -> dict:
    """Parse a report and compute the transitive closure from the entry."""
    report = _load_any(path)
    raw_functions = report.get("functions", [])
    names = [item.get("functionName") or item.get("name") or "" for item in raw_functions]
    demangled = _demangle(names, toolchain or {})
    functions: list[dict] = []
    for raw in raw_functions:
        raw_name = str(raw.get("functionName") or raw.get("name") or "").strip()
        functions.append(_function_record(raw, demangled.get(raw_name, raw_name)))
    entries = _find_entries(functions, entry_name, entry_file)
    warnings: list[str] = []
    if not entries:
        warnings.append(f"entry {entry_name!r} was not found in the report; reachability not applied")
    elif len(entries) > 1:
        warnings.append(
            "multiple entry candidates matched; reachability uses the union: "
            + ", ".join(item.get("name", "") for item in entries[:8])
        )
    counts: dict[str, int] = {}
    for item in functions:
        raw = item.get("raw_name", "")
        if raw:
            counts[raw] = counts.get(raw, 0) + 1
    duplicates = [name for name, count in counts.items() if count > 1]
    if duplicates:
        warnings.append(
            "duplicate function names in the report (static functions in different files); "
            "reachability may pick the first: " + ", ".join(duplicates[:8])
        )
    reachable, synthetic, closure_warnings = _closure(entries, functions)
    warnings.extend(closure_warnings)
    all_functions = functions + synthetic
    for item in all_functions:
        if item["raw_name"]:
            item["source_file"] = _resolve_source(item.get("source_file", ""), repo)
    reachability = {
        "version": 1,
        "report": report.get("path", str(Path(path).resolve())),
        "format": report.get("format", ""),
        "fuzzer_filename": report.get("fuzzer_filename", ""),
        "entry": {
            "requested": entry_name,
            "file": entry_file,
            "matched": [item.get("name") for item in entries],
        },
        "functions": all_functions,
        "reachable": reachable,
        "warnings": warnings,
        "matched": bool(entries),
    }
    annotate_module(reachability, {"entry": {"file": entry_file}, "module_files": [], "target_files": []}, repo)
    reachable_names: set[str] = set()
    for item in reachable:
        reachable_names |= _variants(item.get("name", ""))
        reachable_names |= _variants(item.get("raw_name", ""))
    all_names: set[str] = set()
    for item in all_functions:
        all_names |= _variants(item.get("name", ""))
        all_names |= _variants(item.get("raw_name", ""))
    reachability["reachable_names"] = sorted(reachable_names)
    reachability["all_names"] = sorted(all_names)
    return reachability


def name_is_reachable(name: str, reachability: dict | None) -> bool:
    if not reachability or not reachability.get("matched"):
        return True
    names = reachability.get("reachable_names") or []
    if not names:
        return True
    values = _variants(name)
    if values & set(names):
        return True
    return False


def name_in_report(name: str, reachability: dict | None) -> bool:
    """Return True when the name appears anywhere in the report.

    A name that is absent from the report is *unknown*, not unreachable: the
    report may miss indirect calls, assembly, or functions from a translation
    unit the LTO pass did not see.  Callers should keep unknown symbols in the
    conservative stub scope rather than silently dropping them.
    """
    if not reachability or not reachability.get("matched"):
        return False
    all_names = reachability.get("all_names") or []
    if not all_names:
        return False
    return bool(_variants(name) & set(all_names))


def name_state(name: str, reachability: dict | None) -> str:
    if not reachability or not reachability.get("matched"):
        return "unknown"
    if name_is_reachable(name, reachability):
        return "reachable"
    if name_in_report(name, reachability):
        return "unreachable"
    return "unknown"


def filter_analysis(analysis: dict, reachability: dict | None) -> dict:
    """Annotate external symbols with reachability and drop unreachable mocks."""
    if not reachability or not reachability.get("matched"):
        return analysis
    pending_statuses = {"missing", "excluded_only"}
    for symbol in analysis.get("external_symbols", []):
        names = {symbol.get("name", ""), symbol.get("qualified_name", ""), symbol.get("mangled_name", "")}
        states = [name_state(name, reachability) for name in names if name]
        if "reachable" in states:
            reachable = True
            if symbol.get("must_link"):
                scope = "must_link"
            else:
                scope = "stub_scope" if symbol.get("status") in pending_statuses else "reachable"
        elif states and all(state == "unreachable" for state in states):
            reachable = False
            scope = "unreachable"
        else:
            # Not present in the report: indirect call or frontend gap.  Keep it
            # in the conservative stub scope so we never miss a link dependency.
            reachable = True
            scope = "unknown"
        symbol["reachable"] = reachable
        symbol["scope"] = scope
    pending = [
        item
        for item in analysis.get("external_symbols", [])
        if item.get("reachable", True)
        and item.get("status") in pending_statuses
        and not item.get("must_link")
    ]
    analysis["pending_mock_count"] = len(pending)
    return analysis


def _matching_symbol(item: dict, symbols: list[dict]) -> dict | None:
    names = {item.get("name", ""), item.get("raw_name", ""), _short_name(item.get("name", ""))}
    return next(
        (
            entry
            for entry in symbols
            if names & {entry.get("name", ""), entry.get("qualified_name", ""), entry.get("mangled_name", "")}
        ),
        None,
    )


def _synthetic_symbol(item: dict) -> dict:
    """Create an external-symbol record from a report-only reachable function.

    This is how the introspector *adds* a stub candidate the AST never saw:
    an indirect call, a function pointer, or a frontend gap.  The signature
    comes from the report; the human still has to confirm the mock rule.
    """
    arg_names = list(item.get("arg_names") or [])
    arg_types = list(item.get("arg_types") or [])
    params = []
    for index, type_name in enumerate(arg_types):
        name = arg_names[index] if index < len(arg_names) and arg_names[index] else f"arg{index}"
        params.append({"name": name, "type": type_name})
    return_type = item.get("return_type") or "int"
    rendered = ", ".join(f"{param['type']} {param['name']}".strip() for param in params) or "void"
    signature = item.get("signature") or f"{return_type} {item.get('name', '')}({rendered})"
    source = item.get("source_file") or ""
    return {
        "name": item.get("name", ""),
        "qualified_name": item.get("name", ""),
        "signature": signature,
        "type": "",
        "return_type": return_type,
        "params": params,
        "decl_file": "" if source.startswith("<") else source,
        "definition_files": [],
        "excluded_definition_files": [],
        "call_lines": [],
        "is_method": False,
        "mangled_name": item.get("raw_name", ""),
        "status": "missing",
        "reachable": True,
        "scope": "stub_scope",
        "source": "introspector",
        "introspector_only": True,
    }


def attach(analysis: dict, reachability: dict | None, repo: str | Path) -> dict:
    if not reachability:
        analysis["reachability"] = None
        return analysis
    annotate_module(reachability, analysis, repo)
    filter_analysis(analysis, reachability)
    real_files = set()
    for item in analysis.get("real_files", []) or []:
        try:
            real_files.add(str(Path(item).resolve()))
        except OSError:
            real_files.add(str(item))
    added = []
    for item in reachability.get("external_functions", []):
        if item.get("in_module"):
            continue
        if _matching_symbol(item, analysis.get("external_symbols", [])):
            continue
        source_file = item.get("source_file", "")
        try:
            source_resolved = str(Path(source_file).resolve())
        except OSError:
            source_resolved = str(source_file)
        if source_resolved in real_files:
            continue
        if is_system_function(item):
            continue
        linkage = (item.get("linkage") or "").lower()
        if linkage in {"internallinkage", "privatelinkage"}:
            # A static function outside the linked translation units cannot be
            # stubbed into the binary meaningfully; the link probe will report
            # it if it is actually referenced.
            continue
        synthetic = _synthetic_symbol(item)
        if not synthetic["name"]:
            continue
        analysis.setdefault("external_symbols", []).append(synthetic)
        added.append(synthetic["name"])
    if added:
        reachability.setdefault("warnings", []).append(
            "Fuzz Introspector found reachable external functions the AST did not see; "
            "added as pending mock candidates (verify signatures): " + ", ".join(added[:12])
        )
        filter_analysis(analysis, reachability)
    source_symbols = {item.get("name", "") for item in analysis.get("external_symbols", [])}
    stub_scope = []
    for item in reachability.get("external_functions", []):
        symbol = _matching_symbol(item, analysis.get("external_symbols", []))
        source_file = item.get("source_file", "")
        try:
            source_resolved = str(Path(source_file).resolve())
        except OSError:
            source_resolved = str(source_file)
        if symbol:
            status = symbol.get("status", "missing")
        elif source_resolved in real_files:
            status = "linked_real"
        elif is_system_function(item):
            status = "system"
        else:
            status = "missing"
        stub_scope.append(
            {
                "symbol": item.get("name"),
                "raw_name": item.get("raw_name"),
                "signature": (symbol or {}).get("signature") or item.get("signature") or "",
                "source_file": source_file,
                "linkage": item.get("linkage", ""),
                "complexity": item.get("complexity", 0),
                "status": status,
                "defined_in": (symbol or {}).get("definition_files", []),
                "excluded_in": (symbol or {}).get("excluded_definition_files", []),
                "in_analysis": bool(symbol),
            }
        )
    reachability["stub_scope"] = stub_scope
    reachability["analysis_symbols"] = sorted(source_symbols)
    analysis["reachability"] = {
        "report": reachability.get("report"),
        "format": reachability.get("format"),
        "matched": reachability.get("matched"),
        "entry": reachability.get("entry"),
        "reachable_count": reachability.get("reachable_count"),
        "module_count": reachability.get("module_count"),
        "external_count": reachability.get("external_count"),
        "stub_scope": stub_scope,
        "warnings": reachability.get("warnings", []),
    }
    return analysis


def write_reachability(workspace, reachability: dict) -> Path:
    directory = workspace.root / "introspector"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "reachability.json"
    write_json(path, reachability)
    return path


def run_light(repo: str | Path, out_dir: str | Path, fi_src: str | Path, python: str = "python3") -> Path:
    """Run Fuzz Introspector's source-only frontend (no custom clang needed)."""
    main = Path(fi_src).expanduser().resolve() / "src" / "main.py"
    if not main.is_file():
        raise DtfuzzError(f"Fuzz Introspector entry not found: {main}")
    out_path = Path(out_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    cmd = [
        python,
        str(main),
        "full",
        "--target-dir",
        str(Path(repo).expanduser().resolve()),
        "--language",
        "c-cpp",
        "--module-only",
        "--out-dir",
        str(out_path),
        "--name",
        "dtfuzz",
    ]
    proc = run(cmd, cwd=str(out_path), timeout=1800)
    if proc.returncode != 0:
        raise DtfuzzError(
            "Fuzz Introspector light run failed; check its Python dependencies "
            f"(tree-sitter, pyyaml) in the selected interpreter:\n{(proc.stderr or proc.stdout)[-4000:]}"
        )
    reports = sorted(out_path.glob("*.data.yaml")) + sorted(out_path.glob("**/*.data.yaml"))
    if not reports:
        raise DtfuzzError(f"Fuzz Introspector produced no *.data.yaml under {out_path}")
    return reports[0]


def run_lto(
    repo: str | Path,
    out_dir: str | Path,
    fi_clang: str | Path,
    sources: list[str],
    harness: str,
    extra_flags: list[str] | None = None,
    python: str = "python3",
    fi_src: str | Path | None = None,
) -> Path:
    """Compile with the Fuzz Introspector LTO pass, then run its frontend.

    This requires a clang built with the Fuzz Introspector LLVM pass.  The
    custom clang is not something auto-dtfuzz can bootstrap, so we fail with a
    clear message when it is missing and point at the light frontend instead.
    """
    clang = Path(fi_clang).expanduser()
    if not clang.is_file():
        raise DtfuzzError(
            "FI_CLANG does not point to a compiler with the Fuzz Introspector "
            "LTO pass; build one with fuzz-introspector's build_all.sh or use "
            "`dtfuzz introspect --run-light` / `--report`"
        )
    out_path = Path(out_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    compile_units = [str(Path(item).resolve()) for item in sources] + [str(Path(harness).resolve())]
    cmd = [str(clang), "-flto", "-g", "-fsanitize=fuzzer", "-fuse-ld=gold", *compile_units, "-o", str(out_path / "fi_target")]
    cmd.extend(extra_flags or [])
    env = {"FUZZ_INTROSPECTOR": "1"}
    proc = run(cmd, cwd=str(out_path), env=env, timeout=1800)
    if proc.returncode != 0:
        raise DtfuzzError(
            "Fuzz Introspector LTO compile failed. Ensure FI_CLANG has the "
            "introspector pass and that gold is available on Linux:\n"
            f"{(proc.stderr or proc.stdout)[-4000:]}"
        )
    if fi_src:
        return run_light(repo, out_path, fi_src, python)
    reports = sorted(out_path.glob("*.data.yaml")) + sorted(out_path.glob("**/*.data.yaml"))
    if not reports:
        raise DtfuzzError(
            f"LTO pass produced no *.data.yaml under {out_path}; run the "
            "post-processing frontend from fuzz-introspector (src/main.py full)"
        )
    return reports[0]
