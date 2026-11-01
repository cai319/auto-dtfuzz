from __future__ import annotations

import bisect
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Iterable

from .util import (
    DtfuzzError,
    is_within,
    now_iso,
    read_json,
    rel_to,
    resolve,
    run,
    snippet,
    type_size_c,
    write_json,
)

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
HEADER_EXTS = {".h", ".hh", ".hpp", ".hxx"}
BASE_SKIP_DIRS = {".git", ".hg", ".svn", ".dtfuzz", "node_modules", "__pycache__", "build", "out", "dist", "target", ".venv", "venv"}
DEFAULT_EXCLUDE_DIRS = {"dt", "tests", "test", "mock", "mocks", "stub", "stubs", "fake", "fakes", "fuzz_mocks"}
SKIP_DIRS = BASE_SKIP_DIRS | DEFAULT_EXCLUDE_DIRS
CONTEXT_KINDS = {"NamespaceDecl", "CXXRecordDecl", "RecordDecl", "ClassTemplateDecl", "ClassTemplatePartialSpecializationDecl"}
FUNCTION_KINDS = {"FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl", "CXXConversionDecl"}
CALL_KINDS = {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr", "CUDAKernelCallExpr"}
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else", "catch", "defined", "__attribute__", "decltype"}
IGNORED_CALL_PREFIXES = (
    "__builtin",
    "__cxx",
    "__asan",
    "__ubsan",
    "__tsan",
    "__lsan",
    "__msan",
    "__stack_chk",
    "_GLOBAL__",
)


def iter_files(
    root: str | Path,
    exts: Iterable[str],
    max_size: int = 4 * 1024 * 1024,
    skip_dirs: set[str] | None = None,
) -> Iterable[Path]:
    root_path = Path(root)
    exts = set(exts)
    skipped = SKIP_DIRS if skip_dirs is None else skip_dirs
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in skipped and not d.startswith(".dtfuzz")]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in exts:
                continue
            try:
                if path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield path


def find_entry_candidates(repo: str | Path, name: str) -> list[dict]:
    pattern = re.compile(
        r"(?m)^[ \t]*(?:static[ \t]+)?(?:inline[ \t]+)?(?:extern[ \t]+)?"
        r"[A-Za-z_][\w:<>,*& \t]*?[\s*&]" + re.escape(name) + r"\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{"
    )
    weak = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    candidates: list[dict] = []
    for path in iter_files(repo, SOURCE_EXTS):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            candidates.append({"file": str(path), "line": line, "defined": True})
            continue
        match = weak.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            candidates.append({"file": str(path), "line": line, "defined": False})
    return candidates


def scan_definitions(repo: str | Path, skip_dirs: set[str] | None = None) -> dict[str, list[str]]:
    # Keep signatures on one line; allowing newlines lets a preprocessor token
    # like `defined(` swallow the next function definition.
    pattern = re.compile(r"([A-Za-z_]\w*)\s*\([^;{}\n]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{")
    index: dict[str, list[str]] = {}
    for path in iter_files(repo, SOURCE_EXTS, skip_dirs=skip_dirs):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in pattern.finditer(text):
            name = match.group(1)
            if name in KEYWORDS:
                continue
            index.setdefault(name, [])
            if str(path) not in index[name]:
                index[name].append(str(path))
    return index


def _ast_command(clang: str, source: str | Path, include_dirs: list[str], defines: list[str], std: str) -> list[str]:
    cmd = [clang, "-fsyntax-only", "-Xclang", "-ast-dump=json", "-ferror-limit=50"]
    for directory in include_dirs:
        cmd.extend(["-I", directory])
    for define in defines:
        cmd.append("-D" + define)
    if std:
        cmd.append("-std=" + std)
    cmd.append(str(source))
    return cmd


def parse_ast(clang: str, source: str | Path, include_dirs: list[str], defines: list[str], std: str) -> tuple[dict | None, str]:
    proc = run(_ast_command(clang, source, include_dirs, defines, std), timeout=300)
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout or "clang AST dump failed").strip()
    try:
        return json.loads(proc.stdout), ""
    except json.JSONDecodeError as exc:
        return None, f"clang produced invalid AST JSON: {exc}"


def _node_loc(node: dict) -> dict:
    loc = node.get("loc")
    return loc if isinstance(loc, dict) else {}


def _node_line(node: dict) -> int | None:
    line = _node_loc(node).get("line")
    if line is not None:
        return line
    begin = ((node.get("range") or {}).get("begin") or {})
    return begin.get("line")


def _params(node: dict) -> list[dict]:
    params = []
    for child in node.get("inner", []) or []:
        if child.get("kind") != "ParmVarDecl":
            continue
        type_info = child.get("type", {}) or {}
        params.append(
            {
                "name": child.get("name", ""),
                "type": type_info.get("qualType", ""),
                "desugared_type": type_info.get("desugaredQualType", ""),
            }
        )
    return params


def _has_body(node: dict) -> bool:
    return any(child.get("kind") in {"CompoundStmt", "CXXTryStmt"} for child in node.get("inner", []) or [])


def _qualified(ctx: tuple[str, ...], name: str) -> str:
    return "::".join([part for part in (*ctx, name) if part])


class AstIndex:
    def __init__(self) -> None:
        self.functions: dict[str, list[dict]] = {}
        self.by_mangled: dict[str, dict] = {}
        self.variables: dict[str, list[dict]] = {}
        self.all_nodes: dict[str, dict] = {}
        self.contexts: dict[str, tuple[str, ...]] = {}

    def add_function(self, node: dict, ctx: tuple[str, ...], file: str, state: dict) -> None:
        name = node.get("name", "")
        if not name:
            return
        type_info = node.get("type", {}) or {}
        loc = _node_loc(node)
        line = loc.get("line")
        record = {
            "id": node.get("id", ""),
            "kind": node.get("kind", ""),
            "name": name,
            "qualified_name": _qualified(ctx, name),
            "type": type_info.get("qualType", ""),
            "mangled_name": node.get("mangledName", ""),
            "params": _params(node),
            "file": file,
            "line": line,
            "has_body": _has_body(node),
            "is_method": node.get("kind") in {"CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl", "CXXConversionDecl"},
            "is_static": node.get("storageClass") == "static" or bool(node.get("isStatic")),
            "is_implicit": bool(node.get("isImplicit")),
        }
        key = (record["name"], record["qualified_name"], record["file"], record["line"], record["type"], record["has_body"])
        bucket = self.functions.setdefault(name, [])
        if not any(
            (item["name"], item["qualified_name"], item["file"], item["line"], item["type"], item["has_body"]) == key
            for item in bucket
        ):
            bucket.append(record)
        if record["mangled_name"]:
            self.by_mangled.setdefault(record["mangled_name"], record)
        self.all_nodes[node.get("id", "")] = node
        self.contexts[node.get("id", "")] = ctx

    def add_variable(self, node: dict, file: str) -> None:
        name = node.get("name", "")
        if not name:
            return
        type_info = node.get("type", {}) or {}
        loc = _node_loc(node)
        record = {
            "name": name,
            "type": type_info.get("qualType", ""),
            "file": file,
            "line": loc.get("line"),
            "storage_class": node.get("storageClass", ""),
            "is_implicit": bool(node.get("isImplicit")),
        }
        bucket = self.variables.setdefault(name, [])
        if not any((item["file"], item["type"], item["line"]) == (record["file"], record["type"], record["line"]) for item in bucket):
            bucket.append(record)


def build_index(ast: dict) -> AstIndex:
    index = AstIndex()
    state = {"file": ""}

    def walk(node: Any, ctx: tuple[str, ...]) -> None:
        if isinstance(node, dict):
            loc = node.get("loc")
            if isinstance(loc, dict) and "file" in loc:
                state["file"] = loc["file"]
            kind = node.get("kind", "")
            if kind in FUNCTION_KINDS:
                index.add_function(node, ctx, state["file"], state)
            elif kind == "VarDecl":
                index.add_variable(node, state["file"])
            next_ctx = ctx
            if kind in CONTEXT_KINDS and node.get("name") and not node.get("isImplicit"):
                next_ctx = ctx + (node["name"],)
            for child in node.get("inner", []) or []:
                walk(child, next_ctx)
        elif isinstance(node, list):
            for child in node:
                walk(child, ctx)

    walk(ast, ())
    return index


def find_entry_node(ast: dict, name: str, entry_file: str, repo: str | Path) -> dict | None:
    matches: list[dict] = []
    state = {"file": ""}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            loc = node.get("loc")
            if isinstance(loc, dict) and "file" in loc:
                state["file"] = loc["file"]
            if node.get("kind") in FUNCTION_KINDS and node.get("name") == name:
                if _has_body(node):
                    matches.append({"node": node, "file": state["file"]})
            for child in node.get("inner", []) or []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(ast)
    if not matches:
        return None
    entry_resolved = Path(entry_file).resolve()
    for match in matches:
        file_value = match["file"]
        if not file_value:
            continue
        path = Path(file_value)
        if not path.is_absolute():
            path = Path(repo) / path
        try:
            if path.resolve() == entry_resolved:
                return match["node"]
        except OSError:
            continue
    return matches[0]["node"]


def _decl_ref(node: Any) -> dict | None:
    if isinstance(node, dict):
        ref = node.get("referencedDecl") or node.get("referencedMemberDecl")
        if isinstance(ref, dict) and ref.get("kind") in FUNCTION_KINDS:
            return ref
        for child in node.get("inner", []) or []:
            found = _decl_ref(child)
            if found:
                return found
    elif isinstance(node, list):
        for child in node:
            found = _decl_ref(child)
            if found:
                return found
    return None


def line_offset_map(text: str) -> Callable[[int], int | None]:
    starts = [index for index, char in enumerate(text) if char == "\n"]

    def lookup(offset: int | None) -> int | None:
        if offset is None:
            return None
        return bisect.bisect_right(starts, int(offset)) + 1

    return lookup


def collect_calls(entry_node: dict, line_lookup: Callable[[int], int | None] | None = None) -> list[dict]:
    calls: list[dict] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("kind") in CALL_KINDS:
                ref = _decl_ref(node)
                if ref:
                    name = ref.get("name", "")
                    if name.startswith(IGNORED_CALL_PREFIXES):
                        pass
                    else:
                        type_info = ref.get("type", {}) or {}
                        line = None
                        if line_lookup is not None:
                            begin = ((node.get("range") or {}).get("begin") or {})
                            line = line_lookup(begin.get("offset"))
                        if line is None:
                            line = _node_line(node)
                        calls.append(
                            {
                                "name": name,
                                "kind": ref.get("kind", ""),
                                "type": type_info.get("qualType", ""),
                                "mangled_name": ref.get("mangledName", ""),
                                "line": line,
                            }
                        )
            for child in node.get("inner", []) or []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(entry_node)
    unique: list[dict] = []
    seen: set[tuple] = set()
    for call in calls:
        key = (call["name"], call["type"], call["mangled_name"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(call)
    return unique


def _best_decl(index: AstIndex, call: dict) -> tuple[dict | None, list[dict]]:
    candidates = index.functions.get(call.get("name", ""), [])
    if not candidates:
        return None, []
    mangled = call.get("mangled_name", "")
    if mangled and mangled in index.by_mangled:
        return index.by_mangled[mangled], candidates
    same_type = [item for item in candidates if item.get("type") == call.get("type")]
    if len(same_type) == 1:
        return same_type[0], candidates
    with_body = [item for item in same_type if item.get("has_body")]
    if with_body:
        return with_body[0], candidates
    if same_type:
        return same_type[0], candidates
    return candidates[0], candidates


def _resolve_file(value: str | None, repo: str | Path) -> str:
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        path = Path(repo) / path
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _handle_calls(
    calls: list[dict],
    index: AstIndex,
    repo: str | Path,
    entry_file: str,
    compiled_files: set[str],
    def_index: dict[str, list[str]],
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    internal: list[dict] = []
    external: list[dict] = []
    system: list[dict] = []
    unknown: list[dict] = []
    repo_path = Path(repo).resolve()
    for call in calls:
        decl, candidates = _best_decl(index, call)
        body_decls = [item for item in candidates if item.get("has_body")]
        project_decls = [item for item in candidates if item.get("file") and is_within(_resolve_file(item["file"], repo), repo_path)]
        if body_decls:
            body = body_decls[0]
            file_value = _resolve_file(body.get("file"), repo)
            internal.append({**call, "decl_file": file_value, "definition_file": file_value, "decl": body})
            continue
        if project_decls:
            decl = project_decls[0]
            file_value = _resolve_file(decl.get("file"), repo)
            definition_files = def_index.get(call.get("name", ""), [])
            definition_files = [str(Path(item).resolve()) for item in definition_files if is_within(item, repo_path)]
            external.append(
                {
                    **call,
                    "decl_file": file_value,
                    "definition_files": definition_files,
                    "decl": decl,
                }
            )
            continue
        if decl and decl.get("file") and not is_within(_resolve_file(decl["file"], repo), repo_path):
            system.append({**call, "decl_file": _resolve_file(decl["file"], repo), "decl": decl})
            continue
        unknown.append({**call, "decl_file": _resolve_file((decl or {}).get("file"), repo), "decl": decl})
    return internal, external, system, unknown


def _entry_signature(entry_node: dict) -> dict:
    type_info = entry_node.get("type", {}) or {}
    qual = type_info.get("qualType", "")
    return_type = qual.split(" (", 1)[0] if " (" in qual else qual
    params = _params(entry_node)
    return {"return_type": return_type.strip(), "params": params, "type": qual, "mangled_name": entry_node.get("mangledName", "")}


def _normalize_type(type_name: str) -> str:
    return re.sub(r"\s+", " ", type_name.replace("const", "").replace("volatile", "")).strip()


def propose_input_model(signature: dict, entry_is_method: bool) -> dict:
    params = signature["params"]
    if entry_is_method:
        return {"input_model": "custom", "reason": "C++ 成员函数入口需要构造对象，需人工确认上下文。"}
    buffer_index = None
    for i, param in enumerate(params):
        t = _normalize_type(param["type"])
        if "*" in t and any(token in t for token in ("uint8_t", "char", "void", "unsigned char")):
            buffer_index = i
            break
    if buffer_index is None:
        return {"input_model": "custom", "reason": "未识别到缓冲区参数，需人工指定输入映射。"}
    len_index = None
    for i, param in enumerate(params):
        if i == buffer_index:
            continue
        name = re.sub(r"[^a-z0-9]", "", param["name"].lower())
        if name in {"len", "length", "size", "sz", "n", "datalen", "payloadlen", "buflen", "bytes"}:
            len_index = i
            break
    if len_index is None and buffer_index + 1 < len(params) and "*" not in params[buffer_index + 1]["type"]:
        len_index = buffer_index + 1
    if len_index is None:
        return {"input_model": "custom", "reason": "找到缓冲区参数，但没有配对的长度参数。"}
    type_index = None
    for i, param in enumerate(params):
        if i in {buffer_index, len_index}:
            continue
        name = re.sub(r"[^a-z0-9]", "", param["name"].lower())
        t = _normalize_type(param["type"])
        if "*" in t:
            continue
        if name in {"type", "msgtype", "messagetype", "cmd", "opcode", "kind", "id"} or "enum" in t:
            type_index = i
            break
    endian = "big"
    type_bytes = 0
    if type_index is not None:
        normalized = _normalize_type(params[type_index]["type"])
        type_bytes = type_size_c(normalized) or (4 if "enum" in normalized else 0)
    model = "typed_buffer" if type_index is not None and type_bytes else "buffer"
    roles = {}
    for i, param in enumerate(params):
        if i == buffer_index:
            roles[param["name"]] = "buffer"
        elif i == len_index:
            roles[param["name"]] = "buffer_len"
        elif i == type_index:
            roles[param["name"]] = "msg_type"
        else:
            roles[param["name"]] = "constant"
    return {
        "input_model": model,
        "buffer_param": params[buffer_index]["name"],
        "len_param": params[len_index]["name"],
        "type_param": params[type_index]["name"] if type_index is not None else "",
        "type_bytes": type_bytes,
        "type_endian": endian,
        "roles": roles,
        "reason": "自动识别：类型字段 + 缓冲区 + 长度。" if model == "typed_buffer" else "自动识别：缓冲区 + 长度。",
    }


def _has_main(path: str | Path) -> bool:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(r"(?m)^\s*(?:int|void)\s+(?:w?main)\s*\(", text))


def _is_excluded_path(path: str | Path, repo: str | Path, exclude_dirs: set[str]) -> bool:
    try:
        parts = Path(path).resolve().relative_to(Path(repo).resolve()).parts
    except ValueError:
        return False
    return any(part in exclude_dirs for part in parts)


def analyze_repo(
    repo: str | Path,
    entry_name: str,
    entry_file: str | Path | None,
    clang: str,
    include_dirs: list[str],
    defines: list[str],
    std: str,
    max_files: int = 200,
    exclude_dirs: set[str] | None = None,
) -> dict:
    repo_path = Path(repo).resolve()
    warnings: list[str] = []
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(exclude_dirs or ())
    requested_entry = entry_name
    entry_name = entry_name.split("::")[-1]
    candidates = find_entry_candidates(repo_path, entry_name)
    if entry_file:
        entry_path = resolve(entry_file, repo_path)
        if not entry_path.is_file():
            raise DtfuzzError(f"entry source not found: {entry_path}")
    else:
        defined = [item for item in candidates if item["defined"]]
        if len(defined) == 1:
            entry_path = Path(defined[0]["file"])
        elif len(defined) > 1:
            raise DtfuzzError(
                "entry function is defined in multiple files:\n"
                + "\n".join(f"  {rel_to(item['file'], repo_path)}:{item['line']}" for item in defined)
                + "\npass --source to choose one."
            )
        elif candidates:
            entry_path = Path(candidates[0]["file"])
            warnings.append(f"未找到 {entry_name} 的定义，暂用声明所在文件 {rel_to(entry_path, repo_path)}。")
        else:
            raise DtfuzzError(f"entry function not found in repo: {entry_name}")

    def index_file(path: Path) -> tuple[dict | None, AstIndex | None, dict | None, str]:
        ast, error = parse_ast(clang, path, include_dirs, defines, std)
        if ast is None:
            return None, None, None, error
        index = build_index(ast)
        entry_node = find_entry_node(ast, entry_name, str(path), repo_path)
        return ast, index, entry_node, ""

    ast, index, entry_node, error = index_file(entry_path)
    if ast is None:
        raise DtfuzzError(
            f"clang failed to parse {rel_to(entry_path, repo_path)}:\n{error}\n"
            "Add missing include directories or defines to config.json / pass --include and --define."
        )
    if entry_node is None:
        raise DtfuzzError(f"could not find a definition of {entry_name} in {entry_path}")
    signature = _entry_signature(entry_node)
    entry_is_method = any(
        item.get("is_method") for item in (index.functions.get(entry_name) or []) if item.get("has_body")
    )
    model = propose_input_model(signature, entry_is_method)
    def_index_all = scan_definitions(repo_path, skip_dirs=BASE_SKIP_DIRS)
    def_index: dict[str, list[str]] = {}
    excluded_def_index: dict[str, list[str]] = {}
    for name, files in def_index_all.items():
        allowed = [item for item in files if not _is_excluded_path(item, repo_path, exclude_dirs)]
        blocked = [
            item
            for item in files
            if _is_excluded_path(item, repo_path, exclude_dirs) and "fuzz_mocks" not in Path(item).parts
        ]
        if allowed:
            def_index[name] = allowed
        if blocked:
            excluded_def_index[name] = blocked

    compiled_files: set[str] = {str(entry_path.resolve())}
    queue: list[Path] = [entry_path]
    module_files: list[str] = [str(entry_path.resolve())]
    real_files: list[str] = []
    internal_calls: list[dict] = []
    external_calls: list[dict] = []
    system_calls: list[dict] = []
    unknown_calls: list[dict] = []
    visited: set[str] = set()

    while queue:
        current = queue.pop(0)
        current_resolved = str(current.resolve())
        if current_resolved in visited:
            continue
        visited.add(current_resolved)
        if current_resolved == str(entry_path.resolve()):
            current_index = index
            entry_text = entry_path.read_text(encoding="utf-8", errors="replace")
            current_calls = collect_calls_ast(index, line_offset_map(entry_text))
        else:
            _, current_index, _, error = index_file(current)
            if current_index is None:
                warnings.append(f"跳过内部源文件 {rel_to(current, repo_path)}：{error.splitlines()[0] if error else 'AST 解析失败'}")
                continue
            current_text = current.read_text(encoding="utf-8", errors="replace")
            current_calls = collect_calls_ast(current_index, line_offset_map(current_text))
        internal, external, system, unknown = _handle_calls(
            current_calls, current_index, repo_path, str(entry_path), compiled_files, def_index
        )
        internal_calls.extend(internal)
        external_calls.extend(external)
        system_calls.extend(system)
        unknown_calls.extend(unknown)
        cap_warned = False
        for call in external:
            name = call.get("name", "")
            definition_files = call.get("definition_files") or []
            excluded_files = excluded_def_index.get(name, [])
            call["excluded_definition_files"] = excluded_files
            if len(definition_files) == 1:
                candidate_file = definition_files[0]
                if _has_main(candidate_file) and str(Path(candidate_file).resolve()) != str(entry_path.resolve()):
                    warnings.append(
                        f"{name} 的唯一实现 {rel_to(candidate_file, repo_path)} 含 main()，未作为真实源码链接；"
                        "如确认可链接，请加入 sources.real。"
                    )
                    call["status"] = "main_only"
                    continue
                if candidate_file not in visited and len(compiled_files) < max_files:
                    compiled_files.add(candidate_file)
                    same_directory = Path(candidate_file).parent == entry_path.parent
                    if same_directory:
                        module_files.append(candidate_file)
                    else:
                        real_files.append(candidate_file)
                    queue.append(Path(candidate_file))
                    call["definition_file"] = candidate_file
                    call["status"] = "linked"
                elif len(compiled_files) >= max_files and not cap_warned:
                    warnings.append(
                        f"已达到真实源码扫描上限 {max_files} 个文件；其余有定义的函数未自动加入，"
                        "请把需要的模块加入 sources.real 或调高上限。"
                    )
                    cap_warned = True
                    call["status"] = "over_cap"
            elif len(definition_files) > 1:
                call["status"] = "conflict"
                warnings.append(
                    f"{name} 有多个定义文件，未自动选择："
                    + ", ".join(rel_to(item, repo_path) for item in definition_files[:5])
                    + "；请在 sources.real/sources.exclude 中指定，或给出 mock。"
                )
            else:
                if excluded_files:
                    call["status"] = "excluded_only"
                    warnings.append(
                        f"{name} 只在排除目录中有定义（"
                        + ", ".join(rel_to(item, repo_path) for item in excluded_files[:3])
                        + "），按无法链接处理，需要 mock。"
                    )
                else:
                    call["status"] = "missing"

    def dedup(items: list[dict]) -> list[dict]:
        seen: set[tuple] = set()
        out: list[dict] = []
        for item in items:
            key = (item.get("name"), item.get("type"), item.get("decl_file"), item.get("line"))
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    internal_calls = dedup(internal_calls)
    external_calls = dedup(external_calls)
    system_calls = dedup(system_calls)
    unknown_calls = dedup(unknown_calls)

    external_symbols: list[dict] = []
    seen_external: set[tuple] = set()
    for call in external_calls:
        name = call.get("name", "")
        definition_file = call.get("definition_file", "")
        if call.get("status") == "linked" or (definition_file and definition_file in compiled_files):
            continue
        key = (name, call.get("type", ""))
        if key in seen_external:
            continue
        seen_external.add(key)
        decl = call.get("decl") or {}
        status = call.get("status") or ("missing" if not call.get("definition_files") else "unresolved")
        external_symbols.append(
            {
                "name": name,
                "qualified_name": decl.get("qualified_name", name),
                "signature": _render_signature(decl) if decl else _fallback_signature(call),
                "type": call.get("type", ""),
                "return_type": (call.get("type", "").split(" (", 1)[0] if " (" in call.get("type", "") else call.get("type", "")),
                "params": decl.get("params", []),
                "decl_file": call.get("decl_file", ""),
                "definition_files": call.get("definition_files", []),
                "excluded_definition_files": call.get("excluded_definition_files", []),
                "call_lines": sorted({item.get("line") for item in external_calls if item.get("name") == name and item.get("line")}),
                "is_method": bool(decl.get("is_method")),
                "mangled_name": call.get("mangled_name") or decl.get("mangled_name", ""),
                "status": status,
            }
        )

    module_files = list(dict.fromkeys(str(Path(item).resolve()) for item in module_files))
    real_files = list(dict.fromkeys(str(Path(item).resolve()) for item in real_files if not _has_main(item)))
    target_files = module_files
    coverage_files = list(dict.fromkeys(target_files + [str(entry_path.resolve())]))
    entry_rel = rel_to(entry_path, repo_path)
    header = ""
    entry_records = index.functions.get(entry_name, [])
    for record in entry_records:
        if record.get("has_body") and record.get("file"):
            candidate_header = _resolve_file(record["file"], repo_path)
            if Path(candidate_header).suffix.lower() in HEADER_EXTS:
                header = candidate_header
                break
    if not header:
        for record in entry_records:
            candidate_header = _resolve_file(record.get("file"), repo_path)
            if Path(candidate_header).suffix.lower() in HEADER_EXTS:
                header = candidate_header
                break

    questions: list[dict] = []
    if model.get("input_model") == "custom":
        questions.append(
            {
                "id": "input_model",
                "question": f"入口 {entry_name} 的输入映射无法自动确定：{model.get('reason')}",
                "options": ["缓冲区+长度", "类型字段+缓冲区+长度", "需要自定义调用代码"],
            }
        )
    pending = [
        item
        for item in external_symbols
        if item.get("status") in {"missing", "excluded_only", "conflict", "main_only", "over_cap"}
    ]
    if pending:
        questions.append(
            {
                "id": "mock_rules",
                "question": f"{len(pending)} 个函数无法链接到可用实现，需要你给出 mock 规则（返回值、out 参数、随机行为等）。",
                "options": [
                    "我逐项给规则（固定值/随机错误码/随机定长字节）",
                    "先按成功路径默认值，后续再补失败分支",
                    "某些函数其实有实现，我补充 sources.real",
                ],
            }
        )

    relevant_names = sorted(
        {item.get("name", "") for item in internal_calls + external_calls + unknown_calls} | {entry_name}
    )
    analysis = {
        "version": 1,
        "generated_at": now_iso(),
        "repo": str(repo_path),
        "entry": {
            "name": entry_name,
            "requested_name": requested_entry,
            "file": str(entry_path.resolve()),
            "file_rel": entry_rel,
            "header": header,
            "qualified_name": _entry_qualified(index, entry_node, entry_name),
            "signature": signature,
            "is_method": entry_is_method,
            "source": snippet(entry_path.read_text(encoding="utf-8", errors="replace"), _node_loc(entry_node).get("line") or 1),
        },
        "input_model": model,
        "target_files": coverage_files,
        "internal_files": target_files,
        "module_files": target_files,
        "real_files": real_files,
        "external_symbols": external_symbols,
        "pending_mock_count": len(pending),
        "internal_calls": [_call_summary(item, repo_path) for item in internal_calls],
        "system_calls": [_call_summary(item, repo_path) for item in system_calls],
        "unknown_calls": [_call_summary(item, repo_path) for item in unknown_calls],
        "entry_candidates": [
            {"file": rel_to(item["file"], repo_path), "line": item["line"], "defined": item["defined"]}
            for item in candidates
        ],
        "questions": questions,
        "warnings": warnings,
        "definitions_index": {
            name: [rel_to(item, repo_path) for item in def_index.get(name, [])]
            for name in relevant_names
            if name in def_index
        },
        "excluded_definitions_index": {
            name: [rel_to(item, repo_path) for item in excluded_def_index.get(name, [])]
            for name in relevant_names
            if name in excluded_def_index
        },
    }
    return analysis


def collect_function_refs(entry_node: dict, line_lookup: Callable[[int], int | None] | None = None) -> list[dict]:
    """Functions referenced as values (callbacks, function pointers), not only called."""
    refs: list[dict] = []
    seen: set[tuple] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("kind") == "DeclRefExpr":
                ref = node.get("referencedDecl")
                if isinstance(ref, dict) and ref.get("kind") in FUNCTION_KINDS:
                    name = ref.get("name", "")
                    type_info = ref.get("type", {}) or {}
                    type_name = type_info.get("qualType", "")
                    key = (name, type_name)
                    if name and not name.startswith(IGNORED_CALL_PREFIXES) and key not in seen:
                        seen.add(key)
                        line = None
                        if line_lookup is not None:
                            begin = ((node.get("range") or {}).get("begin") or {})
                            line = line_lookup(begin.get("offset"))
                        if line is None:
                            line = _node_line(node)
                        refs.append(
                            {
                                "name": name,
                                "kind": ref.get("kind", ""),
                                "type": type_name,
                                "mangled_name": ref.get("mangledName", ""),
                                "line": line,
                                "via": "reference",
                            }
                        )
            for child in node.get("inner", []) or []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(entry_node)
    return refs


def collect_calls_ast(index: AstIndex, line_lookup: Callable[[int], int | None] | None = None) -> list[dict]:
    calls: list[dict] = []
    for name, records in index.functions.items():
        for record in records:
            if not record.get("has_body"):
                continue
            node = index.all_nodes.get(record.get("id"))
            if not node:
                continue
            function_calls = collect_calls(node, line_lookup)
            call_keys = {(item.get("name"), item.get("type")) for item in function_calls}
            for ref in collect_function_refs(node, line_lookup):
                if (ref.get("name"), ref.get("type")) not in call_keys:
                    function_calls.append(ref)
            for call in function_calls:
                call["caller"] = record.get("qualified_name", name)
                calls.append(call)
    return calls


def _call_summary(call: dict, repo: str | Path) -> dict:
    return {
        "name": call.get("name", ""),
        "type": call.get("type", ""),
        "line": call.get("line"),
        "caller": call.get("caller", ""),
        "decl_file": rel_to(call["decl_file"], repo) if call.get("decl_file") else "",
        "definition_files": [rel_to(item, repo) for item in call.get("definition_files", [])],
    }


def _render_signature(decl: dict) -> str:
    name = decl.get("qualified_name") or decl.get("name", "")
    params = decl.get("params", [])
    rendered = ", ".join(_render_param(param) for param in params) or "void"
    type_text = decl.get("type", "")
    return_type = type_text.split(" (", 1)[0] if " (" in type_text else type_text
    return f"{return_type} {name}({rendered})"


def _fallback_signature(call: dict) -> str:
    type_text = call.get("type", "")
    return_type = type_text.split(" (", 1)[0] if " (" in type_text else type_text
    return f"{return_type} {call.get('name', '')}()"


def _render_param(param: dict) -> str:
    type_text = param.get("type", "")
    name = param.get("name", "")
    if "(*)" in type_text:
        return type_text.replace("(*)", f"(*{name})", 1)
    if name and type_text:
        return f"{type_text} {name}"
    return type_text or name


def _entry_qualified(index: AstIndex, entry_node: dict, name: str) -> str:
    ctx = index.contexts.get(entry_node.get("id", ""), ())
    return "::".join([*ctx, name]) if ctx else name


def load_analysis_config(config: dict) -> dict:
    entry = config.get("entry", {})
    snippets = config.get("entry", {}).get("signature", {})
    return {"entry": entry, "signature": snippets}


def write_analysis(workspace, analysis: dict) -> None:
    write_json(workspace.analysis_path, analysis)
