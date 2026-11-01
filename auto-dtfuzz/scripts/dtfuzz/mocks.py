from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .util import DtfuzzError, now_iso, rel_to, write_text

C_TYPE_HINTS = {
    "void": "void",
    "int": "0",
    "unsigned": "0",
    "unsigned int": "0",
    "long": "0",
    "unsigned long": "0",
    "short": "0",
    "unsigned short": "0",
    "char": "0",
    "signed char": "0",
    "unsigned char": "0",
    "float": "0.0f",
    "double": "0.0",
    "bool": "false",
    "_Bool": "false",
}


def _is_pointer(type_name: str) -> bool:
    return "*" in type_name


def _is_const_pointer(type_name: str) -> bool:
    return "*" in type_name and "const" in type_name.split("*", 1)[0]


def _default_return(return_type: str) -> str:
    t = re.sub(r"\s+", " ", return_type).strip()
    if not t or t == "void":
        return ""
    if _is_pointer(t):
        return "NULL"
    if t in C_TYPE_HINTS:
        return C_TYPE_HINTS[t]
    if t in {"float", "double", "long double"}:
        return "0.0"
    if t in {"bool", "_Bool"}:
        return "false"
    return "0"


def _looks_like_out(param: dict) -> bool:
    name = re.sub(r"[^a-z0-9]", "", param.get("name", "").lower())
    type_name = param.get("type", "")
    if _is_const_pointer(type_name):
        return False
    if "*" not in type_name:
        return False
    hints = {
        "out",
        "output",
        "reply",
        "response",
        "resp",
        "result",
        "ret",
        "status",
        "value",
        "val",
        "cfg",
        "config",
        "pout",
        "presult",
        "pvalue",
    }
    return name in hints or name.startswith("out") or name.endswith("out")


def _default_out_params(params: list[dict]) -> dict:
    out: dict[str, Any] = {}
    for param in params:
        if not _looks_like_out(param):
            continue
        type_name = param.get("type", "")
        if "void *" in type_name:
            continue
        out[param.get("name", "")] = {"mode": "zero", "size": "sizeof(*{})".format(param.get("name", ""))}
    return out


def default_symbol(symbol: dict) -> dict:
    return_type = symbol.get("return_type", "")
    params = symbol.get("params", [])
    return {
        "name": symbol.get("name", ""),
        "qualified_name": symbol.get("qualified_name", symbol.get("name", "")),
        "signature": symbol.get("signature", ""),
        "return_type": return_type,
        "params": params,
        "decl_file": symbol.get("decl_file", ""),
        "is_method": bool(symbol.get("is_method")),
        "stub": True,
        "confirmed": False,
        "status": symbol.get("status", "missing"),
        "excluded_definition_files": symbol.get("excluded_definition_files", []),
        "return": _default_return(return_type),
        "return_sequence": [],
        "out_params": _default_out_params(params),
        "body": "",
        "source": "pending",
        "note": "",
        "questions": _symbol_questions(symbol),
    }


def _symbol_questions(symbol: dict) -> list[dict]:
    questions = []
    if symbol.get("return_type") not in {"", "void"}:
        questions.append(
            {
                "id": "return",
                "question": f"{symbol.get('name')} 默认返回 { _default_return(symbol.get('return_type', '')) }，是否足够？",
                "options": ["使用默认返回值", "指定固定返回值", "指定调用序列（如先失败后成功）"],
            }
        )
    out_params = [param for param in symbol.get("params", []) if _looks_like_out(param)]
    if out_params:
        names = ", ".join(param.get("name", "") for param in out_params)
        questions.append(
            {
                "id": "out_params",
                "question": f"{symbol.get('name')} 的 out 参数（{names}）默认清零，是否需要写入特定值？",
                "options": ["清零即可", "写入特定字段值", "完全自定义 stub 代码"],
            }
        )
    return questions


def merge_defaults(analysis: dict, existing: dict | None) -> dict:
    mocks = existing or {"version": 1, "symbols": {}, "variables": {}}
    mocks.setdefault("version", 1)
    mocks.setdefault("symbols", {})
    mocks.setdefault("variables", {})
    current_names = {
        symbol.get("qualified_name") or symbol.get("name", "")
        for symbol in analysis.get("external_symbols", [])
    }
    for key in list(mocks["symbols"]):
        entry = mocks["symbols"][key]
        if entry.get("source", "default") in {"default", "auto", "pending"} and key.split("@", 1)[0] not in current_names:
            del mocks["symbols"][key]
    for symbol in analysis.get("external_symbols", []):
        name = symbol.get("name", "")
        if not name:
            continue
        key = symbol.get("qualified_name") or name
        if key in mocks["symbols"] and mocks["symbols"][key].get("type") not in {None, symbol.get("type")}:
            key = f"{key}@{symbol.get('type', '')}"
        if key in mocks["symbols"]:
            current = mocks["symbols"][key]
            current.setdefault("name", name)
            current.setdefault("qualified_name", symbol.get("qualified_name", key))
            current.setdefault("signature", symbol.get("signature", ""))
            current.setdefault("return_type", symbol.get("return_type", ""))
            current.setdefault("params", symbol.get("params", []))
            current.setdefault("type", symbol.get("type", ""))
            current.setdefault("decl_file", symbol.get("decl_file", ""))
            current.setdefault("is_method", bool(symbol.get("is_method")))
            current.setdefault("stub", True)
            current.setdefault("confirmed", False)
            if not current.get("confirmed", False):
                current["status"] = symbol.get("status", "missing")
                current["excluded_definition_files"] = symbol.get("excluded_definition_files", [])
            else:
                current.setdefault("status", symbol.get("status", "missing"))
                current.setdefault("excluded_definition_files", symbol.get("excluded_definition_files", []))
            current.setdefault("return_sequence", [])
            current.setdefault("out_params", _default_out_params(symbol.get("params", [])))
            current.setdefault("body", "")
            current.setdefault("source", "pending")
            current.setdefault("note", "")
            current.setdefault("questions", _symbol_questions(symbol))
            continue
        mocks["symbols"][key] = default_symbol(symbol)
        mocks["symbols"][key]["type"] = symbol.get("type", "")
    return mocks


def set_symbol(mocks: dict, name: str, patch: dict) -> dict:
    symbols = mocks.setdefault("symbols", {})
    if name not in symbols:
        symbols[name] = {
            "name": name,
            "qualified_name": name,
            "signature": "",
            "return_type": "",
            "params": [],
            "decl_file": "",
            "stub": True,
            "return": "0",
            "return_sequence": [],
            "out_params": {},
            "body": "",
            "source": "user",
            "note": "",
            "questions": [],
        }
    symbols[name].update(patch)
    symbols[name]["source"] = patch.get("source", "user")
    symbols[name]["confirmed"] = bool(patch.get("confirmed", True))
    symbols[name].pop("status", None)
    return mocks


def _render_param(param: dict, fallback_name: str) -> str:
    type_text = (param.get("type") or "").strip()
    name = param.get("name") or fallback_name
    if not type_text:
        return name
    if "(*)" in type_text:
        return type_text.replace("(*)", f"(*{name})", 1)
    return f"{type_text} {name}"


def _params_text(params: list[dict]) -> str:
    if not params:
        return "void"
    return ", ".join(_render_param(param, f"arg{i}") for i, param in enumerate(params))


def _indent(code: str, spaces: int = 2) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line if line.strip() else line for line in code.strip("\n").splitlines())


def _out_param_code(param_name: str, spec: dict) -> list[str]:
    mode = spec.get("mode", "zero")
    if mode == "zero":
        size = spec.get("size", f"sizeof(*{param_name})")
        return [f"if ({param_name}) memset({param_name}, 0, {size});"]
    if mode == "fill":
        size = spec.get("size") or spec.get("size_param")
        if not size:
            raise DtfuzzError(f"out param {param_name}: fill mode needs size or size_param")
        byte = spec.get("byte", "0")
        return [f"if ({param_name}) memset({param_name}, {byte}, {size});"]
    if mode == "set":
        value = spec.get("value", "0")
        return [f"if ({param_name}) *{param_name} = {value};"]
    if mode == "set_field":
        field = spec.get("field")
        if not field:
            raise DtfuzzError(f"out param {param_name}: set_field needs field")
        value = spec.get("value", "0")
        return [f"if ({param_name}) {param_name}->{field} = {value};"]
    if mode == "random_bytes":
        size = spec.get("length") or spec.get("size_param") or spec.get("size") or f"sizeof(*{param_name})"
        return [f"if ({param_name}) dtfuzz_random_bytes((uint8_t *){param_name}, {size});"]
    if mode == "random_hex_string":
        size = spec.get("length") or spec.get("size_param") or spec.get("size") or f"sizeof(*{param_name})"
        terminate = "1" if spec.get("terminate") else "0"
        return [f"if ({param_name}) dtfuzz_random_hex((char *){param_name}, {size}, {terminate});"]
    if mode == "raw":
        code = spec.get("code", "")
        return [line for line in code.splitlines()]
    raise DtfuzzError(f"unknown out param mode: {mode}")


def _return_code(symbol: dict, index: int) -> list[str]:
    return_type = (symbol.get("return_type") or "").strip()
    if not return_type or return_type == "void":
        return []
    sequence = symbol.get("return_sequence") or []
    if sequence:
        idx = f"_dtfuzz_idx_{index}"
        last = len(sequence) - 1
        lines = [
            f"unsigned _dtfuzz_pick = {idx} < {len(sequence)} ? {idx} : {last};",
            f"{idx}++;",
            "switch (_dtfuzz_pick) {",
        ]
        for position, value in enumerate(sequence):
            lines.append(f"  case {position}: return {value};")
        lines.append("}")
        lines.append(f"return {sequence[-1]};")
        return lines
    raw_return = symbol.get("return")
    if isinstance(raw_return, dict):
        mode = raw_return.get("mode", "fixed")
        if mode == "fixed":
            value = str(raw_return.get("value", _default_return(return_type)))
            return [f"return {value};"]
        if mode in {"random_choice", "random_error"}:
            if mode == "random_error":
                values = [str(raw_return.get("success", "0"))] + [str(item) for item in raw_return.get("errors", [])]
            else:
                values = [str(item) for item in raw_return.get("values", [])]
            if not values:
                values = [_default_return(return_type)]
            lines = [f"switch (dtfuzz_rand() % {len(values)}) {{"]
            for position, value in enumerate(values):
                lines.append(f"  case {position}: return {value};")
            lines.append("}")
            lines.append(f"return {values[-1]};")
            return lines
        raise DtfuzzError(f"unknown return mode for {symbol.get('name')}: {mode}")
    value = raw_return or _default_return(return_type)
    if return_type in {"bool", "_Bool"} and value in {"0", "false"}:
        value = "false"
    return [f"return {value};"]


def _body_for(symbol: dict, index: int, lang: str) -> str:
    custom = symbol.get("body") or ""
    if custom.strip():
        return _indent(custom)
    lines: list[str] = []
    for param in symbol.get("params", []):
        name = param.get("name")
        if name:
            lines.append(f"(void){name};")
    for name, spec in (symbol.get("out_params") or {}).items():
        try:
            lines.extend(_out_param_code(name, spec))
        except DtfuzzError as exc:
            lines.append(f"/* TODO: {exc} */")
    lines.extend(_return_code(symbol, index))
    return _indent("\n".join(lines))


def _namespace_parts(qualified_name: str) -> list[str]:
    return [part for part in qualified_name.split("::")[:-1] if part]


def _symbol_definition(symbol: dict, index: int, lang: str, repo: str | Path) -> str:
    name = symbol.get("name") or ""
    qualified = symbol.get("qualified_name") or name
    return_type = (symbol.get("return_type") or "").strip()
    params = _params_text(symbol.get("params", []))
    is_method = bool(symbol.get("is_method"))
    if not return_type:
        return f"/* skipped {qualified}: constructor/destructor stubs are not generated */"
    body = _body_for(symbol, index, lang)
    if is_method:
        definition = f"{return_type} {qualified}({params}) {{\n{body}\n}}"
        return definition
    namespaces = _namespace_parts(qualified)
    short_name = qualified.split("::")[-1]
    if not namespaces:
        return f"{return_type} {short_name}({params}) {{\n{body}\n}}"
    open_lines = "\n".join(f"namespace {part} {{" for part in namespaces)
    close_lines = "\n".join("}" for _ in namespaces)
    return f"{open_lines}\n{return_type} {short_name}({params}) {{\n{body}\n}}\n{close_lines}"


def _include_lines(symbols: list[dict], repo: str | Path) -> list[str]:
    include_files: list[str] = []
    for symbol in symbols:
        decl_file = symbol.get("decl_file") or ""
        if not decl_file:
            continue
        suffix = Path(decl_file).suffix.lower()
        if suffix not in {".h", ".hh", ".hpp", ".hxx"}:
            continue
        path = Path(decl_file)
        if path.is_absolute() and not str(path).startswith(str(Path(repo).resolve())):
            include_files.append(str(path))
        else:
            include_files.append(rel_to(path, repo))
    seen: set[str] = set()
    lines = []
    for item in include_files:
        if item in seen:
            continue
        seen.add(item)
        lines.append(f'#include "{item}"')
    return lines


def render_stubs(mocks: dict, repo: str | Path, lang: str = "c") -> str:
    symbols = [
        symbol
        for symbol in mocks.get("symbols", {}).values()
        if symbol.get("stub", True) and symbol.get("confirmed", False)
    ]
    pending = [
        symbol
        for symbol in mocks.get("symbols", {}).values()
        if symbol.get("stub", True) and not symbol.get("confirmed", False)
    ]
    lines = [
        "/* Generated by dtfuzz. Edit mocks.json, then run `dtfuzz gen` again. */",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "#include <string.h>",
        "#include <stdbool.h>",
        '#include "dtfuzz_runtime.h"',
    ]
    if pending:
        lines.append("/* Pending (not generated until confirmed by a human): " + ", ".join(
            symbol.get("qualified_name") or symbol.get("name", "?") for symbol in pending
        ) + " */")
    lines.extend(_include_lines(symbols, repo))
    lines.extend(["", "static unsigned _dtfuzz_mock_reset_count;"])
    for index, symbol in enumerate(symbols):
        if symbol.get("return_sequence") and (symbol.get("return_type") or "") not in {"", "void"}:
            lines.append(f"static unsigned _dtfuzz_idx_{index};")
    lines.append("")
    resets: list[str] = []
    for index, symbol in enumerate(symbols):
        definition = _symbol_definition(symbol, index, lang, repo)
        if definition.startswith("/* skipped"):
            lines.append(definition)
            continue
        lines.append(definition)
        lines.append("")
        if symbol.get("return_sequence"):
            resets.append(f"  _dtfuzz_idx_{index} = 0;")
    reset_code = "\n".join(resets) if resets else "  (void)0;"
    lines.append("void dtfuzz_reset_mocks(void) {")
    lines.append(reset_code)
    lines.append("  _dtfuzz_mock_reset_count++;")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_variables(mocks: dict, repo: str | Path) -> str:
    variables = mocks.get("variables") or {}
    if not variables:
        return ""
    includes = []
    lines = ["/* Generated mock variables. */"]
    for name, spec in variables.items():
        decl_file = spec.get("decl_file", "")
        if decl_file and Path(decl_file).suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}:
            includes.append(f'#include "{rel_to(decl_file, repo)}"')
        type_name = spec.get("type", "int")
        initializer = spec.get("value")
        if initializer is not None and initializer != "":
            lines.append(f"{type_name} {name} = {initializer};")
        else:
            lines.append(f"{type_name} {name};")
    return "\n".join(dict.fromkeys(includes) + lines) + "\n"


def summary(mocks: dict) -> list[dict]:
    rows = []
    for key, symbol in sorted(mocks.get("symbols", {}).items()):
        rows.append(
            {
                "symbol": key,
                "signature": symbol.get("signature", ""),
                "stub": bool(symbol.get("stub", True)),
                "confirmed": bool(symbol.get("confirmed", False)),
                "status": symbol.get("status", "confirmed" if symbol.get("confirmed") else "pending"),
                "return": symbol.get("return", ""),
                "return_sequence": symbol.get("return_sequence", []),
                "out_params": symbol.get("out_params", {}),
                "source": symbol.get("source", "default"),
                "questions": symbol.get("questions", []),
            }
        )
    return rows


def questions(mocks: dict) -> list[dict]:
    result = []
    for key, symbol in sorted(mocks.get("symbols", {}).items()):
        for question in symbol.get("questions", []):
            result.append({"symbol": key, **question})
    return result
