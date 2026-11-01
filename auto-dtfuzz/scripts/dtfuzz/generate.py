from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .util import DtfuzzError, parse_hex, rel_to, sha256_bytes, write_text


def _render_param(param: dict) -> str:
    type_text = (param.get("type") or "").strip()
    name = param.get("name") or "arg"
    if not type_text:
        return name
    if "(*)" in type_text:
        return type_text.replace("(*)", f"(*{name})", 1)
    return f"{type_text} {name}"


def _params_text(params: list[dict]) -> str:
    return ", ".join(_render_param(param) for param in params) if params else "void"


def _namespace_wrap(qualified_name: str, declaration: str) -> str:
    parts = [part for part in qualified_name.split("::")[:-1] if part]
    if not parts:
        return declaration
    open_lines = "\n".join(f"namespace {part} {{" for part in parts)
    close_lines = "\n".join("}" for _ in parts)
    return f"{open_lines}\n{declaration}\n{close_lines}"


def _entry_declaration(config: dict, analysis: dict) -> str:
    entry = config["entry"]
    qualified = entry.get("qualified_name") or entry.get("name", "")
    return_type = entry.get("return_type") or "int"
    params = _params_text(entry.get("params", []))
    if entry.get("is_method"):
        raise DtfuzzError("C++ 成员函数入口需要自定义 harness；请在 config.harness.call_expr 中提供调用代码。")
    return _namespace_wrap(qualified, f"{return_type} {qualified.split('::')[-1]}({params});")


def _input_expression(param: dict, config: dict) -> str:
    entry = config["entry"]
    model = entry.get("input_model", "buffer")
    role = param.get("role", "constant")
    type_bytes = int(entry.get("type_bytes") or 0)
    offset = int(entry.get("type_offset") or 0)
    data_offset = offset + (type_bytes if model == "typed_buffer" else 0)
    name = param.get("name", "")
    type_text = param.get("type", "")
    if role == "buffer":
        return f"({type_text})(Data + {data_offset})"
    if role == "buffer_len":
        return f"({type_text})(Size - {data_offset})"
    if role == "msg_type":
        return f"({type_text})(_dtfuzz_type)"
    if role == "constant":
        values = config.get("harness", {}).get("const_values", {})
        value = values.get(name, "0")
        return f"({type_text})({value})" if type_text else str(value)
    if role == "custom":
        values = config.get("harness", {}).get("const_values", {})
        return values.get(name, "0")
    raise DtfuzzError(f"param {name}: unknown role {role}")


def _type_expression(config: dict) -> str:
    entry = config["entry"]
    type_bytes = int(entry.get("type_bytes") or 0)
    offset = int(entry.get("type_offset") or 0)
    endian = entry.get("type_endian", "big")
    if type_bytes <= 0 or type_bytes > 8:
        raise DtfuzzError(f"unsupported type_bytes: {type_bytes}")
    parts = []
    for i in range(type_bytes):
        if endian == "little":
            shift = 8 * i
        else:
            shift = 8 * (type_bytes - 1 - i)
        parts.append(f"((uint64_t)Data[{offset + i}] << {shift})")
    return " | ".join(parts)


def render_harness(config: dict, analysis: dict) -> tuple[str, str]:
    entry = config["entry"]
    language = config.get("language", "c")
    is_cpp = language in {"cpp", "c++", "cxx"} or Path(entry.get("file", "")).suffix.lower() in {".cc", ".cpp", ".cxx"}
    header = analysis.get("entry", {}).get("header") or ""
    includes = ["#include <stddef.h>", "#include <stdint.h>"]
    for extra in config.get("harness", {}).get("extra_includes", []) or []:
        includes.append(extra if extra.startswith("#") else f'#include "{extra}"')
    if header:
        repo = config.get("repo", "")
        include_path = rel_to(header, repo) if repo else header
        includes.append(f'#include "{include_path}"')
    else:
        includes.append(_entry_declaration(config, analysis))
    includes.append('#include "dtfuzz_runtime.h"')
    body_lines = list(includes)

    model = entry.get("input_model", "buffer")
    type_bytes = int(entry.get("type_bytes") or 0)
    offset = int(entry.get("type_offset") or 0)
    guards: list[str] = []
    if model == "typed_buffer":
        guards.append(f"if (Size < {offset + type_bytes}) return 0;")
    elif offset:
        guards.append(f"if (Size < {offset}) return 0;")

    params = entry.get("params", [])
    args = ", ".join(_input_expression(param, config) for param in params)
    qualified = entry.get("qualified_name") or entry.get("name", "")
    custom_call = config.get("harness", {}).get("call_expr") or ""
    call_expr = custom_call or f"{qualified}({args})"
    call_expr = call_expr.replace("{data}", "Data").replace("{size}", "Size")
    if custom_call:
        call_line = f"  {call_expr};"
    elif entry.get("return_type") in {"", "void"}:
        call_line = f"  {call_expr};"
    else:
        call_line = f"  (void){call_expr};"

    reset_lines = []
    if config.get("mocks", {}).get("enabled", True):
        reset_lines.append("  dtfuzz_reset_mocks();")
    reset_code = (config.get("harness", {}).get("reset_code") or "").strip()
    if reset_code:
        reset_lines.extend("  " + line for line in reset_code.splitlines())
    init_code = (config.get("harness", {}).get("init_code") or "").strip()

    lines = ["/* Generated by dtfuzz. Edit config.json, then run `dtfuzz gen` again. */"]
    lines.extend(body_lines)
    lines.append("")
    if is_cpp:
        lines.append('extern "C" {')
    lines.append("const uint8_t *dtfuzz_current_data = NULL;")
    lines.append("size_t dtfuzz_current_size = 0;")
    lines.append("static uint32_t _dtfuzz_rng_state = 0x9e3779b9u;")
    lines.append("")
    lines.append("uint8_t dtfuzz_input_byte(size_t index) {")
    lines.append("  return index < dtfuzz_current_size ? dtfuzz_current_data[index] : 0;")
    lines.append("}")
    lines.append("")
    lines.append("size_t dtfuzz_input_size(void) {")
    lines.append("  return dtfuzz_current_size;")
    lines.append("}")
    lines.append("")
    lines.append("void dtfuzz_rand_seed(uint32_t seed) {")
    lines.append("  _dtfuzz_rng_state = seed ? seed : 0x9e3779b9u;")
    lines.append("}")
    lines.append("")
    lines.append("uint32_t dtfuzz_rand(void) {")
    lines.append("  uint32_t x = _dtfuzz_rng_state;")
    lines.append("  x ^= x << 13;")
    lines.append("  x ^= x >> 17;")
    lines.append("  x ^= x << 5;")
    lines.append("  _dtfuzz_rng_state = x ? x : 0x9e3779b9u;")
    lines.append("  return _dtfuzz_rng_state;")
    lines.append("}")
    lines.append("")
    lines.append("void dtfuzz_random_bytes(uint8_t *dst, size_t n) {")
    lines.append("  for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)(dtfuzz_rand() & 0xffu);")
    lines.append("}")
    lines.append("")
    lines.append("void dtfuzz_random_hex(char *dst, size_t n, int terminate) {")
    lines.append("  static const char hex[] = \"0123456789abcdef\";")
    lines.append("  for (size_t i = 0; i < n; i++) dst[i] = hex[dtfuzz_rand() & 0x0fu];")
    lines.append("  if (terminate) dst[n] = '\\0';")
    lines.append("}")
    if is_cpp:
        lines.append("}")
    lines.append("")
    if is_cpp:
        lines.append('extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {')
    else:
        lines.append("int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {")
    lines.append("  dtfuzz_current_data = Data;")
    lines.append("  dtfuzz_current_size = Size;")
    lines.append("  uint32_t _dtfuzz_seed = 2166136261u;")
    lines.append("  for (size_t _i = 0; _i < Size; _i++) {")
    lines.append("    _dtfuzz_seed ^= Data[_i];")
    lines.append("    _dtfuzz_seed *= 16777619u;")
    lines.append("  }")
    lines.append("  dtfuzz_rand_seed(_dtfuzz_seed);")
    lines.extend(reset_lines)
    for guard in guards:
        lines.append("  " + guard)
    if model == "typed_buffer":
        lines.append(f"  uint64_t _dtfuzz_type = {_type_expression(config)};")
    lines.append(call_line)
    lines.append("  return 0;")
    lines.append("}")
    if init_code:
        lines.append("")
        if is_cpp:
            lines.append('extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {')
        else:
            lines.append("int LLVMFuzzerInitialize(int *argc, char ***argv) {")
        lines.append("  (void)argc;")
        lines.append("  (void)argv;")
        lines.extend("  " + line for line in init_code.splitlines())
        lines.append("  return 0;")
        lines.append("}")
    suffix = ".cc" if is_cpp else ".c"
    return "\n".join(lines) + "\n", suffix


def _unescape_c(value: str) -> bytes:
    raw = value.encode("utf-8")
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] != 0x5C:
            out.append(raw[i])
            i += 1
            continue
        i += 1
        if i >= len(raw):
            break
        esc = chr(raw[i])
        mapping = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, '"': 34, "'": 39, "a": 7, "b": 8, "f": 12, "v": 11}
        if esc in mapping:
            out.append(mapping[esc])
            i += 1
        elif esc == "x" and i + 2 < len(raw):
            try:
                out.append(int(raw[i + 1 : i + 3], 16))
                i += 3
            except ValueError:
                out.append(0x5C)
        else:
            out.append(ord(esc))
            i += 1
    return bytes(out)


def _dict_escape(data: bytes) -> str:
    parts = []
    for byte in data:
        if byte in (0x22, 0x5C):
            parts.append("\\" + chr(byte))
        elif 0x20 <= byte <= 0x7E:
            parts.append(chr(byte))
        else:
            parts.append(f"\\x{byte:02x}")
    return "".join(parts)


def extract_tokens(repo: str | Path, files: list[str], entry: dict) -> list[bytes]:
    tokens: list[bytes] = []
    seen: set[bytes] = set()

    def add(data: bytes) -> None:
        if not data or len(data) > 64 or data in seen:
            return
        seen.add(data)
        tokens.append(data)

    text_parts = []
    for file_name in files:
        try:
            text_parts.append(Path(file_name).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    text = "\n".join(text_parts)
    for match in re.finditer(r'"((?:\\.|[^"\\])*)"', text):
        value = _unescape_c(match.group(1))
        if 1 <= len(value) <= 32:
            add(value)
    for match in re.finditer(r"'((?:\\.|[^'\\])+)'", text):
        value = _unescape_c(match.group(1))
        if len(value) == 1:
            add(value)
    numbers: list[int] = []
    for match in re.finditer(r"\b(0x[0-9A-Fa-f]+|\d{2,})\b", text):
        try:
            numbers.append(int(match.group(1), 0))
        except ValueError:
            continue
    for value in numbers[:256]:
        if value < 0:
            continue
        if value <= 0xFF:
            add(bytes([value]))
        for width in (2, 4):
            if value < (1 << (8 * width)):
                add(value.to_bytes(width, "big"))
                add(value.to_bytes(width, "little"))
    return tokens


def render_dictionary(tokens: list[bytes]) -> str:
    lines = ["# Generated by dtfuzz"]
    for token in tokens:
        lines.append(f'"{_dict_escape(token)}"')
    return "\n".join(lines) + "\n"


def readme_seeds(repo: str | Path) -> list[bytes]:
    seeds: list[bytes] = []
    root = Path(repo)
    for name in ("README.md", "README.txt", "README"):
        path = root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for block in re.findall(r"```(?:[A-Za-z0-9_-]+)?\n(.*?)```", text, re.S):
            for line in block.splitlines():
                candidate = line.strip()
                if not candidate or len(candidate) < 4:
                    continue
                if not re.fullmatch(r"[0-9a-fA-F][0-9a-fA-F\s]*", candidate):
                    continue
                try:
                    seeds.append(parse_hex(candidate))
                except DtfuzzError:
                    continue
    return seeds


def _type_constants(files: list[str]) -> list[int]:
    values: list[int] = []
    for file_name in files:
        try:
            text = Path(file_name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in re.finditer(r"#\s*define\s+(\w*(?:TYPE|type|MSG|msg|CMD|cmd|OP|op)\w*)\s+(0x[0-9A-Fa-f]+|\d+)", text):
            try:
                values.append(int(match.group(2), 0))
            except ValueError:
                continue
    return sorted(set(values))


def write_corpus_seeds(corpus_dir: str | Path, seeds: list[bytes], metadata: dict | None = None) -> list[dict]:
    root = Path(corpus_dir)
    root.mkdir(parents=True, exist_ok=True)
    created = []
    for data in seeds:
        digest = sha256_bytes(data)
        path = root / f"seed-{digest[:16]}"
        if path.exists():
            continue
        path.write_bytes(data)
        created.append({"file": str(path), "sha256": digest, "size": len(data), "hex": data.hex(), **(metadata or {})})
    return created


def generate_artifacts(config: dict, analysis: dict, workspace, mocks: dict) -> dict:
    workspace.ensure()
    repo = config.get("repo", "")
    files = analysis.get("target_files", []) + [analysis.get("entry", {}).get("file", "")]
    tokens = extract_tokens(repo, [item for item in files if item], config.get("entry", {}))
    dict_text = render_dictionary(tokens)
    dict_path = workspace.harness_dir / "dict.txt"
    write_text(dict_path, dict_text)

    seeds = readme_seeds(repo)
    entry = config.get("entry", {})
    if entry.get("input_model") == "typed_buffer" and entry.get("type_bytes"):
        width = int(entry["type_bytes"])
        endian = entry.get("type_endian", "big")
        for value in _type_constants([item for item in files if item]):
            if value < (1 << (8 * width)):
                prefix = value.to_bytes(width, endian)
                seeds.append(prefix + b"\x00" * 3)
                seeds.append(prefix + b"\xff" * 3)
    seeds.append(b"")
    created = write_corpus_seeds(workspace.corpus_dir, seeds, {"source": "generator"})

    harness_text, suffix = render_harness(config, analysis)
    harness_path = workspace.harness_dir / f"fuzz_target{suffix}"
    write_text(harness_path, harness_text)
    runtime_header = """#ifndef DTFUZZ_RUNTIME_H
#define DTFUZZ_RUNTIME_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
uint8_t dtfuzz_input_byte(size_t index);
size_t dtfuzz_input_size(void);
void dtfuzz_rand_seed(uint32_t seed);
uint32_t dtfuzz_rand(void);
void dtfuzz_random_bytes(uint8_t *dst, size_t n);
void dtfuzz_random_hex(char *dst, size_t n, int terminate);
void dtfuzz_reset_mocks(void);
#ifdef __cplusplus
}
#endif
#endif
"""
    mocks_dir = workspace.mocks_dir(config)
    mocks_dir.mkdir(parents=True, exist_ok=True)
    runtime_path = mocks_dir / "dtfuzz_runtime.h"
    write_text(runtime_path, runtime_header)

    readme_path = mocks_dir / "README.md"
    if not readme_path.is_file():
        write_text(
            readme_path,
            "# Human-maintainable fuzz mocks\n\n"
            "This directory is outside `.dtfuzz`. `mocks.json` is the source of truth;\n"
            "`generated_mocks.c` is generated from confirmed rules. Put handwritten\n"
            "mock code in `custom_mocks.c` (or `.cc` for C++); it is compiled together\n"
            "with the generated file. Pending entries in `mocks.json` are not generated\n"
            "until a human confirms them.\n",
        )

    from .mocks import render_stubs, render_variables

    stubs_text = render_stubs(mocks, repo, config.get("language", "c"))
    variables_text = render_variables(mocks, repo)
    stubs_path = workspace.generated_mocks_path(config)
    write_text(stubs_path, stubs_text)
    variables_path = mocks_dir / ("generated_variables.cc" if suffix == ".cc" else "generated_variables.c")
    if variables_text.strip():
        write_text(variables_path, variables_text)
    return {
        "harness": str(harness_path),
        "runtime_header": str(runtime_path),
        "mocks_dir": str(mocks_dir),
        "generated_mocks": str(stubs_path),
        "generated_variables": str(variables_path) if variables_text.strip() else "",
        "dict": str(dict_path),
        "seeds_created": created,
        "tokens": len(tokens),
    }
