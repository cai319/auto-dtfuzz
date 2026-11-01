from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import externals as externals_mod
from .generate import _dict_escape, _unescape_c, write_corpus_seeds
from .mocks import constraint_summary, constraints_prompt_section, merge_constraints, set_symbol
from .util import DtfuzzError, format_hex, now_iso, read_json, run, snippet, truncate, write_json, write_text

MAX_PROMPT_CHARS = 60000


def _input_layout(config: dict) -> str:
    entry = config.get("entry", {})
    model = entry.get("input_model", "buffer")
    type_bytes = int(entry.get("type_bytes") or 0)
    offset = int(entry.get("type_offset") or 0)
    endian = entry.get("type_endian", "big")
    if model == "typed_buffer":
        return (
            f"输入前 {offset} 字节保留；接着 {type_bytes} 字节（{endian}-endian）是消息类型；"
            "其余字节是 payload，长度参数等于剩余字节数。"
        )
    if model == "buffer":
        return "整个 fuzz 输入就是缓冲区，长度参数等于输入字节数。"
    return "自定义输入映射；请遵守 harness 的 call_expr。"


def _signature_line(config: dict) -> str:
    entry = config.get("entry", {})
    params = ", ".join(
        f"{(param.get('type') or '').strip()} {param.get('name', '')}".strip() for param in entry.get("params", [])
    )
    return f"{entry.get('return_type', 'int')} {entry.get('qualified_name') or entry.get('name', '')}({params});"


def _seed_history(workspace) -> list[dict]:
    path = workspace.optimizer_dir / "seeds.jsonl"
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _source_context(config: dict, analysis: dict, summary: dict, limit: int = 32000) -> str:
    repo = config.get("repo", "")
    uncovered = summary.get("uncovered_lines") or {}
    parts = []
    used = 0
    for rel_name, lines in uncovered.items():
        path = Path(rel_name)
        if not path.is_absolute() and repo:
            path = Path(repo) / rel_name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        ranges = []
        start = prev = None
        for line in sorted(set(int(item) for item in lines)):
            if start is None:
                start = prev = line
            elif line <= prev + 2:
                prev = line
            else:
                ranges.append((start, prev))
                start = prev = line
        if start is not None:
            ranges.append((start, prev))
        for start, end in ranges[:8]:
            block = snippet(text, (start + end) // 2, radius=max(4, end - start + 2), limit=5000)
            header = f"--- {rel_name}:{start}-{end} ---\n"
            if used + len(block) + len(header) > limit:
                break
            parts.append(header + block)
            used += len(block) + len(header)
    return "\n\n".join(parts) if parts else "(未找到可读源码片段)"


def _mocks_section(mocks: dict | None) -> str:
    if not mocks or not mocks.get("symbols"):
        return "(无外部函数 mock)"
    parts = []
    for key, symbol in sorted(mocks.get("symbols", {}).items()):
        if not symbol.get("stub", True):
            continue
        body = (symbol.get("body") or "").strip()
        parts.append(
            f"- {key}: {symbol.get('signature', '')}\n"
            f"  return={symbol.get('return', '')!r} sequence={symbol.get('return_sequence', [])} "
            f"out_params={symbol.get('out_params', {})}\n"
            f"  body={truncate(body, 2000) if body else '(generated)'}"
        )
    return "\n".join(parts)


def build_prompt(config: dict, analysis: dict, summary: dict, mocks: dict | None = None) -> str:
    entry = config.get("entry", {})
    optimizer = config.get("optimizer", {}) or {}
    max_seeds = int(optimizer.get("max_seeds_per_round", 32))
    max_bytes = int(optimizer.get("max_seed_bytes", 4096))
    lines = [
        "你是 libFuzzer 种子语料优化器。你的唯一任务是根据覆盖率缺口生成新的二进制种子和字典条目。",
        "只输出一个 JSON 对象，不要输出解释性正文，不要使用任何工具，不要读取文件。",
        "",
        "## 目标",
        f"入口函数：{_signature_line(config)}",
        f"输入布局：{_input_layout(config)}",
        f"当前轮次覆盖率：lines {summary['line']['percent']}%，functions {summary['function']['percent']}%，branches {summary['branch']['percent']}%。",
        f"libFuzzer 反馈：cov={summary.get('libfuzzer', {}).get('cov')} ft={summary.get('libfuzzer', {}).get('ft')} "
        f"corp={summary.get('libfuzzer', {}).get('corp')}。",
        f"目标：最大化目标源文件的行覆盖与函数覆盖。",
        "",
        "## 未覆盖函数",
    ]
    uncovered = summary.get("uncovered_functions", [])
    if uncovered:
        for item in uncovered[:40]:
            lines.append(f"- {item['name']} ({item['file']}:{item.get('uncovered_lines', ['?'])[0] if item.get('uncovered_lines') else '?'})")
    else:
        lines.append("(无)")
    lines.append("")
    lines.append("## 部分覆盖函数")
    partial = summary.get("partial_functions", [])
    if partial:
        for item in partial[:30]:
            line_values = item.get("uncovered_lines", [])
            lines.append(f"- {item['name']} ({item['file']}) 未覆盖行：{line_values[:20]}")
    else:
        lines.append("(无)")
    lines.append("")
    lines.append("## 源码片段")
    lines.append(_source_context(config, analysis, summary))
    lines.append("")
    lines.append("## 已有字典")
    dict_path = Path(config.get("_workspace_root", "")) / "harness" / "dict.txt" if config.get("_workspace_root") else None
    if dict_path and dict_path.is_file():
        lines.append(truncate(dict_path.read_text(encoding="utf-8", errors="replace"), 6000))
    else:
        lines.append("(无)")
    lines.append("")
    lines.append("## 当前 mock 配置")
    lines.append(_mocks_section(mocks))
    lines.append("")
    lines.append(constraints_prompt_section(mocks))
    lines.append("")
    lines.append("## 外部库/平台组件源码（用户提供的外挂目录，只读）")
    lines.append(externals_mod.source_context(analysis))
    lines.append("")
    lines.append("## 外部函数可控性")
    lines.append(
        "stub body 可以调用 `dtfuzz_input_byte(i)`（越界返回 0）和 `dtfuzz_input_size()`，"
        "让外部函数的返回值/out 参数随 fuzz 输入变化。这是覆盖“成功/失败两侧分支”的首选方法；"
        "只改种子无法改变固定 mock 的返回值。"
    )
    lines.append("")
    lines.append("## 输出格式")
    lines.append(
        json.dumps(
            {
                "seeds": [{"hex": "010203", "reason": "why this input reaches a new branch"}],
                "dict": ["TOKEN", "\\x00\\x07"],
                "mocks": {
                    "peer_lookup": {
                        "body": "if (out) out->code = dtfuzz_input_byte(2) == 0x99 ? 0x99 : 0; return dtfuzz_input_byte(1) & 1 ? 0 : -1;"
                    }
                },
                "constraints": {
                    "input_construction": [
                        {"subject": "buf", "requirement": "...", "reason": "...", "evidence": "src/msg_parser.c:42", "applies_to": "entry"}
                    ],
                    "variable_constraints": [],
                    "input_relations": [],
                    "setup_teardown": [],
                },
                "notes": "optional short note",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    lines.append("")
    lines.append("## 硬性要求")
    lines.append(f"- seeds 最多 {max_seeds} 个，每个解码后不超过 {max_bytes} 字节。")
    lines.append("- hex 必须是偶数个十六进制字符，不带 0x 前缀；必须符合上面的输入布局（尤其是类型字段）。")
    lines.append("- 不要重复已有字典条目；优先构造能进入未覆盖函数/分支的完整消息。")
    lines.append("- dict 条目使用 libFuzzer 字典语法，二进制字节用 \\xNN。")
    lines.append("- mocks 补丁只使用当前配置里已有的符号名；body 必须是完整 C/C++ 语句，且参数名与签名一致。")
    lines.append("- 如果未覆盖行由外部函数返回值控制，优先修改对应 mock body，而不是只生成种子。")
    lines.append(
        "- constraints 是待人工审核的草案：只写有源码/调用方证据的约束，evidence 填 file:line；"
        "不要重复已确认的约束，也不要把草案当成已生效规则。"
    )
    prompt = "\n".join(lines)
    return truncate(prompt, MAX_PROMPT_CHARS)


def _extract_json(text: str) -> dict:
    cleaned = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.S)
    if fence:
        cleaned = fence.group(1)
    else:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            cleaned = cleaned[start : end + 1]
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise DtfuzzError(f"optimizer did not return valid JSON: {exc}\n{truncate(text, 2000)}") from exc
    if not isinstance(data, dict):
        raise DtfuzzError("optimizer JSON must be an object")
    return data


def _validate_seeds(data: dict, config: dict) -> tuple[list[bytes], list[str], str, dict, dict]:
    optimizer = config.get("optimizer", {}) or {}
    max_seeds = int(optimizer.get("max_seeds_per_round", 32))
    max_bytes = int(optimizer.get("max_seed_bytes", 4096))
    raw_seeds = data.get("seeds") or []
    seeds: list[bytes] = []
    reasons: list[str] = []
    for item in raw_seeds[:max_seeds]:
        if isinstance(item, dict):
            value = item.get("hex", "")
            reason = item.get("reason", "")
        else:
            value = str(item)
            reason = ""
        cleaned = re.sub(r"[\s:,_-]+", "", value)
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if len(cleaned) % 2:
            continue
        try:
            seed = bytes.fromhex(cleaned)
        except ValueError:
            continue
        if len(seed) > max_bytes:
            continue
        seeds.append(seed)
        reasons.append(reason)
    raw_dict = data.get("dict") or []
    dict_tokens = [str(item) for item in raw_dict if str(item).strip()][:128]
    mock_patches: dict[str, dict] = {}
    raw_mocks = data.get("mocks") or {}
    if isinstance(raw_mocks, dict):
        for key, patch in raw_mocks.items():
            if not isinstance(patch, dict):
                continue
            clean: dict = {}
            if "return" in patch:
                clean["return"] = str(patch["return"])
            if "return_sequence" in patch and isinstance(patch["return_sequence"], list):
                clean["return_sequence"] = [str(item) for item in patch["return_sequence"]]
            if "out_params" in patch and isinstance(patch["out_params"], dict):
                clean["out_params"] = patch["out_params"]
            if "body" in patch:
                body = patch.get("body")
                if isinstance(body, str) and len(body) <= 20000:
                    clean["body"] = body
            if "stub" in patch:
                clean["stub"] = bool(patch["stub"])
            if "note" in patch:
                clean["note"] = str(patch["note"])
            if clean:
                mock_patches[str(key)] = clean
    constraints_payload = data.get("constraints") or {}
    return seeds, dict_tokens, str(data.get("notes", "")), mock_patches, constraints_payload


def _append_dict(workspace, tokens: list[str]) -> int:
    if not tokens:
        return 0
    path = workspace.harness_dir / "dict.txt"
    existing = set()
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            existing.add(line.strip())
    added = 0
    lines = []
    for token in tokens:
        raw = _unescape_c(token)
        rendered = f'"{_dict_escape(raw)}"'
        if rendered in existing:
            continue
        existing.add(rendered)
        lines.append(rendered)
        added += 1
    if lines:
        exists = path.is_file()
        with open(path, "a", encoding="utf-8") as fh:
            if exists and path.stat().st_size and not path.read_text(encoding="utf-8").endswith("\n"):
                fh.write("\n")
            fh.write("\n".join(lines) + "\n")
    return added


def add_seeds(workspace, seeds: list[bytes], reasons: list[str], source: str, round_no: int) -> list[dict]:
    created = write_corpus_seeds(workspace.corpus_dir, seeds, {"source": source, "round": round_no})
    if not created:
        return []
    history_path = workspace.optimizer_dir / "seeds.jsonl"
    with open(history_path, "a", encoding="utf-8") as fh:
        for record, reason in zip(created, reasons + [""] * len(created)):
            fh.write(
                json.dumps(
                    {
                        "time": now_iso(),
                        "round": round_no,
                        "source": source,
                        "hex": record["hex"],
                        "size": record["size"],
                        "reason": reason,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return created


def _call_claude_cli(config: dict, prompt: str) -> str:
    optimizer = config.get("optimizer", {}) or {}
    cmd = list(optimizer.get("claude_cmd") or ["claude", "-p", "--output-format", "json"])
    model = optimizer.get("model") or ""
    if model and "--model" not in cmd:
        cmd.extend(["--model", model])
    proc = run(cmd, input_text=prompt, timeout=900)
    if proc.returncode != 0:
        raise DtfuzzError(f"claude CLI optimizer failed ({proc.returncode}):\n{(proc.stderr or proc.stdout)[-4000:]}")
    text = proc.stdout.strip()
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            for key in ("result", "text", "content"):
                value = payload.get(key)
                if isinstance(value, str):
                    return value
    except json.JSONDecodeError:
        pass
    return text


def _call_anthropic(config: dict, prompt: str) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise DtfuzzError("ANTHROPIC_API_KEY is not set")
    optimizer = config.get("optimizer", {}) or {}
    model = optimizer.get("model") or "claude-sonnet-5-5"
    base = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    body = json.dumps(
        {
            "model": model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        base + "/v1/messages",
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise DtfuzzError(f"Anthropic API error {exc.code}: {detail[:2000]}") from exc
    except urllib.error.URLError as exc:
        raise DtfuzzError(f"Anthropic API request failed: {exc}") from exc
    texts = [block.get("text", "") for block in payload.get("content", []) if block.get("type") == "text"]
    return "\n".join(texts)


def optimize(workspace, config: dict, analysis: dict, summary: dict, mode: str | None = None) -> dict:
    optimizer = config.get("optimizer", {}) or {}
    mode = mode or optimizer.get("mode") or "none"
    round_no = int(summary.get("round") or 0)
    config = {**config, "_workspace_root": str(workspace.root)}
    mocks = workspace.load_mocks(config)
    prompt = build_prompt(config, analysis, summary, mocks)
    workspace.optimizer_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace.optimizer_dir / f"round-{round_no}-prompt.md"
    write_text(prompt_path, prompt)
    context_path = workspace.optimizer_dir / f"round-{round_no}-context.json"
    write_json(
        context_path,
        {
            "round": round_no,
            "coverage": {
                "line": summary.get("line"),
                "function": summary.get("function"),
                "uncovered_functions": summary.get("uncovered_functions", []),
                "uncovered_lines": summary.get("uncovered_lines", {}),
            },
            "entry": config.get("entry", {}),
        },
    )
    base = {
        "mode": mode,
        "round": round_no,
        "prompt": str(prompt_path),
        "context": str(context_path),
        "seeds_added": [],
        "dict_added": 0,
    }
    if mode in {"none", "prompt", ""}:
        base["mocks_changed"] = False
        base["next"] = (
            f"Read {prompt_path}, generate a JSON object, then run "
            f"`dtfuzz optimize --mode import --file <result.json>`. "
            "The JSON may contain seeds, dict, and mocks body patches."
        )
        return base
    if mode == "claude-cli":
        raw = _call_claude_cli(config, prompt)
    elif mode in {"anthropic-api", "api"}:
        raw = _call_anthropic(config, prompt)
    elif mode == "import":
        raise DtfuzzError("use --file for import mode")
    else:
        raise DtfuzzError(f"unknown optimizer mode: {mode}")
    raw_path = workspace.optimizer_dir / f"round-{round_no}-response.txt"
    write_text(raw_path, raw)
    data = _extract_json(raw)
    seeds, dict_tokens, notes, mock_patches, constraints_payload = _validate_seeds(data, config)
    created = add_seeds(workspace, seeds, [""] * len(seeds), mode, round_no)
    dict_added = _append_dict(workspace, dict_tokens)
    mocks = workspace.load_mocks(config)
    for key, patch in mock_patches.items():
        set_symbol(mocks, key, {**patch, "source": "optimizer"})
    constraints_added = merge_constraints(mocks, constraints_payload, source=mode, confirmed=False)
    if mock_patches or constraints_added:
        workspace.save_mocks(mocks, config)
    base.update(
        {
            "response": str(raw_path),
            "seeds_added": created,
            "dict_added": dict_added,
            "notes": notes,
            "parsed_seeds": len(seeds),
            "mocks_changed": bool(mock_patches),
            "mock_patches": list(mock_patches),
            "constraints_added": constraints_added,
        }
    )
    return base


def _entry_source(config: dict, analysis: dict, limit: int = 24000) -> str:
    source = (analysis.get("entry", {}) or {}).get("source") or ""
    if source:
        return truncate(source, limit)
    file_name = (config.get("entry", {}) or {}).get("file") or ""
    if not file_name:
        return "(入口源码不可用)"
    try:
        return truncate(Path(file_name).read_text(encoding="utf-8", errors="replace"), limit)
    except OSError:
        return "(入口源码不可用)"


def _reachable_context(workspace, config: dict, limit: int = 30000) -> str:
    reach = read_json(workspace.reachability_path, default=None) or {}
    functions = [item for item in reach.get("reachable", []) if item.get("known")]
    functions.sort(key=lambda item: (-(item.get("complexity") or 0), item.get("name", "")))
    parts = []
    used = 0
    for item in functions[:20]:
        header = (
            f"- {item.get('name')}  ({item.get('source_file')}:{item.get('line')}) "
            f"complexity={item.get('complexity', 0)} linkage={item.get('linkage', '')} "
            f"in_module={item.get('in_module', False)}"
        )
        parts.append(header)
        used += len(header)
        file_name = item.get("source_file") or ""
        line = item.get("line")
        if not file_name or not line:
            continue
        try:
            text = Path(file_name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        block = snippet(text, int(line), radius=12, limit=3000)
        if used + len(block) > limit:
            break
        parts.append(block)
        used += len(block)
    return "\n".join(parts) if parts else "(没有可用的 Fuzz Introspector 可达函数信息)"


def build_constraints_prompt(config: dict, analysis: dict, mocks: dict | None, workspace) -> str:
    entry = config.get("entry", {})
    reach = read_json(workspace.reachability_path, default=None) or {}
    lines = [
        "你是 C/C++ 输入约束分析器。请为下面的消息入口起草四类输入约束，供人工审核。",
        "只输出一个 JSON 对象，不要输出解释性正文，不要使用任何工具，不要读取文件。",
        "",
        "## 目标入口",
        f"签名：{_signature_line(config)}",
        f"输入布局：{_input_layout(config)}",
        (
            "Fuzz Introspector 可达性："
            f"report={reach.get('report')} matched={reach.get('matched')} "
            f"reachable={len(reach.get('reachable', []))} external={len(reach.get('external_functions', []))}"
        ),
        "",
        "## 入口源码",
        _entry_source(config, analysis),
        "",
        "## 从入口可达的函数（按复杂度排序，来自 Fuzz Introspector 静态图）",
        _reachable_context(workspace, config),
        "",
        "## 当前 mock",
        _mocks_section(mocks),
        "",
        constraints_prompt_section(mocks or {}),
        "",
        "## 外部库/平台组件源码（用户提供的外挂目录，只读）",
        externals_mod.source_context(analysis),
        "",
        "## 四类约束的定义",
        "1. input_construction：如何构造合法输入/参数。写清使用哪个函数、哪个字段、哪种缓冲区布局；"
        "例如“调用方先用 build_packet() 生成 1 字节 type + 2 字节大端长度 + payload”。",
        "2. variable_constraints：单个变量的隐式约束。范围、非空、以 NUL 结尾、枚举取值、指针对齐、"
        "最大长度等；例如“len 必须大于 0 且不超过 4096”。",
        "3. input_relations：多个输入之间的关系。例如“buf 非空时 len 必须等于剩余 payload 长度”，"
        "“type 字段决定 payload 的解析分支”。",
        "4. setup_teardown：调用入口前必须执行的初始化，以及每次 fuzz 输入后需要清理的状态；"
        "例如“先调用 msg_init() 注册表”，或“每次输入后调用 msg_reset()”。",
        "",
        "## 输出格式",
        json.dumps(
            {
                "constraints": {
                    "input_construction": [
                        {
                            "subject": "buf",
                            "requirement": "buf 指向至少 len 字节的可读缓冲区",
                            "reason": "解析器在 len 范围内读取 payload",
                            "evidence": "src/msg_parser.c:42",
                            "applies_to": "entry",
                        }
                    ],
                    "variable_constraints": [],
                    "input_relations": [],
                    "setup_teardown": [],
                },
                "notes": "optional short note",
            },
            ensure_ascii=False,
            indent=2,
        ),
        "",
        "## 硬性要求",
        "- 每条必须有 requirement；reason 说明为什么重要；evidence 填能定位的 file:line，定位不到就留空。",
        "- 只写源码、调用方或可达函数能支持的约束；不要发明函数、结构体字段或缓冲区布局。",
        "- requirement 必须是可执行的构造/约束描述，不要写成泛泛的功能描述。",
        "- 每类最多 8 条；没有就返回空列表。",
        "- 不要重复已确认的约束；草案默认 confirmed=false，等待人工审核。",
        "- 只输出 JSON，不要输出 Markdown 代码围栏以外的内容。",
    ]
    return truncate("\n".join(lines), MAX_PROMPT_CHARS)


def draft_constraints(workspace, config: dict, analysis: dict, mocks: dict | None = None, mode: str | None = None) -> dict:
    optimizer = config.get("optimizer", {}) or {}
    mode = mode or optimizer.get("mode") or "prompt"
    mocks = mocks or workspace.load_mocks(config)
    prompt = build_constraints_prompt(config, analysis, mocks, workspace)
    workspace.optimizer_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace.optimizer_dir / "constraints-prompt.md"
    write_text(prompt_path, prompt)
    base = {"mode": mode, "prompt": str(prompt_path), "constraints_added": []}
    if mode == "prompt":
        base["next"] = (
            f"Read {prompt_path}, generate one JSON object with a constraints section, then run "
            f"`dtfuzz constraints draft --workdir {workspace.root} --file <result.json>`."
        )
        return base
    if mode == "claude-cli":
        raw = _call_claude_cli(config, prompt)
    elif mode in {"anthropic-api", "api"}:
        raw = _call_anthropic(config, prompt)
    else:
        raise DtfuzzError(f"unknown constraints draft mode: {mode}")
    response_path = workspace.optimizer_dir / "constraints-response.txt"
    write_text(response_path, raw)
    data = _extract_json(raw)
    mocks = workspace.load_mocks(config)
    added = merge_constraints(mocks, data.get("constraints") or data, source=mode, confirmed=False)
    if added:
        workspace.save_mocks(mocks, config)
    base.update(
        {
            "response": str(response_path),
            "constraints_added": added,
            "notes": str(data.get("notes", "")),
        }
    )
    return base


def import_seeds(workspace, config: dict, file_path: str | Path, source: str = "import") -> dict:
    data = read_json(file_path)
    if data is None:
        raise DtfuzzError(f"seed file not found: {file_path}")
    if isinstance(data, list):
        data = {"seeds": data}
    seeds, dict_tokens, notes, mock_patches, constraints_payload = _validate_seeds(data, config)
    round_no = int((read_json(workspace.coverage_dir / "history.json", default=[]) or [{}])[-1].get("round", 0))
    created = add_seeds(workspace, seeds, [""] * len(seeds), source, round_no)
    dict_added = _append_dict(workspace, dict_tokens)
    mocks = workspace.load_mocks(config)
    for key, patch in mock_patches.items():
        set_symbol(mocks, key, {**patch, "source": source})
    constraints_added = merge_constraints(mocks, constraints_payload, source=source, confirmed=False)
    if mock_patches or constraints_added:
        workspace.save_mocks(mocks, config)
    return {
        "seeds_added": created,
        "dict_added": dict_added,
        "parsed_seeds": len(seeds),
        "notes": notes,
        "mocks_changed": bool(mock_patches),
        "mock_patches": list(mock_patches),
        "constraints_added": constraints_added,
    }
