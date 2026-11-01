from __future__ import annotations

import re
from pathlib import Path

from .mocks import summary as mocks_summary
from .util import read_json, write_text


def _clean_crash_text(text: str, workspace) -> str:
    if not text:
        return text
    cleaned = str(text).replace(str(workspace.root), "<workdir>")
    cleaned = re.sub(r"\([^)]*fuzz_target[^)]*\)", "(binary)", cleaned)
    return cleaned


def _table(headers: list[str], rows: list[list[object]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
    return "\n".join(lines)


def generate_report(workspace, config: dict, analysis: dict, mocks: dict) -> str:
    repo = config.get("repo", "")
    entry = config.get("entry", {})
    summary = read_json(workspace.coverage_dir / "summary.json", default={}) or {}
    runs = read_json(workspace.runs_dir / "history.json", default=[]) or []
    coverage_history = read_json(workspace.coverage_dir / "history.json", default=[]) or []
    build_info = read_json(workspace.build_dir / "build.json", default={}) or {}
    campaign = read_json(workspace.root / "campaign.json", default={}) or {}
    lines = [
        f"# dtfuzz report: {config.get('module') or entry.get('name', '')}",
        "",
        f"- 仓库：`{repo}`",
        f"- 入口：`{entry.get('qualified_name') or entry.get('name', '')}`（`{entry.get('file', '')}`）",
        f"- 输入模型：`{entry.get('input_model', '')}`",
        f"- 构建：{'成功' if build_info.get('ok') else '失败'}（`{build_info.get('binary', '')}`）",
        f"- 工具链：`{config.get('toolchain', {}).get('clang', '')}`",
        f"- 真实链接的跨模块源文件：{len(analysis.get('real_files', []) or [])} 个",
        f"- Mock 配置：`{workspace.mocks_config_path(config)}`",
        *(
            [f"- 预构建库：`{library}`" for library in (config.get('sources', {}) or {}).get('libraries', []) or []]
        ),
        "",
    ]
    if not summary:
        last_run = runs[-1] if runs else {}
        stats = last_run.get("stats", {}) or {}
        lines.extend(
            [
                "## 覆盖率",
                "",
                "源码覆盖率工具不可用；本次仅使用 libFuzzer 的覆盖反馈："
                f"cov={stats.get('cov')} ft={stats.get('ft')} corp={stats.get('corp')}。",
                "",
            ]
        )
    if summary:
        lines.extend(
            [
                "## 覆盖率",
                "",
                _table(
                    ["指标", "覆盖/总数", "百分比"],
                    [
                        ["行", f"{summary.get('line', {}).get('covered', 0)}/{summary.get('line', {}).get('count', 0)}", f"{summary.get('line', {}).get('percent', 0)}%"],
                        ["函数", f"{summary.get('function', {}).get('covered', 0)}/{summary.get('function', {}).get('count', 0)}", f"{summary.get('function', {}).get('percent', 0)}%"],
                        ["分支", f"{summary.get('branch', {}).get('covered', 0)}/{summary.get('branch', {}).get('count', 0)}", f"{summary.get('branch', {}).get('percent', 0)}%"],
                    ],
                ),
                "",
            ]
        )
        libfuzzer = summary.get("libfuzzer") or {}
        if libfuzzer:
            execs = libfuzzer.get("execs")
            lines.extend(
                [
                    f"- libFuzzer 覆盖率反馈：cov={libfuzzer.get('cov')} ft={libfuzzer.get('ft')} "
                    f"corp={libfuzzer.get('corp')}" + (f" execs={execs}" if execs else ""),
                    "",
                ]
            )
        file_rows = [
            [name, f"{item['lines']['covered']}/{item['lines']['count']}", f"{item['lines']['percent']}%", f"{item['functions']['percent']}%"]
            for name, item in summary.get("files", {}).items()
        ]
        if file_rows:
            lines.extend(["### 目标文件", "", _table(["文件", "行", "行覆盖", "函数覆盖"], file_rows), ""])
        uncovered = summary.get("uncovered_functions", [])
        if uncovered:
            lines.extend(["### 未覆盖函数", ""])
            for item in uncovered[:40]:
                lines.append(f"- `{item['name']}`（{item['file']}）")
            lines.append("")
        partial = summary.get("partial_functions", [])
        if partial:
            lines.extend(["### 部分覆盖函数", ""])
            for item in partial[:40]:
                lines.append(f"- `{item['name']}`（{item['file']}），未覆盖行：{item.get('uncovered_lines', [])[:15]}")
            lines.append("")
        if partial or summary.get("uncovered_functions"):
            if any(run.get("crashes") for run in runs):
                note = (
                    "> 目标包含崩溃路径：fork 子进程在崩溃时中断，部分崩溃路径行可能未被计入覆盖；"
                    "请结合“崩溃与超时”章节判断，不要把这些行简单当成不可达。"
                )
            else:
                note = (
                    "> 未覆盖行可能来自不可达分支，或由外部函数的固定返回值/out 参数控制。"
                    "后者应通过 mock body 使用 `dtfuzz_input_byte(i)` 让行为随 fuzz 输入变化，而不是只生成种子。"
                )
            lines.extend([note, ""])
    if coverage_history:
        lines.extend(
            [
                "## 轮次历史",
                "",
                _table(
                    ["轮次", "行覆盖", "函数覆盖", "未覆盖函数", "profraw"],
                    [
                        [item.get("round"), f"{item.get('line_percent')}%", f"{item.get('function_percent')}%", item.get("uncovered_functions"), item.get("raw_profiles")]
                        for item in coverage_history[-15:]
                    ],
                ),
                "",
            ]
        )
    crashes = []
    for run in runs:
        crashes.extend(run.get("crashes", []))
    lines.extend(["## 崩溃与超时", ""])
    if crashes:
        seen = set()
        for crash in crashes:
            if crash.get("id") in seen:
                continue
            seen.add(crash.get("id"))
            lines.append(f"### {crash.get('sanitizer')} `{crash.get('id')}`")
            if crash.get("summary"):
                lines.append(f"- 摘要：`{_clean_crash_text(crash.get('summary'), workspace)}`")
            lines.append(f"- 输入：`{crash.get('input')}`（{crash.get('size')} bytes）")
            lines.append(f"- 日志：`{crash.get('stderr')}`")
            for frame in crash.get("frames", [])[:6]:
                lines.append(f"  - `{_clean_crash_text(frame, workspace)}`")
            lines.append(f"- 复现：`dtfuzz repro --workdir {workspace.root} --input {crash.get('input')}`")
            lines.append("")
    else:
        lines.append("未发现崩溃。")
        lines.append("")
    non_target = []
    target_signatures = {
        (crash.get("sanitizer"), crash.get("summary"))
        for run in runs
        for crash in run.get("crashes", [])
    }
    for run in runs:
        non_target.extend(run.get("non_target_crashes", []))
    if non_target:
        seen_non_target = set()
        lines.extend(["### 非目标/运行时崩溃", ""])
        for crash in non_target:
            key = (crash.get("sanitizer"), crash.get("summary"))
            if key in seen_non_target or key in target_signatures:
                continue
            seen_non_target.add(key)
            lines.append(
                f"- `{crash.get('sanitizer')}` {_clean_crash_text(crash.get('summary') or '', workspace)} "
                f"（输入：`{crash.get('input')}`）"
            )
        lines.append("")
    symbols = mocks_summary(mocks)
    lines.extend(
        [
            "## Mock 配置",
            "",
            _table(
                ["符号", "确认", "状态", "返回", "返回序列", "out 参数", "来源"],
                [
                    [
                        item["symbol"],
                        "是" if item.get("confirmed") else "否",
                        item.get("status", ""),
                        item["return"],
                        item["return_sequence"],
                        item["out_params"],
                        item["source"],
                    ]
                    for item in symbols
                ],
            )
            if symbols
            else "未配置外部函数 mock。",
            "",
        ]
    )
    if any(not item.get("confirmed") for item in symbols):
        lines.extend(
            [
                "> 仍有未确认的 mock；它们不会生成代码，构建会保留为未定义符号。"
                "请按人给出的规则确认后再 gen/build。",
                "",
            ]
        )
    corpus_files = [item for item in workspace.corpus_dir.iterdir() if item.is_file()] if workspace.corpus_dir.is_dir() else []
    artifacts = [item for item in workspace.artifacts_dir.iterdir() if item.is_file()] if workspace.artifacts_dir.is_dir() else []
    lines.extend(
        [
            "## 语料与产物",
            "",
            f"- corpus：{len(corpus_files)} 个文件（`{workspace.corpus_dir}`）",
            f"- artifacts：{len(artifacts)} 个文件（`{workspace.artifacts_dir}`）",
            f"- 字典：`{workspace.harness_dir / 'dict.txt'}`",
            f"- 构建脚本：`{workspace.build_dir / 'build.sh'}`",
            f"- 覆盖率原始数据：`{workspace.coverage_dir}`",
            "",
            "## 复现命令",
            "",
            "```sh",
            f"dtfuzz build --workdir {workspace.root}",
            f"dtfuzz run --workdir {workspace.root} --seconds 60",
            f"dtfuzz coverage --workdir {workspace.root}",
            "```",
            "",
        ]
    )
    if campaign:
        lines.extend(
            [
                "## Campaign",
                "",
                f"- 停止原因：{campaign.get('stop_reason', '')}",
                f"- 轮数：{campaign.get('rounds', 0)}",
                "",
            ]
        )
    warnings = (analysis.get("warnings") or []) + (summary.get("warning") and [summary["warning"]] or [])
    if warnings:
        lines.extend(["## 注意事项", ""])
        for warning in dict.fromkeys(warnings):
            lines.append(f"- {warning}")
        lines.append("")
    text = "\n".join(lines)
    write_text(workspace.root / "report.md", text)
    return text
