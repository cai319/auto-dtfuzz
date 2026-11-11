"""Mandatory final-report sections.

The skill contract requires every final report to contain:

1. the full call-chain graph from the tested entry;
2. per-function coverage for every function reached by the final corpus;
3. a stub report naming each stubbed function and why it was stubbed;
4. a problem list and an analysis/conclusion section.

This module builds those sections plus machine-readable JSON sidecars.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any

from .mocks import constraint_summary, summary as mocks_summary
from .util import read_json, write_json

MAX_MERMAID_EDGES = 400
MAX_TABLE_ROWS = 200


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
    return "\n".join(lines)


def _rel(path: str, repo: str) -> str:
    if not path or not repo:
        return path
    try:
        return str(Path(path).resolve().relative_to(Path(repo).resolve()))
    except (ValueError, OSError):
        return path


def _symbol_names(symbol: dict) -> set[str]:
    values = {
        symbol.get("name", ""),
        symbol.get("qualified_name", ""),
        symbol.get("mangled_name", ""),
    }
    return {item for item in values if item}


def _mock_names(mocks: dict) -> set[str]:
    names: set[str] = set()
    for key, symbol in (mocks.get("symbols") or {}).items():
        names.add(key.split("@", 1)[0])
        names |= _symbol_names(symbol)
    return {item for item in names if item}


def _node_type(name: str, analysis: dict, mocks: dict, entry: str) -> str:
    if name == entry:
        return "entry"
    if name in _mock_names(mocks):
        return "mock"
    for symbol in analysis.get("external_symbols", []) or []:
        if name in _symbol_names(symbol) and symbol.get("must_link"):
            return "must-link"
    repo = analysis.get("repo", "")
    module_files = set()
    for item in (analysis.get("module_files") or []) + (analysis.get("target_files") or []) + [analysis.get("entry", {}).get("file", "")]:
        if item:
            try:
                module_files.add(str(Path(item).resolve()))
            except OSError:
                module_files.add(str(item))
    real_files = set()
    for item in analysis.get("real_files", []) or []:
        try:
            real_files.add(str(Path(item).resolve()))
        except OSError:
            real_files.add(str(item))
    for file_name in (analysis.get("definitions_index") or {}).get(name, []) or []:
        path = Path(file_name)
        if not path.is_absolute() and repo:
            path = Path(repo) / path
        try:
            resolved = str(path.resolve())
        except OSError:
            resolved = str(path)
        if resolved in module_files:
            return "module"
        if resolved in real_files:
            return "linked-real"
    for symbol in analysis.get("external_symbols", []) or []:
        if name in _symbol_names(symbol) and symbol.get("status") == "linked_real":
            return "linked-real"
    return "external"


def build_callgraph(analysis: dict, mocks: dict, workspace) -> dict:
    entry = (analysis.get("entry", {}) or {}).get("qualified_name") or (analysis.get("entry", {}) or {}).get("name", "")
    edges: list[dict] = []
    seen: set[tuple] = set()

    def add_edge(caller: str, callee: str, kind: str, line: Any = None, decl_file: str = "") -> None:
        if not caller or not callee:
            return
        key = (caller, callee, kind)
        if key in seen:
            return
        seen.add(key)
        edges.append({"from": caller, "to": callee, "kind": kind, "line": line, "decl_file": decl_file})

    for bucket, kind in (
        ("internal_calls", "internal"),
        ("external_calls", "external"),
        ("system_calls", "system"),
        ("unknown_calls", "unknown"),
    ):
        for call in analysis.get(bucket, []) or []:
            add_edge(
                call.get("caller", "") or entry,
                call.get("name", ""),
                kind,
                call.get("line"),
                call.get("decl_file", ""),
            )

    # Fuzz Introspector's functionsReached adds indirect/cross-module edges that
    # the AST may not see.  The full artifact is kept separately from the
    # summary in analysis.json.
    reach = read_json(workspace.reachability_path, default=None) or {}
    raw_to_name = {
        item.get("raw_name", ""): item.get("name", item.get("raw_name", ""))
        for item in reach.get("functions", []) or []
        if item.get("raw_name")
    }
    for item in reach.get("reachable", []) or []:
        caller = item.get("name", "")
        for callee in item.get("functions_reached", []) or []:
            add_edge(caller, raw_to_name.get(callee, callee), "reachability")

    # Keep only the actual call chain from the tested entry.  Linked real files
    # may contain unrelated functions (for example utility allocators); their
    # calls must not appear in the entry's call graph.
    reachable = {entry} if entry else set()
    reachable |= set(reach.get("reachable_names") or [])
    changed = True
    while changed:
        changed = False
        for edge in edges:
            if edge["from"] in reachable and edge["to"] not in reachable:
                reachable.add(edge["to"])
                changed = True
    edges = [edge for edge in edges if edge["from"] in reachable and edge["to"] in reachable]
    names = set(reachable)
    for edge in edges:
        names.add(edge["from"])
        names.add(edge["to"])
    names.discard("")
    nodes = [
        {"id": f"n{index}", "name": name, "type": _node_type(name, analysis, mocks, entry)}
        for index, name in enumerate(sorted(names))
    ]
    id_by_name = {node["name"]: node["id"] for node in nodes}

    def mermaid_label(name: str, type_name: str) -> str:
        clean = name.replace('"', "'").replace("\n", " ")
        label = f"{clean}<br/>{type_name}"
        if len(label) > 80:
            label = label[:77] + "..."
        return label

    mermaid = ["graph TD"]
    for node in nodes:
        mermaid.append(f'  {node["id"]}["{mermaid_label(node["name"], node["type"])}"]')
    mermaid_edges = edges[:MAX_MERMAID_EDGES]
    for edge in mermaid_edges:
        source = id_by_name.get(edge["from"], "")
        target = id_by_name.get(edge["to"], "")
        if source and target:
            label = edge["kind"] + (f" L{edge['line']}" if edge.get("line") else "")
            mermaid.append(f"  {source} -->|{label}| {target}")
    truncated = len(edges) > MAX_MERMAID_EDGES
    return {
        "entry": entry,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "nodes": nodes,
        "edges": edges,
        "mermaid": "\n".join(mermaid),
        "truncated": truncated,
        "max_mermaid_edges": MAX_MERMAID_EDGES,
    }


def build_function_coverage(summary: dict) -> dict:
    functions = list(summary.get("functions") or [])
    for item in functions:
        item.setdefault("count", 0)
        item.setdefault("total_lines", 0)
        item.setdefault("covered_lines", 0)
        item.setdefault("percent", 0.0)
        item.setdefault("uncovered_lines", [])
    covered = [item for item in functions if int(item.get("count") or 0) > 0]
    uncovered = [item for item in functions if int(item.get("count") or 0) == 0]
    partial = [
        item
        for item in covered
        if item.get("uncovered_lines")
    ]
    covered.sort(key=lambda item: (item.get("file", ""), item.get("name", "")))
    uncovered.sort(key=lambda item: (item.get("file", ""), item.get("name", "")))
    partial.sort(key=lambda item: (item.get("file", ""), item.get("name", "")))
    stale = bool(functions) and all(int(item.get("total_lines") or 0) == 0 for item in functions)
    return {
        "summary": {
            "line": summary.get("line") or {},
            "function": summary.get("function") or {},
            "branch": summary.get("branch") or {},
            "files": summary.get("files", {}),
        },
        "functions": functions,
        "covered_functions": covered,
        "uncovered_functions": uncovered,
        "partial_functions": partial,
        "counts": {
            "total": len(functions),
            "covered": len(covered),
            "uncovered": len(uncovered),
            "partial": len(partial),
        },
        "stale": stale,
    }


def _stub_reason(symbol: dict) -> str:
    status = symbol.get("status", "")
    if symbol.get("reference_only"):
        return "外部源码被用户标记为 reference-only（非生产实现），允许人工 mock"
    if status == "excluded_only":
        return "唯一实现位于排除目录（dt/tests/mock/stub/fake），按策略不链接；人工规则打桩"
    if status == "missing":
        return "仓库和已提供的外部源码中都没有定义；人工规则打桩"
    if status == "resolved_real":
        return "已解析到真实实现，mock 已停用（不是有效打桩）"
    if status == "must_link_real":
        return "存在真实定义，禁止打桩"
    if status == "confirmed":
        return "人工确认的 mock 规则"
    return f"mock 状态：{status or 'unknown'}"


def _behavior(symbol: dict) -> str:
    parts = []
    if symbol.get("return"):
        parts.append(f"return={symbol.get('return')}")
    if symbol.get("return_sequence"):
        parts.append(f"sequence={symbol.get('return_sequence')}")
    if symbol.get("out_params"):
        parts.append(f"out={symbol.get('out_params')}")
    if symbol.get("body"):
        body = str(symbol["body"]).replace("\n", " ")
        parts.append(f"body={body[:160]}")
    return "; ".join(parts) or "(默认/空实现)"


def build_stub_report(mocks: dict, analysis: dict) -> dict:
    confirmed = []
    pending = []
    blocked = []
    for key, symbol in sorted((mocks.get("symbols") or {}).items()):
        names = {key.split("@", 1)[0]} | _symbol_names(symbol)
        external = next(
            (
                item for item in analysis.get("external_symbols", []) or []
                if names & _symbol_names(item)
            ),
            {},
        )
        evidence = (
            ", ".join(symbol.get("excluded_definition_files", [])[:3])
            or ", ".join((external.get("excluded_definition_files") or [])[:3])
            or (external.get("external_source") or {}).get("file", "")
            or ", ".join(symbol.get("definition_files", [])[:3])
            or ", ".join((external.get("definition_files") or [])[:3])
            or symbol.get("decl_file", "")
            or external.get("decl_file", "")
        )
        status = (
            symbol.get("status")
            or external.get("status")
            or ("confirmed" if symbol.get("confirmed") else "pending")
        )
        reason_symbol = {**symbol, "status": status, "reference_only": symbol.get("reference_only") or external.get("reference_only")}
        row = {
            "symbol": key,
            "name": symbol.get("qualified_name") or symbol.get("name", key),
            "signature": symbol.get("signature", ""),
            "status": status,
            "reason": _stub_reason(reason_symbol),
            "behavior": _behavior(symbol),
            "evidence": evidence,
            "source": symbol.get("source", ""),
            "confirmed": bool(symbol.get("confirmed", False)),
            "reachable": symbol.get("reachable", True),
            "scope": symbol.get("scope", "unknown"),
            "must_link": bool(symbol.get("must_link") or external.get("must_link")),
            "reference_only": bool(symbol.get("reference_only") or external.get("reference_only")),
            "note": symbol.get("note", ""),
        }
        if row["must_link"]:
            blocked.append(row)
        elif row["confirmed"] and symbol.get("stub", True):
            confirmed.append(row)
        else:
            pending.append(row)
    # Real definitions that never got a mock entry are still part of the
    # mandatory "do not stub" evidence.
    mock_covered = {item["name"] for item in confirmed + pending + blocked}
    for item in analysis.get("external_symbols", []) or []:
        if not item.get("must_link"):
            continue
        name = item.get("qualified_name") or item.get("name", "")
        if name in mock_covered:
            continue
        blocked.append(
            {
                "symbol": name,
                "name": name,
                "signature": item.get("signature", ""),
                "status": item.get("status", ""),
                "reason": "存在真实定义，禁止打桩；必须链接",
                "behavior": "",
                "evidence": (item.get("external_source") or {}).get("file", "")
                or ", ".join(item.get("definition_files", [])[:3]),
                "source": "analysis",
                "confirmed": False,
                "reachable": True,
                "scope": item.get("scope", "must_link"),
                "must_link": True,
                "reference_only": False,
                "note": "",
            }
        )
    return {"confirmed": confirmed, "pending": pending, "blocked": blocked}


def build_problem_list(
    config: dict,
    analysis: dict,
    summary: dict,
    mocks: dict,
    build_info: dict,
    runs: list[dict],
) -> list[dict]:
    problems: list[dict] = []

    def add(severity: str, category: str, problem: str, evidence: str, action: str) -> None:
        problems.append(
            {
                "id": f"P{len(problems) + 1:03d}",
                "severity": severity,
                "category": category,
                "problem": problem,
                "evidence": evidence,
                "action": action,
            }
        )

    if not build_info.get("ok"):
        add(
            "high",
            "build",
            "fuzz 目标未构建成功",
            build_info.get("log", "") or build_info.get("stage", ""),
            "读取 build/build.log；修复后重新 gen/build。",
        )
    make_host = build_info.get("make_host") or {}
    if make_host and not make_host.get("ok"):
        add(
            "medium",
            "build",
            "make-host 未产出 host 对象/库",
            make_host.get("log", ""),
            "检查 make-host.log、compiler shims、架构相关 TU；必要时排除或提供 host 替身。",
        )
    for item in analysis.get("external_symbols", []) or []:
        if item.get("must_link"):
            add(
                "high",
                "must-link",
                f"{item.get('qualified_name') or item.get('name')} 有真实定义但未链接",
                (item.get("external_source") or {}).get("file", "")
                or ", ".join(item.get("definition_files", [])[:3]),
                "加入 sources.real / 调整 sources.exclude，或 externals add --link；禁止打桩。",
            )
    for item in (mocks.get("symbols") or {}).values():
        if item.get("must_link"):
            add(
                "high",
                "must-link",
                f"{item.get('name')} 的 mock 被禁止（真实定义存在）",
                item.get("note", ""),
                "链接真实实现；不要确认该 mock。",
            )
        elif not item.get("confirmed") and item.get("stub", True):
            add(
                "medium",
                "mock",
                f"{item.get('name')} 仍是未确认 mock",
                item.get("signature", ""),
                "向用户确认返回值/out 参数规则，或链接真实实现。",
            )
    coverage_cfg = config.get("coverage", {}) or {}
    if summary:
        line_target = float(coverage_cfg.get("line_target", 0) or 0)
        function_target = float(coverage_cfg.get("function_target", 0) or 0)
        line_percent = float((summary.get("line") or {}).get("percent", 0) or 0)
        function_percent = float((summary.get("function") or {}).get("percent", 0) or 0)
        if line_target and line_percent < line_target:
            add(
                "medium",
                "coverage",
                f"行覆盖率 {line_percent}% 低于目标 {line_target}%",
                f"covered={summary.get('line', {}).get('covered')} total={summary.get('line', {}).get('count')}",
                "按未覆盖函数/行分类：种子、mock body、不可达；进行 optimize。",
            )
        if function_target and function_percent < function_target:
            add(
                "medium",
                "coverage",
                f"函数覆盖率 {function_percent}% 低于目标 {function_target}%",
                f"covered={summary.get('function', {}).get('covered')} total={summary.get('function', {}).get('count')}",
                "检查未调用函数是否可达，补充入口或种子。",
            )
        for item in (summary.get("uncovered_functions") or [])[:40]:
            add(
                "low",
                "coverage",
                f"函数未覆盖：{item.get('name')}",
                f"{item.get('file')}",
                "判断是种子可达、mock 控制还是入口不可达；不要简单归为不可达。",
            )
        for item in (summary.get("partial_functions") or [])[:40]:
            add(
                "low",
                "coverage",
                f"函数部分覆盖：{item.get('name')}",
                f"{item.get('file')} 未覆盖行 {item.get('uncovered_lines', [])[:10]}",
                "构造满足前置条件的种子，或让 mock body 随输入变化。",
            )
    for run in runs:
        for crash in run.get("crashes", []) or []:
            add(
                "high",
                "crash",
                f"目标崩溃：{crash.get('sanitizer')} {crash.get('summary', '')}",
                crash.get("input", ""),
                f"dtfuzz repro --workdir {config.get('_workspace_root', 'WORK')} --input {crash.get('input', 'INPUT')}；确认可达性/影响后再定性。",
            )
    for item in analysis.get("external_source_questions", []) or []:
        add(
            "medium",
            "external-source",
            item.get("question", "外部源码/头文件缺失"),
            item.get("symbol") or item.get("header") or "",
            item.get("action", "提供外部组件源码目录后 externals add/scan。"),
        )
    for item in constraint_summary(mocks):
        if item.get("highlight"):
            add(
                "low",
                "constraint",
                f"输入约束待审核：{item.get('requirement')}",
                item.get("evidence", ""),
                f"dtfuzz constraints confirm --id {item.get('id')} 或 reject。",
            )
    for warning in dict.fromkeys((analysis.get("warnings") or []) + (summary.get("warning") and [summary["warning"]] or [])):
        add("low", "analysis", str(warning), "", "检查对应分析项/源码。")
    return problems


def build_analysis_report(
    config: dict,
    analysis: dict,
    summary: dict,
    mocks: dict,
    build_info: dict,
    runs: list[dict],
    stubs: dict,
    problems: list[dict],
) -> dict:
    line = (summary.get("line") or {}) if summary else {}
    function = (summary.get("function") or {}) if summary else {}
    branch = (summary.get("branch") or {}) if summary else {}
    crashes = sum(len(run.get("crashes", []) or []) for run in runs)
    non_target = sum(len(run.get("non_target_crashes", []) or []) for run in runs)
    must_link = [item for item in analysis.get("external_symbols", []) or [] if item.get("must_link")]
    conclusions = []
    if not build_info.get("ok"):
        conclusions.append("构建未成功：当前覆盖率/崩溃数据不能视为有效验证。")
    if must_link:
        conclusions.append(f"存在 {len(must_link)} 个真实定义未链接：违反“真实定义不得打桩”的强制规则。")
    if summary:
        conclusions.append(
            f"行覆盖 {line.get('percent', 0)}%（{line.get('covered', 0)}/{line.get('count', 0)}），"
            f"函数覆盖 {function.get('percent', 0)}%，分支覆盖 {branch.get('percent', 0)}%。"
        )
    else:
        conclusions.append("没有源码覆盖率数据；只能依赖 libFuzzer cov/ft/corp 反馈。")
    if crashes:
        conclusions.append(f"发现 {crashes} 个目标代码崩溃，需要逐个复现并确认可达性/影响。")
    else:
        conclusions.append("未发现目标代码崩溃。")
    if stubs.get("confirmed"):
        conclusions.append(f"确认打桩 {len(stubs['confirmed'])} 个函数；每个都必须在报告中给出原因。")
    if stubs.get("pending"):
        conclusions.append(f"仍有 {len(stubs['pending'])} 个未确认 mock：构建不会生成它们。")
    if stubs.get("blocked"):
        conclusions.append(f"有 {len(stubs['blocked'])} 个真实定义被禁止打桩。")
    high = [item for item in problems if item.get("severity") == "high"]
    recommendations = []
    if high:
        recommendations.append("先处理高优先级问题（构建失败、must-link、目标崩溃）。")
    if stubs.get("pending"):
        recommendations.append("向用户确认 pending mock 的返回值/out 参数，或链接真实实现。")
    if analysis.get("external_source_questions"):
        recommendations.append("询问并登记外部安全库/平台组件源码，再重新扫描。")
    if summary and float((config.get("coverage", {}) or {}).get("line_target", 0) or 0) > float(line.get("percent", 0) or 0):
        recommendations.append("按未覆盖函数/行分类继续 optimize：种子、mock body、或确认不可达。")
    if not recommendations:
        recommendations.append("当前没有高优先级阻塞项；可扩大 fuzz 时长/轮次或增加接口级 campaign。")
    return {
        "build_ok": bool(build_info.get("ok")),
        "build_mode": (config.get("build", {}) or {}).get("mode", "direct"),
        "make_host_ok": (build_info.get("make_host") or {}).get("ok"),
        "coverage": {"line": line, "function": function, "branch": branch},
        "crashes": {"target": crashes, "non_target": non_target},
        "stubs": {key: len(value) for key, value in stubs.items()},
        "must_link": len(must_link),
        "external_source_questions": len(analysis.get("external_source_questions", []) or []),
        "constraints_pending": sum(1 for item in constraint_summary(mocks) if item.get("highlight")),
        "problems": len(problems),
        "conclusions": conclusions,
        "recommendations": recommendations,
    }


def build_sections(
    workspace,
    config: dict,
    analysis: dict,
    mocks: dict,
    summary: dict,
    runs: list[dict],
    build_info: dict,
) -> tuple[list[str], dict]:
    callgraph = build_callgraph(analysis, mocks, workspace)
    function_cov = build_function_coverage(summary)
    stubs = build_stub_report(mocks, analysis)
    problems = build_problem_list(config, analysis, summary, mocks, build_info, runs)
    report = build_analysis_report(config, analysis, summary, mocks, build_info, runs, stubs, problems)
    artifacts = {
        "callgraph": workspace.root / "callgraph.json",
        "function_coverage": workspace.root / "function_coverage.json",
        "stubs": workspace.root / "stubs.json",
        "problems": workspace.root / "problems.json",
        "analysis_report": workspace.root / "analysis_report.json",
    }
    write_json(artifacts["callgraph"], callgraph)
    write_json(artifacts["function_coverage"], function_cov)
    write_json(artifacts["stubs"], stubs)
    write_json(artifacts["problems"], problems)
    write_json(artifacts["analysis_report"], report)

    lines: list[str] = []
    lines.extend(["## 报告摘要", ""])
    lines.extend(
        [
            f"- 入口：`{analysis.get('entry', {}).get('qualified_name') or analysis.get('entry', {}).get('name', '')}`",
            f"- 构建：{'成功' if build_info.get('ok') else '失败'}",
            f"- 行覆盖：{function_cov['summary'].get('line', {}).get('percent', 0)}%",
            f"- 函数覆盖：{function_cov['summary'].get('function', {}).get('percent', 0)}%",
            f"- 目标崩溃：{report['crashes']['target']}；非目标崩溃：{report['crashes']['non_target']}",
            f"- 打桩：确认 {len(stubs['confirmed'])}，待确认 {len(stubs['pending'])}，禁止 {len(stubs['blocked'])}",
            f"- 问题：{len(problems)}（高 {sum(1 for p in problems if p['severity'] == 'high')}）",
            "",
        ]
    )

    lines.extend(["## 1. 被测入口与调用链", ""])
    lines.append(f"- 入口：`{callgraph['entry']}`")
    lines.append(f"- 节点 {len(callgraph['nodes'])}，边 {len(callgraph['edges'])}")
    lines.extend(["", "```mermaid", callgraph["mermaid"], "```", ""])
    if callgraph.get("truncated"):
        lines.append(
            f"> 图中仅显示前 {callgraph['max_mermaid_edges']} 条边；完整图见 `callgraph.json`。"
        )
        lines.append("")
    if callgraph["edges"]:
        rows = [
            [
                edge["from"],
                edge["to"],
                edge["kind"],
                edge.get("line", ""),
            ]
            for edge in callgraph["edges"][:MAX_TABLE_ROWS]
        ]
        lines.extend([_table(["caller", "callee", "kind", "line"], rows), ""])
        if len(callgraph["edges"]) > MAX_TABLE_ROWS:
            lines.append(f"> 边表仅显示前 {MAX_TABLE_ROWS} 条；完整数据见 `callgraph.json`。")
            lines.append("")
    else:
        lines.extend(["未从分析数据中构建出调用边。", ""])

    lines.extend(["## 2. 函数级覆盖情况", ""])
    counts = function_cov["counts"]
    lines.append(
        f"- 函数总数 {counts['total']}：已覆盖 {counts['covered']}，未覆盖 {counts['uncovered']}，部分覆盖 {counts['partial']}"
    )
    if function_cov.get("stale"):
        lines.append("> 当前 summary.json 缺少逐函数行数字段（旧数据）；请重新运行 `dtfuzz coverage` 后再生成报告。")
    lines.append("")
    if function_cov["covered_functions"]:
        rows = [
            [
                item.get("name", ""),
                item.get("file", ""),
                item.get("count", 0),
                f"{item.get('covered_lines', 0)}/{item.get('total_lines', 0)}",
                f"{item.get('percent', 0)}%",
                ",".join(str(v) for v in item.get("uncovered_lines", [])[:10]),
            ]
            for item in function_cov["covered_functions"][:MAX_TABLE_ROWS]
        ]
        lines.extend(
            [
                "### 已覆盖函数",
                "",
                _table(["函数", "文件", "libFuzzer count", "行覆盖", "行%", "未覆盖行"], rows),
                "",
            ]
        )
    else:
        lines.extend(["没有函数被最终语料覆盖（检查 harness/种子/构建）。", ""])
    if function_cov["partial_functions"]:
        rows = [
            [
                item.get("name", ""),
                item.get("file", ""),
                item.get("count", 0),
                f"{item.get('covered_lines', 0)}/{item.get('total_lines', 0)}",
                f"{item.get('percent', 0)}%",
                ",".join(str(v) for v in item.get("uncovered_lines", [])[:10]),
            ]
            for item in function_cov["partial_functions"][:MAX_TABLE_ROWS]
        ]
        lines.extend(
            [
                "### 部分覆盖函数",
                "",
                _table(["函数", "文件", "count", "行覆盖", "行%", "未覆盖行"], rows),
                "",
            ]
        )
    if function_cov["uncovered_functions"]:
        rows = [
            [item.get("name", ""), item.get("file", ""), item.get("raw_name", "")]
            for item in function_cov["uncovered_functions"][:MAX_TABLE_ROWS]
        ]
        lines.extend(
            [
                "### 未覆盖函数",
                "",
                _table(["函数", "文件", "raw name"], rows),
                "",
            ]
        )
    lines.append("> 完整逐函数数据见 `function_coverage.json`。")
    lines.append("")

    lines.extend(["## 3. 打桩函数报告", ""])
    if stubs["confirmed"]:
        rows = [
            [
                item["symbol"],
                item["signature"],
                item["status"],
                item["reason"],
                item["behavior"],
                item["evidence"],
                item["source"],
            ]
            for item in stubs["confirmed"][:MAX_TABLE_ROWS]
        ]
        lines.extend(
            [
                "### 已确认打桩",
                "",
                _table(["符号", "签名", "状态", "打桩原因", "行为", "证据", "来源"], rows),
                "",
            ]
        )
    else:
        lines.extend(["没有已确认的打桩函数。", ""])
    if stubs["pending"]:
        rows = [
            [item["symbol"], item["signature"], item["status"], item["reason"]]
            for item in stubs["pending"][:MAX_TABLE_ROWS]
        ]
        lines.extend(
            [
                "### 待确认 mock（未生成）",
                "",
                _table(["符号", "签名", "状态", "原因"], rows),
                "",
            ]
        )
    if stubs["blocked"]:
        rows = [
            [item["symbol"], item["status"], item["reason"], item["evidence"]]
            for item in stubs["blocked"][:MAX_TABLE_ROWS]
        ]
        lines.extend(
            [
                "### 禁止打桩的真实定义",
                "",
                _table(["符号", "状态", "原因", "定义位置"], rows),
                "",
            ]
        )
    lines.append("> 完整打桩数据见 `stubs.json`。")
    lines.append("")

    lines.extend(["## 4. 问题列表", ""])
    if problems:
        rows = [
            [item["id"], item["severity"], item["category"], item["problem"], item["evidence"], item["action"]]
            for item in problems[:MAX_TABLE_ROWS]
        ]
        lines.extend([_table(["ID", "严重性", "类别", "问题", "证据", "建议"], rows), ""])
        if len(problems) > MAX_TABLE_ROWS:
            lines.append(f"> 仅显示前 {MAX_TABLE_ROWS} 条；完整列表见 `problems.json`。")
            lines.append("")
    else:
        lines.extend(["没有登记问题。", ""])

    lines.extend(["## 5. 分析报告与建议", ""])
    lines.append("### 结论")
    lines.extend(f"- {item}" for item in report["conclusions"])
    lines.append("")
    lines.append("### 建议")
    lines.extend(f"- {item}" for item in report["recommendations"])
    lines.append("")
    lines.append("> 机器可读摘要见 `analysis_report.json`。")
    lines.append("")
    lines.extend(
        [
            "## 报告产物",
            "",
            f"- `callgraph.json`：{artifacts['callgraph']}",
            f"- `function_coverage.json`：{artifacts['function_coverage']}",
            f"- `stubs.json`：{artifacts['stubs']}",
            f"- `problems.json`：{artifacts['problems']}",
            f"- `analysis_report.json`：{artifacts['analysis_report']}",
            "",
        ]
    )
    return lines, artifacts
