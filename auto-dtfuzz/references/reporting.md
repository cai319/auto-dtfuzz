# Mandatory final-report contract

Every final `dtfuzz report` must contain five sections and five JSON sidecars.
This is a skill-level requirement, not an optional reporting style.

| # | Section | Sidecar |
| --- | --- | --- |
| 1 | 被测入口与调用链 | `callgraph.json` |
| 2 | 函数级覆盖情况 | `function_coverage.json` |
| 3 | 打桩函数报告 | `stubs.json` |
| 4 | 问题列表 | `problems.json` |
| 5 | 分析报告与建议 | `analysis_report.json` |

An empty section is allowed only if it explicitly says "空/无" and why. Never
silently omit a section.

## 1. Call-chain graph (`callgraph.json`)

The graph is the **reachable chain from the tested entry**, not every function
that happens to be compiled or linked. Unrelated functions in linked real files
are excluded by a reachability traversal over the AST edges plus Fuzz
Introspector `functionsReached`.

```json
{
  "entry": "msg_dispatch",
  "nodes": [
    {"id": "n5", "name": "msg_dispatch", "type": "entry"},
    {"id": "n8", "name": "parse_data", "type": "module"},
    {"id": "n12", "name": "proto_crc32", "type": "mock"},
    {"id": "n2", "name": "logger_write", "type": "linked-real"}
  ],
  "edges": [
    {"from": "msg_dispatch", "to": "parse_data", "kind": "internal", "line": 85, "decl_file": "src/msg_parser.c"},
    {"from": "parse_data", "to": "proto_crc32", "kind": "external", "line": 27, "decl_file": "include/msg_proto.h"}
  ],
  "mermaid": "graph TD\n...",
  "truncated": false
}
```

Node types: `entry`, `module`, `linked-real`, `mock`, `external`, `must-link`.
Edge kinds: `internal`, `external`, `system`, `unknown`, `reachability`.
`report.md` embeds the Mermaid graph and an edge table. If the Mermaid graph is
truncated, the full edge list remains in `callgraph.json`.

## 2. Per-function coverage (`function_coverage.json`)

All functions recorded by `llvm-cov export` for the configured target files,
with libFuzzer hit count and line coverage:

```json
{
  "summary": {"line": {}, "function": {}, "branch": {}, "files": {}},
  "functions": [
    {
      "name": "msg_dispatch",
      "raw_name": "msg_dispatch",
      "file": "src/msg_parser.c",
      "count": 3680082,
      "total_lines": 31,
      "covered_lines": 31,
      "percent": 100.0,
      "uncovered_lines": []
    }
  ],
  "covered_functions": [],
  "uncovered_functions": [],
  "partial_functions": [],
  "counts": {"total": 6, "covered": 6, "uncovered": 0, "partial": 1}
}
```

`count > 0` means the final corpus entered the function. `count == 0` means it
was never reached. `partial_functions` are covered functions with uncovered
code regions. The markdown report has three tables (covered / partial /
uncovered) and points to the JSON for the full list.

## 3. Stub report (`stubs.json`)

Every stubbed function must name the function and the reason:

```json
{
  "confirmed": [
    {
      "symbol": "proto_crc32",
      "name": "proto_crc32",
      "signature": "int proto_crc32(const uint8_t *, size_t)",
      "status": "excluded_only",
      "reason": "唯一实现位于排除目录（dt/tests/mock/stub/fake），按策略不链接；人工规则打桩",
      "behavior": "return={'mode': 'random_choice', 'values': ['0', '-1']}",
      "evidence": "/repo/dt/fake_deps.c",
      "source": "user",
      "reachable": true,
      "scope": "stub_scope",
      "must_link": false,
      "reference_only": false
    }
  ],
  "pending": [],
  "blocked": []
}
```

Reason taxonomy:

- `excluded_only` — only definition is in excluded `dt/tests/mock/stub/fake`.
- `missing` — no definition in the repo or provided external source.
- `reference_only` — external source explicitly marked non-production.
- `resolved_real` / `must_link_real` — real definition; not a valid stub.

`pending` are unconfirmed mocks (not generated). `blocked` are real definitions
that must be linked instead of stubbed.

## 4. Problem list (`problems.json`)

```json
[
  {
    "id": "P001",
    "severity": "high",
    "category": "must-link",
    "problem": "proto_crc32 有真实定义但未链接",
    "evidence": "/opt/lib/secure.c:4",
    "action": "externals add --link 或加入 sources.real；禁止打桩。"
  }
]
```

Severities: `high` (build failure, target crash, must-link, unresolved),
`medium` (coverage below target, pending mock, external-source question),
`low` (partial function, unconfirmed constraint, analysis warning).

Categories: `build`, `must-link`, `coverage`, `crash`, `mock`,
`external-source`, `constraint`, `analysis`.

## 5. Analysis report (`analysis_report.json`)

```json
{
  "build_ok": true,
  "coverage": {"line": {}, "function": {}, "branch": {}},
  "crashes": {"target": 0, "non_target": 0},
  "stubs": {"confirmed": 4, "pending": 0, "blocked": 0},
  "must_link": 0,
  "external_source_questions": 4,
  "constraints_pending": 18,
  "problems": 8,
  "conclusions": [],
  "recommendations": []
}
```

The markdown section contains the same conclusions and recommendations in
Chinese. It must state whether the build is valid, coverage vs target, crash
count, and unresolved stub/must-link/external-source items.

## Validation checklist

- `report.md` contains all five headings (including empty-state text).
- All five sidecars exist under the workspace root.
- Every confirmed stub has a non-empty `reason` and `evidence`.
- Every `must_link` symbol appears in `stubs.blocked` and `problems`.
- Function coverage uses the final corpus profile (rerun `coverage` after the
  last `round`; a stale `summary.json` can lack per-function fields).
- Call graph only contains the entry's reachable chain.
