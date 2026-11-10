from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dtfuzz.config import Workspace  # noqa: E402
from dtfuzz.report import generate_report  # noqa: E402
from dtfuzz.reporting import (  # noqa: E402
    build_callgraph,
    build_function_coverage,
    build_problem_list,
    build_sections,
    build_stub_report,
)


def analysis() -> dict:
    return {
        "repo": "/repo",
        "entry": {"name": "msg_dispatch", "qualified_name": "msg_dispatch", "file": "/repo/src/msg_parser.c"},
        "module_files": ["/repo/src/msg_parser.c", "/repo/src/msg_tables.c"],
        "target_files": ["/repo/src/msg_parser.c", "/repo/src/msg_tables.c"],
        "real_files": ["/repo/deps/logger.c"],
        "definitions_index": {
            "msg_dispatch": ["src/msg_parser.c"],
            "parse_data": ["src/msg_parser.c"],
            "table_lookup": ["src/msg_tables.c"],
            "logger_write": ["deps/logger.c"],
        },
        "internal_calls": [
            {"caller": "msg_dispatch", "name": "parse_data", "line": 10, "decl_file": "src/msg_parser.c"},
        ],
        "external_calls": [
            {"caller": "parse_data", "name": "proto_crc32", "line": 20, "decl_file": "include/msg_proto.h"},
            {"caller": "msg_dispatch", "name": "logger_write", "line": 30, "decl_file": "include/msg_proto.h"},
        ],
        "system_calls": [
            {"caller": "msg_alloc", "name": "malloc", "line": 5, "decl_file": "stdlib.h"},
        ],
        "unknown_calls": [],
        "external_symbols": [
            {
                "name": "proto_crc32",
                "qualified_name": "proto_crc32",
                "signature": "int proto_crc32(const uint8_t *, size_t)",
                "status": "excluded_only",
                "excluded_definition_files": ["/repo/dt/fake_deps.c"],
                "reachable": True,
            },
            {
                "name": "must_link_fn",
                "qualified_name": "must_link_fn",
                "signature": "int must_link_fn(void)",
                "status": "external_definition",
                "must_link": True,
                "external_source": {"file": "/ext/lib.c", "line": 4},
                "reachable": True,
            },
        ],
        "warnings": [],
        "external_source_questions": [],
    }


def mocks() -> dict:
    return {
        "version": 1,
        "constraints": {},
        "symbols": {
            "proto_crc32": {
                "name": "proto_crc32",
                "qualified_name": "proto_crc32",
                "signature": "int proto_crc32(const uint8_t *, size_t)",
                "confirmed": True,
                "stub": True,
                "return": {"mode": "random_choice", "values": ["0", "-1"]},
                "out_params": {},
                "source": "user",
                "reachable": True,
            },
            "pending_fn": {
                "name": "pending_fn",
                "qualified_name": "pending_fn",
                "signature": "int pending_fn(void)",
                "confirmed": False,
                "stub": True,
                "return": "0",
                "out_params": {},
                "source": "pending",
                "reachable": True,
            },
        },
    }


def summary() -> dict:
    return {
        "line": {"count": 100, "covered": 90, "percent": 90.0},
        "function": {"count": 3, "covered": 2, "percent": 66.67},
        "branch": {"count": 20, "covered": 15, "percent": 75.0},
        "files": {"src/msg_parser.c": {"lines": {"count": 100, "covered": 90, "percent": 90.0}, "functions": {"count": 3, "covered": 2, "percent": 66.67}, "branches": {"count": 20, "covered": 15, "percent": 75.0}}},
        "functions": [
            {
                "name": "msg_dispatch",
                "raw_name": "msg_dispatch",
                "file": "src/msg_parser.c",
                "count": 100,
                "total_lines": 30,
                "covered_lines": 30,
                "percent": 100.0,
                "uncovered_lines": [],
            },
            {
                "name": "parse_data",
                "raw_name": "parse_data",
                "file": "src/msg_parser.c",
                "count": 50,
                "total_lines": 20,
                "covered_lines": 15,
                "percent": 75.0,
                "uncovered_lines": [21, 22, 23, 24, 25],
            },
            {
                "name": "unused_fn",
                "raw_name": "unused_fn",
                "file": "src/msg_parser.c",
                "count": 0,
                "total_lines": 10,
                "covered_lines": 0,
                "percent": 0.0,
                "uncovered_lines": [30, 31, 32],
            },
        ],
        "uncovered_functions": [{"name": "unused_fn", "file": "src/msg_parser.c"}],
        "partial_functions": [{"name": "parse_data", "file": "src/msg_parser.c", "uncovered_lines": [21, 22]}],
    }


class ReportingTests(unittest.TestCase):
    def test_callgraph_is_entry_reachable_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Workspace(tmp)
            graph = build_callgraph(analysis(), mocks(), ws)
            names = {node["name"] for node in graph["nodes"]}
            self.assertIn("msg_dispatch", names)
            self.assertIn("parse_data", names)
            self.assertIn("proto_crc32", names)
            self.assertNotIn("msg_alloc", names)
            self.assertNotIn("malloc", names)
            self.assertTrue(any(edge["from"] == "parse_data" and edge["to"] == "proto_crc32" for edge in graph["edges"]))
            self.assertIn("graph TD", graph["mermaid"])

    def test_function_coverage_splits(self) -> None:
        cov = build_function_coverage(summary())
        self.assertEqual(cov["counts"], {"total": 3, "covered": 2, "uncovered": 1, "partial": 1})
        self.assertEqual(cov["covered_functions"][0]["percent"], 100.0)

    def test_stub_report_reasons_and_blocked(self) -> None:
        report = build_stub_report(mocks(), analysis())
        self.assertTrue(any(item["symbol"] == "proto_crc32" for item in report["confirmed"]))
        stub = next(item for item in report["confirmed"] if item["symbol"] == "proto_crc32")
        self.assertIn("排除目录", stub["reason"])
        self.assertIn("fake_deps.c", stub["evidence"])
        self.assertTrue(any(item["symbol"] == "must_link_fn" for item in report["blocked"]))

    def test_problems_include_build_must_link_and_crash(self) -> None:
        problems = build_problem_list(
            {"coverage": {"line_target": 95}},
            analysis(),
            summary(),
            mocks(),
            {"ok": False, "log": "build.log"},
            [{"crashes": [{"sanitizer": "AddressSanitizer", "summary": "heap-buffer-overflow", "input": "crashes/1/input"}]}],
        )
        categories = {item["category"] for item in problems}
        self.assertIn("build", categories)
        self.assertIn("must-link", categories)
        self.assertIn("crash", categories)
        self.assertTrue(any(item["severity"] == "high" for item in problems))


    def test_empty_summary_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Workspace(tmp)
            ws.ensure()
            lines, artifacts = build_sections(
                ws,
                {"repo": "/repo", "module": "msg", "entry": {}, "coverage": {}},
                analysis(),
                mocks(),
                {},
                [],
                {"ok": True},
            )
            text = "\n".join(lines)
            self.assertIn("## 2. 函数级覆盖情况", text)
            self.assertIn("没有函数被最终语料覆盖", text)
            for path in artifacts.values():
                self.assertTrue(Path(path).is_file(), path)

    def test_sections_write_sidecars_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Workspace(tmp)
            ws.ensure()
            (ws.coverage_dir / "summary.json").write_text(json.dumps(summary()), encoding="utf-8")
            (ws.runs_dir / "history.json").write_text("[]", encoding="utf-8")
            (ws.build_dir / "build.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
            lines, artifacts = build_sections(
                ws,
                {"repo": "/repo", "module": "msg", "entry": {}, "coverage": {"line_target": 95}},
                analysis(),
                mocks(),
                summary(),
                [],
                {"ok": True},
            )
            text = "\n".join(lines)
            for heading in ("报告摘要", "1. 被测入口与调用链", "2. 函数级覆盖情况", "3. 打桩函数报告", "4. 问题列表", "5. 分析报告与建议"):
                self.assertIn(heading, text)
            for path in artifacts.values():
                self.assertTrue(Path(path).is_file(), path)
            report = generate_report(
                ws,
                {"repo": "/repo", "module": "msg", "entry": {}, "coverage": {"line_target": 95}},
                analysis(),
                mocks(),
            )
            self.assertIn("## 1. 被测入口与调用链", report)
            self.assertIn("## 2. 函数级覆盖情况", report)
            self.assertIn("## 3. 打桩函数报告", report)
            self.assertIn("## 4. 问题列表", report)
            self.assertIn("## 5. 分析报告与建议", report)


if __name__ == "__main__":
    unittest.main()
