from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dtfuzz.mocks import (  # noqa: E402
    constraint_summary,
    constraints_prompt_section,
    default_constraints,
    merge_constraints,
    merge_defaults,
    set_constraint_status,
)


def payload() -> dict:
    return {
        "constraints": {
            "input_construction": [
                {
                    "subject": "buf",
                    "requirement": "调用方用 build_packet() 生成 1 字节 type + 2 字节大端长度 + payload",
                    "reason": "parse_data 先读 declared length",
                    "evidence": "src/msg_parser.c:34",
                }
            ],
            "variable_constraints": [
                {"subject": "len", "requirement": "len 必须在 1..31", "reason": "栈上 key 拷贝"}
            ],
            "input_relations": [
                {"subject": "buf,len", "requirement": "declared == len - 2", "reason": "否则返回 -2"}
            ],
            "setup_teardown": [
                {"subject": "msg_dispatch", "requirement": "每次输入前调用 msg_reset()", "reason": "清理全局状态"}
            ],
        }
    }


class ConstraintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mocks = {"version": 1, "symbols": {}, "variables": {}, "constraints": default_constraints()}

    def test_import_creates_highlighted_drafts(self) -> None:
        added = merge_constraints(self.mocks, payload(), source="llm")
        self.assertEqual(len(added), 4)
        rows = constraint_summary(self.mocks)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(item["highlight"] for item in rows))
        self.assertTrue(all(not item["confirmed"] for item in rows))
        prefixes = {item["id"].split("-", 1)[0] for item in rows}
        self.assertEqual(prefixes, {"ic", "vc", "ir", "st"})

    def test_confirm_and_reject(self) -> None:
        added = merge_constraints(self.mocks, payload(), source="llm")
        self.assertTrue(set_constraint_status(self.mocks, added[0], confirmed=True, status="active"))
        self.assertTrue(set_constraint_status(self.mocks, added[1], confirmed=False, status="rejected"))
        rows = {item["id"]: item for item in constraint_summary(self.mocks)}
        self.assertFalse(rows[added[0]]["highlight"])
        self.assertTrue(rows[added[0]]["confirmed"])
        self.assertEqual(rows[added[1]]["status"], "rejected")

    def test_confirmed_not_overwritten_by_draft(self) -> None:
        added = merge_constraints(self.mocks, payload(), source="llm")
        set_constraint_status(self.mocks, added[0], confirmed=True, status="active")
        revised = payload()
        revised["constraints"]["input_construction"][0]["id"] = added[0]
        revised["constraints"]["input_construction"][0]["requirement"] = "LLM 改写"
        merge_constraints(self.mocks, revised, source="llm")
        rows = {item["id"]: item for item in constraint_summary(self.mocks)}
        self.assertNotEqual(rows[added[0]]["requirement"], "LLM 改写")

    def test_prompt_marks_unconfirmed(self) -> None:
        merge_constraints(self.mocks, payload(), source="llm")
        text = constraints_prompt_section(self.mocks)
        self.assertIn("待审核约束", text)
        self.assertIn("build_packet", text)

    def test_merge_defaults_skips_unreachable_symbols(self) -> None:
        analysis = {
            "external_symbols": [
                {"name": "reachable_fn", "qualified_name": "reachable_fn", "status": "missing", "reachable": True},
                {"name": "dead_fn", "qualified_name": "dead_fn", "status": "missing", "reachable": False},
            ]
        }
        merged = merge_defaults(analysis, self.mocks)
        self.assertIn("reachable_fn", merged["symbols"])
        self.assertNotIn("dead_fn", merged["symbols"])

    def test_merge_defaults_prunes_unreachable_pending(self) -> None:
        self.mocks["symbols"]["dead_fn"] = {
            "name": "dead_fn",
            "qualified_name": "dead_fn",
            "source": "pending",
            "confirmed": False,
            "stub": True,
            "reachable": True,
        }
        analysis = {
            "external_symbols": [
                {"name": "dead_fn", "qualified_name": "dead_fn", "status": "missing", "reachable": False},
            ]
        }
        merged = merge_defaults(analysis, self.mocks)
        self.assertNotIn("dead_fn", merged["symbols"])


if __name__ == "__main__":
    unittest.main()
