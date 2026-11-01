from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dtfuzz.introspect import (  # noqa: E402
    annotate_module,
    attach,
    filter_analysis,
    load_report,
    name_state,
    parse_data_yaml,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPO = Path("/tmp/dtfuzz-unit-repo")
MODULE_FILES = [str(REPO / "src" / "msg_parser.c"), str(REPO / "src" / "msg_tables.c")]
ENTRY_FILE = str(REPO / "src" / "msg_parser.c")


def report(name: str) -> dict:
    return load_report(
        FIXTURES / name,
        "msg_dispatch",
        ENTRY_FILE,
        REPO,
        {"llvm_cxxfilt": "llvm-cxxfilt"},
    )


class ParseTests(unittest.TestCase):
    def test_parses_all_functions(self) -> None:
        parsed = parse_data_yaml(FIXTURES / "msg_full.data.yaml")
        self.assertEqual(len(parsed["functions"]), 13)
        by_name = {item["functionName"]: item for item in parsed["functions"]}
        self.assertEqual(by_name["msg_dispatch"]["linkageType"], "externalLinkage")
        self.assertIn("parse_event", by_name["msg_dispatch"]["functionsReached"])
        self.assertEqual(by_name["parse_config"]["argNames"], ["buf", "len"])

    def test_full_closure_keeps_reachable_external(self) -> None:
        reach = report("msg_full.data.yaml")
        names = {item["name"] for item in reach["reachable"]}
        self.assertIn("peer_lookup", names)
        self.assertIn("cfg_get_u16", names)
        self.assertNotIn("unrelated_helper", names)
        self.assertNotIn("unused_external", names)

    def test_narrow_closure_drops_event_branch(self) -> None:
        reach = report("msg_narrow.data.yaml")
        names = {item["name"] for item in reach["reachable"]}
        self.assertNotIn("parse_event", names)
        self.assertNotIn("peer_lookup", names)
        self.assertIn("parse_config", names)

    def test_entry_matching_is_by_name_not_file(self) -> None:
        reach = report("msg_full.data.yaml")
        self.assertEqual(reach["entry"]["matched"], ["msg_dispatch"])
        self.assertTrue(reach["matched"])

    def test_unknown_name_is_not_called_unreachable(self) -> None:
        reach = report("msg_full.data.yaml")
        self.assertEqual(name_state("parse_event", reach), "reachable")
        self.assertEqual(name_state("unrelated_helper", reach), "unreachable")
        self.assertEqual(name_state("not_in_report", reach), "unknown")


class ModuleTests(unittest.TestCase):
    def test_annotate_module_and_stub_scope(self) -> None:
        reach = report("msg_full.data.yaml")
        analysis = {
            "entry": {"file": ENTRY_FILE},
            "module_files": MODULE_FILES,
            "target_files": MODULE_FILES,
            "external_symbols": [],
        }
        annotate_module(reach, analysis, REPO)
        self.assertEqual(reach["reachable_count"], 11)
        self.assertEqual(reach["module_count"], 6)
        self.assertEqual(reach["external_count"], 5)
        external = {item["name"] for item in reach["external_functions"]}
        self.assertIn("logger_write", external)
        self.assertIn("proto_crc32", external)

    def test_filter_analysis_marks_unreachable(self) -> None:
        reach = report("msg_full.data.yaml")
        analysis = {
            "entry": {"file": ENTRY_FILE},
            "module_files": MODULE_FILES,
            "target_files": MODULE_FILES,
            "external_symbols": [
                {"name": "proto_crc32", "qualified_name": "proto_crc32", "status": "excluded_only"},
                {"name": "unrelated_helper", "qualified_name": "unrelated_helper", "status": "missing"},
                {"name": "not_in_report", "qualified_name": "not_in_report", "status": "missing"},
            ],
        }
        filter_analysis(analysis, reach)
        self.assertTrue(analysis["external_symbols"][0]["reachable"])
        self.assertFalse(analysis["external_symbols"][1]["reachable"])
        self.assertTrue(analysis["external_symbols"][2]["reachable"])
        self.assertEqual(analysis["external_symbols"][2]["scope"], "unknown")

    def test_report_only_reachable_external_is_added(self) -> None:
        reach = report("msg_full.data.yaml")
        extra = {
            "raw_name": "report_only_fn",
            "name": "report_only_fn",
            "source_file": "<external>",
            "line": None,
            "linkage": "externalLinkage",
            "depth": 1,
            "complexity": 2,
            "bb_count": 1,
            "return_type": "int",
            "signature": "int report_only_fn(int x)",
            "arg_names": ["x"],
            "arg_types": ["int"],
            "functions_reached": [],
            "known": True,
            "reachable": True,
            "in_module": False,
        }
        reach["functions"].append(extra)
        reach["reachable"].append(extra)
        reach["external_functions"].append(extra)
        reach["reachable_names"].append("report_only_fn")
        reach["all_names"].append("report_only_fn")
        analysis = {
            "entry": {"file": ENTRY_FILE},
            "module_files": MODULE_FILES,
            "target_files": MODULE_FILES,
            "real_files": [str(REPO / "deps" / "logger.c")],
            "external_symbols": [],
        }
        attach(analysis, reach, REPO)
        by_name = {item["name"]: item for item in analysis["external_symbols"]}
        self.assertIn("report_only_fn", by_name)
        self.assertEqual(by_name["report_only_fn"]["source"], "introspector")
        self.assertEqual(by_name["report_only_fn"]["params"], [{"name": "x", "type": "int"}])
        self.assertTrue(by_name["report_only_fn"]["reachable"])

    def test_system_symbols_are_not_synthesized(self) -> None:
        reach = report("msg_full.data.yaml")
        extra = {
            "raw_name": "memcpy",
            "name": "memcpy",
            "source_file": "<external>",
            "linkage": "externalLinkage",
            "return_type": "void *",
            "signature": "",
            "arg_names": [],
            "arg_types": [],
            "functions_reached": [],
            "known": True,
            "reachable": True,
            "in_module": False,
        }
        reach["reachable"].append(extra)
        reach["external_functions"].append(extra)
        reach["reachable_names"].append("memcpy")
        reach["all_names"].append("memcpy")
        analysis = {
            "entry": {"file": ENTRY_FILE},
            "module_files": MODULE_FILES,
            "target_files": MODULE_FILES,
            "real_files": [],
            "external_symbols": [],
        }
        attach(analysis, reach, REPO)
        self.assertNotIn("memcpy", {item["name"] for item in analysis["external_symbols"]})


if __name__ == "__main__":
    unittest.main()
