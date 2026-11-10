from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dtfuzz.externals import add_source, attach  # noqa: E402
from dtfuzz.mocks import (  # noqa: E402
    enforce_real_definitions,
    is_real_definition,
    matching_real_definition,
    merge_defaults,
    render_stubs,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
EXTLIB = FIXTURES / "external_lib"


def analysis() -> dict:
    return {
        "entry": {"file": str(FIXTURES / "module_using_secure.c")},
        "module_files": [str(FIXTURES / "module_using_secure.c")],
        "target_files": [str(FIXTURES / "module_using_secure.c")],
        "external_symbols": [
            {
                "name": "proto_crc32",
                "qualified_name": "proto_crc32",
                "signature": "int proto_crc32(const uint8_t *data, size_t len)",
                "status": "excluded_only",
                "reachable": True,
                "decl_file": "",
            }
        ],
    }


class RealDefinitionTests(unittest.TestCase):
    def test_statuses_are_real(self) -> None:
        for status in ("conflict", "main_only", "over_cap", "external_definition"):
            self.assertTrue(is_real_definition({"status": status}), status)
        self.assertFalse(is_real_definition({"status": "missing"}))
        self.assertFalse(is_real_definition({"status": "excluded_only"}))
        self.assertTrue(is_real_definition({"external_source": {"file": "x.c"}}))
        self.assertFalse(
            is_real_definition({"external_source": {"file": "x.c"}, "reference_only": True})
        )

    def test_external_definition_blocks_mock(self) -> None:
        config = {"repo": str(FIXTURES), "external_sources": [], "sources": {}}
        add_source(config, EXTLIB, name="securec")
        data = analysis()
        attach(data, config)
        self.assertTrue(data["external_symbols"][0]["must_link"])
        merged = merge_defaults(data, None)
        self.assertNotIn("proto_crc32", merged.get("symbols", {}))

    def test_existing_confirmed_mock_is_disabled(self) -> None:
        config = {"repo": str(FIXTURES), "external_sources": [], "sources": {}}
        add_source(config, EXTLIB, name="securec")
        data = analysis()
        attach(data, config)
        mocks = {
            "version": 1,
            "symbols": {
                "proto_crc32": {
                    "name": "proto_crc32",
                    "qualified_name": "proto_crc32",
                    "confirmed": True,
                    "stub": True,
                }
            },
            "variables": {},
            "constraints": {},
        }
        blocked = enforce_real_definitions(mocks, data)
        self.assertIn("proto_crc32", blocked)
        entry = mocks["symbols"]["proto_crc32"]
        self.assertFalse(entry["confirmed"])
        self.assertFalse(entry["stub"])
        self.assertEqual(entry["status"], "must_link_real")
        rendered = render_stubs(mocks, FIXTURES)
        self.assertNotIn("int proto_crc32(", rendered)
        self.assertIn("Blocked", rendered)

    def test_reference_only_allows_mock(self) -> None:
        config = {"repo": str(FIXTURES), "external_sources": [], "sources": {}}
        add_source(config, EXTLIB, name="securec", reference_only=True)
        data = analysis()
        attach(data, config)
        symbol = data["external_symbols"][0]
        self.assertTrue(symbol["reference_only"])
        self.assertFalse(symbol.get("must_link"))
        merged = merge_defaults(data, None)
        self.assertIn("proto_crc32", merged.get("symbols", {}))

    def test_matching_real_definition(self) -> None:
        data = analysis()
        data["external_symbols"][0]["must_link"] = True
        found = matching_real_definition("proto_crc32", data)
        self.assertIsNotNone(found)
        self.assertIsNone(matching_real_definition("not_in_report", data))


if __name__ == "__main__":
    unittest.main()
