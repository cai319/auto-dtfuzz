from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dtfuzz.externals import (  # noqa: E402
    add_source,
    attach,
    remove_source,
    scan_external,
    source_context,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
EXTLIB = FIXTURES / "external_lib"
MODULE = FIXTURES / "module_using_secure.c"


def analysis() -> dict:
    return {
        "entry": {"file": str(MODULE)},
        "module_files": [str(MODULE)],
        "target_files": [str(MODULE)],
        "external_symbols": [
            {
                "name": "proto_crc32",
                "qualified_name": "proto_crc32",
                "signature": "int proto_crc32(const uint8_t *data, size_t len)",
                "status": "excluded_only",
                "reachable": True,
                "decl_file": "",
            },
            {
                "name": "not_in_library",
                "qualified_name": "not_in_library",
                "signature": "int not_in_library(void)",
                "status": "missing",
                "reachable": True,
                "decl_file": "",
            },
        ],
    }


class ExternalSourceTests(unittest.TestCase):
    def test_scan_functions_macros_types(self) -> None:
        scanned = scan_external(EXTLIB)
        self.assertIn("proto_crc32", scanned["functions"])
        self.assertIn("SECURE_MAX_LEN", scanned["macros"])
        self.assertIn("secure_reply_t", scanned["types"])
        snippet = scanned["functions"]["proto_crc32"][0]["snippet"]
        self.assertIn("SECURE_MAX_LEN", snippet)
        self.assertNotIn("reply_send", snippet)

    def test_attach_maps_symbols_and_asks_for_unknown(self) -> None:
        config = {"repo": str(FIXTURES), "external_sources": [], "sources": {}}
        add_source(config, EXTLIB, name="securec")
        data = analysis()
        attach(data, config)
        by_name = {item["name"]: item for item in data["external_symbols"]}
        self.assertIn("external_source", by_name["proto_crc32"])
        self.assertEqual(by_name["proto_crc32"]["external_source"]["line"], 4)
        self.assertNotIn("external_source", by_name["not_in_library"])
        self.assertTrue(any(item.get("symbol") == "not_in_library" for item in data["external_source_questions"]))
        self.assertTrue(any(item.get("name") == "SECURE_MAX_LEN" for item in data["external_macros"]))
        self.assertTrue(any(item.get("name") == "secure_reply_t" for item in data["external_types"]))
        self.assertTrue(any(item.get("header") == "secure.h" for item in data["external_includes"]))
        self.assertIn("SECURE_MAX_LEN", source_context(data))

    def test_link_and_unlink(self) -> None:
        config = {"repo": str(FIXTURES), "external_sources": [], "sources": {}}
        add_source(config, EXTLIB, name="securec", link=True, include_dirs=[str(EXTLIB)])
        real = config["sources"]["real"]
        self.assertTrue(any(item.endswith("secure.c") for item in real))
        self.assertIn(str(EXTLIB.resolve()), config["sources"]["include_dirs"])
        remove_source(config, EXTLIB)
        self.assertEqual(config["sources"]["real"], [])
        self.assertEqual(config["external_sources"], [])


if __name__ == "__main__":
    unittest.main()
