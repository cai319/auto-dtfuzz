from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dtfuzz.config import Workspace  # noqa: E402
from dtfuzz.makefile import generate_shims, introspect, run_host_make  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CROSS = FIXTURES / "cross-make"


class MakefileTests(unittest.TestCase):
    def test_introspect_cross_makefile(self) -> None:
        info = introspect(CROSS)
        self.assertIn("arm-linux-gnueabihf-gcc", info["compilers"])
        self.assertTrue(any(item.endswith("src/msg.c") for item in info["sources"]))
        self.assertIn(str((CROSS / "include").resolve()), info["include_dirs"])
        self.assertIn("MSG_PROTO_V2=1", info["defines"])
        self.assertEqual(info["std"], "gnu11")
        self.assertIn("-march=armv7-a", info["target_flags"])
        flags = next(iter(info["flags_by_source"].values()))
        self.assertIn("-DMSG_PROTO_V2=1", flags)
        self.assertNotIn("-march=armv7-a", flags)

    def test_generate_shims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Workspace(tmp)
            ws.ensure()
            shims = generate_shims(ws, ["arm-linux-gnueabihf-gcc", "arm-linux-gnueabihf-g++"])
            self.assertIn("arm-linux-gnueabihf-gcc", shims["created"])
            self.assertTrue(Path(shims["created"]["arm-linux-gnueabihf-gcc"]).is_file())
            text = Path(shims["created"]["arm-linux-gnueabihf-gcc"]).read_text()
            self.assertIn("DROP_PREFIXES", text)
            self.assertIn("-march=", text)

    def test_run_host_make_with_shims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            shutil.copytree(CROSS, repo)
            ws = Workspace(root / ".dtfuzz" / "msg")
            ws.ensure()
            info = introspect(repo)
            config = {
                "repo": str(repo),
                "build": {"mode": "make-host", "makefile": "Makefile", "make_target": "all"},
                "toolchain": {},
            }
            result = run_host_make(ws, config, {}, info)
            self.assertTrue(result["ok"], result.get("log"))
            self.assertTrue(any(item.endswith(".o") for item in result["objects"]))
            self.assertTrue(any(item.endswith(".a") for item in result["libraries"]))
            self.assertTrue(Path(result["log"]).is_file())


if __name__ == "__main__":
    unittest.main()
