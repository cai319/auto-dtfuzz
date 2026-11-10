from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from dtfuzz import setup  # noqa: E402
from dtfuzz.util import DtfuzzError  # noqa: E402


def platform(os_name: str, distro: str = "", wsl: bool = False) -> dict:
    return {
        "os": os_name,
        "wsl": wsl,
        "distro": distro,
        "distro_like": "",
        "version": "",
        "pretty": distro,
        "kernel": "test",
        "machine": "x86_64",
    }


class SetupPlanTests(unittest.TestCase):
    def test_ubuntu_base_commands(self) -> None:
        commands = setup._base_commands(platform("linux", "ubuntu", True))
        text = "\n".join(item["display"] for item in commands)
        self.assertIn("apt-get update", text)
        self.assertIn("apt-get install", text)
        self.assertIn("libclang-rt", text)

    def test_fedora_and_arch(self) -> None:
        fedora = "\n".join(item["display"] for item in setup._base_commands(platform("linux", "fedora")))
        arch = "\n".join(item["display"] for item in setup._base_commands(platform("linux", "arch")))
        self.assertIn("dnf install", fedora)
        self.assertIn("pacman -S", arch)

    def test_wsl_plan_notes_and_mnt_warning(self) -> None:
        fake_info = {
            "fuzz_ok": False,
            "coverage_ok": False,
            "llvm_symbolizer": None,
            "llvm_cxxfilt": None,
        }
        with (
            patch.object(setup, "detect_platform", return_value=platform("linux", "ubuntu", True)),
            patch.object(setup, "doctor", return_value=fake_info),
            patch.object(setup.shutil, "which", return_value=None),
        ):
            plan = setup.build_plan(["base", "fi-light"], fi_src="/tmp/fi-test", repo="/mnt/c/repo")
        self.assertTrue(any("WSL2" in note for note in plan["notes"]))
        self.assertTrue(any("/mnt/" in warning for warning in plan["warnings"]))
        self.assertIn("base", plan["components"])
        self.assertIn("fi-light", plan["components"])
        self.assertTrue(any("fuzz-introspector" in cmd["display"] for cmd in plan["components"]["fi-light"]))

    def test_unknown_component_rejected(self) -> None:
        with self.assertRaises(DtfuzzError):
            setup.build_plan(["nope"])

    def test_install_requires_yes(self) -> None:
        with self.assertRaises(DtfuzzError):
            setup.install({"components": {}}, yes=False)


if __name__ == "__main__":
    unittest.main()
