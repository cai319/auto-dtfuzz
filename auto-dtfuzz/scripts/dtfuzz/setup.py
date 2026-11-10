"""Platform-aware setup planner/installer for dtfuzz toolchains.

Design rules:

* ``dtfuzz setup`` (no flags) only prints a plan.  It never changes the system.
* ``dtfuzz setup --install --yes`` is required to execute commands.
* ``sudo`` is never run unless passwordless sudo works (``sudo -n true``).
  Otherwise the plan is printed for the user to run manually.
* Fuzz Introspector is optional.  The light frontend is a clone + venv + pip
  install; the LTO pass needs a custom clang build and is not attempted by
  default.
* Windows support is WSL2 only.  The plan includes WSL-specific path/sudo notes.
"""

from __future__ import annotations

import os
import platform as platform_module
import shlex
import shutil
from pathlib import Path
from typing import Any

from .detect import doctor
from .util import DtfuzzError, run

DEFAULT_FI_SRC = "~/.local/share/fuzz-introspector"
DEFAULT_COMPONENTS = ("base", "fi-light")


def _read_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return data
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"')
    return data


def _is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    for candidate in ("/proc/version", "/proc/sys/kernel/osrelease"):
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            if "microsoft" in path.read_text(encoding="utf-8", errors="replace").lower():
                return True
        except OSError:
            continue
    return False


def detect_platform() -> dict[str, Any]:
    system = platform_module.system().lower()
    if os.name == "nt":
        system = "windows"
    release = _read_os_release()
    distro = release.get("ID", "").lower()
    distro_like = release.get("ID_LIKE", "").lower()
    return {
        "os": system,
        "wsl": _is_wsl() if system == "linux" else False,
        "distro": distro,
        "distro_like": distro_like,
        "version": release.get("VERSION_ID", ""),
        "pretty": release.get("PRETTY_NAME", ""),
        "kernel": platform_module.release(),
        "machine": platform_module.machine(),
    }


def _cmd(display: str, argv: list[str], cwd: str | None = None, note: str = "") -> dict[str, Any]:
    return {"display": display, "argv": argv, "cwd": cwd, "note": note}


def _base_commands(plat: dict[str, Any]) -> list[dict[str, Any]]:
    distro = f"{plat.get('distro', '')} {plat.get('distro_like', '')}".lower()
    if plat["os"] == "darwin":
        return [
            _cmd("brew install llvm", ["brew", "install", "llvm"], note="Homebrew LLVM ships libFuzzer and llvm-cov."),
        ]
    if "ubuntu" in distro or "debian" in distro:
        return [
            _cmd("sudo apt-get update", ["sudo", "apt-get", "update"]),
            _cmd(
                "sudo apt-get install -y clang llvm lld binutils git python3 python3-venv python3-pip build-essential",
                [
                    "sudo", "apt-get", "install", "-y", "clang", "llvm", "lld", "binutils", "git",
                    "python3", "python3-venv", "python3-pip", "build-essential",
                ],
                note="Ubuntu/Debian. If libclang_rt.fuzzer is still missing, install libclang-rt-<major>-dev.",
            ),
            _cmd(
                "sudo apt-get install -y libclang-rt-dev || sudo apt-get install -y libclang-rt-$(clang -dumpversion | cut -d. -f1)-dev",
                ["bash", "-lc", "sudo apt-get install -y libclang-rt-dev || sudo apt-get install -y libclang-rt-$(clang -dumpversion | cut -d. -f1)-dev"],
                note="The package name is versioned on some releases.",
            ),
        ]
    if "fedora" in distro or "rhel" in distro:
        return [
            _cmd(
                "sudo dnf install -y clang compiler-rt llvm lld binutils git python3 python3-pip python3-virtualenv make gcc gcc-c++",
                [
                    "sudo", "dnf", "install", "-y", "clang", "compiler-rt", "llvm", "lld", "binutils",
                    "git", "python3", "python3-pip", "python3-virtualenv", "make", "gcc", "gcc-c++",
                ],
                note="Fedora/RHEL. Enable CRB/PowerTools if compiler-rt is unavailable.",
            )
        ]
    if "arch" in distro:
        return [
            _cmd(
                "sudo pacman -S --needed clang llvm compiler-rt lld binutils git python python-pip make",
                [
                    "sudo", "pacman", "-S", "--needed", "clang", "llvm", "compiler-rt", "lld",
                    "binutils", "git", "python", "python-pip", "make",
                ],
            )
        ]
    if plat["os"] == "windows" and not plat["wsl"]:
        return [
            _cmd(
                "wsl --install -d Ubuntu-22.04",
                ["wsl", "--install", "-d", "Ubuntu-22.04"],
                note="Native Windows is not supported. Install WSL2 and run dtfuzz inside Ubuntu.",
            )
        ]
    return []


def _fi_light_commands(fi_src: str) -> list[dict[str, Any]]:
    root = str(Path(fi_src).expanduser())
    commands: list[dict[str, Any]] = []
    if not Path(root).exists():
        commands.append(
            _cmd(
                f"git clone --depth 1 https://github.com/ossf/fuzz-introspector {root}",
                ["git", "clone", "--depth", "1", "https://github.com/ossf/fuzz-introspector", root],
            )
        )
    commands.extend(
        [
            _cmd(
                f"python3 -m venv {root}/.venv",
                ["python3", "-m", "venv", f"{root}/.venv"],
                note="Fuzz Introspector has its own Python dependencies; keep them in a venv.",
            ),
            _cmd(
                f"{root}/.venv/bin/pip install -r {root}/requirements.txt",
                [f"{root}/.venv/bin/pip", "install", "-r", f"{root}/requirements.txt"],
                note="Installs tree-sitter/pyyaml and the rest of Fuzz Introspector's requirements.",
            ),
        ]
    )
    return commands


def _fi_lto_commands(fi_src: str) -> list[dict[str, Any]]:
    root = str(Path(fi_src).expanduser())
    return [
        _cmd(
            f"git clone --depth 1 https://github.com/ossf/fuzz-introspector {root}",
            ["git", "clone", "--depth", "1", "https://github.com/ossf/fuzz-introspector", root],
        ),
        _cmd(
            "sudo apt-get install -y binutils texinfo cmake ninja-build",
            ["sudo", "apt-get", "install", "-y", "binutils", "texinfo", "cmake", "ninja-build"],
            note="The LTO pass needs a custom LLVM 15 build and gold; this is slow and Linux-only.",
        ),
        _cmd(
            f"cd {root} && ./build_all.sh",
            ["bash", "-lc", f"cd {root} && ./build_all.sh"],
            note="Builds a custom clang with the Fuzz Introspector pass. Expect a long build; then pass --fi-clang.",
        ),
    ]


def _docker_commands() -> list[dict[str, Any]]:
    return [
        _cmd(
            "sudo apt-get install -y docker.io git",
            ["sudo", "apt-get", "install", "-y", "docker.io", "git"],
            note="Or use Docker Desktop for Windows with WSL2 integration. Docker is only needed for OSS-Fuzz helper.",
        ),
        _cmd(
            "git clone --depth 1 https://github.com/google/oss-fuzz",
            ["git", "clone", "--depth", "1", "https://github.com/google/oss-fuzz"],
            note="Then: cd oss-fuzz && python3 infra/helper.py introspector PROJECT_NAME",
        ),
    ]


def _missing_tools(info: dict[str, Any]) -> list[str]:
    missing = []
    if not info.get("fuzz_ok"):
        missing.append("clang + libFuzzer runtime")
    if not info.get("coverage_ok"):
        missing.append("llvm-cov / llvm-profdata")
    for key, label in (
        ("llvm_symbolizer", "llvm-symbolizer"),
        ("llvm_cxxfilt", "llvm-cxxfilt"),
    ):
        if not info.get(key):
            missing.append(label)
    for tool in ("git", "python3"):
        if not shutil.which(tool):
            missing.append(tool)
    if not shutil.which("python3"):
        missing.append("python3 (venv/pip)")
    return missing


def _sudo_passwordless() -> bool:
    proc = run(["sudo", "-n", "true"], timeout=10)
    return proc.returncode == 0


def build_plan(
    components: list[str] | None = None,
    fi_src: str = DEFAULT_FI_SRC,
    repo: str | None = None,
) -> dict[str, Any]:
    plat = detect_platform()
    info = doctor(repo) if repo else doctor()
    components = list(components or DEFAULT_COMPONENTS)
    unknown = set(components) - {"base", "fi-light", "fi-lto", "docker"}
    if unknown:
        raise DtfuzzError(f"unknown setup components: {', '.join(sorted(unknown))}")
    missing = _missing_tools(info)
    notes: list[str] = []
    warnings: list[str] = []

    if plat["os"] == "windows" and not plat["wsl"]:
        warnings.append("原生 Windows 不受支持；请先安装 WSL2，在 Ubuntu 里运行 dtfuzz。")
    if plat["wsl"]:
        notes.append("WSL2 环境：工具链必须装在 WSL 的 Linux 发行版内，不是 Windows 侧。")
        notes.append("仓库放在 ~/src 等 Linux 文件系统，避免 /mnt/c 的 I/O 和权限问题。")
        notes.append("如果 sudo 需要密码，dtfuzz setup --install 会拒绝执行并打印命令，请手动运行。")
    if repo and str(repo).startswith("/mnt/"):
        warnings.append(f"{repo} 位于 /mnt/（Windows 盘）。扫描可以，但 fuzz 构建/语料建议复制到 ~/src。")

    groups: dict[str, list[dict[str, Any]]] = {}
    if "base" in components:
        groups["base"] = _base_commands(plat)
        if not groups["base"]:
            warnings.append(f"没有为 {plat['pretty'] or plat['os']} 生成基础安装命令；请手动安装 clang/LLVM。")
    if "fi-light" in components:
        groups["fi-light"] = _fi_light_commands(fi_src)
        notes.append(
            "安装后设置 config.introspector.fi_src 和 introspector.python 指向 "
            f"{Path(fi_src).expanduser()}/.venv/bin/python，再运行 dtfuzz introspect --run-light。"
        )
    if "fi-lto" in components:
        groups["fi-lto"] = _fi_lto_commands(fi_src)
        notes.append("fi-lto 会构建自定义 LLVM/Clang，耗时很长；优先使用 --report 或 --run-light。")
    if "docker" in components:
        groups["docker"] = _docker_commands()
        notes.append("Docker 仅用于 OSS-Fuzz helper 生成报告，不是 fuzz 本身的前置条件。")

    commands = [cmd for group in groups.values() for cmd in group]
    needs_sudo = any(
        "sudo" in (cmd.get("display") or "")
        or "sudo" in " ".join(cmd.get("argv") or [])
        for cmd in commands
    )
    can_install = _sudo_passwordless() if needs_sudo else True
    return {
        "ok": True,
        "platform": plat,
        "missing": missing,
        "components": groups,
        "notes": notes,
        "warnings": warnings,
        "sudo_passwordless": can_install,
        "installable": can_install,
        "fi_src": str(Path(fi_src).expanduser()),
        "next": [
            "dtfuzz doctor --json",
            f"dtfuzz setup --json --components {' '.join(components)}",
            "dtfuzz init --repo <REPO> --entry <ENTRY> --source <FILE> --workdir <REPO>/.dtfuzz/<MODULE> --json",
        ],
    }


def format_plan(plan: dict[str, Any]) -> str:
    plat = plan["platform"]
    label = plat["pretty"] or plat["os"]
    if plat.get("wsl"):
        label += " (WSL2)"
    lines = [
        f"platform: {label} ({plat.get('kernel', '')}, {plat.get('machine', '')})",
        "missing: " + (", ".join(plan["missing"]) or "none"),
    ]
    for name, commands in plan["components"].items():
        lines.append("")
        lines.append(f"[{name}]")
        for index, command in enumerate(commands, 1):
            lines.append(f"  {index}. {command['display']}")
            if command.get("note"):
                lines.append(f"     note: {command['note']}")
    if plan["notes"]:
        lines.append("")
        lines.append("notes:")
        lines.extend(f"- {item}" for item in plan["notes"])
    if plan["warnings"]:
        lines.append("")
        lines.append("warnings:")
        lines.extend(f"- {item}" for item in plan["warnings"])
    lines.append("")
    lines.append("next:")
    lines.extend(f"- {item}" for item in plan["next"])
    return "\n".join(lines)


def install(plan: dict[str, Any], yes: bool = False) -> dict[str, Any]:
    if not yes:
        raise DtfuzzError("refusing to install without --yes; run `dtfuzz setup` to review the plan first")
    commands = [cmd for group in plan["components"].values() for cmd in group]
    if not plan.get("installable", False):
        return {
            "ok": False,
            "reason": "sudo requires a password; run the printed commands manually in this terminal",
            "executed": [],
            "manual": [cmd["display"] for cmd in commands],
        }
    results = []
    for command in commands:
        argv = command.get("argv") or []
        if not argv:
            continue
        proc = run(argv, cwd=command.get("cwd"), timeout=1800)
        record = {
            "command": command["display"],
            "returncode": proc.returncode,
            "stdout_tail": (proc.stdout or "")[-2000:],
            "stderr_tail": (proc.stderr or "")[-2000:],
        }
        results.append(record)
        if proc.returncode != 0:
            return {"ok": False, "executed": results, "failed": record}
    return {"ok": True, "executed": results}
