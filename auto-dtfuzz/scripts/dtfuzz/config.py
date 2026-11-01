from __future__ import annotations

import copy
from pathlib import Path

from .util import DtfuzzError, read_json, resolve, write_json

DEFAULT_CONFIG: dict = {
    "version": 1,
    "module": "",
    "repo": "",
    "language": "c",
    "build_system": "unknown",
    "entry": {
        "name": "",
        "file": "",
        "header": "",
        "qualified_name": "",
        "return_type": "int",
        "params": [],
        "input_model": "buffer",
        "type_bytes": 0,
        "type_endian": "big",
        "type_offset": 0,
    },
    "sources": {
        "target": [],
        "real": [],
        "libraries": [],
        "exclude": [],
        "exclude_dirs": ["dt", "tests", "test", "mock", "mocks", "stub", "stubs", "fake", "fakes", "fuzz_mocks"],
        "include_dirs": [],
        "defines": [],
        "std": "",
        "extra_cflags": [],
        "extra_ldflags": [],
    },
    "mocks": {
        "enabled": True,
        "dir": "",
        "config_file": "",
        "generated_file": "",
        "custom_files": ["custom_mocks.c", "custom_mocks.cc"],
        "auto_stub": False,
        "variables": {},
    },
    "fuzz": {
        "sanitizers": "address",
        "max_len": 4096,
        "timeout": 10,
        "rss_limit_mb": 2048,
        "seconds_per_round": 60,
        "runs_per_round": 0,
        "use_value_profile": True,
        "fork": False,
        "triage_limit": 256,
        "extra_args": [],
    },
    "coverage": {
        "target_files": [],
        "line_target": 90.0,
        "function_target": 0.0,
        "stall_rounds": 3,
        "stall_delta": 1.0,
        "max_rounds": 10,
    },
    "optimizer": {
        "mode": "none",
        "model": "",
        "claude_cmd": ["claude", "-p", "--output-format", "json"],
        "max_seeds_per_round": 32,
        "max_seed_bytes": 4096,
    },
    "introspector": {
        "report": "",
        "auto": True,
        "fi_clang": "",
        "fi_src": "",
        "python": "python3",
    },
    "external_sources": [],
    "harness": {
        "reset_code": "",
        "init_code": "",
        "call_expr": "",
        "const_values": {},
        "extra_includes": [],
    },
    "toolchain": {
        "clang": "",
        "llvm_cov": "",
        "llvm_profdata": "",
        "llvm_symbolizer": "",
        "llvm_cxxfilt": "",
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


class Workspace:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()

    @property
    def config_path(self) -> Path:
        return self.root / "config.json"

    @property
    def mocks_path(self) -> Path:
        # Legacy location; new workspaces use <repo>/fuzz_mocks/<module>/mocks.json.
        return self.root / "mocks.json"

    def mocks_dir(self, config: dict) -> Path:
        configured = (config.get("mocks", {}) or {}).get("dir") or ""
        if configured:
            return resolve(configured, config.get("repo", "."))
        return Path(config.get("repo", ".")).expanduser().resolve() / "fuzz_mocks" / (config.get("module") or "module")

    def mocks_config_path(self, config: dict) -> Path:
        configured = (config.get("mocks", {}) or {}).get("config_file") or ""
        if configured:
            return resolve(configured, config.get("repo", "."))
        return self.mocks_dir(config) / "mocks.json"

    def generated_mocks_path(self, config: dict) -> Path:
        configured = (config.get("mocks", {}) or {}).get("generated_file") or ""
        if configured:
            return resolve(configured, config.get("repo", "."))
        suffix = ".cc" if str(config.get("language", "")).lower() in {"cpp", "c++", "cxx"} else ".c"
        return self.mocks_dir(config) / f"generated_mocks{suffix}"

    @property
    def analysis_path(self) -> Path:
        return self.root / "analysis.json"

    @property
    def harness_dir(self) -> Path:
        return self.root / "harness"

    @property
    def build_dir(self) -> Path:
        return self.root / "build"

    @property
    def corpus_dir(self) -> Path:
        return self.root / "corpus"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def coverage_dir(self) -> Path:
        return self.root / "coverage"

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"

    @property
    def optimizer_dir(self) -> Path:
        return self.root / "optimizer"

    @property
    def crashes_dir(self) -> Path:
        return self.root / "crashes"

    @property
    def introspector_dir(self) -> Path:
        return self.root / "introspector"

    @property
    def reachability_path(self) -> Path:
        return self.introspector_dir / "reachability.json"

    @property
    def binary_path(self) -> Path:
        return self.build_dir / "fuzz_target"

    def ensure(self) -> None:
        for directory in (
            self.root,
            self.harness_dir,
            self.build_dir,
            self.corpus_dir,
            self.artifacts_dir,
            self.coverage_dir,
            self.coverage_dir / "raw",
            self.runs_dir,
            self.optimizer_dir,
            self.crashes_dir,
            self.introspector_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        ignore = self.root / ".gitignore"
        if not ignore.exists():
            ignore.write_text("*\n", encoding="utf-8")

    def load_config(self) -> dict:
        data = read_json(self.config_path)
        if data is None:
            raise DtfuzzError(f"workspace not initialized: {self.config_path}")
        return deep_merge(DEFAULT_CONFIG, data)

    def save_config(self, config: dict) -> None:
        write_json(self.config_path, config)

    def load_mocks(self, config: dict | None = None) -> dict:
        path = self.mocks_config_path(config) if config else self.mocks_path
        if config and not path.is_file() and self.mocks_path.is_file():
            path = self.mocks_path
        data = read_json(path, default=None)
        if data is None:
            return {"version": 1, "symbols": {}, "variables": {}, "constraints": {}}
        data.setdefault("version", 1)
        data.setdefault("symbols", {})
        data.setdefault("variables", {})
        data.setdefault("constraints", {})
        return data

    def save_mocks(self, mocks: dict, config: dict | None = None) -> None:
        path = self.mocks_config_path(config) if config else self.mocks_path
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(path, mocks)

    def load_analysis(self) -> dict:
        data = read_json(self.analysis_path)
        if data is None:
            raise DtfuzzError(f"analysis missing, run `dtfuzz analyze`: {self.analysis_path}")
        return data

    def resolve(self, relative: str) -> Path:
        return resolve(relative, self.root.parent)


def default_workspace_path(repo: str | Path, module: str) -> Path:
    return Path(repo).expanduser().resolve() / ".dtfuzz" / module
