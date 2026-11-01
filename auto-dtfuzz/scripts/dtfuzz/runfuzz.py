from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from .util import DtfuzzError, now_iso, run, sha256_bytes, sha256_file, write_json, write_text

COV_RE = re.compile(r"cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*(\d+)")
DONE_RE = re.compile(r"Done\s+(\d+)\s+runs?\s+in\s+(\d+)\s+second")
STAT_RE = re.compile(r"stat::([A-Za-z0-9_]+):\s*(\d+)")
FRAME_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+)$")
SUMMARY_RE = re.compile(r"SUMMARY:\s*([^\n]+)")


def parse_stats(text: str) -> dict:
    stats: dict[str, Any] = {}
    cov_matches = COV_RE.findall(text)
    if cov_matches:
        cov, ft, corp = cov_matches[-1]
        stats["cov"] = int(cov)
        stats["ft"] = int(ft)
        stats["corp"] = int(corp)
    done = DONE_RE.search(text)
    if done:
        stats["runs"] = int(done.group(1))
        stats["seconds"] = int(done.group(2))
    for key, value in STAT_RE.findall(text):
        stats[key] = int(value)
    return stats


def _artifact_files(artifacts: Path) -> list[Path]:
    if not artifacts.is_dir():
        return []
    wanted = ("crash-", "timeout-", "oom-", "leak-", "slow-unit-")
    files = [path for path in artifacts.iterdir() if path.is_file() and path.name.startswith(wanted)]
    return sorted(files, key=lambda item: item.stat().st_mtime)


def _frames(text: str) -> list[str]:
    frames = []
    for line in text.splitlines():
        match = FRAME_RE.match(line)
        if match:
            frames.append(match.group(1).strip())
    return frames


def _sanitizer_summary(text: str) -> str:
    match = SUMMARY_RE.search(text)
    return match.group(1).strip() if match else ""


def _crash_signature(text: str, sanitizer: str) -> str:
    summary = _sanitizer_summary(text)
    frames = _frames(text)
    return "\n".join([sanitizer, summary, *frames[:3]]) or text[:500]


def _sanitizer(text: str) -> str:
    for name in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "LeakSanitizer", "MemorySanitizer", "ThreadSanitizer"):
        if name in text:
            return name
    if "timeout" in text.lower():
        return "timeout"
    if "out-of-memory" in text.lower():
        return "oom"
    return "unknown"


def _target_file_names(analysis: dict) -> list[str]:
    names = []
    target_basenames = set()
    for item in (analysis.get("target_files") or []) + [analysis.get("entry", {}).get("file", "")]:
        if item:
            basename = Path(str(item)).name
            names.append(basename)
            target_basenames.add(basename)
    entry = analysis.get("entry", {}) or {}
    for value in (entry.get("name", ""), entry.get("qualified_name", "")):
        if value:
            names.append(value)
            names.append(value.split("::")[-1])
    for name, files in (analysis.get("definitions_index") or {}).items():
        if any(Path(str(item)).name in target_basenames for item in files):
            names.append(name)
    return list(dict.fromkeys(names))


def _artifact_kind(path: Path) -> str:
    for kind in ("crash-", "timeout-", "oom-", "leak-", "slow-unit-"):
        if path.name.startswith(kind):
            return kind.rstrip("-")
    return "artifact"


def triage_artifacts(workspace, config: dict, artifacts: list[Path], binary: str, analysis: dict) -> list[dict]:
    workspace.crashes_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    seen: dict[str, str] = {}
    timeout = int((config.get("fuzz", {}) or {}).get("timeout", 10))
    limit = int((config.get("fuzz", {}) or {}).get("triage_limit", 256))
    target_names = _target_file_names(analysis)
    artifact_prefix = workspace.crashes_dir / "artifacts"
    artifact_prefix.mkdir(parents=True, exist_ok=True)
    triage_env = {"LLVM_PROFILE_FILE": os.devnull}
    symbolizer = (config.get("toolchain", {}) or {}).get("llvm_symbolizer")
    if symbolizer:
        triage_env["PATH"] = str(Path(symbolizer).parent) + os.pathsep + os.environ.get("PATH", "")
    for artifact in artifacts[:limit]:
        cmd = [
            binary,
            str(artifact),
            "-runs=1",
            f"-timeout={timeout}",
            f"-artifact_prefix={artifact_prefix}/",
        ]
        proc = run(
            cmd,
            cwd=config.get("repo") or None,
            env=triage_env,
            timeout=timeout + 60,
        )
        text = (proc.stderr or "") + "\n" + (proc.stdout or "")
        kind = _artifact_kind(artifact)
        sanitizer = _sanitizer(text)
        if kind in {"timeout", "oom", "leak", "slow-unit"} and sanitizer == "unknown":
            sanitizer = kind
        frames = _frames(text)
        summary = _sanitizer_summary(text)
        signature = _crash_signature(text, sanitizer)
        digest = sha256_bytes(signature.encode("utf-8"))[:16]
        cleaned = text.replace(str(workspace.root), "").replace(str(binary), "")
        cleaned = re.sub(r"\([^)]*fuzz_target[^)]*\)", "(BIN)", cleaned)
        target = any(name and name in cleaned for name in target_names)
        crash_dir = workspace.crashes_dir / digest
        crash_dir.mkdir(parents=True, exist_ok=True)
        input_path = crash_dir / "input"
        if not input_path.exists():
            shutil.copyfile(artifact, input_path)
        write_text(crash_dir / "stderr.txt", text)
        write_text(crash_dir / "command.txt", " ".join(cmd) + "\n")
        record = {
            "id": digest,
            "artifact": str(artifact),
            "input": str(input_path),
            "size": artifact.stat().st_size,
            "sanitizer": sanitizer,
            "kind": kind,
            "target": target,
            "summary": summary,
            "frames": frames[:8],
            "duplicate": digest in seen,
            "stderr": str(crash_dir / "stderr.txt"),
        }
        if digest in seen:
            record["first_seen"] = seen[digest]
        else:
            seen[digest] = str(input_path)
            results.append(record)
    return results


def run_fuzz(
    workspace,
    config: dict,
    analysis: dict,
    seconds: int | None = None,
    runs: int | None = None,
    fork: bool | None = None,
    extra_args: list[str] | None = None,
) -> dict:
    binary = workspace.binary_path
    if not binary.is_file():
        raise DtfuzzError("fuzz binary missing; run `dtfuzz build` first")
    workspace.ensure()
    fuzz_cfg = config.get("fuzz", {}) or {}
    if seconds is None:
        seconds = int(fuzz_cfg.get("seconds_per_round", 60))
    if runs is None and int(fuzz_cfg.get("runs_per_round", 0) or 0) > 0:
        runs = int(fuzz_cfg["runs_per_round"])
    if fork is None:
        fork = bool(fuzz_cfg.get("fork", False))
    corpus = workspace.corpus_dir
    artifacts = workspace.artifacts_dir
    corpus.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    dict_path = workspace.harness_dir / "dict.txt"
    raw_dir = workspace.coverage_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for stale in raw_dir.glob("*.profraw"):
        try:
            stale.unlink()
        except OSError:
            pass
    env = {
        "LLVM_PROFILE_FILE": str(raw_dir / "%p.profraw"),
        **({} if os.environ.get("ASAN_OPTIONS") else {"ASAN_OPTIONS": "abort_on_error=0:symbolize=1:detect_leaks=0"}),
    }
    symbolizer = (config.get("toolchain", {}) or {}).get("llvm_symbolizer")
    if symbolizer:
        env["PATH"] = str(Path(symbolizer).parent) + os.pathsep + env.get("PATH", os.environ.get("PATH", ""))
        env["UBSAN_OPTIONS"] = "symbolize=1"
    cmd = [str(binary), str(corpus)]
    if runs:
        cmd.append(f"-runs={runs}")
    else:
        cmd.append(f"-max_total_time={seconds}")
    cmd.extend(
        [
            f"-max_len={int(fuzz_cfg.get('max_len', 4096))}",
            f"-timeout={int(fuzz_cfg.get('timeout', 10))}",
            f"-rss_limit_mb={int(fuzz_cfg.get('rss_limit_mb', 2048))}",
            "-print_final_stats=1",
            f"-artifact_prefix={artifacts}/",
        ]
    )
    if fuzz_cfg.get("use_value_profile", True):
        cmd.append("-use_value_profile=1")
    if dict_path.is_file() and dict_path.stat().st_size > 0:
        cmd.append(f"-dict={dict_path}")
    if fork:
        cmd.extend(["-fork=1", "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1", "-ignore_leaks=1"])
    cmd.extend([str(item) for item in (fuzz_cfg.get("extra_args") or [])])
    cmd.extend(extra_args or [])
    before_artifacts = {path.name for path in artifacts.iterdir() if path.is_file()}
    start = time.time()
    timeout = 600 if runs else seconds + 180
    proc = run(cmd, cwd=config.get("repo") or None, env=env, timeout=timeout)
    elapsed = time.time() - start
    log_path = workspace.runs_dir / f"run-{int(start)}.log"
    header = f"$ {' '.join(cmd)}\n\n"
    write_text(log_path, header + (proc.stdout or "") + "\n" + (proc.stderr or ""))
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    stats = parse_stats(text)
    all_artifacts = _artifact_files(artifacts)
    new_artifacts = [path for path in all_artifacts if path.name not in before_artifacts]
    triaged = triage_artifacts(workspace, config, new_artifacts, str(binary), analysis)
    crashes = [item for item in triaged if item.get("target")]
    non_target_crashes = [item for item in triaged if not item.get("target")]
    previous = {}
    history_path = workspace.runs_dir / "history.json"
    if history_path.is_file():
        try:
            import json

            history = json.loads(history_path.read_text(encoding="utf-8"))
            previous = history[-1] if history else {}
        except Exception:
            previous = {}
    record = {
        "time": now_iso(),
        "seconds": round(elapsed, 2),
        "command": cmd,
        "returncode": proc.returncode,
        "log": str(log_path),
        "stats": stats,
        "crashes": crashes,
        "non_target_crashes": non_target_crashes,
        "corpus_files": len([item for item in corpus.iterdir() if item.is_file()]),
        "artifact_count": len(new_artifacts),
        "previous": previous,
    }
    if proc.returncode != 0 and not crashes and not new_artifacts:
        record["stderr_tail"] = (proc.stderr or "")[-4000:]
    history = []
    import json

    if history_path.is_file():
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except Exception:
            history = []
    history.append(record)
    write_json(history_path, history)
    return record
