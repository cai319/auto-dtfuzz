from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class DtfuzzError(Exception):
    """A user-facing error with a stable message."""


def which(name: str, extra_dirs: Iterable[str] = ()) -> str | None:
    for directory in extra_dirs:
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def run(
    cmd: list[str],
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 600,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=merged,
            input=input_text,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise DtfuzzError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DtfuzzError(f"command timed out after {timeout}s: {' '.join(cmd)}") from exc


def run_ok(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    proc = run(cmd, **kwargs)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise DtfuzzError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{detail}")
    return proc


def read_json(path: str | Path, default: Any = None) -> Any:
    p = Path(path)
    if not p.is_file():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DtfuzzError(f"invalid JSON in {p}: {exc}") from exc


def write_json(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=p.name + ".", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_text(path: str | Path, text: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def resolve(path: str | Path, base: str | Path | None = None) -> Path:
    p = Path(path)
    if not p.is_absolute() and base is not None:
        p = Path(base) / p
    return p.expanduser().resolve()


def is_within(path: str | Path, root: str | Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def rel_to(path: str | Path, root: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"


def snippet(text: str, line: int, radius: int = 6, limit: int = 6000) -> str:
    lines = text.splitlines()
    lo = max(0, line - 1 - radius)
    hi = min(len(lines), line + radius)
    out = [f"{i + 1:5d}  {lines[i]}" for i in range(lo, hi)]
    return truncate("\n".join(out), limit)


def parse_hex(value: str) -> bytes:
    cleaned = re.sub(r"[\s,;:_-]+", "", value)
    cleaned = cleaned[2:] if cleaned.lower().startswith("0x") else cleaned
    if len(cleaned) % 2:
        raise DtfuzzError(f"hex string must have an even number of digits: {value!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise DtfuzzError(f"invalid hex string: {value!r}") from exc


def format_hex(data: bytes, limit: int = 64) -> str:
    head = data[:limit].hex(" ")
    if len(data) > limit:
        return head + f" ... ({len(data)} bytes)"
    return head


def print_json(data: Any) -> None:
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def quote_c_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


def type_size_c(type_name: str) -> int | None:
    normalized = re.sub(r"\b(const|volatile|signed|unsigned)\b", "", type_name)
    normalized = normalized.replace("std::", "").replace("::", "").replace(" ", "")
    table = {
        "uint8_t": 1,
        "int8_t": 1,
        "char": 1,
        "bool": 1,
        "uint16_t": 2,
        "int16_t": 2,
        "short": 2,
        "uint32_t": 4,
        "int32_t": 4,
        "int": 4,
        "unsigned": 4,
        "float": 4,
        "uint64_t": 8,
        "int64_t": 8,
        "long": 8,
        "double": 8,
        "size_t": 8,
    }
    return table.get(normalized)
