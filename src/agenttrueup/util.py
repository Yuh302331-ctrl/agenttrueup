"""Small utilities: time parsing, shell-aware tokenization, fingerprints."""

from __future__ import annotations

import hashlib
import re
import shlex
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_since(spec: str) -> datetime | None:
    """Parse --since values like 7d, 24h, 2w, 3m(months->30d), or an ISO date."""
    spec = (spec or "").strip().lower()
    if not spec:
        return None
    m = re.fullmatch(r"(\d+)\s*(h|d|w|m|y)", spec)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        delta = {"h": timedelta(hours=n), "d": timedelta(days=n),
                 "w": timedelta(weeks=n), "m": timedelta(days=30 * n),
                 "y": timedelta(days=365 * n)}[unit]
        return datetime.now(timezone.utc) - delta
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.strptime(spec, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(spec)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_ts(value) -> datetime | None:
    """Parse an ISO-8601-ish timestamp from various agent formats."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # seconds or milliseconds epoch
        v = float(value)
        if v > 1e12:  # ms
            v /= 1000.0
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    s = str(value).strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.fromisoformat(s.split(".")[0].split("+")[0])
            dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def split_command(cmd: str) -> list[str]:
    """Split a shell command into tokens, tolerating broken quoting."""
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def resolve_path(raw: str, cwd: str | None) -> Path | None:
    """Resolve a path mentioned in a session against the session cwd."""
    if not raw:
        return None
    raw = raw.strip().strip("\"'`")
    if not raw or " " in raw or len(raw) > 512:
        return None
    p = Path(raw)
    if p.is_absolute():
        return p
    if cwd:
        try:
            return Path(cwd) / p
        except (ValueError, OSError):
            return None
    return None


def looks_like_path(token: str) -> bool:
    t = token.strip().strip("\"'`")
    if not t or " " in t or len(t) > 512:
        return False
    if re.match(r"^[A-Za-z]:[\\/]", t) or t.startswith("/") or t.startswith("~"):
        return True
    if "/" in t or "\\\\" in t or "\\" in t:
        return True
    # a filename with an extension: config.yaml, src.py, .env
    base = t.rsplit("/", 1)[-1].rsplit("\\\\", 1)[-1]
    return bool(re.match(r"^\.[\w.-]+$|^\w[\w.+-]*\.[A-Za-z0-9]{1,10}$", base))


def iter_files(root: Path, suffixes: set[str], limit: int = 5000) -> list[Path]:
    out: list[Path] = []
    try:
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in suffixes:
                out.append(p)
                if len(out) >= limit:
                    break
    except OSError:
        pass
    return sorted(out)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
