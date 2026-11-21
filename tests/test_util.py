"""Unit tests for util: time parsing, tokenization, path resolution."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agenttrueup.util import (
    fingerprint,
    iso,
    iter_files,
    looks_like_path,
    parse_since,
    parse_ts,
    resolve_path,
    split_command,
)


# ---------------------------------------------------------------- parse_since


def test_parse_since_relative():
    now = datetime.now(timezone.utc)
    got = parse_since("7d")
    assert timedelta(days=7) - (now - got) < timedelta(seconds=5)
    assert parse_since("24h") > now - timedelta(hours=25)
    assert parse_since("2w") < now - timedelta(days=13)
    assert parse_since("3m") < now - timedelta(days=89)
    assert parse_since("1y") < now - timedelta(days=364)


def test_parse_since_dates():
    assert parse_since("2026-01-31") == datetime(2026, 1, 31, tzinfo=timezone.utc)
    got = parse_since("2026-01-31T10:30")
    assert (got.year, got.month, got.day, got.hour, got.minute) == (2026, 1, 31, 10, 30)


def test_parse_since_empty_and_garbage():
    assert parse_since("") is None
    assert parse_since("   ") is None
    assert parse_since("not-a-date") is None
    assert parse_since("12x") is None


# ---------------------------------------------------------------- parse_ts


def test_parse_ts_epochs():
    dt = parse_ts(1700000000)          # seconds
    assert dt is not None and dt.year == 2023
    dt_ms = parse_ts(1700000000000)    # milliseconds
    assert dt_ms == dt
    assert parse_ts(1e15) is None      # out of range


def test_parse_ts_strings():
    assert parse_ts(None) is None
    assert parse_ts("") is None
    dt = parse_ts("2026-11-20T10:00:00Z")
    assert dt is not None and dt.tzinfo is not None
    dt2 = parse_ts("2026-11-20T10:00:00")           # naive -> utc
    assert dt2 is not None and dt2.tzinfo is not None
    assert parse_ts("garbage") is None
    assert parse_ts("2026-13-99") is None


def test_iso_helper():
    assert iso(None) is None
    assert iso(datetime(2026, 1, 1, tzinfo=timezone.utc)) == "2026-01-01T00:00:00+00:00"


# ---------------------------------------------------------------- fingerprint


def test_fingerprint_stable_and_short():
    a = fingerprint("secret-value")
    b = fingerprint("secret-value")
    c = fingerprint("other")
    assert a == b and a != c and len(a) == 12


# ---------------------------------------------------------------- split_command


def test_split_command_normal_and_broken():
    assert split_command("git push --force") == ["git", "push", "--force"]
    # unmatched quote -> shlex raises -> whitespace fallback
    assert split_command('echo "unterminated') == ["echo", '"unterminated']


# ---------------------------------------------------------------- resolve_path


def test_resolve_path_absolute(tmp_path):
    p = tmp_path / "abs.txt"
    p.write_text("x", encoding="utf-8")
    assert resolve_path(str(p), None) == p


def test_resolve_path_relative_exists(tmp_path):
    (tmp_path / "rel.txt").write_text("x", encoding="utf-8")
    got = resolve_path("rel.txt", str(tmp_path))
    assert got is not None and got.exists()


def test_resolve_path_walks_up(tmp_path):
    # session cwd is a subdir; the transcript carries repo-root-relative path
    repo = tmp_path / "repo"
    (repo / "sub" / "deep").mkdir(parents=True)
    (repo / "target.md").write_text("x", encoding="utf-8")
    got = resolve_path("target.md", str(repo / "sub" / "deep"))
    assert got is not None and got.exists()


def test_resolve_path_rejects_garbage():
    assert resolve_path("", None) is None
    assert resolve_path("two words", None) is None
    assert resolve_path("x" * 600, None) is None
    assert resolve_path("missing_relative.txt", None) is None


# ---------------------------------------------------------------- looks_like_path


def test_looks_like_path():
    assert looks_like_path("/abs/path.txt")
    assert looks_like_path("~/notes.md")
    assert looks_like_path("src/app.py")
    assert looks_like_path(".env")
    assert looks_like_path("config.yaml")
    assert not looks_like_path("")
    assert not looks_like_path("two words")
    assert not looks_like_path("justword")


def test_looks_like_path_windows_drive():
    assert looks_like_path("C:\\Users\\x\\file.txt")


# ---------------------------------------------------------------- iter_files


def test_iter_files_suffix_and_limit(tmp_path):
    (tmp_path / "a.jsonl").write_text("{}", encoding="utf-8")
    (tmp_path / "b.json").write_text("{}", encoding="utf-8")
    (tmp_path / "c.txt").write_text("x", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "d.jsonl").write_text("{}", encoding="utf-8")
    got = iter_files(tmp_path, {".jsonl", ".json"})
    names = [p.name for p in got]
    assert names == ["a.jsonl", "b.json", "d.jsonl"]  # sorted, recursive
    assert iter_files(tmp_path, {".jsonl"}, limit=1) == [tmp_path / "a.jsonl"]
    assert iter_files(tmp_path / "missing", {".jsonl"}) == []
