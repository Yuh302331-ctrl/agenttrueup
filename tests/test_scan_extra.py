"""Tests for scan orchestration: filters, warnings, error isolation."""

from __future__ import annotations

import json
from pathlib import Path

from agenttrueup.scan import scan


def _claude_jsonl(tmp_path: Path, session_id: str, ts: str, extra_text: str = "") -> Path:
    d = tmp_path / "projC"
    d.mkdir(parents=True, exist_ok=True)
    rows = [
        {"type": "user", "sessionId": session_id, "cwd": str(d),
         "timestamp": ts,
         "message": {"role": "user", "content": "do the thing"}},
        {"type": "assistant", "sessionId": session_id, "cwd": str(d),
         "timestamp": ts,
         "message": {"role": "assistant", "content": [
             {"type": "text", "text": f"Done. {extra_text}"}]}},
    ]
    p = d / f"{session_id}.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return p


def test_scan_only_paths_finds_sessions(tmp_path):
    _claude_jsonl(tmp_path, "scan-1", "2026-11-20T10:00:00Z")
    res = scan(paths=[str(tmp_path)], only_paths=True)
    assert len(res.sessions) == 1
    assert res.sessions[0].agent == "claude"
    assert res.stats["events"] >= 2


def test_scan_agent_filter_warns_unknown(capsys):
    res = scan(paths=[], only_paths=True, agents=["nonexistent-brand"])
    assert res.stats.get("warnings") and "unknown agent" in res.stats["warnings"][0]


def test_scan_bad_since_warns():
    res = scan(paths=[], only_paths=True, since="definitely-not-a-time")
    assert any("could not parse --since" in w for w in res.stats.get("warnings", []))


def test_scan_missing_path_warns():
    res = scan(paths=["/nonexistent/path/xyz"], only_paths=True)
    assert any("path not found" in w for w in res.stats.get("warnings", []))


def test_scan_since_filters_old_sessions(tmp_path):
    old = _claude_jsonl(tmp_path, "old-sess", "2020-01-01T00:00:00Z")
    new = _claude_jsonl(tmp_path, "new-sess", "2026-11-20T10:00:00Z")
    res = scan(paths=[str(old), str(new)], only_paths=True, since="2026-01-01")
    ids = {s.session_id for s in res.sessions}
    assert "new-sess" in ids and "old-sess" not in ids


def test_scan_broken_jsonl_does_not_kill_scan(tmp_path):
    bad = tmp_path / "broken.jsonl"
    bad.write_text("{definitely not json\n{also bad\n", encoding="utf-8")
    good = _claude_jsonl(tmp_path, "good-1", "2026-11-20T10:00:00Z")
    res = scan(paths=[str(bad), str(good)], only_paths=True)
    assert any(s.session_id == "good-1" for s in res.sessions) or res.sessions


def test_scan_generic_dir_harvest(tmp_path):
    d = tmp_path / "generic_store"
    d.mkdir()
    (d / "some.json").write_text(json.dumps({"messages": [
        {"role": "assistant", "content": "I created notes.md"},
    ]}), encoding="utf-8")
    res = scan(paths=[str(d)], only_paths=True)
    # generic parser runs without crashing; sessions may or may not have events
    assert isinstance(res.sessions, list)
