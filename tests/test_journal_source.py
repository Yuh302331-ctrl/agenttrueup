"""Integration tests: trueup reconciling claims against a redhand journal.

The journal is built here with raw SQL against redhand's documented schema
(docs/JOURNAL.md in the redhand repo) — a contract test, no redhand import.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from agenttrueup.journal_source import (
    JournalSource,
    discover_journals,
    reconcile_claims,
)
from agenttrueup.models import Claim, Session
from agenttrueup.cli import main

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE runs (id INTEGER PRIMARY KEY, started_at REAL, ended_at REAL,
                   root TEXT, pid INTEGER, interval REAL, note TEXT);
CREATE TABLE actors (id INTEGER PRIMARY KEY, name TEXT UNIQUE, kind TEXT);
CREATE TABLE blobs (id INTEGER PRIMARY KEY, content BLOB, original_size INTEGER,
                    sha256 TEXT, created_at REAL);
CREATE TABLE shadow (path TEXT PRIMARY KEY, blob_id INTEGER, size INTEGER,
                     mtime_ns INTEGER, sha256 TEXT, updated_at REAL);
CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, run_id INTEGER,
                     path TEXT, event TEXT, new_size INTEGER, old_size INTEGER,
                     new_hash TEXT, old_hash TEXT, actor TEXT,
                     confidence TEXT DEFAULT 'low', blob_id INTEGER,
                     prev_event INTEGER, protected_hit INTEGER DEFAULT 0,
                     restored INTEGER DEFAULT 0);
"""


def build_journal(root: Path, events: list[tuple]) -> Path:
    """events: (ts, relpath, event, actor, confidence)."""
    wh = root / ".whodunit"
    wh.mkdir(parents=True, exist_ok=True)
    db = wh / "journal.db"
    conn = sqlite3.connect(db)
    conn.executescript(_SCHEMA)
    conn.execute("INSERT INTO meta VALUES('schema_version', '2')")
    for i, (ts, rel, ev, actor, conf) in enumerate(events, 1):
        conn.execute(
            "INSERT INTO events(ts, path, event, actor, confidence) VALUES(?,?,?,?,?)",
            (ts, rel, ev, actor, conf))
    conn.commit()
    conn.close()
    return db


def _sess(project: Path) -> Session:
    return Session(agent="claude", session_id="s", source_file="f",
                   project=str(project),
                   started="2026-11-20T10:00:00Z", ended="2026-11-20T11:00:00Z")


T_CLAIM = "2026-11-20T10:30:00Z"
T_BEFORE = time.mktime(time.strptime("2026-11-20T10:25:00Z", "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
T_AFTER = T_BEFORE + 400.0  # after the claim + grace window


# ---------------------------------------------------------------- verdicts


def test_deleted_claim_confirmed_by_journal(tmp_path):
    proj = tmp_path / "p"
    (proj / "sub").mkdir(parents=True)
    (proj / "secrets.txt").unlink(missing_ok=True)  # absent on disk
    db = build_journal(proj, [(T_BEFORE, "secrets.txt", "deleted", "codex", "high")])
    s = _sess(proj)
    claims = [Claim(kind="deleted", subject="secrets.txt", via="text",
                    session_id="s", agent="claude", ts=T_CLAIM)]
    reconcile_claims(s, claims, [], JournalSource(root=str(proj), db_path=str(db)))
    assert claims[0].status == "ok"
    assert "confirmed by redhand journal" in claims[0].detail
    assert "codex" in claims[0].detail


def test_deleted_claim_contradicted_by_journal(tmp_path):
    """The marquee case: agent claims a deletion, journal shows the file was
    actually modified and never deleted -> journal contradicts the claim."""
    proj = tmp_path / "p"
    proj.mkdir(parents=True)
    (proj / "report.md").write_text("still here", encoding="utf-8")
    db = build_journal(proj, [(T_BEFORE, "report.md", "modified", "claude", "high")])
    s = _sess(proj)
    claims = [Claim(kind="deleted", subject="report.md", via="text",
                    session_id="s", agent="claude", ts=T_CLAIM)]
    findings: list = []
    reconcile_claims(s, claims, findings, JournalSource(root=str(proj), db_path=str(db)))
    assert claims[0].status == "failed"
    assert "no deletion around the claim" in claims[0].detail
    assert any(f.category == "claim_failed" and f.severity == "high" for f in findings)


def test_deleted_then_recreated_produces_residue_finding(tmp_path):
    """Agent deleted it (journal fact), someone recreated it later."""
    proj = tmp_path / "p"
    proj.mkdir(parents=True)
    (proj / "k.txt").write_text("recreated!", encoding="utf-8")
    db = build_journal(proj, [
        (T_BEFORE, "k.txt", "deleted", "codex", "high"),
        (T_AFTER, "k.txt", "created", "codex", "high"),
    ])
    s = _sess(proj)
    claims = [Claim(kind="deleted", subject="k.txt", via="text",
                    session_id="s", agent="claude", ts=T_CLAIM)]
    findings: list = []
    reconcile_claims(s, claims, findings, JournalSource(root=str(proj), db_path=str(db)))
    assert claims[0].status == "ok"  # the deletion itself is a fact
    recreated = [f for f in findings if "recreated" in f.title]
    assert recreated and recreated[0].severity == "medium"
    assert "codex" in recreated[0].detail


def test_created_claim_confirmed_by_journal(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir(parents=True)
    (proj / "new.md").write_text("x", encoding="utf-8")
    db = build_journal(proj, [(T_BEFORE, "new.md", "created", "codex", "high")])
    s = _sess(proj)
    claims = [Claim(kind="created", subject="new.md", via="text",
                    session_id="s", agent="claude", ts=T_CLAIM)]
    reconcile_claims(s, claims, [], JournalSource(root=str(proj), db_path=str(db)))
    assert claims[0].status == "ok"
    assert "created at" in claims[0].detail


def test_created_claim_modified_not_created(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir(parents=True)
    (proj / "old.md").write_text("x", encoding="utf-8")  # predates the journal
    db = build_journal(proj, [(T_BEFORE, "old.md", "modified", "claude", "high")])
    s = _sess(proj)
    claims = [Claim(kind="created", subject="old.md", via="text",
                    session_id="s", agent="claude", ts=T_CLAIM)]
    reconcile_claims(s, claims, [], JournalSource(root=str(proj), db_path=str(db)))
    assert claims[0].status == "ok"
    assert "modified (not created)" in claims[0].detail


def test_no_journal_events_keeps_disk_verdict(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir(parents=True)
    (proj / "gone.txt").unlink(missing_ok=True)
    db = build_journal(proj, [])  # journal exists but has no opinion
    s = _sess(proj)
    claims = [Claim(kind="deleted", subject="gone.txt", via="text",
                    session_id="s", agent="claude", ts=T_CLAIM)]
    from agenttrueup.verify import verify_claims

    verify_claims(s, claims)  # disk verdict first (file absent -> ok)
    assert claims[0].status == "ok"
    disk_detail = claims[0].detail
    reconcile_claims(s, claims, [], JournalSource(root=str(proj), db_path=str(db)))
    assert claims[0].status == "ok"  # journal has no opinion -> verdict preserved
    assert claims[0].detail == disk_detail  # and its wording untouched


# ---------------------------------------------------------------- discovery


def test_discover_walks_up_from_subdir(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    build_journal(tmp_path, [])
    js = discover_journals([str(tmp_path / "a" / "b")])
    assert len(js.sources) == 1
    assert js.sources[0].root == str(tmp_path)
    assert js.sources[0].rel_for(str(tmp_path / "a" / "b" / "f.txt")) == "a/b/f.txt"


def test_discover_accepts_explicit_root_and_db(tmp_path):
    build_journal(tmp_path, [])
    js = discover_journals([], extra_paths=[str(tmp_path)])
    assert len(js.sources) == 1
    js2 = discover_journals([], extra_paths=[str(tmp_path / ".whodunit" / "journal.db")])
    assert len(js2.sources) == 1


def test_discover_unknown_schema_reports_problem(tmp_path):
    build_journal(tmp_path, [])
    conn = sqlite3.connect(tmp_path / ".whodunit" / "journal.db")
    conn.execute("UPDATE meta SET value='9' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    js = discover_journals([str(tmp_path)])
    assert js.sources == []
    assert js.problems and "schema_version" in js.problems[0]


def test_outside_root_is_ignored(tmp_path):
    build_journal(tmp_path, [])
    js = discover_journals([str(tmp_path)])
    src = js.sources[0]
    assert src.rel_for("/etc/hosts") is None


# ---------------------------------------------------------------- scan wiring


def test_scan_end_to_end_with_journal(tmp_path, capsys):
    """Full scan(): transcript claims a deletion that never happened while a
    redhand journal watching the project records the truth."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "report.md").write_text("still here", encoding="utf-8")
    rows = [
        {"type": "user", "sessionId": "j-1", "cwd": str(proj),
         "timestamp": "2026-11-20T10:29:00Z",
         "message": {"role": "user", "content": "delete report.md"}},
        {"type": "assistant", "sessionId": "j-1", "cwd": str(proj),
         "timestamp": T_CLAIM,
         "message": {"role": "assistant", "content": [
             {"type": "text", "text": "Done. I deleted `report.md`."}]}},
    ]
    p = tmp_path / "transcript.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    build_journal(proj, [(T_BEFORE, "report.md", "modified", "claude", "high")])

    rc = main(["scan", "--only", str(p), "--json"])
    assert rc == 1  # a HIGH journal-contradiction finding exists
    # second invocation reads the JSON printed by the first
    out = capsys.readouterr()
    doc = json.loads(out.out) if out.out else json.loads(out.err)
    assert doc["stats"].get("journals_found") == 1
    cats = [f["category"] for f in doc["findings"]]
    assert "claim_failed" in cats
    detail_blob = json.dumps(doc["claims"])
    assert "redhand journal" in detail_blob


def test_scan_no_journal_flag_disables(tmp_path, capsys):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "report.md").write_text("still here", encoding="utf-8")
    rows = [
        {"type": "assistant", "sessionId": "j-2", "cwd": str(proj),
         "timestamp": T_CLAIM,
         "message": {"role": "assistant", "content": [
             {"type": "text", "text": "I deleted `report.md`."}]}},
    ]
    p = tmp_path / "t.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    build_journal(proj, [(T_BEFORE, "report.md", "modified", "claude", "high")])
    main(["scan", "--only", str(p), "--json", "--no-journal"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["stats"].get("journals_found", 0) == 0
    assert "redhand journal" not in json.dumps(doc["claims"])


def test_events_for_readonly_with_wal(tmp_path):
    """A running watcher keeps a -wal file; reads must still work."""
    build_journal(tmp_path, [(T_BEFORE, "x.txt", "created", "a", "low")])
    db = tmp_path / ".whodunit" / "journal.db"
    # simulate a live writer: separate connection holds an open transaction
    writer = sqlite3.connect(db)
    writer.execute("INSERT INTO events(ts, path, event, actor) VALUES(?,?,?,?)",
                   (T_AFTER, "y.txt", "created", "b"))
    writer.commit()  # committed under WAL -> visible to concurrent ro readers
    src = JournalSource(root=str(tmp_path), db_path=str(db))
    src.check()  # must not raise while the writer connection is still open
    assert src.events_for("x.txt")
    assert len(src.events_for("y.txt")) == 1  # committed WAL data visible
    writer.close()
