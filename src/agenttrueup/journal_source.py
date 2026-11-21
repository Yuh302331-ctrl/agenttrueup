"""Facts source: redhand's change journal, read as an external contract.

redhand (https://github.com/Yuh302331-ctrl/redhand) records every file
change in a SQLite journal at `<root>/.whodunit/journal.db` — events with
timestamps, relative paths and the attributed actor. This module reads that
journal READ-ONLY (by schema contract, not by importing redhand) and lets
claim verification compare what the agent *said* against what actually
happened over time, instead of only against the current disk state.

Schema contract (redhand 0.2.x, schema_version '2'):
    events(ts REAL, path TEXT /*'/'-separated, relative to root*/,
           event TEXT /*created|modified|deleted*/, actor TEXT,
           confidence TEXT /*high|medium|low*/, ...)

WAL mode: readers must open with uri=True + mode=ro and tolerate a -wal
file being present; a running watcher is never blocked or modified.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

STATE_DIR = ".whodunit"
JOURNAL_NAME = "journal.db"
SUPPORTED_SCHEMA_VERSIONS = {"1", "2"}

#: claims made right after acting; the journal polls on an interval, so an
#: event can legitimately land slightly after the sentence that describes it
CLAIM_GRACE_SEC = 60.0

_VERBS = {"created": "created", "modified": "modified", "deleted": "deleted"}


class JournalError(RuntimeError):
    """The journal exists but cannot be read (corrupt, unknown schema)."""


@dataclass
class JournalSource:
    root: str                    # watched root (absolute, platform separators)
    db_path: str                 # absolute path to journal.db

    def __post_init__(self) -> None:
        self.root = os.path.abspath(self.root)

    # ------------------------------------------------------------- paths

    def rel_for(self, abs_path: str) -> Optional[str]:
        """'/'-separated journal-relative path for an absolute file path,
        or None when the file is outside this watched root."""
        try:
            root = os.path.abspath(self.root)
            p = os.path.abspath(abs_path)
            if os.path.commonpath([p, root]) != root:
                return None
            rel = os.path.relpath(p, root)
        except (ValueError, OSError):
            return None
        return rel.replace(os.sep, "/")

    # ------------------------------------------------------------- queries

    def _connect(self) -> sqlite3.Connection:
        uri = "file:" + self.db_path.replace("?", "%3f").replace("#", "%23") + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def check(self) -> None:
        """Raise JournalError when the journal cannot be used."""
        if not os.path.exists(self.db_path):
            raise JournalError(f"missing journal: {self.db_path}")
        try:
            conn = self._connect()
        except sqlite3.Error as exc:
            raise JournalError(f"cannot open {self.db_path}: {exc}") from None
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'").fetchone()
            version = row["value"] if row else None
            if version is not None and version not in SUPPORTED_SCHEMA_VERSIONS:
                raise JournalError(
                    f"journal schema_version {version} unsupported "
                    f"(supported: {', '.join(sorted(SUPPORTED_SCHEMA_VERSIONS))})")
            conn.execute("SELECT COUNT(*) FROM events")
        except sqlite3.Error as exc:
            raise JournalError(f"journal unreadable: {exc}") from None
        finally:
            conn.close()

    def events_for(self, rel_path: str) -> List[Dict[str, Any]]:
        """All events for a journal-relative path, oldest first."""
        out: List[Dict[str, Any]] = []
        try:
            conn = self._connect()
        except sqlite3.Error:
            return out
        try:
            rows = conn.execute(
                "SELECT ts, event, actor, confidence, new_size AS size, old_size "
                "FROM events WHERE path = ? ORDER BY ts ASC, id ASC",
                (rel_path,),
            ).fetchall()
            for r in rows:
                out.append(dict(r))
        except sqlite3.Error:
            return []
        finally:
            conn.close()
        return out


@dataclass
class JournalSet:
    """All journals known to this scan, keyed by watched root."""

    sources: List[JournalSource] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)

    def for_abs_path(self, abs_path: str) -> Optional[JournalSource]:
        for s in self.sources:
            if s.rel_for(abs_path) is not None:
                return s
        return None


def discover_journals(projects: List[str],
                      extra_paths: Optional[List[str]] = None) -> JournalSet:
    """Find journals near session projects (bounded walk-up) plus explicit ones.

    Explicit `extra_paths` may be a journal.db file, a .whodunit directory,
    or a watched root directory.
    """
    js = JournalSet()
    seen_roots: set = set()

    def try_db(db_path: Optional[str], root_hint: Optional[str] = None) -> None:
        if not db_path or not os.path.exists(db_path):
            return
        root = root_hint or os.path.dirname(os.path.dirname(os.path.abspath(db_path)))
        key = os.path.abspath(root)
        if key in seen_roots:
            return
        seen_roots.add(key)
        src = JournalSource(root=key, db_path=os.path.abspath(db_path))
        try:
            src.check()
        except JournalError as exc:
            js.problems.append(str(exc))
            return
        js.sources.append(src)

    for proj in projects[:40]:
        if not proj:
            continue
        base = Path(proj).resolve()
        for _ in range(3):            # bounded walk-up
            try_db(str(base / STATE_DIR / JOURNAL_NAME), root_hint=str(base))
            base = base.parent

    for extra in (extra_paths or [])[:40]:
        p = Path(extra).expanduser()
        if p.is_file() and p.name == JOURNAL_NAME:
            try_db(str(p))
        elif p.is_dir():
            try_db(str(p / STATE_DIR / JOURNAL_NAME), root_hint=str(p))
        else:
            js.problems.append(f"journal path not found: {p}")
    return js


def _fmt_ts(ts: Optional[float]) -> str:
    if ts is None:
        return "?"
    import datetime as _dt

    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def reconcile_claims(session, claims, findings, journal: JournalSource) -> None:
    """Upgrade claim verdicts using the journal's event stream (in place).

    * deleted  + journal shows the deletion   -> ok, confirmed by journal
    * deleted  + journal shows no deletion,
                 file existed per journal      -> failed, journal contradicts
    * created  + journal shows the creation   -> ok, confirmed by journal
    * edited   + journal shows a modification -> ok, confirmed by journal
    * any confirmed deletion later followed by a re-creation -> medium finding
    """
    for c in claims:
        if c.kind not in ("deleted", "created", "edited"):
            continue
        abs_path = _resolve_claim(session, c.subject)
        if abs_path is None:
            continue
        rel = journal.rel_for(abs_path)
        if rel is None:
            continue
        events = journal.events_for(rel)
        if not events:
            continue  # journal has no opinion; keep the disk-state verdict

        claim_ts = _ts_of(c.ts)
        window = [e for e in events
                  if claim_ts is None or e["ts"] <= claim_ts + CLAIM_GRACE_SEC]
        later = [e for e in events
                 if claim_ts is not None and e["ts"] > claim_ts + CLAIM_GRACE_SEC]

        last_in_window = window[-1] if window else None
        deletes_in_window = [e for e in window if e["event"] == "deleted"]

        if c.kind == "deleted":
            if deletes_in_window:
                ev = deletes_in_window[-1]
                c.status = "ok"
                c.detail = (f"confirmed by redhand journal: deleted at "
                            f"{_fmt_ts(ev['ts'])} (actor {ev['actor']})")
                _note_recreation(findings, session, rel, later)
            elif last_in_window is not None and last_in_window["event"] != "deleted":
                ev = last_in_window
                c.status = "failed"
                c.detail = (f"per redhand journal: no deletion around the claim — "
                            f"last recorded event was {ev['event']} at "
                            f"{_fmt_ts(ev['ts'])} (actor {ev['actor']})")
                _journal_contradiction(findings, session, c, ev)
            # no relevant journal events in window: keep disk-state verdict
        elif c.kind == "created":
            creates = [e for e in window if e["event"] == "created"]
            if creates:
                ev = creates[-1]
                c.status = "ok"
                c.detail = (f"confirmed by redhand journal: created at "
                            f"{_fmt_ts(ev['ts'])} (actor {ev['actor']})")
            elif last_in_window is not None and last_in_window["event"] == "modified":
                ev = last_in_window
                c.status = "ok"
                c.detail = (f"exists; per redhand journal the file was modified "
                            f"(not created) at {_fmt_ts(ev['ts'])} by {ev['actor']}")
        elif c.kind == "edited":
            mods = [e for e in window if e["event"] in ("modified", "created")]
            if mods:
                ev = mods[-1]
                c.status = "ok"
                c.detail = (f"confirmed by redhand journal: {ev['event']} at "
                            f"{_fmt_ts(ev['ts'])} (actor {ev['actor']})")


def _journal_contradiction(findings, session, claim, ev) -> None:
    from .models import Finding

    findings.append(Finding(
        severity="high", category="claim_failed",
        title="agent's claim is contradicted by the redhand event stream",
        detail=(f"claimed {claim.kind} '{claim.subject}', but the journal records "
                f"{ev['event']} as the last event around the claim "
                f"(actor {ev['actor']}, {_fmt_ts(ev['ts'])})"),
        where=session.project or "unknown project",
        session_id=session.session_id, agent=session.agent,
        evidence=claim.evidence[:200],
        fix="The event stream is the recorded facts — treat the claim as false.",
        ts=claim.ts,
    ))


def _note_recreation(findings, session, rel: str, later_events) -> None:
    creates = [e for e in later_events if e["event"] == "created"]
    if not creates:
        return
    ev = creates[-1]
    from .models import Finding

    findings.append(Finding(
        severity="medium", category="residue",
        title="deleted file was recreated after the deletion",
        detail=(f"{rel} was deleted as claimed, then created again at "
                f"{_fmt_ts(ev['ts'])} (actor {ev['actor']})"),
        where=session.project or "unknown project",
        session_id=session.session_id, agent=session.agent,
        evidence="",
        fix="Check whether the recreation is wanted; the deleted state is in "
            "the journal (restore with redhand if not).",
        ts=ev["ts"],
    ))


def _resolve_claim(session, subject: str):
    from .util import resolve_path

    return resolve_path(subject, session.project)


def _ts_of(ts_str: Optional[str]) -> Optional[float]:
    if not ts_str:
        return None
    from .util import parse_ts

    dt = parse_ts(ts_str)
    return dt.timestamp() if dt else None
