"""Core data model for agenttrueup."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def sev_at_least(sev: str, floor: str) -> bool:
    return SEV_ORDER.get(sev, 0) >= SEV_ORDER.get(floor, 0)


@dataclass
class Event:
    """One interesting thing that happened inside a session."""

    kind: str  # command | file_write | file_edit | assistant | user | tool_result | note
    text: str = ""
    path: str | None = None
    ts: str | None = None  # ISO-8601 if known
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Session:
    agent: str  # claude | codex | zcode | generic | ...
    session_id: str
    source_file: str  # main transcript file (or dir for zcode artifact groups)
    project: str | None  # working directory the agent operated in, if known
    started: str | None = None
    ended: str | None = None
    model: str | None = None
    cli_version: str | None = None
    events: list[Event] = field(default_factory=list)
    # richer per-event payloads kept aside (e.g. artifact before/after content)
    artifacts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["events"] = [e if isinstance(e, dict) else dataclasses.asdict(e) for e in self.events]
        return d


@dataclass
class Claim:
    """A statement by (or through) the agent about something it did.

    kind: created | edited | deleted | installed | text_only
    status is filled in by verify: ok | failed | unverifiable
    """

    kind: str
    subject: str
    via: str  # command | tool | text
    session_id: str
    agent: str
    ts: str | None = None
    evidence: str = ""
    status: str = "unverifiable"  # ok | failed | unverifiable
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Finding:
    severity: str  # critical | high | medium | low | info
    category: str  # secret | danger | exfil | claim_failed | residue | settings_leak | ...
    title: str
    detail: str = ""
    where: str = ""  # file path or "session"
    session_id: str = ""
    agent: str = ""
    evidence: str = ""  # MUST be redacted before output
    fix: str = ""
    ts: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ScanResult:
    sessions: list[Session] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stats": self.stats,
            "sessions": [
                {"agent": s.agent, "session_id": s.session_id, "project": s.project,
                 "started": s.started, "ended": s.ended, "events": len(s.events),
                 "source_file": s.source_file}
                for s in self.sessions
            ],
            "claims": [c.to_dict() for c in self.claims],
            "findings": [f.to_dict() for f in self.findings],
        }
