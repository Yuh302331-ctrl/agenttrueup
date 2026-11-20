"""Scan orchestration: stores -> sessions -> claims/findings -> ScanResult."""

from __future__ import annotations

import time
from pathlib import Path

from . import extract, stores
from .models import ScanResult, Session
from .parsers import (merge_sessions, parse_claude_file, parse_codex_file,
                      parse_generic_file, parse_zcode_artifacts_dir,
                      parse_zcode_rollout)
from .redact import redact
from .util import iter_files, parse_since, parse_ts
from .verify import (residue_findings, settings_leak_findings, verify_claims)


def _parse_extra_path(p: Path) -> list[Session]:
    kind = stores.sniff_file(p) if p.is_file() else "dir"
    if p.is_file():
        if kind == "codex":
            return [parse_codex_file(p)]
        if kind == "claude":
            return [parse_claude_file(p)]
        if kind == "zcode":
            return parse_zcode_rollout(p)
        return [parse_generic_file(p)]
    # directory: try known layouts, else generic harvest
    out: list[Session] = []
    jsonl = iter_files(p, {".jsonl"})
    jsons = iter_files(p, {".json"})
    if jsonl and any(stores.sniff_file(f) == "codex" for f in jsonl[:3]):
        out.extend(parse_codex_file(f) for f in jsonl)
        return out
    if jsonl and any(stores.sniff_file(f) == "claude" for f in jsonl[:3]):
        out.extend(parse_claude_file(f) for f in jsonl)
        return out
    if jsonl and any(stores.sniff_file(f) == "zcode" for f in jsonl[:3]):
        for f in jsonl:
            out.extend(parse_zcode_rollout(f))
        return out
    for f in jsonl[:500]:
        out.append(parse_generic_file(f))
    for f in jsons[:500]:
        out.append(parse_generic_file(f))
    return [s for s in out if s.events]


def scan(paths: list[str] | None = None, agents: list[str] | None = None,
         since: str | None = None, reveal: bool = False,
         verbose: bool = False) -> ScanResult:
    t0 = time.time()
    result = ScanResult()
    since_dt = parse_since(since) if since else None
    agent_set = {a.strip().lower() for a in (agents or []) if a.strip()}
    errors = 0
    files_seen = 0

    def emit(msg: str):
        if verbose:
            print(msg, flush=True, file=__import__("sys").stderr)

    sessions: list[Session] = []

    def add_store_sessions(new: list[Session], label: str):
        sessions.extend([s for s in new if s is not None])
        emit(f"  {label}: {len(new)} session file(s)")

    present = stores.discover()
    if agent_set:
        present = [s for s in present if s.agent in agent_set]

    for store in present:
        root = store.root
        try:
            if store.kind == "claude_projects":
                files = iter_files(root, {".jsonl"})
                files_seen += len(files)
                add_store_sessions([parse_claude_file(f) for f in files], store.label)
            elif store.kind == "codex_sessions":
                files = iter_files(root, {".jsonl"})
                files_seen += len(files)
                add_store_sessions([parse_codex_file(f) for f in files], store.label)
            elif store.kind == "zcode_rollout":
                files = [f for f in root.glob("model-io-*.jsonl") if f.is_file()]
                files_seen += len(files)
                new: list[Session] = []
                for f in files:
                    new.extend(parse_zcode_rollout(f))
                add_store_sessions(new, store.label)
            elif store.kind == "zcode_artifacts":
                dirs = [d for d in root.iterdir() if d.is_dir()] if root.is_dir() else []
                files_seen += len(dirs)
                new = [parse_zcode_artifacts_dir(d) for d in dirs]
                add_store_sessions([s for s in new if s is not None], store.label)
            elif store.kind == "generic_dir":
                short = store.label.split(" ")[0].lower()
                files = iter_files(root, {".jsonl", ".json"})
                files_seen += len(files)
                new = [parse_generic_file(f, agent=short) for f in files[:400]]
                add_store_sessions([s for s in new if s.events], store.label)
        except Exception as e:  # a broken store must not kill the scan
            errors += 1
            emit(f"  ! {store.label}: error {e}")

    for extra in (paths or []):
        p = Path(extra).expanduser()
        try:
            add_store_sessions(_parse_extra_path(p), f"extra: {p}")
        except Exception as e:
            errors += 1
            emit(f"  ! extra path {p}: error {e}")

    sessions = merge_sessions(sessions)

    if since_dt:
        def _keep(s: Session) -> bool:
            end = parse_ts(s.ended)
            if end is None:
                return True
            return end >= since_dt
        sessions = [s for s in sessions if _keep(s)]

    if agent_set:
        sessions = [s for s in sessions if s.agent in agent_set]

    result.sessions = sessions
    findings = []
    claims = []
    projects: list[str] = []
    claude_root = None
    for s in stores.candidate_stores():
        if s.agent == "claude":
            claude_root = s.root.parent
            break

    for s in sessions:
        if s.project:
            projects.append(s.project)
        cl = extract.claims_from_session(s)
        claims.extend(cl)
        findings.extend(verify_claims(s, cl))
        findings.extend(extract.security_findings_for_session(s))
        findings.extend(residue_findings(s))
    findings.extend(settings_leak_findings(claude_root, projects))

    if not reveal:
        for f in findings:
            f.evidence = redact(f.evidence or "")
        for c in claims:
            c.evidence = redact(c.evidence or "")

    result.claims = claims
    result.findings = findings
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    result.stats = {
        "stores_found": len(present),
        "files_seen": files_seen,
        "sessions": len(sessions),
        "events": sum(len(s.events) for s in sessions),
        "claims": len(claims),
        "claims_failed": sum(1 for c in claims if c.status == "failed"),
        "claims_ok": sum(1 for c in claims if c.status == "ok"),
        "claims_unverifiable": sum(1 for c in claims if c.status == "unverifiable"),
        "findings": len(findings),
        "findings_by_severity": by_sev,
        "errors": errors,
        "duration_sec": round(time.time() - t0, 2),
        "reveal": reveal,
    }
    return result
