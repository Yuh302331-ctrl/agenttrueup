"""Verification: reconcile claims and residue against the real filesystem,
git state and dependency manifests.  Read-only — never mutates anything."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .models import Claim, Finding, Session
from .util import resolve_path

SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git", "dist",
             "build", ".next", ".tox", ".mypy_cache", ".pytest_cache"}
MAX_MANIFESTS = 50
MANIFEST_NAMES = {"package.json": "npm", "pyproject.toml": "pypi",
                  "go.mod": "go", "Cargo.toml": "cargo", "Gemfile": "ruby"}
LITTER_PATTERNS = ["*.bak", "*.orig", "*.rej", "*.swp", "*~", "*.tmp"]

# paths under these markers are ephemeral — agents write scratch files there
# all the time, and "claimed created but now gone" is expected, not suspicious
TEMP_PATH_MARKERS = ("\\temp\\", "/tmp/", "/temp/", "temp/", "\\tmp\\",
                     "pytest-of-", "__pycache__", "/var/folders/",
                     "node_modules", ".venv", "site-packages", "/cache/",
                     "\\appdata\\local\\temp")


def _git_available() -> bool:
    return shutil.which("git") is not None


def _git_porcelain(project: str) -> dict[str, str]:
    """path -> status code (XY), for the current worktree."""
    if not _git_available() or not project:
        return {}
    try:
        proc = subprocess.run(
            ["git", "-C", project, "status", "--porcelain=v1"],
            capture_output=True, text=True, timeout=15, errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if proc.returncode != 0:
        return {}
    out: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if len(line) >= 4:
            out[line[3:].strip().strip('"')] = line[:2]
    return out


def find_manifests(project: str | None) -> list[Path]:
    if not project:
        return []
    root = Path(project)
    if not root.is_dir():
        return []
    out: list[Path] = []
    try:
        stack = [(root, 0)]
        while stack and len(out) < MAX_MANIFESTS:
            d, depth = stack.pop()
            if depth > 3:
                continue
            try:
                entries = list(d.iterdir())
            except OSError:
                continue
            for p in entries:
                if p.is_file() and (p.name in MANIFEST_NAMES
                                    or p.name.startswith("requirements")):
                    out.append(p)
            try:
                children = [c for c in d.iterdir() if c.is_dir()]
            except OSError:
                continue
            for c in children:
                if c.name in SKIP_DIRS or c.name.startswith("."):
                    continue
                stack.append((c, depth + 1))
    except OSError:
        pass
    return out[:MAX_MANIFESTS]


def manifest_contains(manifest: Path, package: str) -> bool:
    eco = MANIFEST_NAMES.get(manifest.name)
    pkg_l = package.lower()
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if manifest.name == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return False
        for key in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
            deps = data.get(key)
            if isinstance(deps, dict) and pkg_l in {k.lower() for k in deps}:
                return True
        return False
    if manifest.name == "pyproject.toml":
        try:
            import tomllib
            data = tomllib.loads(text)
        except Exception:
            return False
        proj = data.get("project", {})
        dep_list = list(proj.get("dependencies") or []) + \
            sum((list(v or []) for v in (proj.get("optional-dependencies") or {}).values()), [])
        poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
        names = set()
        for d in dep_list:
            names.add(re.split(r"[=<>!\[ ;]", str(d), maxsplit=1)[0].strip().lower())
        names |= {k.lower() for k in poetry}
        return pkg_l in names
    if manifest.name == "requirements.txt" or manifest.name.startswith("requirements"):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("-", "#", "git+")):
                continue
            if re.split(r"[=<>!\[ ]", line, maxsplit=1)[0].strip().lower() == pkg_l:
                return True
        return False
    if manifest.name == "go.mod":
        return bool(re.search(r"(?m)^\s*[\w./-]*" + re.escape(package) + r"\b", text))
    if manifest.name == "Cargo.toml":
        try:
            import tomllib
            data = tomllib.loads(text)
        except Exception:
            return False
        return pkg_l in {k.lower() for k in (data.get("dependencies") or {})}
    if manifest.name == "Gemfile":
        return bool(re.search(r"""gem\s+['"]""" + re.escape(package) + r"""['"]""", text))
    return False


def _resolve_claim_path(subject: str, session: Session) -> Path | None:
    p = resolve_path(subject, session.project)
    if p is not None:
        return p
    return None


def _is_ephemeral(p: Path | None) -> bool:
    if p is None:
        return False
    s = str(p).lower().replace("\\\\", "\\")
    return any(marker in s for marker in TEMP_PATH_MARKERS)


def verify_claims(session: Session, claims: list[Claim]) -> list[Finding]:
    findings: list[Finding] = []
    from .util import parse_ts
    started = parse_ts(session.started)

    # artifact content snapshots let us do exact content verification (zcode)
    artifact_by_path: dict[str, dict] = {}
    for art in session.artifacts:
        artifact_by_path.setdefault(str(art.get("path")), art)

    for c in claims:
        if c.kind == "deleted":
            p = _resolve_claim_path(c.subject, session)
            if p is None:
                c.status = "unverifiable"
                c.detail = "path could not be resolved"
                continue
            if p.exists():
                c.status = "failed"
                c.detail = f"claimed deleted but still exists: {p}"
                findings.append(Finding(
                    severity="high", category="claim_failed",
                    title="agent claimed a deletion, but the file still exists",
                    detail=c.detail, where=str(p), session_id=session.session_id,
                    agent=session.agent, evidence=c.evidence,
                    fix="Delete it yourself if it should be gone, or ask the agent why it survived.",
                    ts=c.ts))
            else:
                c.status = "ok"
                c.detail = "confirmed gone"
        elif c.kind in ("created", "edited"):
            p = _resolve_claim_path(c.subject, session)
            if p is None:
                c.status = "unverifiable"
                c.detail = "path could not be resolved"
                continue
            if not p.exists():
                if _is_ephemeral(p):
                    c.status = "ok"
                    c.detail = "temporary/scratch path, expected to disappear"
                    continue
                c.status = "failed"
                c.detail = f"claimed {c.kind} but the file is missing now: {p}"
                findings.append(Finding(
                    severity="low", category="claim_failed",
                    title=f"agent claimed to {c.kind} a file, but it does not exist",
                    detail=c.detail, where=str(p), session_id=session.session_id,
                    agent=session.agent, evidence=c.evidence,
                    fix="Check whether it was moved, reverted, or never written.",
                    ts=c.ts))
                continue
            art = artifact_by_path.get(str(p)) or artifact_by_path.get(str(p).replace("\\", "/"))
            if art and isinstance(art.get("after"), str):
                try:
                    current = p.read_text(encoding="utf-8", errors="replace")
                except (OSError, ValueError):
                    current = None
                if current is not None:
                    if current.strip() == art["after"].strip():
                        c.status = "ok"
                        c.detail = "content on disk matches what the tool wrote"
                    else:
                        c.status = "ok"
                        c.detail = "file changed since the agent wrote it"
                    continue
            if c.kind == "edited" and started:
                try:
                    mtime = p.stat().st_mtime
                    from datetime import datetime, timezone
                    m_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
                    # allow small clock slack
                    if m_dt < started.replace(tzinfo=m_dt.tzinfo):
                        c.status = "failed"
                        c.detail = ("claimed edited but file mtime predates the "
                                    f"session ({m_dt.isoformat(timespec='seconds')})")
                        findings.append(Finding(
                            severity="medium", category="claim_failed",
                            title="agent claimed an edit, but the file shows no change since",
                            detail=c.detail, where=str(p), session_id=session.session_id,
                            agent=session.agent, evidence=c.evidence,
                            fix="Diff the file against git HEAD; the edit may never have landed.",
                            ts=c.ts))
                        continue
                except OSError:
                    pass
            c.status = "ok"
            c.detail = "exists" + (" and changed after session start" if c.kind == "edited" else "")
        elif c.kind == "installed":
            eco, _, pkg = c.subject.partition(":")
            if not pkg:
                pkg = eco
                eco = ""
            manifests = find_manifests(session.project)
            if not manifests:
                c.status = "unverifiable"
                c.detail = "no dependency manifest found near the session project"
                continue
            relevant = [m for m in manifests
                        if MANIFEST_NAMES.get(m.name) == eco] if eco else manifests
            if eco and not relevant:
                relevant = manifests
            if any(manifest_contains(m, pkg) for m in relevant):
                c.status = "ok"
                c.detail = "found in manifest"
            else:
                c.status = "failed"
                checked = ", ".join(m.name for m in relevant[:6])
                c.detail = f"not found in any manifest ({checked})"
                findings.append(Finding(
                    severity="high", category="claim_failed",
                    title="agent claims a dependency was installed, but no manifest records it",
                    detail=c.detail, where=session.project or "unknown project",
                    session_id=session.session_id, agent=session.agent,
                    evidence=c.evidence,
                    fix="The install may have gone to the wrong directory, or was never run. "
                        "Re-add the dependency deliberately.",
                    ts=c.ts))
    return findings


def residue_findings(session: Session) -> list[Finding]:
    findings: list[Finding] = []
    written = []
    for ev in session.events:
        if ev.kind == "file_write" and ev.path:
            written.append(ev.path)
    for art in session.artifacts:
        if not art.get("existed_before") and art.get("path"):
            written.append(str(art["path"]))
    written = list(dict.fromkeys(written))[:100]
    if not written:
        return findings

    project = session.project
    porcelain = _git_porcelain(project) if project else {}
    untracked: list[str] = []
    missing: list[str] = []
    for w in written:
        p = resolve_path(w, project)
        if p is None or not p.exists():
            missing.append(w)
            continue
        if porcelain:
            try:
                rel = str(p.relative_to(Path(project))).replace("\\", "/")
            except ValueError:
                rel = str(p)
            st = porcelain.get(rel)
            if st and st.startswith("??"):
                untracked.append(rel)
    if untracked:
        preview = ", ".join(untracked[:5]) + ("…" if len(untracked) > 5 else "")
        findings.append(Finding(
            severity="low", category="residue",
            title=f"agent created {len(untracked)} file(s) still uncommitted in git",
            detail=preview, where=project or "", session_id=session.session_id,
            agent=session.agent, evidence="",
            fix="Commit, gitignore, or delete them deliberately."))
    # backup litter near the project root
    litter: list[str] = []
    if project and Path(project).is_dir():
        for pat in LITTER_PATTERNS:
            try:
                litter.extend(str(p) for p in Path(project).glob(pat))
            except OSError:
                pass
    litter = sorted(set(litter))[:20]
    if litter:
        findings.append(Finding(
            severity="low", category="residue",
            title=f"{len(litter)} backup/litter file(s) in the project root",
            detail=", ".join(Path(x).name for x in litter[:8]),
            where=project, session_id=session.session_id, agent=session.agent,
            evidence="", fix="Remove editor/agent litter from the repo root."))
    return findings


def settings_leak_findings(claude_root: Path | None,
                           projects: list[str]) -> list[Finding]:
    """Claude Code saves approved commands to settings.local.json — those
    commands sometimes contain credentials (documented 2026 leak pattern)."""
    from .redact import find_secrets, redact
    candidates: list[Path] = []
    if claude_root and claude_root.is_dir():
        candidates += [claude_root / "settings.json", claude_root / "settings.local.json"]
    for proj in projects[:20]:
        if not proj:
            continue
        d = Path(proj) / ".claude"
        if d.is_dir():
            candidates += [d / "settings.json", d / "settings.local.json"]
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for p in candidates:
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            continue
        flat: list[str] = []

        def walk(v):
            if isinstance(v, str):
                flat.append(v)
            elif isinstance(v, list):
                for x in v:
                    walk(x)
            elif isinstance(v, dict):
                for x in v.values():
                    walk(x)
        walk(data)
        for s in flat:
            for hit in find_secrets(s):
                key = (hit.kind, hit.fingerprint)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    severity="high", category="settings_leak",
                    title=f"{hit.kind} persisted in Claude Code permission settings",
                    detail=f"{p} — sha256:{hit.fingerprint}",
                    where=str(p), agent="claude",
                    evidence=redact(hit.context)[:200],
                    fix="Remove the rule, purge the file from git history, rotate the credential."))
    return findings
