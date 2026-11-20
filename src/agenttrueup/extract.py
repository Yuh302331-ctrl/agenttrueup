"""Extract security-relevant signals and claims from parsed sessions."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import Claim, Event, Finding, Session
from .redact import find_secrets, redact
from .util import looks_like_path, split_command

# --------------------------------------------------------------- danger

_DANGER: list[tuple[str, str, str, str]] = [
    # (severity, title, regex, fix hint)
    ("critical", "recursive delete targeting filesystem root",
     r"\brm\b[^|;&>]*\s-[a-zA-Z]*r[a-zA-Z]*\s+[\"']?/(\"|\s|$)",
     "Never run rm -rf on /. Check what the agent was trying to do."),
    ("critical", "raw disk write (dd/mkfs)",
     r"\bdd\b[^|;&]*\bof=/dev/|\bmkfs\b", "Verify no physical/virtual disk was overwritten."),
    ("critical", "fork bomb", r":\(\)\s*\{\s*:\|:&\s*\};", "Remove the fork bomb definition."),
    ("critical", "environment dump piped to the network",
     r"\b(env|printenv|set)\b[^|;&]*\|\s*(curl|wget|nc|netcat)\b",
     "This can exfiltrate every environment secret. Rotate credentials if it ran."),
    ("high", "recursive delete of home directory",
     r"\brm\b[^|;&]*\s-[a-zA-Z]*r[a-zA-Z]*[^|;&]*\s+[\"']?(~|\$HOME)(/|\s|\"|$)",
     "Check what remains in your home directory."),
    ("high", "shell downloaded and piped straight into an interpreter",
     r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|fi|da)?sh\b",
     "If this ran, assume arbitrary code executed. Review what URL was fetched."),
    ("high", "force push (rewrites remote history)",
     r"\bgit\s+push\b[^|;&]*\s--force\b(?!-with-lease)",
     "Check the remote branch for lost commits (git reflog)."),
    ("high", "anti-forensics: shell history wiped",
     r"\bhistory\s+-c+\b|\brm\b[^|;&]*\.(bash|zsh|python)_history\b",
     "Why was history erased? Treat with suspicion."),
    ("high", "chmod -R 777", r"\bchmod\s+(-R\s+)?777\b",
     "Fix permissions of the affected tree."),
    ("high", "database structure/data destroyed",
     r"(?i)\bdrop\s+(table|database|schema)\b",
     "Restore from backup if the statement executed."),
    ("high", "package published to a registry",
     r"\bnpm\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bdotnet\s+nuget\s+push\b",
     "Check the registry for an unintended release."),
    ("high", "obfuscated payload executed",
     r"\bbase64\s+-d+\b[^|;&]*\|\s*(ba|z|fi)?sh\b",
     "Base64-decoded content was executed. Identify the payload source."),
    ("medium", "working tree reset, uncommitted changes discarded",
     r"\bgit\s+reset\s+--hard\b", "Recover with git fsck / reflog if needed."),
    ("medium", "untracked files removed (git clean)",
     r"\bgit\s+clean\b[^|;&]*-[a-zA-Z]*f", "Check git stash / trash for recoverable files."),
    ("medium", "recursive force delete", r"\brm\b[^|;&>]*\s-[a-zA-Z]*r", 
     "Confirm the deleted path was intended."),
    ("medium", "sudo used with rm", r"\bsudo\s+rm\b", "Confirm system files were not removed."),
    ("medium", "remote history rewritten (force-with-lease)",
     r"--force-with-lease\b", "Compare remote branch with local reflog."),
    ("medium", "machine power state change", r"\b(shutdown|reboot|halt|poweroff)\b",
     "Confirm this was intended."),
    ("medium", "DELETE without visible WHERE clause",
     r"(?i)\bdelete\s+from\s+[\w`\"'.\[\]]+\s*(;|$)", "Verify table scope and row counts."),
    ("low", "commit/hooks bypassed", r"--no-verify\b", "Check what skipped the hooks."),
]

# precompile once
_DANGER = [(sev, title, re.compile(rx, re.MULTILINE), fix)
           for sev, title, rx, fix in _DANGER]

EXFIL_HOST_RE = re.compile(
    r"(webhook\.site|pipedream\.net|requestbin\.[a-z]+|hookb\.in|postb\.in|"
    r"hooks\.slack\.com|discord(app)?\.com/api/webhooks|api\.telegram\.org|"
    r"oast\.(fun|pro|live|site|to)|interact\.sh|burpcollaborator\.net|"
    r"ngrok\.(io|com|dev|app)|serveo\.net|localtunnel\.me)")

URL_RE = re.compile(r"https?://[^\s'\"<>`]+")


def split_compound(cmd: str) -> list[str]:
    """Split a shell line into sub-commands on ;, &&, ||, | (naive but useful)."""
    parts = re.split(r"&&|\|\||;|\|", cmd)
    return [p.strip() for p in parts if p.strip()]


def _danger_findings(cmd: str, ts, session_id: str, agent: str) -> list[Finding]:
    out: list[Finding] = []
    seen_titles: set[str] = set()
    for sev, title, rx, fix in _DANGER:
        m = rx.search(cmd)
        if not m:
            continue
        if title in seen_titles:
            continue
        seen_titles.add(title)
        out.append(Finding(
            severity=sev, category="danger", title=title,
            detail=f"command matched: {m.group(0)[:160]}",
            where="session command", session_id=session_id, agent=agent,
            evidence=cmd[:400], fix=fix, ts=ts))
    return out


def _exfil_findings(cmd: str, ts, session_id: str, agent: str) -> list[Finding]:
    out: list[Finding] = []
    for url_m in URL_RE.finditer(cmd):
        try:
            host = (urlparse(url_m.group(0)).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        if EXFIL_HOST_RE.search(host):
            out.append(Finding(
                severity="critical", category="exfil",
                title="request to a known request-capture/exfil endpoint",
                detail=f"endpoint: https://{host}/…",
                where="session command", session_id=session_id, agent=agent,
                evidence=cmd[:400], ts=ts,
                fix="Rotate any credentials the agent could have sent. Check the endpoint logs."))
    if not out and re.search(r"\b(curl|wget|nc|netcat)\b", cmd) and re.search(
            r"(--data|-d\s|--data-binary|--data-raw|--upload-file|-T\s|--post)", cmd):
        out.append(Finding(
            severity="high", category="exfil",
            title="data-bearing network request",
            detail="a command uploads/sends data over the network",
            where="session command", session_id=session_id, agent=agent,
            evidence=cmd[:400], ts=ts,
            fix="Check what payload was sent and where."))
    return out


# --------------------------------------------------------------- deletion targets

_RM_FLAGS = re.compile(r"^-{1,2}[\w-]+$")
_BROAD_TARGETS = {"/", "\\", "*", "~", ".", "..", "/*", "~/*", "$HOME", "~/"}


def deletion_targets(cmd: str) -> list[str]:
    targets: list[str] = []
    for sub in split_compound(cmd):
        toks = split_command(sub)
        if not toks:
            continue
        head = toks[0].lower()
        if head in ("rm", "unlink", "rmdir", "del", "erase", "rd",
                    "remove-item", "ri"):
            win_style = head in ("del", "erase", "rd", "remove-item", "ri")
            for t in toks[1:]:
                if t.startswith("-") or _RM_FLAGS.match(t):
                    continue
                if win_style and t.startswith("/"):
                    continue  # del /f, rd /s … flags, not targets
                if t in ("&&", "||", ";", "|"):
                    break
                # broad targets ("/", "*", "~") are danger findings, not
                # meaningful "deletion claims" to verify against disk
                if t.strip("\"'") in _BROAD_TARGETS:
                    continue
                targets.append(t)
        elif head.endswith(("\\del.exe", "/del.exe")):
            targets.extend(t for t in toks[1:] if not t.startswith("/"))
    return targets[:20]


_INSTALL_SPECS: list[tuple[str, re.Pattern[str]]] = [
    # (ecosystem, regex capturing the argument tail after the install verb)
    ("npm", re.compile(r"\b(?:npm|pnpm)\s+(?:i|install|add)\s+(?P<args>[^\n|;&]+)")),
    ("npm", re.compile(r"\byarn\s+(?:add|install)\s+(?P<args>[^\n|;&]+)")),
    ("pypi", re.compile(r"\bpip3?\s+install\s+(?P<args>[^\n|;&]+)")),
    ("pypi", re.compile(r"\buv\s+(?:add|pip\s+install)\s+(?P<args>[^\n|;&]+)")),
    ("pypi", re.compile(r"\bpoetry\s+add\s+(?P<args>[^\n|;&]+)")),
    ("cargo", re.compile(r"\bcargo\s+add\s+(?P<args>[^\n|;&]+)")),
    ("go", re.compile(r"\bgo\s+get\s+(?P<args>[^\n|;&]+)")),
    ("ruby", re.compile(r"\bgem\s+install\s+(?P<args>[^\n|;&]+)")),
    ("dotnet", re.compile(r"\bdotnet\s+add\s+package\s+(?P<args>[^\n|;&]+)")),
    ("os", re.compile(r"\b(?:apt|apt-get|brew|choco|winget|dnf)\s+install\s+(?P<args>[^\n|;&]+)")),
]

_PKG_STRIP = re.compile(r"[=<>!~].*$|@[0-9^~][^/]*$|\[[^\]]*\]$")
_PKG_OK = re.compile(r"^[@\w][\w@/.\-+]*$")
_NOT_PKGS = (".txt", ".toml", ".lock", ".json", ".cfg", ".in", ".yaml", ".yml")


def installed_packages(cmd: str) -> list[tuple[str, str]]:
    """(ecosystem, package) pairs a command claims to install."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for eco, rx in _INSTALL_SPECS:
        for m in rx.finditer(cmd):
            for t in split_command(m.group("args")):
                if t.startswith("-"):
                    continue
                if "://" in t or t.startswith(("./", "../", "/", ".")):
                    continue  # local/git paths, not registry packages
                if t.lower().endswith(_NOT_PKGS):
                    continue  # -r requirements.txt and friends
                pkg = _PKG_STRIP.sub("", t).strip()
                if not pkg or " " in pkg:
                    continue
                if eco != "os" and not _PKG_OK.match(pkg):
                    continue
                key = (eco, pkg.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append((eco, pkg))
    return out[:20]


# --------------------------------------------------------------- text claims

_DEL_CLAIM = re.compile(
    r"\b(?:deleted|removed|cleaned? up|cleared|erased|got rid of)\b[^`'\".|]{0,60}?"
    r"[`'\"]([^\s`'\"]+)[`'\"]", re.I)
_CREATE_CLAIM = re.compile(
    r"\b(?:created|wrote|added|generated|scaffolded|set up)\b[^`'\".|]{0,60}?"
    r"[`'\"]([^\s`'\"]+)[`'\"]", re.I)
_EDIT_CLAIM = re.compile(
    r"\b(?:updated|modified|edited|changed|fixed|refactored|patched|rewrote)\b[^`'\".|]{0,60}?"
    r"[`'\"]([^\s`'\"]+)[`'\"]", re.I)
_INSTALL_CLAIM = re.compile(
    r"\b(?:installed|added|pinned)\b[^`'\".|]{0,40}?[`'\"]"
    r"(@?[\w][\w@/.\-+]*)[`'\"]", re.I)


def _text_claims(text: str) -> list[tuple[str, str]]:
    claims: list[tuple[str, str]] = []
    for rx, kind in ((_DEL_CLAIM, "deleted"), (_CREATE_CLAIM, "created"),
                     (_EDIT_CLAIM, "edited")):
        for m in rx.finditer(text):
            subj = m.group(1).rstrip(".,;:")
            if looks_like_path(subj):
                claims.append((kind, subj))
    for m in _INSTALL_CLAIM.finditer(text):
        subj = m.group(1).rstrip(".,;:")
        # "added `style.css`" is a file mention, not a dependency install
        if looks_like_path(subj):
            continue
        if 2 <= len(subj) <= 120 and "/" not in subj.replace("@", "", 1):
            claims.append(("installed", subj))
    return claims


# --------------------------------------------------------------- per-session scan

def claims_from_session(session: Session) -> list[Claim]:
    claims: list[Claim] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, subject: str, via: str, ts, evidence: str):
        key = (kind, subject.lower())
        if key in seen:
            return
        seen.add(key)
        claims.append(Claim(kind=kind, subject=subject, via=via,
                            session_id=session.session_id, agent=session.agent,
                            ts=ts, evidence=evidence[:200]))

    for ev in session.events:
        if ev.kind == "command":
            for t in deletion_targets(ev.text):
                add("deleted", t, "command", ev.ts, ev.text)
            for eco, pkg in installed_packages(ev.text):
                add("installed", f"{eco}:{pkg}", "command", ev.ts, ev.text)
        elif ev.kind in ("file_write", "file_edit"):
            if ev.path:
                add("created" if ev.kind == "file_write" else "edited",
                    ev.path, "tool", ev.ts, f"tool={ev.extra.get('tool')}")
        elif ev.kind == "note" and ev.extra.get("deleted") and ev.path:
            add("deleted", ev.path, "tool", ev.ts, ev.text)
        elif ev.kind in ("assistant", "user"):
            if ev.kind == "assistant":
                for kind, subj in _text_claims(ev.text):
                    add(kind, subj, "text", ev.ts, ev.text[:160])

    # artifact-level truth (zcode): exact files the tool wrote
    for art in session.artifacts:
        kind = "edited" if art.get("existed_before") else "created"
        add(kind, str(art.get("path")), "artifact", art.get("ts"), f"tool={art.get('tool')}")
    return claims


def security_findings_for_session(session: Session,
                                  max_events: int = 4000) -> list[Finding]:
    findings: list[Finding] = []
    seen_secret: set[tuple[str, str]] = set()
    events = session.events[:max_events]
    scanned: list[str] = []
    for ev in events:
        scanned.append(ev.text or "")
    for art in session.artifacts[:200]:
        after = art.get("after") or ""
        scanned.append(after[:20000])
        mc = art.get("must_contain") or ""
        if mc:
            scanned.append(mc[:20000])  # Claude Edit new_string may carry secrets
    for text in scanned:
        if not text:
            continue
        for hit in find_secrets(text):
            key = (hit.kind, hit.fingerprint)
            if key in seen_secret:
                continue
            seen_secret.add(key)
            findings.append(Finding(
                severity=hit.severity, category="secret",
                title=f"{hit.kind} exposed in agent session",
                detail=f"{hit.kind} — sha256:{hit.fingerprint} (use --reveal to see it)",
                where=session.source_file, session_id=session.session_id,
                agent=session.agent, evidence=redact(hit.context),
                fix="Rotate this credential and scrub the transcript.",
                ts=None))
    for ev in events:
        if ev.kind == "command":
            findings.extend(_danger_findings(ev.text, ev.ts, session.session_id, session.agent))
            findings.extend(_exfil_findings(ev.text, ev.ts, session.session_id, session.agent))
    return findings
