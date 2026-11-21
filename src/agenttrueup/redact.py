"""Secret detection and redaction.

Detection runs on text pulled from agent transcripts (commands, messages,
written-file snapshots).  Output is ALWAYS redacted unless the user passes
--reveal, so the audit itself never re-leaks what it finds.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from typing import Any

from .util import fingerprint

# (kind, compiled regex, severity, value-group-index or None)
# Keep patterns high-precision to avoid drowning users in false positives.
# value-group tells the junk filter which capture group holds the secret
# itself (so a padded value can't be rescued by its `password=` prefix).
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, int | None]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", None),
    ("aws_secret_key", re.compile(r"(?i)\baws.{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]"), "high", 1),
    ("github_pat",
     re.compile(r"\bghp_[A-Za-z0-9]{36,50}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), "high", None),
    ("github_oauth",
     re.compile(r"\bgho_[A-Za-z0-9]{36}\b|\bghu_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b"), "high", None),
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"), "high", None),
    # anthropic before openai, and the openai pattern excludes sk-ant- —
    # otherwise one Anthropic key is reported twice (both patterns match it)
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b"), "high", None),
    ("openai_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b"), "high", None),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high", None),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "high", None),
    ("stripe_key", re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b"), "high", None),
    ("private_key_block",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"),
     "critical", None),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"), "medium", None),
    ("uri_credentials", re.compile(
        r"\b[a-z][a-z0-9+.\-]{2,20}://[^\s:/@'\"<>]{1,64}:[^\s@'\"<>]{4,128}@[^\s'\"<>]+"), "high", None),
    ("assigned_credential", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|credential)\b['\"]?\s*[:=]\s*['\"]?"
        r"([A-Za-z0-9+/_\-=]{16,128})"), "medium", 2),
    ("gcp_private_key_json", re.compile(r"\"private_key\"\s*:\s*\"-----BEGIN"), "critical", None),
]

# length guard: skip obviously-junk matches (all same char, or too short after
# stripping prefixes) to keep false positives manageable
_MIN_SECRET_LEN = 12


@dataclass
class SecretHit:
    kind: str
    severity: str
    match: str      # raw matched string (never printed unredacted)
    fingerprint: str
    pos: int
    context: str    # short redacted line for display

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _junk(m: re.Match[str], value_group: int | None) -> bool:
    # for key=value patterns, judge the value itself so a padded secret can't
    # be rescued by its `password=` prefix; for structured tokens, the whole
    # match is the value
    if value_group is not None and value_group <= len(m.groups()):
        core = (m.group(value_group) or "")
    else:
        core = m.group(0)
    core = core.strip("\"'`=: ")
    if len(core) < _MIN_SECRET_LEN:
        return True
    if len(set(core)) <= 3:
        return True
    return False


def find_secrets(text: str) -> list[SecretHit]:
    if not text:
        return []
    hits: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()
    for kind, rx, sev, vg in SECRET_PATTERNS:
        for m in rx.finditer(text):
            matched = m.group(0)
            if _junk(m, vg):
                continue
            key = (kind, fingerprint(matched))
            if key in seen:
                continue
            seen.add(key)
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            if line_end == -1:
                line_end = len(text)
            context = redact(text[line_start:line_end])[:160]
            hits.append(SecretHit(kind, sev, matched, fingerprint(matched), m.start(), context))
    hits.sort(key=lambda h: (SEV_POS.get(h.severity, 0), h.pos), reverse=True)
    hits.sort(key=lambda h: h.pos)
    return hits


SEV_POS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def redact(text: str, reveal: bool = False) -> str:
    """Redact every secret-looking match, keeping kind + fingerprint."""
    if not text:
        return text

    def _sub(m: re.Match[str], kind: str) -> str:
        matched = m.group(0)
        if reveal:
            return matched
        return f"<{kind}:{fingerprint(matched)}>"

    out = text
    for kind, rx, _sev, _vg in SECRET_PATTERNS:
        out = rx.sub(lambda m, k=kind: _sub(m, k), out)
    return out


def describe_hit(hit: SecretHit) -> str:
    return f"{hit.kind} (sha256:{hit.fingerprint})"
