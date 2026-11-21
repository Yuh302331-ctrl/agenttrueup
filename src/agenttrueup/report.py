"""Rendering: human text report, machine JSON, and SARIF 2.1.0."""

from __future__ import annotations

import json
import re
import sys

from .models import SEV_ORDER, ScanResult
from .util import now_iso

BANNER = "trueup — trust, but reconcile"


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _c(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def red(self, t): return self._c("31;1", t)
    def yellow(self, t): return self._c("33;1", t)
    def green(self, t): return self._c("32;1", t)
    def cyan(self, t): return self._c("36", t)
    def dim(self, t): return self._c("90", t)
    def bold(self, t): return self._c("1", t)


def _sev_badge(st: Style, sev: str) -> str:
    label = {"critical": "CRIT", "high": "HIGH", "medium": "MED",
             "low": "LOW", "info": "INFO"}[sev]
    if sev == "critical":
        return st.red(f"[{label}]")
    if sev == "high":
        return st.red(f"[{label}] ")
    if sev == "medium":
        return st.yellow(f"[{label}]")
    return st.dim(f"[{label}]")


def render_text(res: ScanResult, st: Style) -> str:
    out: list[str] = []
    s = res.stats
    out.append(st.bold(BANNER))
    header = (f"scanned {s.get('stores_found', 0)} store(s), "
              f"{s.get('sessions', 0)} session(s), {s.get('events', 0)} event(s) "
              f"in {s.get('duration_sec', 0)}s")
    by_agent = s.get("sessions_by_agent") or {}
    if by_agent:
        header += st.dim("  [" + ", ".join(f"{a}: {n}" for a, n in sorted(by_agent.items())) + "]")
    out.append(header)
    for w in s.get("warnings") or []:
        out.append(st.yellow(f"⚠ {w}"))
    out.append("")

    findings = sorted(res.findings,
                      key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.category, f.title))
    counts = s.get("findings_by_severity", {})
    summary = "  ".join(f"{sev}:{counts[sev]}" for sev in
                        ("critical", "high", "medium", "low", "info") if counts.get(sev))
    if findings:
        out.append(st.bold(f"FINDINGS ({len(findings)})") +
                   (st.dim(f"   {summary}") if summary else ""))
        cur_sev = None
        for f in findings:
            if f.severity != cur_sev:
                cur_sev = f.severity
            out.append("")
            out.append(f" {_sev_badge(st, f.severity)} {st.cyan(f.category)}  {f.title}")
            if f.detail:
                out.append(st.dim(f"        {f.detail}"))
            loc = f.where or ""
            if f.agent or f.session_id:
                loc += (f"   [{f.agent} · {f.session_id[:22]}]" if f.session_id
                        else f"   [{f.agent}]")
            if loc.strip():
                out.append(st.dim(f"        at {loc}"))
            if f.evidence:
                ev_lines = f.evidence.splitlines()[:3]
                for ln in ev_lines:
                    out.append(f"        | {ln[:200]}")
            if f.fix:
                out.append(st.green(f"        → {f.fix}"))
    else:
        out.append(st.green("FINDINGS (0)  — nothing alarming found"))

    # claims ledger
    claims = res.claims
    if claims:
        out.append("")
        out.append(st.bold(f"CLAIMS LEDGER ({len(claims)})") +
                   st.dim(f"   ✓ {s.get('claims_ok', 0)} verified   "
                          f"✗ {s.get('claims_failed', 0)} failed   "
                          f"○ {s.get('claims_unverifiable', 0)} unverifiable"))
        order = {"failed": 0, "ok": 1, "unverifiable": 2}
        shown = sorted(claims, key=lambda c: order.get(c.status, 3))[:80]
        for c in shown:
            if c.status == "failed":
                icon, col = "✗", st.red
            elif c.status == "ok":
                icon, col = "✓", st.green
            else:
                icon, col = "○", st.dim
            subj = c.subject if len(c.subject) <= 72 else c.subject[:69] + "…"
            detail = f" — {c.detail}" if c.detail else ""
            out.append(f"  {col(icon)} {c.kind:<9} {subj}{st.dim(detail)}"
                       f"{st.dim(f'   [{c.agent} {c.via}]')}")
        if len(claims) > len(shown):
            out.append(st.dim(f"  … and {len(claims) - len(shown)} more (use --json)"))
    out.append("")
    if s.get("errors"):
        out.append(st.yellow(f"note: {s['errors']} parse error(s) skipped"))
    if s.get("hint_pair_with_redhand"):
        out.append(st.cyan(
            "tip: no redhand journal found — pairing with redhand "
            "(github.com/Yuh302331-ctrl/redhand) upgrades claim verification "
            "from disk-state to the recorded event stream."))
    out.append(st.dim("exit code reflects --fail-on (default: high). "
                      "outputs: --json, --sarif. see --reveal for raw secrets."))
    return "\n".join(out)


def render_json(res: ScanResult) -> str:
    doc = {
        "tool": "agenttrueup",
        "version": _version(),
        "generated": now_iso(),
        **res.to_dict(),
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _version() -> str:
    from . import __version__
    return __version__


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def render_sarif(res: ScanResult) -> str:
    rules = []
    rule_ids = {}
    for f in res.findings:
        rid = re.sub(r"[^A-Za-z0-9]+", "-", f"{f.category}-{f.title}")[:80].strip("-").lower()
        if rid not in rule_ids:
            rule_ids[rid] = True
            rules.append({
                "id": rid,
                "name": f.category,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
                "properties": {"severity": f.severity},
            })
    results = []
    for f in res.findings:
        rid = re.sub(r"[^A-Za-z0-9]+", "-", f"{f.category}-{f.title}")[:80].strip("-").lower()
        loc = {}
        if f.where and not f.where.startswith("session"):
            loc = {"physicalLocation": {"artifactLocation": {"uri": f.where.replace("\\", "/")}}}
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title}. {f.detail}".strip()},
            **({"partialFingerprints": {"agenttrueup/v1": f"{f.category}:{f.title}"}}),
            **({"locations": [loc]} if loc else {}),
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "agenttrueup",
                                "informationUri": "https://github.com/Yuh302331-ctrl/agenttrueup",
                                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def enable_windows_vt() -> None:
    if sys.platform == "win32":
        try:
            import os
            os.system("")  # enables ANSI escape handling in classic consoles
        except Exception:
            pass
