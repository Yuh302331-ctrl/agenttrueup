"""Unit tests for report rendering: text, JSON, SARIF, styles."""

from __future__ import annotations

import json

from agenttrueup.models import Claim, Finding, ScanResult, Session
from agenttrueup.report import Style, render_json, render_sarif, render_text


def _result() -> ScanResult:
    s = Session(agent="claude", session_id="sess_abc", source_file="/tmp/x.jsonl",
                project="/proj", events=[])
    claims = [
        Claim(kind="deleted", subject="old.txt", via="command", session_id="sess_abc",
              agent="claude", status="ok"),
        Claim(kind="created", subject="missing.txt", via="text", session_id="sess_abc",
              agent="claude", status="failed", detail="does not exist"),
        Claim(kind="edited", subject="maybe.txt", via="tool", session_id="sess_abc",
              agent="claude", status="unverifiable"),
    ]
    findings = [
        Finding(severity="high", category="claim_failed", title="claim contradicted",
                detail="missing.txt does not exist", where="/proj",
                session_id="sess_abc", agent="claude", fix="re-add it"),
        Finding(severity="critical", category="exfil", title="data-bearing upload",
                detail="webhook.site POST", where="session sess_abc", agent="claude"),
        Finding(severity="low", category="residue", title="backup litter",
                detail="old.bak", where="/proj/old.bak"),
    ]
    stats = {
        "stores_found": 1, "sessions": 1, "events": 3, "duration_sec": 0.1,
        "findings_by_severity": {"critical": 1, "high": 1, "low": 1},
        "claims_ok": 1, "claims_failed": 1, "claims_unverifiable": 1,
        "sessions_by_agent": {"claude": 1},
    }
    return ScanResult(sessions=[s], claims=claims, findings=findings, stats=stats)


# ---------------------------------------------------------------- text


def test_render_text_sections():
    out = render_text(_result(), Style(False))
    assert "trueup — trust, but reconcile" in out
    assert "FINDINGS (3)" in out
    assert "critical:1" in out and "high:1" in out and "low:1" in out
    assert "CLAIMS LEDGER (3)" in out
    assert "✓" in out and "✗" in out and "○" in out
    assert "scanned 1 store(s)" in out
    assert "[claude: 1]" in out


def test_render_text_findings_sorted_critical_first():
    out = render_text(_result(), Style(False))
    crit = out.index("data-bearing upload")
    high = out.index("claim contradicted")
    low = out.index("backup litter")
    assert crit < high < low


def test_render_text_plain_when_style_disabled():
    out = render_text(_result(), Style(False))
    assert "\x1b[" not in out


def test_render_text_ansi_when_enabled():
    out = render_text(_result(), Style(True))
    assert "\x1b[" in out


def test_render_text_truncates_evidence_lines():
    res = _result()
    res.findings[0].evidence = "\n".join(f"line{i}" for i in range(10))
    out = render_text(res, Style(False))
    assert "line2" in out and "line3" not in out  # first 3 evidence lines only


def test_render_text_empty_result():
    res = ScanResult(stats={})
    out = render_text(res, Style(False))
    assert "FINDINGS (0)" in out
    assert "nothing alarming found" in out


def test_render_text_claims_truncated():
    res = _result()
    res.claims = [Claim(kind="created", subject=f"f{i}.txt", via="text",
                        session_id="s", agent="a") for i in range(90)]
    out = render_text(res, Style(False))
    assert "… and 10 more (use --json)" in out


# ---------------------------------------------------------------- json


def test_render_json_roundtrip():
    doc = json.loads(render_json(_result()))
    assert doc["tool"] == "agenttrueup"
    assert doc["version"]
    assert doc["stats"]["findings_by_severity"]["critical"] == 1
    assert len(doc["findings"]) == 3
    assert len(doc["claims"]) == 3


# ---------------------------------------------------------------- sarif


def test_render_sarif_structure():
    doc = json.loads(render_sarif(_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "agenttrueup"
    # rules deduped: 3 findings with distinct (category,title) -> 3 rules
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == 3


def test_render_sarif_level_mapping():
    doc = json.loads(render_sarif(_result()))
    levels = {r["message"]["text"][:20]: r["level"] for r in doc["runs"][0]["results"]}
    assert any(v == "error" for v in levels.values())   # critical/high
    assert any(v == "note" for v in levels.values())    # low


def test_render_sarif_fingerprints_stable():
    doc1 = json.loads(render_sarif(_result()))
    doc2 = json.loads(render_sarif(_result()))
    f1 = [r["partialFingerprints"]["agenttrueup/v1"] for r in doc1["runs"][0]["results"]]
    f2 = [r["partialFingerprints"]["agenttrueup/v1"] for r in doc2["runs"][0]["results"]]
    assert f1 == f2


def test_render_sarif_locations_only_for_paths():
    doc = json.loads(render_sarif(_result()))
    by_fp = {r["partialFingerprints"]["agenttrueup/v1"]: r for r in doc["runs"][0]["results"]}
    # 'session sess_abc' where -> no location
    sess_res = [r for r in doc["runs"][0]["results"]
                if "data-bearing" in r["message"]["text"]][0]
    assert "locations" not in sess_res
    # path where -> artifactLocation
    path_res = by_fp["residue:backup litter"]
    assert path_res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("/proj")
