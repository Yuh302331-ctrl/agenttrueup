"""End-to-end test anchored to the shipped demo artifacts."""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"

from agenttrueup.scan import scan


def test_demo_session_produces_expected_verdicts():
    res = scan(paths=[str(EXAMPLES / "demo-claude-session.jsonl")],
               only_paths=True)
    findings = res.findings
    # 1. exfil: webhook.site POST -> critical
    assert any(f.category == "exfil" and f.severity == "critical" for f in findings)
    # 2. secret: fake AWS example key, redacted in evidence
    secrets = [f for f in findings if f.category == "secret"]
    assert secrets and all("AKIAIOSFODNN7EXAMPLE" not in (f.evidence or "")
                           for f in secrets)
    # 3. danger: curl | sh
    assert any(f.category == "danger" and "piped straight" in f.title
               for f in findings)
    # 4. claims: deleted demo-key.txt -> still exists -> failed
    del_claims = [c for c in res.claims if c.kind == "deleted"
                  and "demo-key.txt" in c.subject]
    assert del_claims and all(c.status == "failed" for c in del_claims)
    # 5. claims: installed left-pad -> not in any manifest -> failed
    inst = [c for c in res.claims if c.kind == "installed" and "left-pad" in c.subject]
    assert inst and inst[0].status == "failed"
    # 6. claims: created report.md -> missing -> failed (low)
    created = [c for c in res.claims if c.kind == "created"
               and c.subject.endswith("report.md")]
    assert created and created[0].status == "failed"
    assert any(f.severity == "low" and "report.md" in f.where for f in findings)


def test_demo_session_json_redaction():
    res = scan(paths=[str(EXAMPLES / "demo-claude-session.jsonl")],
               only_paths=True)
    doc = json.dumps(res.to_dict(), ensure_ascii=False)
    assert "AKIAIOSFODNN7EXAMPLE" not in doc
    assert "aws_access_key" in doc
