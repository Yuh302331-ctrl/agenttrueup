import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

from agenttrueup.scan import scan


def test_scan_finds_exfil_and_claims(claude_store):
    res = scan(paths=[str(claude_store["root"])], only_paths=True)
    cats = {f.category for f in res.findings}
    assert "exfil" in cats  # webhook.site
    assert any(f.severity == "critical" and f.category == "exfil" for f in res.findings)
    # claims: deleted secrets.txt (verified ok), created out/report.md (ok), installed left-pad
    claims = {(c.kind, c.subject): c for c in res.claims}
    assert ("deleted", "secrets.txt") in claims
    assert claims[("deleted", "secrets.txt")].status == "ok"
    assert any(k == "installed" and "left-pad" in s for k, s in claims)
    assert res.stats["sessions"] >= 1


def test_scan_codex_danger_and_secret(codex_store):
    res = scan(paths=[str(codex_store["file"].parent)], only_paths=True)
    titles = {f.title for f in res.findings}
    assert any("root" in t for t in titles)
    assert any(f.category == "claim_failed" for f in res.findings)  # torch not in manifest
    # "rm -rf /" is a broad target (danger finding only, no deletion claim) and
    # the unquoted "I removed /tmp/old.log" text must NOT create a claim either
    del_claims = [c for c in res.claims if c.kind == "deleted"]
    assert not del_claims, f"unexpected deletion claims: {del_claims}"


def test_scan_zcode_merge(zcode_store):
    res = scan(paths=[str(zcode_store["root"])], only_paths=True)
    assert any(s.agent == "zcode" for s in res.sessions)
    titles = {f.title for f in res.findings}
    assert any("force push" in t for t in titles)
    assert any(c.kind == "edited" and c.subject.endswith("style.css") for c in res.claims)


def test_cli_json_redacts_and_exit_code(claude_store):
    # inject a real-looking key into the session to test redaction
    root = claude_store["root"]
    f = next(root.rglob("*.jsonl"))
    rows = f.read_text(encoding="utf-8").splitlines()
    rows.append(json.dumps({
        "type": "assistant", "sessionId": "abc-1", "cwd": str(claude_store["proj"]),
        "timestamp": "2026-11-20T10:00:08Z",
        "message": {"role": "assistant", "content": [
            {"type": "text", "text": "your key is AKIAABCDEFGHIJKLMNOP"}]}}))
    f.write_text("\n".join(rows), encoding="utf-8")

    p = subprocess.run([sys.executable, "-m", "agenttrueup", "scan", "--only", str(root), "--json"],
                       capture_output=True, text=True,
                       env={**__import__("os").environ, "PYTHONPATH": str(SRC)})
    assert p.returncode == 1  # critical exfil -> fail-on high
    doc = json.loads(p.stdout)
    assert doc["stats"]["findings"] >= 1
    blob = p.stdout
    assert "AKIAABCDEFGHIJKLMNOP" not in blob  # redaction holds in JSON too
    assert "aws_access_key" in blob


def test_cli_sarif(claude_store):
    p = subprocess.run([sys.executable, "-m", "agenttrueup", "scan", "--only",
                        str(claude_store["root"]), "--sarif"],
                       capture_output=True, text=True,
                       env={**__import__("os").environ, "PYTHONPATH": str(SRC)})
    doc = json.loads(p.stdout)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]
    assert doc["runs"][0]["tool"]["driver"]["rules"]


def test_doctor_runs():
    p = subprocess.run([sys.executable, "-m", "agenttrueup", "doctor"],
                       capture_output=True, text=True,
                       env={**__import__("os").environ, "PYTHONPATH": str(SRC)})
    assert p.returncode == 0
    assert "doctor" in p.stdout
