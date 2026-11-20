import json

from agenttrueup.models import Claim, Session
from agenttrueup.verify import (find_manifests, manifest_contains,
                                residue_findings, verify_claims)


def _sess(project):
    return Session(agent="test", session_id="s", source_file="f", project=str(project),
                   started="2026-11-20T10:00:00Z", ended="2026-11-20T11:00:00Z")


def test_manifests_and_contains(tmp_path):
    proj = tmp_path / "p"
    (proj / "sub").mkdir(parents=True)
    (proj / "package.json").write_text(json.dumps(
        {"dependencies": {"react": "^18"}}), encoding="utf-8")
    (proj / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests>=2", "flask"]\n', encoding="utf-8")
    (proj / "sub" / "requirements.txt").write_text("numpy\n", encoding="utf-8")
    ms = find_manifests(str(proj))
    names = {m.name for m in ms}
    assert {"package.json", "pyproject.toml", "requirements.txt"} <= names
    pj = next(m for m in ms if m.name == "package.json")
    assert manifest_contains(pj, "react") and not manifest_contains(pj, "vue")
    py = next(m for m in ms if m.name == "pyproject.toml")
    assert manifest_contains(py, "requests") and not manifest_contains(py, "django")
    rq = next(m for m in ms if m.name == "requirements.txt")
    assert manifest_contains(rq, "numpy")


def test_deleted_claim_verified(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    gone = proj / "old.txt"
    here = proj / "here.txt"
    here.write_text("x", encoding="utf-8")
    s = _sess(proj)
    claims = [
        Claim(kind="deleted", subject="old.txt", via="command", session_id="s", agent="t"),
        Claim(kind="deleted", subject="here.txt", via="command", session_id="s", agent="t"),
    ]
    findings = verify_claims(s, claims)
    by_subject = {c.subject: c for c in claims}
    assert by_subject["old.txt"].status == "ok"
    assert by_subject["here.txt"].status == "failed"
    assert findings and findings[0].category == "claim_failed"


def test_created_missing_claim_fails(tmp_path, monkeypatch):
    import agenttrueup.verify as verify
    monkeypatch.setattr(verify, "TEMP_PATH_MARKERS", ())
    proj = tmp_path / "p"
    proj.mkdir()
    s = _sess(proj)
    claims = [Claim(kind="created", subject=str(proj / "nope.md"), via="tool",
                    session_id="s", agent="t")]
    findings = verify_claims(s, claims)
    assert claims[0].status == "failed"
    assert findings[0].severity == "low"


def test_created_missing_temp_path_counts_as_ok(tmp_path):
    # tmp_path lives under pytest-of-* — the built-in ephemeral filter
    # must treat scratch paths as expected-to-disappear, not failures
    proj = tmp_path / "p"
    proj.mkdir()
    s = _sess(proj)
    claims = [Claim(kind="created", subject=str(proj / "scratch.md"), via="tool",
                    session_id="s", agent="t")]
    verify_claims(s, claims)
    assert claims[0].status == "ok"
    assert "temporary" in claims[0].detail


def test_installed_claim_against_manifest(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests"]\n', encoding="utf-8")
    s = _sess(proj)
    claims = [
        Claim(kind="installed", subject="pypi:requests", via="command", session_id="s", agent="t"),
        Claim(kind="installed", subject="pypi:torch", via="command", session_id="s", agent="t"),
    ]
    findings = verify_claims(s, claims)
    by_subject = {c.subject: c for c in claims}
    assert by_subject["pypi:requests"].status == "ok"
    assert by_subject["pypi:torch"].status == "failed"
    assert any("manifest" in f.title for f in findings)


def test_residue_untracked(git_repo):
    (git_repo / "agent_new_file.txt").write_text("leftover", encoding="utf-8")
    s = Session(agent="test", session_id="s", source_file="f", project=str(git_repo))
    s.events = []
    from agenttrueup.models import Event
    s.events.append(Event("file_write", path=str(git_repo / "agent_new_file.txt")))
    findings = residue_findings(s)
    assert any(f.category == "residue" and "uncommitted" in f.title for f in findings)
    # tracked + committed files must NOT be flagged
    (git_repo / "tracked.txt").write_text("one\n", encoding="utf-8")
    s2 = Session(agent="test", session_id="s2", source_file="f", project=str(git_repo))
    from agenttrueup.models import Event
    s2.events.append(Event("file_write", path=str(git_repo / "tracked.txt")))
    assert residue_findings(s2) == []
