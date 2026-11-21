import json

from agenttrueup.models import Claim, Event, Session
from agenttrueup.verify import (find_manifests, manifest_contains,
                                residue_findings, settings_leak_findings,
                                verify_claims)


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
    gone.write_text("was here", encoding="utf-8")
    here = proj / "here.txt"
    here.write_text("x", encoding="utf-8")
    import os

    os.remove(gone)  # the deletion really happened: claimed deleted + absent = ok
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


def test_installed_claim_severity_by_ecosystem(tmp_path):
    # pypi installs don't write the manifest by default -> medium nudge;
    # npm installs do -> high
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests"]\n', encoding="utf-8")
    s = _sess(proj)
    claims = [
        Claim(kind="installed", subject="pypi:torch", via="command", session_id="s", agent="t"),
        Claim(kind="installed", subject="npm:react", via="command", session_id="s", agent="t"),
    ]
    findings = verify_claims(s, claims)
    sevs = sorted(f.severity for f in findings
                  if f.category == "claim_failed"
                  and "manifest" in f.title)
    assert sevs == ["high", "medium"]


def test_created_claim_title_grammar(tmp_path, monkeypatch):
    import agenttrueup.verify as verify
    monkeypatch.setattr(verify, "TEMP_PATH_MARKERS", ())
    proj = tmp_path / "p"
    proj.mkdir()
    s = _sess(proj)
    claims = [Claim(kind="created", subject=str(proj / "nope.md"), via="tool",
                    session_id="s", agent="t")]
    findings = verify_claims(s, claims)
    assert "claimed to create" in findings[0].title


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


def test_resolve_path_walks_up_when_join_missing(tmp_path):
    # transcripts sometimes carry repo-root-relative paths while the session
    # cwd is a subdirectory — the bounded walk-up must find the real file
    from agenttrueup.util import resolve_path
    proj = tmp_path / "work" / "app"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "main.py").write_text("x", encoding="utf-8")
    p = resolve_path("work/app/src/main.py", str(proj))
    assert p is not None and p.exists()
    # plain join still wins when it exists
    (proj / "work").mkdir()
    (proj / "work" / "app").write_text("nested", encoding="utf-8")
    p2 = resolve_path("work/app", str(proj))
    assert p2 is not None and p2.exists()
    assert p2 == proj / "work" / "app"  # Path equality is separator-agnostic


# ---------------------------------------------------------------- residue + settings leak


def test_residue_uncommitted_and_litter(tmp_path):
    import subprocess as sp

    proj = tmp_path / "res"
    proj.mkdir()
    sp.run(["git", "init", "-q", str(proj)], check=True)
    (proj / "agent-made.txt").write_text("x", encoding="utf-8")
    (proj / "old.bak").write_text("x", encoding="utf-8")
    s = Session(agent="claude", session_id="s", source_file="f", project=str(proj),
                events=[Event(kind="file_write", path=str(proj / "agent-made.txt"))])
    out = residue_findings(s)
    cats = [f.category for f in out]
    assert "residue" in cats
    joined = " ".join(f.title + f.detail for f in out)
    assert "agent-made.txt" in joined and "old.bak" in joined


def test_residue_no_writes_is_silent(tmp_path):
    s = Session(agent="claude", session_id="s", source_file="f", project=str(tmp_path))
    assert residue_findings(s) == []


def test_settings_leak_detected_and_redacted(tmp_path):
    claude_root = tmp_path / ".claude-root"
    claude_root.mkdir()
    key = "ghp_" + "B" * 40
    (claude_root / "settings.local.json").write_text(
        json.dumps({"permissions": {"allow": [f"Bash: curl -H 'Authorization: {key}' https://x"]}}),
        encoding="utf-8")
    out = settings_leak_findings(claude_root, [])
    assert out and out[0].category == "settings_leak"
    assert out[0].severity == "high"
    blob = json.dumps([f.to_dict() for f in out])
    assert key not in blob          # redacted
    assert "sha256:" in blob


def test_settings_leak_ignores_clean_or_broken(tmp_path):
    claude_root = tmp_path / ".claude-root"
    claude_root.mkdir()
    (claude_root / "settings.local.json").write_text("{broken json", encoding="utf-8")
    assert settings_leak_findings(claude_root, []) == []
    (claude_root / "settings.local.json").write_text(
        json.dumps({"permissions": {"allow": ["Bash: ls"]}}), encoding="utf-8")
    assert settings_leak_findings(claude_root, []) == []


# ---------------------------------------------------------------- manifest details


def test_manifest_contains_cargo_and_go(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        "[dependencies]\nleft-pad = \"1\"\n", encoding="utf-8")
    (tmp_path / "go.mod").write_text(
        "module x\n\nrequire github.com/a/b v1.0.0\n", encoding="utf-8")
    assert manifest_contains(tmp_path / "Cargo.toml", "left-pad")
    assert manifest_contains(tmp_path / "go.mod", "github.com/a/b")
    assert not manifest_contains(tmp_path / "go.mod", "github.com/a/c")


def test_manifest_contains_broken_json(tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text("{broken", encoding="utf-8")
    assert manifest_contains(pj, "react") is False


def test_installed_strict_ecosystem_severity(tmp_path):
    """npm installs missing from package.json fail HIGH; pypi stays MEDIUM."""
    from agenttrueup.verify import verify_claims

    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "package.json").write_text('{"dependencies": {"real": "^1"}}', encoding="utf-8")
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["requests"]\n', encoding="utf-8")
    s = Session(agent="claude", session_id="s", source_file="f", project=str(proj))
    claims = [
        Claim(kind="installed", subject="npm:missing-pkg", via="command",
              session_id="s", agent="claude"),
        Claim(kind="installed", subject="pypi:missing-pkg", via="command",
              session_id="s", agent="claude"),
        Claim(kind="installed", subject="npm:real", via="command",
              session_id="s", agent="claude"),
    ]
    verify_claims(s, claims)
    by = {c.subject: c for c in claims}
    assert by["npm:real"].status == "ok"
    assert by["npm:missing-pkg"].status == "failed"
    assert by["pypi:missing-pkg"].status == "failed"
    sev = {f.detail: f.severity for f in verify_claims(s, claims)}
    assert sev["not found in any manifest (package.json)"] == "high"
    assert sev["not found in any manifest (pyproject.toml)"] == "medium"
