"""Tests for R1/R2 polish fixes: install parsing, ephemeral paths, content
verification, timezone-aware merging, BOM tolerance, warnings."""

import json

from agenttrueup.extract import (_text_claims, deletion_targets,
                                  installed_packages)
from agenttrueup.models import Claim, Event, Session
from agenttrueup.parsers import merge_sessions, parse_claude_file
from agenttrueup.verify import manifest_contains, verify_claims


def _sess(project=None):
    return Session(agent="test", session_id="s", source_file="f", project=project,
                   started="2026-11-20T10:00:00Z", ended="2026-11-20T11:00:00Z")


# ---------------------------------------------------- install parsing fixes

def test_installed_packages_sudo():
    pkgs = installed_packages("sudo npm install left-pad")
    assert ("npm", "left-pad") in pkgs
    assert ("npm", "install") not in pkgs
    assert ("npm", "npm") not in pkgs


def test_installed_packages_requirements_flag():
    assert installed_packages("pip install -r requirements.txt") == []


def test_installed_packages_bare_install():
    assert installed_packages("npm i") == []
    assert ("npm", "chalk") in installed_packages("npm i chalk")


def test_installed_packages_uv_pip():
    assert ("pypi", "numpy") in installed_packages("uv pip install numpy")


def test_deletion_targets_windows_flags():
    assert deletion_targets("del /f /q report.docx") == ["report.docx"]
    assert deletion_targets("Remove-Item -Recurse -Force build") == ["build"]
    assert deletion_targets("rm /tmp/old.log") == ["/tmp/old.log"]


def test_text_install_claim_ignores_paths():
    claims = _text_claims("I added `style.css` to make it pretty.")
    assert all(kind != "installed" for kind, _ in claims)
    assert ("installed", "left-pad") in _text_claims("I installed `left-pad`.")


# ------------------------------------------------------- ephemeral deleted

def test_deleted_temp_path_still_exists_is_low(tmp_path):
    here = tmp_path / "scratch.bin"
    here.write_text("x", encoding="utf-8")
    claims = [Claim(kind="deleted", subject=str(here), via="command",
                    session_id="s", agent="t")]
    findings = verify_claims(_sess(tmp_path), claims)
    assert claims[0].status == "failed"
    assert findings[0].severity == "low"  # tmp paths are expected churn


def test_deleted_temp_path_gone_is_ok(tmp_path):
    claims = [Claim(kind="deleted", subject=str(tmp_path / "gone.tmp"), via="command",
                    session_id="s", agent="t")]
    verify_claims(_sess(tmp_path), claims)
    assert claims[0].status == "ok"


# --------------------------------------------------- content verification

def test_claude_write_content_artifact(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    target = proj / "made.md"
    target.write_text("# hello", encoding="utf-8")
    rows = [{"type": "assistant", "sessionId": "c1", "cwd": str(proj),
             "timestamp": "2026-11-20T10:00:05Z",
             "message": {"role": "assistant", "content": [
                 {"type": "tool_use", "id": "t1", "name": "Write",
                  "input": {"file_path": str(target), "content": "# hello"}}]}}]
    f = tmp_path / "claude" / "c1.jsonl"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    s = parse_claude_file(f)
    assert s.artifacts and s.artifacts[0]["after"] == "# hello"
    claims = [Claim(kind="created", subject=str(target), via="tool",
                    session_id="s.session_id", agent="claude")]
    verify_claims(s, claims)
    assert claims[0].status == "ok"
    assert "matches" in claims[0].detail


def test_claude_edit_must_contain(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    target = proj / "app.py"
    target.write_text("def main():\n    return 42\n", encoding="utf-8")
    rows = [{"type": "assistant", "sessionId": "c2", "cwd": str(proj),
             "timestamp": "2026-11-20T10:00:05Z",
             "message": {"role": "assistant", "content": [
                 {"type": "tool_use", "id": "t1", "name": "Edit",
                  "input": {"file_path": str(target), "old_string": "return 0",
                            "new_string": "return 42"}}]}}]
    f = tmp_path / "claude" / "c2.jsonl"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    s = parse_claude_file(f)
    assert s.artifacts[0]["must_contain"] == "return 42"
    claims = [Claim(kind="edited", subject=str(target), via="tool",
                    session_id="s.session_id", agent="claude")]
    verify_claims(s, claims)
    assert claims[0].status == "ok"
    assert "present" in claims[0].detail


def test_apply_patch_add_file_content(codex_store):
    from agenttrueup.parsers import parse_codex_file
    s = parse_codex_file(codex_store["file"])
    add_art = [a for a in s.artifacts if a.get("tool") == "apply_patch"]
    assert add_art and add_art[0]["after"] == "hello"


# --------------------------------------------------------------- merging

def test_merge_sessions_timezone_order():
    a = Session(agent="x", session_id="1", source_file="a", project=None,
                started="2026-11-20T09:00:00.500Z")
    b = Session(agent="x", session_id="1", source_file="b", project=None,
                started="2026-11-20T09:00:00Z")
    merged = merge_sessions([a, b])
    assert len(merged) == 1
    # .500Z is chronologically later; naive string min() would pick it wrongly
    assert merged[0].started == "2026-11-20T09:00:00Z"


def test_merge_sessions_events_and_project():
    a = Session(agent="x", session_id="1", source_file="a", project=None,
                events=[Event("command", text="ls")])
    b = Session(agent="x", session_id="1", source_file="b", project="/p",
                events=[Event("user", text="hi")])
    merged = merge_sessions([a, b])
    assert len(merged[0].events) == 2
    assert merged[0].project == "/p"


# --------------------------------------------------------------- BOM

def test_bom_tolerant_parsing(claude_store):
    f = next(claude_store["root"].rglob("*.jsonl"))
    raw = f.read_bytes()
    f.write_bytes(b"\xef\xbb\xbf" + raw)  # prepend UTF-8 BOM
    s = parse_claude_file(f)
    assert s.events, "BOM must not swallow the first line"


# --------------------------------------------------------------- manifests

def test_pyproject_dependency_groups(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    m = proj / "pyproject.toml"
    m.write_text(
        '[project]\nname = "x"\n'
        "[dependency-groups]\ndev = [\"pytest>=8\"]\n", encoding="utf-8")
    assert manifest_contains(m, "pytest")
    assert not manifest_contains(m, "django")


# --------------------------------------------------------------- scan stats

def test_scan_stats_include_agent_breakdown(claude_store):
    from agenttrueup.scan import scan
    res = scan(paths=[str(claude_store["root"])])
    assert res.stats["sessions_by_agent"].get("claude") >= 1


def test_scan_warnings_for_bad_args(claude_store, tmp_path):
    from agenttrueup.scan import scan
    res = scan(paths=[str(claude_store["root"]), str(tmp_path / "missing-dir")],
               agents=["bogus-agent"], since="not-a-date")
    warnings = res.stats["warnings"]
    assert any("--since" in w for w in warnings)
    assert any("bogus-agent" in w for w in warnings)
    assert any("path not found" in w for w in warnings)
