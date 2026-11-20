from agenttrueup.parsers import (parse_claude_file, parse_codex_file,
                                 parse_zcode_artifacts_dir, parse_zcode_rollout)


def test_parse_claude_file(claude_store):
    f = next(claude_store["root"].rglob("*.jsonl"))
    s = parse_claude_file(f)
    assert s.agent == "claude"
    assert s.project == str(claude_store["proj"])
    kinds = {e.kind for e in s.events}
    assert {"user", "assistant", "command", "file_write"} <= kinds
    cmds = [e.text for e in s.events if e.kind == "command"]
    assert any("webhook.site" in c for c in cmds)
    assert any("npm install left-pad" in c for c in cmds)
    writes = [e.path for e in s.events if e.kind == "file_write"]
    assert any(w.endswith("report.md") for w in writes)


def test_parse_codex_file(codex_store):
    s = parse_codex_file(codex_store["file"])
    assert s.agent == "codex"
    assert s.project == str(codex_store["proj"])
    assert s.session_id == "cdx-9"
    cmds = [e.text for e in s.events if e.kind == "command"]
    assert any("rm -rf /" in c for c in cmds)
    assert any("pip install torch" in c for c in cmds)
    writes = [e.path for e in s.events if e.kind == "file_write"]
    assert any(w.endswith("notes.txt") for w in writes)
    texts = [e.text for e in s.events if e.kind == "assistant"]
    assert any("removed /tmp/old.log" in t for t in texts)


def test_parse_zcode_rollout_and_artifacts(zcode_store):
    sessions = parse_zcode_rollout(zcode_store["rollout"])
    assert len(sessions) == 1
    s = sessions[0]
    assert s.agent == "zcode"
    assert s.session_id == "sess_5f0f"
    assert any(e.kind == "command" and "--force" in e.text for e in s.events)
    assert any(e.kind == "assistant" for e in s.events)

    art = parse_zcode_artifacts_dir(zcode_store["artifacts"])
    assert art is not None
    assert any(e.kind == "file_write" and e.path.endswith("style.css")
               for e in art.events)
    assert art.artifacts and art.artifacts[0]["after"].startswith("body{")
