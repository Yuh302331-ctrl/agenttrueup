"""Tests for the zero-dependency MCP stdio server."""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
EXAMPLES = REPO_ROOT / "examples"

from agenttrueup.mcp import serve


class FakeStdin:
    def __init__(self, lines):
        self._lines = lines

    def __iter__(self):
        return iter(self._lines)


class FakeStdout:
    def __init__(self):
        self.chunks = []

    def write(self, s):
        self.chunks.append(s)

    def flush(self):
        pass

    @property
    def messages(self):
        return [json.loads(c) for c in self.chunks if c.strip()]


def _rpc(rid, method, params=None):
    req = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        req["params"] = params
    return json.dumps(req)


def test_mcp_handshake_and_tools():
    out = FakeStdout()
    lines = [
        _rpc(1, "initialize", {"protocolVersion": "2024-11-05"}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        _rpc(2, "tools/list"),
        _rpc(3, "ping"),
    ]
    serve(FakeStdin(lines), out)
    msgs = out.messages
    init = next(m for m in msgs if m.get("id") == 1)
    assert init["result"]["serverInfo"]["name"] == "agenttrueup"
    tools = next(m for m in msgs if m.get("id") == 2)["result"]["tools"]
    assert {t["name"] for t in tools} == {"trueup_scan", "trueup_doctor"}
    # notification produced no response; ping answered
    assert all(m.get("id") != "notifications/initialized" for m in msgs)
    assert next(m for m in msgs if m.get("id") == 3)["result"] == {}


def test_mcp_scan_tool_on_demo():
    out = FakeStdout()
    lines = [
        _rpc(1, "tools/call", {
            "name": "trueup_scan",
            "arguments": {"paths": [str(EXAMPLES / "demo-claude-session.jsonl")],
                          "only_paths": True, "fail_on": "high"},
        }),
    ]
    serve(FakeStdin(lines), out)
    resp = out.messages[0]["result"]
    doc = json.loads(resp["content"][0]["text"])
    assert doc["summary"]["findings"] >= 5
    assert any(f["category"] == "exfil" for f in doc["findings"])
    # fail_on=high + critical/high present -> isError
    assert resp["isError"] is True
    blob = json.dumps(doc, ensure_ascii=False)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob, "MCP output must stay redacted"


def test_mcp_error_paths():
    out = FakeStdout()
    lines = [
        _rpc(1, "no/such/method"),
        _rpc(2, "tools/call", {"name": "nope"}),
        "not json at all",
    ]
    serve(FakeStdin(lines), out)
    msgs = out.messages
    err1 = next(m for m in msgs if m.get("id") == 1)
    assert err1["error"]["code"] == -32601
    err2 = next(m for m in msgs if m.get("id") == 2)
    assert err2["error"]["code"] == -32602
    assert len(msgs) == 2  # garbage line ignored, no crash


def test_mcp_subprocess_end_to_end():
    """Spawn the real CLI as an MCP server and speak protocol to it."""
    p = subprocess.run(
        [sys.executable, "-m", "agenttrueup", "mcp"],
        input="\n".join([
            _rpc(1, "initialize", {}),
            _rpc(2, "tools/call", {"name": "trueup_doctor", "arguments": {}}),
        ]) + "\n",
        capture_output=True, text=True, timeout=120,
        env={**__import__("os").environ, "PYTHONPATH": str(SRC)})
    lines = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    assert lines[0]["result"]["serverInfo"]["version"]
    doc = json.loads(lines[1]["result"]["content"][0]["text"])
    assert "stores" in doc
