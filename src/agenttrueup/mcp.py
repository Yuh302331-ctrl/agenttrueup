"""Minimal MCP (Model Context Protocol) stdio server for agenttrueup.

Lets the *current* AI coding agent audit itself or past sessions through the
standard MCP tool protocol, with zero third-party dependencies (JSON-RPC 2.0
over stdio lines).  All scan results are redacted exactly like the CLI.

Usage:  trueup mcp        (or: python -m agenttrueup mcp)
"""

from __future__ import annotations

import json
import sys

from . import __version__
from .models import sev_at_least
from .scan import scan as run_scan

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "trueup_scan",
        "description": (
            "Audit local AI coding agent sessions: verify agent claims "
            "(deleted/created/edited/installed) against the filesystem, list "
            "secret exposures (redacted), dangerous commands, exfiltration "
            "signals and leftover residue. Read-only, offline."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Extra transcript files/dirs to audit.",
                },
                "only_paths": {
                    "type": "boolean",
                    "description": "Audit ONLY the given paths, skip auto-detected stores.",
                },
                "agents": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Agent filter: claude, codex, zcode, gemini, goose, opencode, qwen.",
                },
                "since": {
                    "type": "string",
                    "description": "Only sessions updated after this: 7d, 24h, 2w, or ISO date.",
                },
                "fail_on": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info", "never"],
                    "description": "Severity floor that sets isError=true on the result.",
                },
            },
        },
    },
    {
        "name": "trueup_doctor",
        "description": "Show which agent session stores exist on this machine.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _tool_scan(args: dict) -> tuple[str, bool]:
    res = run_scan(
        paths=[str(p) for p in (args.get("paths") or [])],
        agents=[str(a) for a in (args.get("agents") or [])],
        since=str(args.get("since") or ""),
        reveal=False,
        verbose=False,
        only_paths=bool(args.get("only_paths")),
    )
    doc = {
        "summary": {
            "sessions": res.stats.get("sessions", 0),
            "events": res.stats.get("events", 0),
            "findings": res.stats.get("findings", 0),
            "findings_by_severity": res.stats.get("findings_by_severity", {}),
            "claims": res.stats.get("claims", 0),
            "claims_failed": res.stats.get("claims_failed", 0),
            "warnings": res.stats.get("warnings", []),
        },
        "findings": [f.to_dict() for f in res.findings],
        "claims": [c.to_dict() for c in res.claims
                   if c.status != "ok"][:200],
        "stats": res.stats,
    }
    fail_on = str(args.get("fail_on") or "never").lower()
    bad = fail_on != "never" and any(
        sev_at_least(f.severity, fail_on) for f in res.findings)
    return json.dumps(doc, ensure_ascii=False, indent=2), bool(bad)


def _tool_doctor(_args: dict) -> tuple[str, bool]:
    from .stores import candidate_stores
    doc = {"version": __version__,
           "stores": [s.to_dict() for s in candidate_stores()]}
    return json.dumps(doc, ensure_ascii=False, indent=2), False


def _dispatch(req: dict) -> dict | None:
    method = req.get("method")
    rid = req.get("id")
    is_notification = "id" not in req
    try:
        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agenttrueup", "version": __version__},
            }
        elif method == "notifications/initialized" or method.startswith("notifications/"):
            return None  # notifications get no response
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = (req.get("params") or {}).get("name")
            args = (req.get("params") or {}).get("arguments") or {}
            if name == "trueup_scan":
                text, bad = _tool_scan(args)
                result = {"content": [{"type": "text", "text": text}],
                          "isError": bad}
            elif name == "trueup_doctor":
                text, _ = _tool_doctor(args)
                result = {"content": [{"type": "text", "text": text}],
                          "isError": False}
            else:
                return {"jsonrpc": "2.0", "id": rid,
                        "error": {"code": -32602,
                                  "message": f"unknown tool: {name}"}}
        elif method == "resources/list":
            result = {"resources": []}
        else:
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601,
                              "message": f"method not found: {method}"}}
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    except Exception as e:  # a failed tool call must not kill the server
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32603, "message": f"internal error: {e}"}}


def serve(stdin=None, stdout=None) -> int:
    """JSON-RPC loop.  Injectable streams make the server unit-testable."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        resp = _dispatch(req)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0
