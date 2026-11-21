"""Discovery of local AI coding agent session stores (read-only)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Store:
    agent: str      # claude | codex | zcode | generic
    kind: str       # claude_projects | codex_sessions | zcode_rollout | zcode_artifacts | generic_dir
    root: Path
    label: str

    def to_dict(self) -> dict:
        return {"agent": self.agent, "kind": self.kind, "root": str(self.root),
                "label": self.label, "exists": self.root.exists()}


def _home() -> Path:
    return Path.home()


def candidate_stores() -> list[Store]:
    """All stores agenttrueup knows how to look for (present or not)."""
    h = _home()
    return [
        Store("claude", "claude_projects", h / ".claude" / "projects", "Claude Code (~/.claude/projects)"),
        Store("codex", "codex_sessions", h / ".codex" / "sessions", "Codex CLI (~/.codex/sessions)"),
        Store("zcode", "zcode_rollout", h / ".zcode" / "cli" / "rollout", "ZCode transcripts (~/.zcode/cli/rollout)"),
        Store("zcode", "zcode_artifacts", h / ".zcode" / "cli" / "artifacts",
              "ZCode file-op artifacts (~/.zcode/cli/artifacts)"),
        Store("generic", "generic_dir", h / ".gemini" / "tmp", "Gemini CLI (best effort)"),
        Store("generic", "generic_dir", h / ".config" / "goose" / "sessions", "Goose (best effort)"),
        Store("generic", "generic_dir", h / ".local" / "share" / "opencode", "OpenCode (best effort)"),
        Store("generic", "generic_dir", h / ".qwen" / "projects", "Qwen Code (best effort)"),
    ]


def discover() -> list[Store]:
    """Stores that actually exist on this machine."""
    return [s for s in candidate_stores() if s.root.exists()]


def sniff_file(path: Path) -> str:
    """Guess which agent produced a transcript file, from its first line."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for _ in range(5):
                line = fh.readline()
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(obj, dict):
                    continue
                if obj.get("type") == "session_meta" or (
                        isinstance(obj.get("payload"), dict) and obj["payload"].get("session_id")):
                    return "codex"
                if obj.get("type") == "model_io" or str(obj.get("sessionId", "")).startswith(("sess_", "session_")):
                    return "zcode"
                if ("sessionId" in obj and "cwd" in obj) or ("message" in obj and "sessionId" in obj):
                    return "claude"
                if "toolCallId" in obj or "toolName" in obj:
                    return "zcode_artifact"
                return "generic"
    except OSError:
        pass
    return "generic"
