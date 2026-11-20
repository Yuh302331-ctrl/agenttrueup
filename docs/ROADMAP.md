# Roadmap & optimization ideas

Recorded during the 0.2.0 polish cycle — ideas in rough priority order.
Nothing here is committed; each item needs a design pass.

## P1 — higher-value verification

- **MCP server mode** (`trueup mcp`): expose `scan`/`get_claim_history` as MCP
  tools so the *current* agent can self-audit ("list the claims you made today
  that failed verification"). Stdio JSON-RPC, zero deps, ~150 lines.
- **Claude Code hook integration**: a `PreToolUse` hook script that appends
  claims to a sidecar log — enables verifying claims *at completion time*,
  not just after the fact.
- **Secret allowlist config** (`~/.config/agenttrueup/allow.toml`): fingerprint
  allowlists so known-safe values (e.g. AWS docs example keys) stop firing.
- **Diff-vs-git-HEAD verification**: for `edited` claims in git repos, check
  whether the claimed region actually differs from HEAD instead of relying on
  mtime only.

## P2 — coverage

- **More parsers with real ground truth**: Gemini CLI (`~/.gemini/tmp`), Aider
  (`.aider.chat.history.md` markdown), Cursor (sqlite `state.vscdb`), Windsurf,
  Copilot CLI, Crush, OpenCode's real format. Each needs a captured schema first.
- **Windows Terminal/PowerShell install docs** (`pipx`, `uv tool install`).

## P3 — UX & performance

- **SQLite cache** for very large stores (index by file mtime; incremental scan).
  Current full scan of 3 stores / 36 sessions runs in ~1.2 s, so only worth it
  past ~10k sessions.
- **`watch` mode**: rescan every N minutes, surface *new* critical/high findings
  (notification hook).
- **HTML report** (`--html report.html`): severity heatmap per project/agent.
- **`show <session>` command**: pretty-print one session transcript with
  findings inline.

## Known limitations (documented, accepted for 0.2.0)

- Danger/secret regexes run on command text, so quoted strings that merely
  *mention* a dangerous pattern can fire (e.g. `grep "rm -rf"`). Precision would
  require shell parsing; flagged as future work.
- Text-claim extraction is conservative by design (backticked/quoted path-like
  tokens only). Recall could improve with an LLM pass — explicitly out of scope
  for a deterministic, offline tool.
- Deleted-claim verification is point-in-time: a file removed *after* the
  session reads as "confirmed gone".
