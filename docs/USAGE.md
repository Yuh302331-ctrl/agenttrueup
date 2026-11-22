# Usage reference

`trueup` has two subcommands: `doctor` (what can I see?) and `scan` (audit it).

## doctor

```bash
trueup doctor          # human-readable
trueup doctor --json   # machine-readable
```

Lists every agent store agenttrueup knows about and whether it exists on this
machine, plus file counts. Use this first if a scan finds "0 sessions".

## scan

```bash
trueup scan [PATHS...] [options]
```

| Option | Meaning |
|---|---|
| `PATHS...` | extra transcript files or directories (JSONL/JSON), in addition to auto-detected stores |
| `--only` | audit **only** the given paths, ignore auto-detected stores |
| `--agent a,b` | restrict to agents: `claude`, `codex`, `zcode`, `gemini`, `goose`, `opencode`, `qwen` |
| `--since 7d` | only sessions updated after this: `24h`, `7d`, `2w`, `3m`, or `2026-01-31` |
| `--json` | machine-readable JSON (all data, still redacted) |
| `--sarif` | SARIF 2.1.0 (GitHub code scanning / IDE ingestion) |
| `--fail-on LEVEL` | exit `1` when findings ≥ LEVEL; LEVEL ∈ `critical/high/medium/low/info/never` (default `high`) |
| `--reveal` | show raw secret values instead of `<kind:sha256>` placeholders |
| `--no-color` | disable ANSI colors (auto-disabled when output is not a TTY) |
| `-v, --verbose` | progress per store on stderr |

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` usage error.

## mcp — server mode for agents

`trueup mcp` runs agenttrueup as an **MCP (Model Context Protocol) stdio
server** so your current coding agent can audit sessions itself:

- tools: `trueup_scan` (args: `paths[]`, `only_paths`, `agents[]`, `since`,
  `fail_on`) and `trueup_doctor`
- results are the same redacted JSON the CLI produces; when findings reach
  `fail_on` severity the tool result is marked `isError` so the agent notices

Register it with an MCP client, e.g. Claude Code:

```bash
claude mcp add trueup -- trueup mcp
```

or a generic JSON config:

```json
{ "mcpServers": { "trueup": { "command": "trueup", "args": ["mcp"] } } }
```

Raw protocol exchange looks like:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"trueup_scan","arguments":{"since":"7d","fail_on":"high"}}}
```

## Recipes

Audit everything from the last two weeks, only Claude + Codex:

```bash
trueup scan --since 2w --agent claude,codex
```

On GitHub Actions, write a SARIF report and fail the job on high or critical findings.

```yaml
- name: trueup audit
  run: |
    python -m pip install "agenttrueup @ git+https://github.com/Yuh302331-ctrl/agenttrueup.git"
    trueup scan --sarif --fail-on high > trueup.sarif
  continue-on-error: false
```

Audit one folder of transcripts you were handed, nothing else:

```bash
trueup scan --only ~/Downloads/agent-logs/
```

Inspect a single session file:

```bash
trueup scan --only ~/.codex/sessions/2026/11/20/rollout-2026-11-20T09-00-00-….jsonl
```

See raw secret values (only when YOU need them; the default never prints them):

```bash
trueup scan --only session.jsonl --reveal --json | jq '.findings'
```

30-second demo (synthetic data shipped in the repo):

```bash
trueup scan --only examples/demo-claude-session.jsonl
```

## Interpreting the claims ledger

| Status | Meaning |
|---|---|
| `✓ ok` | claim confirmed against disk/manifests (details say how) |
| `✗ failed` | claim contradicted by current reality — see the paired finding |
| `○ unverifiable` | path could not be resolved, or no manifest exists to check |

"created but missing" on temporary/scratch paths is treated as expected churn
(`ok`), not a failure.

## Troubleshooting

- **"scanned 0 store(s)"** — run `trueup doctor`; your agent may store sessions
  elsewhere. Pass the directory explicitly: `trueup scan --only ~/.claude/projects`.
- **Python < 3.11** — not supported (tomllib is required). Use `uv python install 3.12`.
- **Weird paths like `/nonexistent-dir` on Windows in Git Bash** — MSYS rewrites
  leading slashes; quote Windows paths (`trueup scan "C:\\logs\\x.jsonl"`).
- **Secrets flagged in YOUR OWN old sessions** — that is the tool working: those
  values really are in the transcripts. Rotate + scrub; see README limitations.
