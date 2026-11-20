# agenttrueup (`trueup`)

**Trust, but reconcile.** Verify what your AI coding agent *said* against what your
filesystem, git state and dependency manifests *actually show* — and flag what it
left behind.

**信任，但要对账。** 把 AI 编码智能体“说它做过的事”与文件系统、git 状态、依赖清单里的
“实际发生的事”逐条核对，并报告它留下的残留物。

100% local · read-only · zero dependencies (pure Python stdlib) · redacted output by default

---

## Why this exists

AI coding agents now run with alarming autonomy, and 2026 research keeps confirming
the trust gap:

- Claude Code's "don't ask again" approvals **stored secrets in plaintext** in
  `settings.local.json` — Apiiro found **2,539 real secrets across 1,994 public GitHub
  repos** ([Apiiro, Nov 2026](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again),
  [CSA research note, Nov 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-claude-code-settings-secret-leak-20261108)).
- Agents routinely **claim** work ("deleted the key file", "installed the dependency",
  "tests pass") that the filesystem does not confirm. Existing tools tell you *what
  the agent did* — none of them reconcile *what it said* with *what is true now*.

`trueup` closes that gap. It parses the session transcripts your agents already write
to disk, extracts claims and risky actions, and checks each one against reality.

## What it checks

| Check | Meaning |
|---|---|
| **Claims ledger** | Every "created / edited / deleted / installed X" claim gets a verdict: ✓ verified against disk · ✗ contradicted by disk · ○ unverifiable |
| **Secrets exposure** | API keys, tokens, private-key blocks, credential-bearing URLs inside commands, messages and written-file snapshots — **shown redacted** (kind + sha256 fingerprint), `--reveal` to see raw |
| **Dangerous commands** | `rm -rf /`, `curl \| sh`, force pushes, `git reset --hard`, `chmod -R 777`, `dd of=/dev/…`, history wiping, DB `DROP` … severity-graded |
| **Exfiltration signals** | Requests to webhook.site / Discord / Telegram-bot / request-bin style endpoints, or any data-bearing upload — flagged **critical** |
| **Settings leak** | Secrets persisted inside Claude Code permission files (the documented 2026 leak pattern) |
| **Residue** | Agent-created files still uncommitted, editor/backup litter (`.bak`, `.orig`, …) |

Plus an **MCP server mode** (`trueup mcp`): your *current* agent can call
`trueup_scan` / `trueup_doctor` as MCP tools and self-audit — zero dependencies,
stdio JSON-RPC.

Verification is deterministic — no LLM, no network, no judgment calls you can't audit:

- *deleted* claim → does the file **still exist**? → ✗ high
- *created* claim → does the file exist? missing → ✗ low (temporary/scratch paths are expected and excluded)
- *edited* claim → does the file exist, and does its mtime postdate the session?
- ZCode sessions: the artifact store records **exact before/after content** — trueup
  re-reads the file and compares byte-for-byte
- *installed* claim → is the package recorded in `package.json` / `pyproject.toml` /
  `requirements*.txt` / `go.mod` / `Cargo.toml` / `Gemfile`? → ✗ high if missing

## Quick start

Requires Python 3.11+ (stdlib only — no runtime dependencies).

```bash
# any of these install routes
pip install agenttrueup            # from PyPI (once published)
pipx install agenttrueup           # isolated CLI install
uv tool install agenttrueup        # uv users
pip install .                      # from a clone

python -m agenttrueup doctor       # or run without installing at all
```

**Try it in 30 seconds** — audit the synthetic demo shipped in this repo
(synthetic data, no real credentials):

```bash
trueup scan --only examples/demo-claude-session.jsonl
```

Then audit your real machine (read-only):

```bash
trueup doctor          # which agent stores were detected?
trueup scan            # audit every detected store
trueup scan --since 7d --agent claude,codex
trueup scan --json     # machine-readable
trueup scan --sarif    # SARIF 2.1.0 for GitHub code scanning
trueup scan --fail-on high && echo "clean"   # CI gate (exit 1 if ≥ high)
trueup mcp             # MCP server: agents self-audit via tools/call
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` (default `high`) · `2` usage error.

Full command reference: [docs/USAGE.md](docs/USAGE.md) · architecture & how to
add an agent parser: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · planned
features: [docs/ROADMAP.md](docs/ROADMAP.md) · runnable demo: [examples/](examples/).

### Sample output (real run, secrets redacted)

```
trueup — trust, but reconcile
scanned 3 store(s), 35 session(s), 762 event(s) in 1.15s

FINDINGS (52)   critical:1  high:5  medium:1  low:45

 [CRIT] secret  private_key_block exposed in agent session
        private_key_block — sha256:8bcac7908eb9 (use --reveal to see it)
        at ~/.zcode/cli/rollout/model-io-session_….jsonl   [zcode · session_55259fc0f5]
        |     hits = find_secrets("<private_key_block:8bcac7908eb9>")
        → Rotate this credential and scrub the transcript.

CLAIMS LEDGER (276)   ✓ 227 verified   ✗ 45 failed   ○ 4 unverifiable
  ✗ created   …/workspace/default/daily-news/2026-11-05.txt — claimed created but the file is missing now   [zcode tool]
  ✓ created   …/style.css — content on disk matches what the tool wrote   [zcode artifact]
  ○ installed pypi:torch — no dependency manifest found near the session project   [codex command]
```

## Supported agents

| Agent | Source | Coverage |
|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` | full (commands, tools, messages) |
| Codex CLI | `~/.codex/sessions/**/*.jsonl` | full incl. `apply_patch` file ops |
| ZCode | `~/.zcode/cli/rollout/*.jsonl` + `~/.zcode/cli/artifacts/` | full incl. byte-exact write verification |
| Gemini CLI / Goose / OpenCode / Qwen | generic best-effort harvest | commands/messages basics |
| Anything else | pass files/dirs to `trueup scan PATH` | generic sniffing |

## How it differs from related tools

| Tool | What it does | What trueup adds |
|---|---|---|
| [coding_agent_session_search](https://github.com/dicklesworthstone/coding_agent_session_search) | search across 30+ agent transcript stores | not verification — trueup *reconciles claims vs reality* |
| [ranwhat](https://github.com/MatijaMiki/ranwhat), [sessionguard](https://github.com/sessionguard/sessionguard) | post-session audit of *what ran* | trueup also checks *whether what the agent said matches what ran and what's on disk* |
| [trustbut](https://github.com/isAlmogK/trustbut), [writeguard](https://github.com/brokenbartender/writeguard) | verify claimed edits (single agent, hash-based) | trueup verifies deleted/created/installed claims, residue, secrets and exfil — multi-agent |
| [AgentLint](https://github.com/agentlint/agentlint) | lints CLAUDE.md/AGENTS.md quality | different layer: instruction files, not session behavior |
| [gitleaks](https://github.com/gitleaks/gitleaks) | scans repo *files* for secrets | trueup scans *transcripts* — secrets that only ever existed inside a session (commands, tool outputs) never touch repo files |

## Limitations (honest)

- Claims extracted from natural language are conservative (quoted/backticked path-like
  subjects only); "tests pass"-style claims are listed as unverifiable, never faked.
- Verification is point-in-time: a file deleted *after* the session looks like "missing".
- Generic (non-Claude/Codex/ZCode) parsing is best-effort string harvesting.
- Heuristics can produce false positives/negatives — findings are leads, not verdicts.

## Privacy & safety

- Reads transcripts under your home directory and `paths` you pass; **writes nothing**
  except its own stdout. No network access, no telemetry.
- Secrets are redacted in every output mode (text/JSON/SARIF) by default; `--reveal`
  exists for when *you* need the raw value.

## Development

```bash
python -m pytest tests/          # 47 tests, no network needed
```

CI runs the suite on Ubuntu / macOS / Windows × Python 3.11–3.13
([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## License

MIT — see [LICENSE](LICENSE).
