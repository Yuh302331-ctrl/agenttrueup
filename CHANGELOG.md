# Changelog

All notable changes to agenttrueup.

## 0.3.1 — 2026-11-22

### Added — usability
- `--min-severity` display filter: report only findings at/above a severity
  (`findings_by_severity` in stats always reflects the full scan; the
  findings list is what gets filtered). Exit codes still honor `--fail-on`.
- `doctor` now declares parsing coverage per store — `[full parsing]` for
  claude/codex/zcode, `[generic parser — best effort]` for everything else —
  with an explicit note that generic-agent results are less complete, so
  unsupported-agent users know their audit is partial.

## 0.3.0 — 2026-11-21

### Added — facts source: redhand journal integration
- **trueup now reads redhand's change journal** (`<root>/.whodunit/journal.db`,
  read-only, schema contract — no redhand dependency) when auditing claims.
  Claim verdicts upgrade from "current disk state" to "recorded event stream":
  a `deleted` claim confirmed by a journal deletion event says so (with actor
  and timestamp); a claimed deletion with no journal deletion is contradicted
  by the event stream (HIGH finding, category `claim_failed`).
- **Recreated-after-deletion detection**: a file deleted as claimed but
  created again later (by any actor) yields a MEDIUM residue finding — the
  "显示没删干净" class of confusion now has a facts-backed answer.
- Journals are auto-discovered by walking up from each session's project
  (bounded, 3 levels); `--journal PATH` adds explicit roots (repeatable,
  accepts journal.db / .whodunit dir / watched root); `--no-journal` disables.
- `stats.journals_found` reports how many journals were used; unreadable or
  unknown-schema journals degrade to a warning, never a crash.
- 13 new tests (journal contract, discovery, reconciliation, WAL concurrency,
  end-to-end scan wiring). 123 tests total, coverage 84%.

## 0.2.1 — 2026-11-21

### Fixed (detection accuracy)
- **Anthropic keys are no longer double-reported**: the `openai_key` pattern
  also matched `sk-ant-…` tokens, so one key produced both an `openai_key` and
  an `anthropic_key` finding. The openai pattern now excludes `sk-ant-`.
- **`git push -f` (short form) is now caught** by the force-push rule, which
  previously only matched `--force`.
- **Generic data-bearing requests downgraded high → medium**, and the network
  tool + payload flag must now sit in the *same* sub-command — ordinary
  `git ls-remote … | awk` pipelines and long composite lines no longer trip it.
- **Heredoc bodies are stripped before danger scanning** (`python - <<'EOF'`):
  words appearing inside written script content (e.g. a `shutdown()` call in
  code the agent wrote) no longer fire shell-danger findings.
- **Installed claims deduplicated**: "installed `left-pad`" (assistant text)
  and `npm:left-pad` (command) were two claims + two findings for one event;
  the ecosystem-prefixed claim now wins.
- **`go.mod` installs are now actually detected**: the matcher anchored the
  module path to line start, but real files read `require github.com/a/b
  v1.0.0` — every go "installed" claim failed verification (found by the new
  regression test; go is a strict ecosystem, so these were HIGH findings).
- **Relative-path resolution walks up (bounded)** when the plain cwd join does
  not exist, so repo-root-relative tool paths under a subdirectory cwd no
  longer produce fake "claimed created but missing" verdicts.

### Added (quality gates)
- CLI and report rendering were untested: +53 tests cover exit codes, JSON/
  SARIF/text rendering, redaction end-to-end, scan filters and warnings, time
  parsing, path resolution. Coverage 67% → 83%; flake8 clean.

### Changed (calibration)
- Installed-claim failures for ecosystems whose install does *not* record the
  package in the manifest by default (pypi/ruby/os) are now **medium**, not
  high; npm/go/cargo/dotnet keep **high** (their installs do write manifests).

### Added
- Python < 3.11 now refuses to run with a clear error instead of silently
  mis-verifying manifest claims (`tomllib` unavailable).
- A warning is emitted when a store hits the 5,000-file scan cap.

### Docs
- README no longer claims byte-for-byte content comparison (it is a trimmed
  text compare); exfil severity wording synced; scan-cap limitation added.

## Unreleased

### Added
- **MCP server mode** (`trueup mcp`): zero-dependency Model Context Protocol
  stdio server exposing `trueup_scan` and `trueup_doctor` tools so the current
  AI agent can self-audit; results redacted, `fail_on` maps to `isError`.
  4 new protocol tests including a real subprocess handshake.

## 0.2.0 — 2026-11-21

### Fixed (correctness)
- `installed_packages` now captures arguments **after** the install verb, so
  `sudo npm install left-pad` no longer reports `npm`/`install` as packages;
  `-r requirements.txt` and bare `npm i` no longer produce phantom installs.
- "added `style.css`"-style text no longer creates a false *installed* claim
  (path-like subjects are filtered out of install claims).
- Residue detection uses `git status --porcelain -uall`, so files inside
  *untracked directories* are now found.
- Session start/end merging parses timestamps (mixed `Z` / `+00:00` / fractional
  formats no longer mis-order lexicographically).
- Transcript readers accept UTF-8 BOM (some Windows writers emit it).
- Claude Code `apply_patch` now captures **Add File** content for byte-exact
  verification.

### Added
- Content-level verification for **Claude Code**: `Write` snapshots the exact
  content written and `Edit` snapshots `new_string`; verification compares them
  against the current file (byte-match / superseded), matching ZCode's behavior.
- `--only` flag: audit just the given paths, ignoring auto-detected stores.
- Warnings surfaced in the report for unparseable `--since`, unknown `--agent`
  names, and missing paths (also in `stats.warnings`).
- Per-agent session counts in the header and `stats.sessions_by_agent`.
- PEP 735 `dependency-groups` and poetry group dependencies supported in
  pyproject verification; manifest search results are cached per project.
- Runnable demo: `examples/demo-claude-session.jsonl` +
  `tests/test_examples.py` end-to-end regression anchored to it.
- Docs: `docs/USAGE.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`.

### Changed
- Deleted-claim verification on temporary/scratch paths: "still exists" is now
  **low** severity (expected churn) instead of high.
- CLI reconfigures stdout *and* stderr to UTF-8 on Windows consoles.

## 0.1.0 — 2026-11-21

Initial release: parsers for Claude Code / Codex CLI / ZCode (+ generic
sniffing), claim-vs-reality verification, secrets scanning with redaction-first
output, dangerous-command grading, exfiltration signals, Claude settings leak
scan, residue detection, text/JSON/SARIF outputs, `--fail-on` CI gate, 21 tests.
