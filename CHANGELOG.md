# Changelog

All notable changes to agenttrueup.

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
