# Architecture

## Data flow

```
stores.discover()                 # ~/.claude/projects, ~/.codex/sessions, ~/.zcode/…
      │
      ▼
parsers (per agent, tolerant)     # raw files → Session{events[], artifacts[]}
      │   ├─ claude:  projects/**/*.jsonl   (tool_use Write/Edit → content snapshots)
      │   ├─ codex:   sessions/**/*.jsonl   (exec_command, custom exec, apply_patch)
      │   ├─ zcode:   rollout/*.jsonl + artifacts/<sess>/*.json (before/after content)
      │   └─ generic: any dir (string harvesting by key names)
      ▼
merge_sessions()                  # (agent, session_id) — zcode rollout + artifacts
      │
      ▼
extract                           # pure functions over events
      │   ├─ claims_from_session()          created/edited/deleted/installed
      │   ├─ security_findings_for_session() secrets, danger, exfil
      ▼
verify                            # reality checks (read-only)
      │   ├─ verify_claims()      exists? mtime? content match? manifest entry?
      │   ├─ residue_findings()   git status -uall, backup litter
      │   └─ settings_leak_findings()  ~/.claude/settings*.json
      ▼
redact (default ON)               # every evidence string → <kind:sha256:12>
      ▼
report                            # text / json / sarif 2.1.0
```

## Key invariants

1. **Read-only**: nothing in the pipeline mutates any file outside agenttrueup's
   own process. Verification uses `Path.exists/stat/read_text`, `git status`,
   manifest parsing — never writes, never network.
2. **Redaction-first**: `scan()` redacts all finding/claim evidence unless
   `reveal=True`; the report layer never handles raw secrets.
3. **Tolerance**: a malformed line/never crashes a scan. `_jsonl` skips bad
   lines; per-store failures increment `stats["errors"]`.
4. **Determinism**: no LLM, no randomness; the same store yields the same report.

## Claim semantics

| Claim kind | Extracted from | Verified against | Failure |
|---|---|---|---|
| `deleted` | `rm`/`del`/`unlink` commands (non-broad targets), "deleted `path`" text, apply_patch Delete File | `Path.exists()` | still exists → high (low on temp paths) |
| `created` | Write tool_use, apply_patch Add File, "created `path`" text | `Path.exists()` + exact content match when a snapshot exists | missing → low |
| `edited` | Edit tool_use (+`new_string` snapshot), apply_patch Update File, "updated `path`" text | exists + content contains edit, else mtime ≥ session start | mtime predates session → medium |
| `installed` | npm/pip/uv/poetry/cargo/go/gem/dotnet/apt/brew… commands; "installed `pkg`" text | manifest search (≤3 levels deep, SKIP_DIRS pruned) in session project | not recorded → high |

## Adding a new agent parser

1. Capture ground truth: find the store on a real machine, dump the JSON schema
   (keys only) for one session file — event types, role names, command/file-path
   fields, timestamp format.
2. Add a `parse_<agent>_file(path) -> Session` in `src/agenttrueup/parsers/__init__.py`
   emitting `Event`s: `command` (full command text), `file_write`/`file_edit`
   (+ a snapshot in `session.artifacts` when the store has before/after content —
   it enables byte-exact verification), `assistant`/`user` text, `tool_result`.
3. Register detection in `stores.sniff_file()` and a store root in
   `stores.candidate_stores()`; wire it into `scan.scan()`.
4. Add fixtures + tests (see `tests/conftest.py` builders; mirror
   `test_parsers.py`).

## Testing notes

- Tests never touch real agent stores; fixtures build synthetic stores in
  `tmp_path` (real schemas, fake content).
- `tests/test_examples.py` is anchored to the shipped `examples/` demo and acts
  as an end-to-end regression on a known artifact.
- Windows portability: no POSIX-only calls; paths via `pathlib`; ANSI VT enabled
  opportunistically; subprocess `git` guarded by `shutil.which` and timeouts.
