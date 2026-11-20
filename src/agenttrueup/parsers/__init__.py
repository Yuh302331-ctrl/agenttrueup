"""Session parsers.  Each parser turns raw agent store files into
``Session`` objects (events only — all judgment happens later).

Parsers are deliberately tolerant: a malformed line is skipped, never fatal.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event, Session
from ..util import parse_ts

_SENTINEL_DT = datetime.max.replace(tzinfo=timezone.utc)

MAX_TEXT = 4000          # per-event text cap for scanning purposes
MAX_LINES = 20000        # per-file line cap (safety on giant transcripts)
MAX_FILE_EVENTS = 6000   # per-session event cap


def _clamp(text: str, limit: int = MAX_TEXT) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + f"…[+{len(text) - limit} chars]"


def _jsonl(path: Path):
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= MAX_LINES:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def _content_text(content) -> str:
    """Flatten Claude/Codex-style content (str or list of blocks) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                t = block.get("text") or block.get("content") or ""
                if isinstance(t, list):  # tool_result content can be nested
                    t = " ".join(str(x.get("text", x)) if isinstance(x, dict) else str(x) for x in t)
                parts.append(str(t))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return ""


def _finish(session: Session) -> Session:
    if len(session.events) > MAX_FILE_EVENTS:
        session.events = session.events[:MAX_FILE_EVENTS]
    stamps = sorted([e.ts for e in session.events if e.ts])
    if stamps:
        session.started = session.started or stamps[0]
        session.ended = stamps[-1]
    return session


# ---------------------------------------------------------------- claude code

def parse_claude_file(path: Path) -> Session:
    sid = path.stem
    project: str | None = None
    session = Session(agent="claude", session_id=sid, source_file=str(path), project=None)
    for obj in _jsonl(path):
        if not isinstance(obj, dict):
            continue
        ts = obj.get("timestamp")
        if obj.get("sessionId"):
            session.session_id = str(obj["sessionId"])
        if obj.get("cwd") and project is None:
            project = str(obj["cwd"])
            session.project = project
        mtype = obj.get("type")
        msg = obj.get("message") if isinstance(obj.get("message"), dict) else None
        if mtype in ("user", "assistant") and msg is not None:
            role = msg.get("role") or mtype
            content = msg.get("content")
            if isinstance(content, str):
                text = content
                if text.strip():
                    session.events.append(Event("assistant" if role == "assistant" else "user",
                                                text=_clamp(text), ts=ts))
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "text":
                        text = str(block.get("text") or "")
                        if text.strip():
                            session.events.append(Event("assistant" if role == "assistant" else "user",
                                                        text=_clamp(text), ts=ts))
                    elif btype == "tool_use":
                        name = str(block.get("name") or "")
                        inp = block.get("input") if isinstance(block.get("input"), dict) else {}
                        _tool_use_event(session, name, inp, ts)
                    elif btype == "tool_result":
                        text = _content_text(block.get("content"))
                        if text.strip():
                            session.events.append(Event("tool_result", text=_clamp(text, 2000), ts=ts))
        elif mtype == "summary":
            pass
    session.project = session.project or project
    return _finish(session)


def _tool_use_event(session: Session, name: str, inp: dict, ts):
    low = name.lower()
    cmd = inp.get("command")
    if isinstance(cmd, str) and cmd.strip():
        session.events.append(Event("command", text=_clamp(cmd, 2000), ts=ts,
                                    extra={"tool": name}))
        return
    fpath = inp.get("file_path") or inp.get("notebook_path") or inp.get("path")
    if isinstance(fpath, str) and fpath.strip():
        if low in ("write", "notebookwrite"):
            session.events.append(Event("file_write", path=fpath, ts=ts,
                                        extra={"tool": name}))
            content = inp.get("content")
            if isinstance(content, str) and content:
                # exact bytes the tool wrote → enables content-level verification
                session.artifacts.append({"path": fpath, "existed_before": False,
                                          "after": content, "ts": ts, "tool": name})
        else:
            session.events.append(Event("file_edit", path=fpath, ts=ts,
                                        extra={"tool": name}))
            new = inp.get("new_string") or inp.get("newText")
            if isinstance(new, str) and new.strip():
                session.artifacts.append({"path": fpath, "existed_before": True,
                                          "must_contain": new, "ts": ts,
                                          "tool": name})
        return
    # any other tool: keep a note with its string inputs for secret scanning
    interesting = {k: v for k, v in inp.items() if isinstance(v, (str, int, float)) and v}
    if interesting:
        blob = "; ".join(f"{k}={v}" for k, v in list(interesting.items())[:8])
        session.events.append(Event("note", text=_clamp(blob, 1000), ts=ts,
                                    extra={"tool": name}))


# ------------------------------------------------------------------- codex

_APPLY_PATCH_OPS = re.compile(
    r"^\*\*\* (?P<op>Add File|Update File|Delete File|Move to): (?P<path>.+?)\s*$", re.M)


def parse_codex_file(path: Path) -> Session:
    session = Session(agent="codex", session_id=path.stem, source_file=str(path), project=None)
    meta_seen = False
    for obj in _jsonl(path):
        if not isinstance(obj, dict):
            continue
        ts = obj.get("timestamp")
        p = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
        otype = obj.get("type")
        ptype = p.get("type")
        if otype == "session_meta" and not meta_seen:
            meta_seen = True
            session.session_id = str(p.get("session_id") or session.session_id)
            session.project = p.get("cwd")
            session.cli_version = p.get("cli_version")
            continue
        if otype == "turn_context":
            cfg = p.get("thread_settings") or {}
            if cfg.get("model"):
                session.model = cfg["model"]
            continue
        if otype != "response_item":
            continue
        if ptype == "message":
            role = p.get("role")
            if role in ("user", "assistant"):
                text = _content_text(p.get("content"))
                if text.strip():
                    session.events.append(Event(role, text=_clamp(text), ts=ts))
        elif ptype == "function_call":
            name = str(p.get("name") or "")
            args_raw = p.get("arguments")
            args: dict = {}
            if isinstance(args_raw, str):
                try:
                    parsed = json.loads(args_raw)
                    # arguments may legally be a JSON array/string — keep a dict
                    args = parsed if isinstance(parsed, dict) else {"_raw": str(parsed)[:500]}
                except ValueError:
                    args = {"_raw": args_raw}
            elif isinstance(args_raw, dict):
                args = args_raw
            if name == "apply_patch" or (isinstance(args.get("input"), str) and "*** " in args["input"]):
                patch = args.get("input") or args.get("patch") or ""
                _apply_patch_events(session, str(patch), ts)
                continue
            cmd = args.get("cmd") or args.get("command")
            if isinstance(cmd, list):
                cmd = " ".join(str(x) for x in cmd)
            if isinstance(cmd, str) and cmd.strip():
                session.events.append(Event("command", text=_clamp(cmd, 2000), ts=ts,
                                            extra={"tool": name, "workdir": args.get("workdir")}))
            elif args:
                blob = "; ".join(f"{k}={v}" for k, v in list(args.items())[:8] if isinstance(v, (str, int, float)))
                if blob:
                    session.events.append(Event("note", text=_clamp(blob, 1000), ts=ts, extra={"tool": name}))
        elif ptype == "custom_tool_call":
            name = str(p.get("name") or "")
            inp = p.get("input")
            if isinstance(inp, str):
                if name == "apply_patch" or "*** " in inp:
                    _apply_patch_events(session, inp, ts)
                elif name in ("exec", "shell", "bash") or name:
                    session.events.append(Event("command", text=_clamp(inp, 2000), ts=ts, extra={"tool": name}))
            elif isinstance(inp, dict):
                cmd = inp.get("cmd") or inp.get("command")
                if isinstance(cmd, str) and cmd.strip():
                    session.events.append(Event("command", text=_clamp(cmd, 2000), ts=ts, extra={"tool": name}))
        elif ptype == "function_call_output":
            out = p.get("output")
            if isinstance(out, list):
                out = _content_text(out)
            if isinstance(out, str) and out.strip():
                session.events.append(Event("tool_result", text=_clamp(out, 2000), ts=ts))
    return _finish(session)


def _apply_patch_events(session: Session, patch: str, ts):
    cur_op: str | None = None
    cur_path: str | None = None
    buf: list[str] = []

    def flush():
        nonlocal cur_op, cur_path, buf
        if cur_op == "Add File" and cur_path and buf:
            session.artifacts.append({"path": cur_path, "existed_before": False,
                                      "after": "\n".join(buf), "ts": ts,
                                      "tool": "apply_patch"})
        cur_op = cur_path = None
        buf = []

    for line in patch.splitlines():
        m = _APPLY_PATCH_OPS.match(line)
        if m:
            flush()
            cur_op, cur_path = m.group("op"), m.group("path").strip()
            if cur_op == "Add File":
                session.events.append(Event("file_write", path=cur_path, ts=ts,
                                            extra={"tool": "apply_patch"}))
            elif cur_op == "Update File":
                session.events.append(Event("file_edit", path=cur_path, ts=ts,
                                            extra={"tool": "apply_patch"}))
            elif cur_op == "Delete File":
                session.events.append(Event(
                    "note", text=f"apply_patch deleted {cur_path}", path=cur_path,
                    ts=ts, extra={"tool": "apply_patch", "deleted": True}))
            elif cur_op == "Move to":
                session.events.append(Event(
                    "note", text=f"apply_patch moved file to {cur_path}", path=cur_path,
                    ts=ts, extra={"tool": "apply_patch"}))
            continue
        if line.startswith("*** End Patch"):
            flush()
            continue
        if cur_op == "Add File" and line.startswith("+"):
            buf.append(line[1:])
    flush()


# -------------------------------------------------------------------- zcode

_ZC_ROLLOUT_RE = re.compile(r"model-io-(?:session_)?([\w-]+)\.jsonl$", re.I)


def parse_zcode_rollout(path: Path) -> list[Session]:
    sessions: dict[str, Session] = {}
    seen_user_hashes: set[str] = set()
    for obj in _jsonl(path):
        if not isinstance(obj, dict) or obj.get("type") != "model_io":
            continue
        sid = str(obj.get("sessionId") or path.stem)
        if sid not in sessions:
            sessions[sid] = Session(agent="zcode", session_id=sid, source_file=str(path), project=None)
        s = sessions[sid]
        ts = obj.get("startedAt") or obj.get("completedAt")
        resp = obj.get("response") if isinstance(obj.get("response"), dict) else {}
        text = resp.get("text")
        if isinstance(text, str) and text.strip():
            s.events.append(Event("assistant", text=_clamp(text), ts=ts))
        for tc in resp.get("toolCalls") or []:
            if not isinstance(tc, dict):
                continue
            inp = tc.get("input") if isinstance(tc.get("input"), dict) else {}
            cmd = inp.get("command") or inp.get("cmd")
            if isinstance(cmd, str) and cmd.strip():
                s.events.append(Event("command", text=_clamp(cmd, 2000), ts=ts,
                                      extra={"tool": tc.get("name")}))
            else:
                blob = "; ".join(f"{k}={v}" for k, v in list(inp.items())[:6]
                                 if isinstance(v, (str, int, float)))
                if blob:
                    s.events.append(Event("note", text=_clamp(blob, 800), ts=ts,
                                          extra={"tool": tc.get("name")}))
        req = obj.get("request") if isinstance(obj.get("request"), dict) else {}
        for m in req.get("messages") or []:
            if not isinstance(m, dict) or m.get("role") != "user":
                continue
            ctext = _content_text(m.get("content"))
            if not ctext.strip():
                continue
            import hashlib as _h
            h = _h.sha1(ctext.encode("utf-8", "replace")).hexdigest()
            if h in seen_user_hashes:
                continue
            seen_user_hashes.add(h)
            s.events.append(Event("user", text=_clamp(ctext, 1500), ts=ts))
    out = [s for s in sessions.values()]
    for s in out:
        _finish(s)
    return out


def parse_zcode_artifacts_dir(d: Path) -> Session | None:
    sid = d.name
    session = Session(agent="zcode", session_id=sid, source_file=str(d), project=None)
    found = False
    for f in sorted(d.glob("*.json")):
        try:
            obj = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            continue
        if not isinstance(obj, dict) or "files" not in obj:
            continue
        found = True
        ts = obj.get("createdAt")
        tool = obj.get("toolName")
        for fe in obj.get("files") or []:
            if not isinstance(fe, dict):
                continue
            fpath = fe.get("path")
            if not fpath:
                continue
            existed = bool(fe.get("existedBefore"))
            kind = "file_edit" if existed else "file_write"
            ev = Event(kind, path=str(fpath), ts=ts, extra={"tool": tool})
            session.events.append(ev)
            after = fe.get("afterContent")
            if isinstance(after, str):
                session.artifacts.append({
                    "path": str(fpath), "existed_before": existed, "after": after,
                    "ts": ts, "tool": tool,
                })
    if not found:
        return None
    return _finish(session)


# ------------------------------------------------------------------ generic

_GENERIC_STR_KEYS = ("command", "cmd", "input", "text", "content", "file_path",
                     "path", "output", "message", "instructions")
_GENERIC_ROLE_KEYS = ("role", "author", "speaker")


def parse_generic_file(path: Path, agent: str = "generic") -> Session:
    session = Session(agent=agent, session_id=path.stem, source_file=str(path), project=None)
    try:
        raw = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return _finish(session)
    objs: list = []
    if path.suffix.lower() == ".json":
        # whole-file JSON first (incl. pretty-printed), then fall back to JSONL
        try:
            obj = json.loads(raw)
            objs = [obj] if isinstance(obj, dict) else []
        except ValueError:
            objs = []
    if not objs:
        lines = raw.splitlines()
        for i, line in enumerate(lines):
            if i >= MAX_LINES:
                break
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except ValueError:
                continue
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        ts = obj.get("createdAt") or obj.get("timestamp") or obj.get("ts") or obj.get("time")
        _harvest(session, obj, ts, depth=0)
    return _finish(session)


def _harvest(session: Session, obj: dict, ts, depth: int) -> None:
    if depth > 6 or len(session.events) > MAX_FILE_EVENTS:
        return
    role = None
    for rk in _GENERIC_ROLE_KEYS:
        if isinstance(obj.get(rk), str):
            role = obj[rk].lower()
            break
    file_ops = obj.get("files")
    if isinstance(file_ops, list):
        for fe in file_ops:
            if isinstance(fe, dict) and fe.get("path"):
                kind = "file_edit" if fe.get("existedBefore") else "file_write"
                session.events.append(Event(kind, path=str(fe["path"]), ts=ts))
                after = fe.get("afterContent")
                if isinstance(after, str):
                    session.artifacts.append({"path": str(fe["path"]), "existed_before": bool(fe.get("existedBefore")),
                                              "after": after, "ts": ts})
    for k, v in list(obj.items()):
        if not isinstance(v, str):
            if isinstance(v, dict):
                _harvest(session, v, ts, depth + 1)
            continue
        if k not in _GENERIC_STR_KEYS or not v.strip():
            continue
        if k in ("command", "cmd"):
            session.events.append(Event("command", text=_clamp(v, 2000), ts=ts))
        elif k == "file_path" or (k == "path" and not v.startswith(("http", "node:", "python:"))):
            session.events.append(Event("file_edit", path=v, ts=ts))
        else:
            if role in ("user", "human"):
                session.events.append(Event("user", text=_clamp(v, 1500), ts=ts))
            elif role in ("assistant", "ai", "model"):
                session.events.append(Event("assistant", text=_clamp(v, 4000), ts=ts))
            else:
                session.events.append(Event("note", text=_clamp(v, 1000), ts=ts, extra={"key": k}))


def _earliest(a: str | None, b: str | None) -> str | None:
    da, db = parse_ts(a), parse_ts(b)
    if da is None:
        return b
    if db is None:
        return a
    return a if da <= db else b


def _latest(a: str | None, b: str | None) -> str | None:
    da, db = parse_ts(a), parse_ts(b)
    if da is None:
        return b
    if db is None:
        return a
    return a if da >= db else b


def merge_sessions(sessions: list[Session]) -> list[Session]:
    """Merge sessions that share (agent, session_id) — e.g. zcode rollout +
    artifacts describe the same session."""
    by_key: dict[tuple[str, str], Session] = {}
    for s in sessions:
        key = (s.agent, s.session_id)
        if key not in by_key:
            by_key[key] = s
            continue
        tgt = by_key[key]
        tgt.events.extend(s.events)
        tgt.artifacts.extend(s.artifacts)
        if tgt.project is None:
            tgt.project = s.project
        tgt.started = _earliest(tgt.started, s.started)
        tgt.ended = _latest(tgt.ended, s.ended)
    out = list(by_key.values())
    for s in out:
        stamps = sorted([e.ts for e in s.events if e.ts],
                        key=lambda t: parse_ts(t) or _SENTINEL_DT)
        if stamps:
            s.started = s.started or stamps[0]
            s.ended = s.ended or stamps[-1]
    return out
