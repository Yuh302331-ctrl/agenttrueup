"""trueup CLI entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__, scan as scanmod
from .models import sev_at_least
from .report import Style, enable_windows_vt, render_json, render_sarif, render_text
from .stores import candidate_stores


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="trueup",
        description="Trust, but reconcile: verify what your AI coding agent "
                    "said against what your filesystem actually shows. "
                    "100% local, read-only, zero dependencies.")
    ap.add_argument("--version", action="version",
                    version=f"trueup (agenttrueup) {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_doc = sub.add_parser("doctor", help="show which agent stores were detected")
    ap_doc.add_argument("--json", action="store_true", help="machine-readable output")

    ap_scan = sub.add_parser("scan", help="audit agent sessions and reconcile claims")
    ap_scan.add_argument("paths", nargs="*", default=[],
                         help="extra transcript files or directories (in addition to auto-detected stores)")
    ap_scan.add_argument("--agent", default="",
                         help="comma-separated agent filter: claude,codex,zcode,gemini,goose,opencode,qwen")
    ap_scan.add_argument("--only", action="store_true",
                         help="scan ONLY the paths given, ignore auto-detected stores")
    ap_scan.add_argument("--since", default="",
                         help="only sessions updated after: 7d, 24h, 2w, or ISO date")
    ap_scan.add_argument("--json", action="store_true", help="JSON output")
    ap_scan.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output (for CI)")
    ap_scan.add_argument("--min-severity", dest="min_severity", default=None,
                         choices=["critical", "high", "medium", "low", "info"],
                         help="only report findings at this severity or above "
                              "(counts in stats always reflect the full scan)")
    ap_scan.add_argument("--fail-on", default="high",
                         choices=["critical", "high", "medium", "low", "info", "never"],
                         help="exit 1 when findings at this severity or above exist (default: high)")
    ap_scan.add_argument("--reveal", action="store_true",
                         help="show raw secret values in output (default: redacted)")
    ap_scan.add_argument("--no-color", action="store_true")
    ap_scan.add_argument("--journal", dest="journals", action="append", default=[],
                         metavar="PATH",
                         help="redhand journal.db / .whodunit dir / watched root "
                              "(repeatable; auto-discovery also runs by default)")
    ap_scan.add_argument("--no-journal", dest="use_journal_sources",
                         action="store_false",
                         help="disable redhand journal auto-discovery")
    ap_scan.add_argument("-v", "--verbose", action="store_true")

    sub.add_parser("mcp",
                   help="run as an MCP (Model Context Protocol) stdio server — "
                        "lets AI agents audit sessions via tools/call")
    return ap


def _cmd_doctor(args) -> int:
    stores_found = [s for s in candidate_stores() if s.root.exists()]
    if args.json:
        import json
        print(json.dumps({"version": __version__,
                          "stores": [s.to_dict() for s in candidate_stores()]},
                         indent=2))
        return 0
    print(f"trueup {__version__} — doctor")
    print(f"python {sys.version.split()[0]}")
    print("")
    print("agent session stores:")
    if not stores_found:
        print("  (none found — run a Claude Code / Codex / ZCode session first, "
              "or pass paths explicitly to `trueup scan`)")
    generic_seen = []
    for s in candidate_stores():
        mark = "✓" if s.root.exists() else "✗"
        note = ""
        if s.root.exists():
            n = sum(1 for _, _ in zip(s.root.rglob("*"), range(2000)))
            note = f" ({n}+ entries)" if n == 2000 else f" ({n} entries)"
        parsing = ("full parsing" if s.kind != "generic_dir"
                   else "generic parser — best effort")
        if s.kind == "generic_dir" and s.root.exists():
            generic_seen.append(s.label)
        print(f"  {mark} {s.label}{note}  [{parsing}]")
    if generic_seen:
        print("")
        print("  note: sessions from the [generic parser] stores above are "
              "handled best-effort — claims and danger detection are less "
              "complete there than for claude/codex/zcode.")
    return 0


def _cmd_scan(args) -> int:
    enable_windows_vt()
    st = Style(not args.no_color and sys.stdout.isatty())
    agents = [a for a in args.agent.split(",") if a.strip()]
    res = scanmod.scan(paths=args.paths, agents=agents, since=args.since,
                       reveal=args.reveal, verbose=args.verbose,
                       only_paths=args.only, journals=args.journals,
                       use_journal_sources=args.use_journal_sources,
                       min_severity=args.min_severity)

    if args.sarif:
        print(render_sarif(res))
    elif args.json:
        print(render_json(res))
    else:
        print(render_text(res, st))

    if args.fail_on == "never":
        return 0
    bad = [f for f in res.findings if sev_at_least(f.severity, args.fail_on)]
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    # pyproject gates pip installs, but running from a clone skips that check —
    # without tomllib (3.11+) manifest checks would silently mis-verify
    if sys.version_info < (3, 11):
        print(f"agenttrueup requires Python 3.11+ (for tomllib); "
              f"you are running {sys.version.split()[0]}.", file=sys.stderr)
        return 2
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = _build_parser()
    args = ap.parse_args(argv)
    try:
        if args.cmd == "doctor":
            return _cmd_doctor(args)
        if args.cmd == "scan":
            return _cmd_scan(args)
        if args.cmd == "mcp":
            from .mcp import serve
            return serve()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
