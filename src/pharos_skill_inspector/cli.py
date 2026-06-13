"""Command-line interface for the Pharos Skill Inspector."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .engine import scan
from .report import render

# Exit code thresholds (handy for CI gating).
_FAIL_LEVELS = {"low": 1, "medium": 21, "high": 51, "critical": 81}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pharos-skill-inspector",
        description="Security scanner for Pharos AI agent skills "
                    "(prompt injection, data leakage, vulnerable deps, dangerous code, on-chain risks).",
    )
    p.add_argument("--version", action="version", version=f"pharos-skill-inspector {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a skill (directory, SKILL.md, .zip, or URL).")
    s.add_argument("path", metavar="SOURCE",
                   help="A skill directory, a single file, a .zip archive, or a remote URL "
                        "(git repo such as https://github.com/owner/repo, or a .zip URL).")
    s.add_argument("-f", "--format", choices=["terminal", "json", "markdown", "sarif"],
                   default="terminal", help="Output format (default: terminal).")
    s.add_argument("-o", "--output", help="Write the report to a file instead of stdout.")
    s.add_argument("--no-network", action="store_true",
                   help="Skip OSV.dev lookups (use the offline fallback DB only).")
    s.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output.")
    s.add_argument("--fail-on", choices=list(_FAIL_LEVELS), default=None,
                   help="Exit non-zero if risk meets/exceeds this severity (for CI).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        try:
            result = scan(args.path, use_network=not args.no_network)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except RuntimeError as exc:  # remote fetch / clone / download failure
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:  # pragma: no cover
            print(f"error: scan failed: {exc}", file=sys.stderr)
            return 2

        color = sys.stdout.isatty() and not args.no_color and not args.output
        text = render(result, args.format, color=color)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"Report written to {args.output} "
                  f"(score {result.risk_score}/100, {result.risk_severity.value}).")
        else:
            print(text)

        if args.fail_on and result.risk_score >= _FAIL_LEVELS[args.fail_on]:
            return 1
        return 0

    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
