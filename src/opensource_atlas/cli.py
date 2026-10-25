"""Command-line interface for OpenSource Atlas."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .github import GitHubAPIError, fetch_repository
from .report import build_report, to_json, to_markdown
from .scoring import score_repository


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atlas",
        description="Inspect a public GitHub repository and generate an explainable report.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect", help="Inspect a repository.")
    inspect.add_argument("repository", help="GitHub owner/name or repository URL.")
    inspect.add_argument("--format", choices=("markdown", "json"), default="markdown")
    inspect.add_argument("--output", "-o", help="Write report to a file instead of stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.command == "inspect":
        try:
            repository = fetch_repository(args.repository)
            report = build_report(repository, score_repository(repository))
        except (GitHubAPIError, ValueError) as exc:
            print(f"atlas: error: {exc}", file=sys.stderr)
            return 2

        rendered = to_json(report) if args.format == "json" else to_markdown(report)
        if args.output:
            try:
                Path(args.output).write_text(rendered, encoding="utf-8")
            except OSError as exc:
                print(f"atlas: could not write report: {exc}", file=sys.stderr)
                return 2
            print(f"Report written to {args.output}")
        else:
            print(rendered)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
