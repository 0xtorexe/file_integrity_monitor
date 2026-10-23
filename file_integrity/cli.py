"""Command-line interface for the File Integrity Monitor."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .baseline import DEFAULT_BASELINE_NAME
from .errors import BaselineExistsError, FimError
from .report import format_baseline_summary, render_report, report_as_dict
from .service import check_integrity, create_baseline

EXIT_OK = 0
EXIT_CHANGES = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="Detect modified, added and deleted files using SHA-256 hashes.",
        epilog=(
            "Exit codes: 0 = no changes, 1 = changes detected, 2 = error. "
            "See README.md for examples."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, metavar="{baseline,check,ui}"
    )

    baseline_parser = subparsers.add_parser(
        "baseline",
        help="scan a directory and save its file hashes as the baseline",
        description="Scan a directory and save a new baseline file.",
    )
    _add_scan_arguments(baseline_parser)
    baseline_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing baseline file",
    )

    check_parser = subparsers.add_parser(
        "check",
        help="rescan a directory and compare it with the baseline",
        description="Scan a directory again and report changes since the baseline.",
    )
    _add_scan_arguments(check_parser)
    check_parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON instead of text",
    )
    check_parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors in the terminal report",
    )

    return parser


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "directory",
        help="directory to scan",
    )
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help=(
            "baseline file to use "
            f"(default: <directory>/{DEFAULT_BASELINE_NAME})"
        ),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help=(
            "skip files matching a glob pattern; can be used several times "
            "(e.g. --exclude '*.log' --exclude 'cache/*')"
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "baseline":
            return _run_baseline(args)
        if args.command == "check":
            return _run_check(args)
        parser.error(f"unknown command: {args.command}")
    except FimError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return EXIT_ERROR


def _run_baseline(args: argparse.Namespace) -> int:
    try:
        baseline, scan = create_baseline(
            args.directory,
            baseline=args.baseline,
            excludes=args.exclude,
            force=args.force,
        )
    except BaselineExistsError as exc:
        raise FimError(
            f"{exc}\n"
            "Use --force to replace it, or choose another path with --baseline."
        ) from exc

    print(format_baseline_summary(baseline, scan, color=_color_enabled(args)))
    return EXIT_OK


def _run_check(args: argparse.Namespace) -> int:
    outcome = check_integrity(
        args.directory,
        baseline=args.baseline,
        excludes=args.exclude,
    )

    if args.json:
        payload = report_as_dict(outcome.comparison, outcome.baseline, outcome.scan)
        payload["has_changes"] = outcome.comparison.has_changes
        print(json.dumps(payload, indent=2))
    else:
        print(
            render_report(
                outcome.comparison,
                outcome.baseline,
                outcome.scan,
                color=_color_enabled(args),
            )
        )

    return EXIT_CHANGES if outcome.comparison.has_changes else EXIT_OK


def _color_enabled(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


if __name__ == "__main__":
    raise SystemExit(main())
