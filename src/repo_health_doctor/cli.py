from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .doctor import (
    DEFAULT_LARGE_FILE_THRESHOLD_MB,
    determine_exit_code,
    diagnose_repo,
    format_json,
    format_text,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-health-doctor",
        description="Diagnose basic repository health signals.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository path to inspect.")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 when any warning or failure is present.",
    )
    parser.add_argument(
        "--large-file-threshold-mb",
        type=int,
        default=DEFAULT_LARGE_FILE_THRESHOLD_MB,
        help="Treat files at or above this size in MB as large files.",
    )
    parser.add_argument(
        "--output",
        help="Write the rendered report to a file while also printing to stdout.",
    )
    parser.add_argument(
        "--secrets-ignore",
        action="append",
        default=[],
        help="Ignore a path prefix during secrets scanning. Can be passed multiple times.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.path)
    if not target.exists():
        parser.error(f"path does not exist: {target}")
    if args.large_file_threshold_mb <= 0:
        parser.error("--large-file-threshold-mb must be greater than 0")

    report = diagnose_repo(
        target,
        large_file_threshold_mb=args.large_file_threshold_mb,
        secrets_ignores=tuple(args.secrets_ignore),
    )
    output = format_json(report) if args.format == "json" else format_text(report)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    sys.stdout.write(output)
    return determine_exit_code(report, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
