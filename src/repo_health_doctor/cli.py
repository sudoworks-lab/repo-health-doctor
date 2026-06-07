from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .doctor import (
    DEFAULT_LARGE_FILE_THRESHOLD_MB,
    TOOL_VERSION,
    determine_exit_code,
    diagnose_repo,
    format_json,
    format_markdown,
    format_text,
    validate_policy,
)


def build_parser(command: str = "scan") -> argparse.ArgumentParser:
    validate_mode = command == "validate-policy"
    parser = argparse.ArgumentParser(
        prog="repo-health-doctor validate-policy" if validate_mode else "repo-health-doctor",
        description=(
            "Validate policy configuration without scanning repository contents."
            if validate_mode
            else "Diagnose basic repository health signals."
        ),
        epilog=(
            "Policy-only mode: repo-health-doctor validate-policy <path> [--format json|markdown]"
            if not validate_mode
            else None
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository path to inspect.")
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "md"),
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        help="Write the rendered report to a file while also printing to stdout.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"repo-health-doctor {TOOL_VERSION}",
    )
    if not validate_mode:
        parser.add_argument(
            "--fail-on",
            choices=("block", "warn"),
            default="block",
            help="Exit with code 1 on block findings, or on warn and block findings.",
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Alias for --fail-on warn.",
        )
        parser.add_argument(
            "--large-file-threshold-mb",
            type=int,
            default=DEFAULT_LARGE_FILE_THRESHOLD_MB,
            help="Treat files at or above this size in MB as large files.",
        )
        parser.add_argument(
            "--secrets-ignore",
            action="append",
            default=[],
            help="Ignore a path prefix during secrets scanning. Can be passed multiple times.",
        )
        parser.add_argument(
            "--public-safety",
            action="store_true",
            help="Enable extra checks for public release safety.",
        )
    parser.add_argument(
        "--config",
        help="Read policy from this file. Defaults to repo-health-doctor.yml when present.",
    )
    parser.add_argument(
        "--local-config",
        help="Read local policy from this file. Defaults to .repo-health-doctor.local.yml when present.",
    )
    parser.add_argument(
        "--no-local-config",
        action="store_true",
        help="Do not read the local policy config.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    command = "scan"
    if raw_args and raw_args[0] == "validate-policy":
        command = "validate-policy"
        raw_args = raw_args[1:]

    parser = build_parser(command)
    args = parser.parse_args(raw_args)

    target = Path(args.path)
    if not target.exists():
        parser.error(f"path does not exist: {target}")

    if command == "validate-policy":
        report = validate_policy(
            target,
            config_path=args.config,
            local_config_path=args.local_config,
            load_local_config=not args.no_local_config,
        )
        fail_on = "block"
    else:
        if args.large_file_threshold_mb <= 0:
            parser.error("--large-file-threshold-mb must be greater than 0")
        report = diagnose_repo(
            target,
            large_file_threshold_mb=args.large_file_threshold_mb,
            secrets_ignores=tuple(args.secrets_ignore),
            public_safety=args.public_safety,
            config_path=args.config,
            local_config_path=args.local_config,
            load_local_config=not args.no_local_config,
        )
        fail_on = "warn" if args.strict else args.fail_on
    if args.format == "json":
        output = format_json(report)
    elif args.format in {"markdown", "md"}:
        output = format_markdown(report)
    else:
        output = format_text(report)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    sys.stdout.write(output)
    return determine_exit_code(report, fail_on=fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
