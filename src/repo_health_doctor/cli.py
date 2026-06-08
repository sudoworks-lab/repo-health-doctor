from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .doctor import (
    DEFAULT_LARGE_FILE_THRESHOLD_MB,
    POLICY_ALLOW_STATUS_EXPIRED,
    POLICY_ALLOW_STATUS_EXPIRING_SOON,
    POLICY_ALLOW_STATUS_VALUES,
    TOOL_VERSION,
    determine_exit_code,
    diagnose_repo,
    diff_reports,
    format_json,
    format_markdown,
    format_text,
    list_policy_allows,
    validate_policy,
)


def build_parser(command: str = "scan") -> argparse.ArgumentParser:
    validate_mode = command == "validate-policy"
    list_allows_mode = command == "list-allows"
    diff_reports_mode = command == "diff-reports"
    parser = argparse.ArgumentParser(
        prog=(
            "repo-health-doctor diff-reports"
            if diff_reports_mode
            else
            "repo-health-doctor validate-policy"
            if validate_mode
            else "repo-health-doctor list-allows"
            if list_allows_mode
            else "repo-health-doctor"
        ),
        description=(
            "Compare two repo-health-doctor JSON reports."
            if diff_reports_mode
            else
            "Validate policy configuration without scanning repository contents."
            if validate_mode
            else "List allow entries with stale-policy status."
            if list_allows_mode
            else "Diagnose basic repository health signals."
        ),
        epilog=(
            "Report diff mode: repo-health-doctor diff-reports before.json after.json [--format json|markdown]"
            if diff_reports_mode
            else
            "Policy-only mode: repo-health-doctor validate-policy <path> [--format json|markdown]"
            if not validate_mode and not list_allows_mode
            else "Allow inventory mode: repo-health-doctor list-allows <path> [--format json|markdown]"
            if list_allows_mode
            else None
        ),
    )
    if diff_reports_mode:
        parser.add_argument("before_report", help="Earlier repo-health-doctor JSON report.")
        parser.add_argument("after_report", help="Later repo-health-doctor JSON report.")
    else:
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
    if not validate_mode and not list_allows_mode and not diff_reports_mode:
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
    if list_allows_mode:
        parser.add_argument(
            "--status",
            choices=POLICY_ALLOW_STATUS_VALUES,
            help="Only display allow entries with this status.",
        )
        parser.add_argument(
            "--fail-on",
            choices=(POLICY_ALLOW_STATUS_EXPIRED, POLICY_ALLOW_STATUS_EXPIRING_SOON),
            help="Exit with code 1 when stale allow entries meet this threshold.",
        )
    if not diff_reports_mode:
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
    elif raw_args and raw_args[0] == "list-allows":
        command = "list-allows"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "diff-reports":
        command = "diff-reports"
        raw_args = raw_args[1:]

    parser = build_parser(command)
    args = parser.parse_args(raw_args)

    if command == "diff-reports":
        before_report = Path(args.before_report)
        after_report = Path(args.after_report)
        if not before_report.exists():
            parser.error(f"path does not exist: {before_report}")
        if not after_report.exists():
            parser.error(f"path does not exist: {after_report}")
        try:
            report = diff_reports(before_report, after_report)
        except ValueError as exc:
            parser.error(str(exc))
        fail_on = None
    else:
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
        elif command == "list-allows":
            report = list_policy_allows(
                target,
                config_path=args.config,
                local_config_path=args.local_config,
                load_local_config=not args.no_local_config,
                status_filter=args.status,
                fail_on=args.fail_on,
            )
            fail_on = args.fail_on or "block"
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
    return 0 if fail_on is None else determine_exit_code(report, fail_on=fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
