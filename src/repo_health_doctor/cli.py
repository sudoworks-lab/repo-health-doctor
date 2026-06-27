from __future__ import annotations

import argparse
import json
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
    release_check,
    validate_policy,
)
from .sandbox import (
    format_sandbox_run_json,
    format_sandbox_run_markdown,
    format_sandbox_run_text,
    format_sandbox_json,
    format_sandbox_markdown,
    format_sandbox_text,
    format_unknown_repo_approval_draft_json,
    format_unknown_repo_approval_draft_markdown,
    format_unknown_repo_approval_draft_text,
    format_unknown_repo_profile_json,
    format_unknown_repo_profile_markdown,
    format_unknown_repo_profile_text,
    generate_unknown_repo_approval_draft,
    make_fake_runner,
    profile_unknown_repo,
    run_sandbox,
    run_sandbox_run,
)
from .gate import (
    build_execution_authorization_draft,
    evaluate_gate_decision_from_v3_report,
    format_gate_summary,
    validate_execution_authorization,
)


def build_parser(command: str = "scan") -> argparse.ArgumentParser:
    sandbox_mode = command == "sandbox"
    sandbox_run_mode = command == "sandbox-run"
    sandbox_profile_mode = command == "sandbox-profile"
    sandbox_approval_draft_mode = command == "sandbox-approval-draft"
    validate_mode = command == "validate-policy"
    list_allows_mode = command == "list-allows"
    diff_reports_mode = command == "diff-reports"
    release_check_mode = command == "release-check"
    authorization_draft_mode = command == "authorization-draft"
    authorization_validate_mode = command == "authorization-validate"
    parser = argparse.ArgumentParser(
        prog=(
            "repo-health-doctor sandbox"
            if sandbox_mode
            else "repo-health-doctor sandbox-run"
            if sandbox_run_mode
            else "repo-health-doctor sandbox-profile"
            if sandbox_profile_mode
            else "repo-health-doctor sandbox-approval-draft"
            if sandbox_approval_draft_mode
            else "repo-health-doctor diff-reports"
            if diff_reports_mode
            else
            "repo-health-doctor release-check"
            if release_check_mode
            else "repo-health-doctor authorization draft"
            if authorization_draft_mode
            else "repo-health-doctor authorization validate"
            if authorization_validate_mode
            else
            "repo-health-doctor validate-policy"
            if validate_mode
            else "repo-health-doctor list-allows"
            if list_allows_mode
            else "repo-health-doctor"
        ),
        description=(
            "Plan sandbox checks and only run explicitly gated probes."
            if sandbox_mode
            else "Run an explicitly approved command inside an experimental constrained Docker sandbox."
            if sandbox_run_mode
            else "Profile an unknown repository read-only without generating approvals or executing code."
            if sandbox_profile_mode
            else "Generate a non-executable unknown-repository approval draft for human review."
            if sandbox_approval_draft_mode
            else "Compare two repo-health-doctor JSON reports."
            if diff_reports_mode
            else
            "Summarize release readiness across scan, policy, allow inventory, and optional report diff."
            if release_check_mode
            else "Build a non-approved execution authorization draft for human review."
            if authorization_draft_mode
            else "Validate a human-controlled execution authorization artifact."
            if authorization_validate_mode
            else
            "Validate policy configuration without scanning repository contents."
            if validate_mode
            else "List allow entries with stale-policy status."
            if list_allows_mode
            else "Diagnose basic repository health signals."
        ),
        epilog=(
            "Sandbox mode: repo-health-doctor sandbox <path> [--approval-file approvals.json] [--format json|markdown]"
            if sandbox_mode
            else "Sandbox-run mode: repo-health-doctor sandbox-run <path> --approval approval.json --image IMAGE --profile no-network-default -- COMMAND ARG..."
            if sandbox_run_mode
            else "Unknown repository profile mode: repo-health-doctor sandbox-profile <path> [--format json|markdown]"
            if sandbox_profile_mode
            else "Unknown repository approval draft mode: repo-health-doctor sandbox-approval-draft <path> [--format json|markdown] [--phase phase2_install_probe|phase3_runtime_probe --kind KIND --cwd /workspace --argv ARG ...]; --argv must be last"
            if sandbox_approval_draft_mode
            else "Report diff mode: repo-health-doctor diff-reports before.json after.json [--format json|markdown]"
            if diff_reports_mode
            else
            "Release mode: repo-health-doctor release-check <path> [--baseline-report before.json] [--format json|markdown]"
            if release_check_mode
            else "Authorization draft mode: repo-health-doctor authorization draft --gate-decision gate.json --argv-json argv.json --output authorization.json"
            if authorization_draft_mode
            else "Authorization validate mode: repo-health-doctor authorization validate --authorization authorization.json --gate-decision gate.json --argv-json argv.json"
            if authorization_validate_mode
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
    elif authorization_draft_mode or authorization_validate_mode:
        pass
    else:
        parser.add_argument("path", nargs="?", default=".", help="Repository path to inspect.")
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "md"),
        default="text",
        help=(
            "Stdout format. --output always writes the machine-readable JSON report."
            if sandbox_run_mode
            else "Output format."
        ),
    )
    parser.add_argument(
        "--output",
        help=(
            "Write the sandbox-run JSON report to a file while also printing the selected stdout format."
            if sandbox_run_mode
            else "Write the rendered report to a file while also printing to stdout."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"repo-health-doctor {TOOL_VERSION}",
    )
    if not validate_mode and not list_allows_mode and not diff_reports_mode and not sandbox_mode and not sandbox_run_mode and not sandbox_profile_mode and not sandbox_approval_draft_mode and not authorization_draft_mode and not authorization_validate_mode:
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
    if not validate_mode and not list_allows_mode and not diff_reports_mode and not sandbox_mode and not sandbox_run_mode and not sandbox_profile_mode and not sandbox_approval_draft_mode and not authorization_draft_mode and not authorization_validate_mode:
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
    if not validate_mode and not list_allows_mode and not diff_reports_mode and not release_check_mode and not sandbox_mode and not sandbox_run_mode and not sandbox_profile_mode and not sandbox_approval_draft_mode and not authorization_draft_mode and not authorization_validate_mode:
        parser.add_argument(
            "--public-safety",
            action="store_true",
            help="Enable extra checks for public release safety.",
        )
        parser.add_argument(
            "--gate-decision-output",
            help="Opt-in sidecar path for a pre-execution gate decision JSON. The default v3 report output is unchanged.",
        )
        parser.add_argument(
            "--gate-summary",
            action="store_true",
            help="Opt-in human-readable gate summary for demos and review. The default v3 report output is unchanged.",
        )
    if release_check_mode:
        parser.add_argument(
            "--baseline-report",
            help="Optional earlier scan JSON report to summarize current changes against.",
        )
    if authorization_draft_mode or authorization_validate_mode:
        parser.add_argument("--gate-decision", required=True, help="Gate decision JSON used as the authorization basis.")
        parser.add_argument("--argv-json", required=True, help="JSON array containing the exact argv to authorize or validate.")
    if authorization_validate_mode:
        parser.add_argument("--authorization", required=True, help="Execution authorization artifact JSON to validate.")
    if sandbox_mode:
        parser.add_argument(
            "--plan",
            action="store_true",
            help="Emit a plan-only sandbox report. This remains the default mode.",
        )
        parser.add_argument(
            "--approval-file",
            help="Read an approval file and match it against normalized command candidates.",
        )
        parser.add_argument(
            "--docker-image",
            help="Explicit Docker image reference for sandbox execution gates. Prefer registry digest references; local images require explicit sanctioning and a matching full expected image ID.",
        )
        parser.add_argument(
            "--allow-local-image",
            action="store_true",
            help="Allow a local Docker image reference only when --expected-image-id is also supplied and matches docker image inspect output exactly.",
        )
        parser.add_argument(
            "--expected-image-id",
            help="Expected full local image ID for --allow-local-image, for example sha256:<64 lowercase hex>.",
        )
        parser.add_argument(
            "--run-preflight",
            action="store_true",
            help="Run fixed harmless Docker preflight commands only when all sandbox safety gates are satisfied.",
        )
        parser.add_argument(
            "--run-strace-smoke",
            action="store_true",
            help="Run a fixed harmless target-process strace smoke only when image policy, Docker preflight, and observer gates pass.",
        )
        parser.add_argument(
            "--preflight-timeout-seconds",
            type=int,
            default=10,
            help="Timeout in seconds for each fixed Docker preflight command.",
        )
        parser.add_argument(
            "--run-phase1",
            action="store_true",
            help="Run Phase 1 dependency fetch commands only when an accepted execution image and Docker preflight gates pass.",
        )
        parser.add_argument(
            "--phase1-timeout-seconds",
            type=int,
            default=180,
            help="Timeout in seconds for each Phase 1 dependency fetch command.",
        )
        parser.add_argument(
            "--run-phase2",
            action="store_true",
            help="Run approved Phase 2 install-script probes only when all sandbox safety gates, observer gates, and approval gates pass.",
        )
        parser.add_argument(
            "--run-phase3",
            action="store_true",
            help="Run approved Phase 3 runtime probes only when all sandbox safety gates, observer gates, and approval gates pass.",
        )
        parser.add_argument(
            "--dynamic-timeout-seconds",
            type=int,
            default=60,
            help="Timeout in seconds for each Phase 2 or Phase 3 dynamic probe command.",
        )
    if sandbox_run_mode:
        parser.add_argument("--approval", help="Sandbox-run approval artifact JSON. Missing or mismatched approval blocks execution.")
        parser.add_argument("--image", help="Docker image reference. The image must match approval and be available locally.")
        parser.add_argument(
            "--profile",
            default="no-network-default",
            choices=("no-network-default", "no-network-readonly", "network-explicit"),
            help="Sandbox profile. network-explicit is reserved and fails closed in S-001.",
        )
        parser.add_argument(
            "--timeout-seconds",
            type=int,
            default=30,
            help="Python-enforced timeout. It must not exceed the approved timeout.",
        )
        parser.add_argument(
            "--runner",
            default="docker",
            choices=("docker", "fake", "fake-docker-unavailable", "fake-image-unavailable", "fake-timeout", "fake-failure"),
            help="Runner backend. Fake modes are for tests and documentation smoke checks only.",
        )
    if sandbox_approval_draft_mode:
        parser.add_argument("--phase", choices=("phase2_install_probe", "phase3_runtime_probe"))
        parser.add_argument("--kind", help="Normalized candidate kind. T0 requires a harmless_ kind.")
        parser.add_argument("--cwd", help="Logical candidate cwd, limited to /workspace.")
        parser.add_argument("--argv", nargs=argparse.REMAINDER, help="Exact argv candidate; must be last and shell forms are rejected.")
        parser.add_argument("--env-allow", action="append", default=[], help="Allowed environment variable name. Can be passed multiple times.")
        parser.add_argument("--shell", action="store_true", help="Rejected: shell candidates are never draftable.")
        parser.add_argument("--network-policy", default="none", help="Only 'none' is accepted; network-enabled candidates are rejected.")
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
    if not diff_reports_mode and not sandbox_mode and not sandbox_run_mode and not sandbox_profile_mode and not sandbox_approval_draft_mode and not authorization_draft_mode and not authorization_validate_mode:
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
    sandbox_run_argv: list[str] = []
    if raw_args and raw_args[0] == "validate-policy":
        command = "validate-policy"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "list-allows":
        command = "list-allows"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "diff-reports":
        command = "diff-reports"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "release-check":
        command = "release-check"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "sandbox":
        command = "sandbox"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "sandbox-run":
        command = "sandbox-run"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "sandbox-profile":
        command = "sandbox-profile"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "sandbox-approval-draft":
        command = "sandbox-approval-draft"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "authorization":
        if len(raw_args) < 2 or raw_args[1] not in {"draft", "validate"}:
            command = "authorization-draft"
            raw_args = raw_args[1:]
        else:
            command = f"authorization-{raw_args[1]}"
            raw_args = raw_args[2:]

    if command == "sandbox-run" and "--" in raw_args:
        separator_index = raw_args.index("--")
        sandbox_run_argv = raw_args[separator_index + 1:]
        raw_args = raw_args[:separator_index]

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
    elif command in {"authorization-draft", "authorization-validate"}:
        try:
            gate_decision = _load_json_object(Path(args.gate_decision), "gate decision")
            argv = _load_argv_json(Path(args.argv_json))
            if command == "authorization-draft":
                report = build_execution_authorization_draft(gate_decision, argv)
                authorization_valid = True
            else:
                authorization = _load_json_object(Path(args.authorization), "authorization")
                validation = validate_execution_authorization(authorization, gate_decision, argv)
                report = validation.to_dict()
                authorization_valid = validation.execution_authorized
        except ValueError as exc:
            parser.error(str(exc))
        fail_on = None
    else:
        target = Path(args.path)
        if not target.exists():
            parser.error(f"path does not exist: {target}")
        if command == "sandbox":
            if args.preflight_timeout_seconds <= 0:
                parser.error("--preflight-timeout-seconds must be greater than 0")
            if args.phase1_timeout_seconds <= 0:
                parser.error("--phase1-timeout-seconds must be greater than 0")
            if args.dynamic_timeout_seconds <= 0:
                parser.error("--dynamic-timeout-seconds must be greater than 0")
            report = run_sandbox(
                target,
                approval_file=args.approval_file,
                docker_image=args.docker_image,
                allow_local_image=args.allow_local_image,
                expected_image_id=args.expected_image_id,
                run_preflight=args.run_preflight,
                run_strace_smoke=args.run_strace_smoke,
                preflight_timeout_seconds=args.preflight_timeout_seconds,
                run_phase1=args.run_phase1,
                phase1_timeout_seconds=args.phase1_timeout_seconds,
                run_phase2=args.run_phase2,
                run_phase3=args.run_phase3,
                dynamic_timeout_seconds=args.dynamic_timeout_seconds,
            )
            fail_on = "block"
        elif command == "sandbox-run":
            if args.timeout_seconds <= 0:
                parser.error("--timeout-seconds must be greater than 0")
            runner = None if args.runner == "docker" else make_fake_runner(args.runner)
            report = run_sandbox_run(
                target,
                approval_path=Path(args.approval) if args.approval else None,
                image=args.image,
                profile_name=args.profile,
                command_argv=sandbox_run_argv,
                timeout_seconds=args.timeout_seconds,
                runner=runner,
            )
            fail_on = None
        elif command == "sandbox-profile":
            report = profile_unknown_repo(target)
            fail_on = "block"
        elif command == "sandbox-approval-draft":
            try:
                report = generate_unknown_repo_approval_draft(
                    target,
                    phase=args.phase,
                    kind=args.kind,
                    cwd=args.cwd,
                    argv=tuple(args.argv or ()),
                    env_allowlist=tuple(args.env_allow),
                    shell=args.shell,
                    network_policy=args.network_policy,
                )
            except ValueError as exc:
                parser.error(str(exc))
            fail_on = "block"
        elif command == "validate-policy":
            report = validate_policy(
                target,
                config_path=args.config,
                local_config_path=args.local_config,
                load_local_config=not args.no_local_config,
            )
            fail_on = "block"
        elif command == "release-check":
            if args.large_file_threshold_mb <= 0:
                parser.error("--large-file-threshold-mb must be greater than 0")
            if args.baseline_report:
                baseline_report = Path(args.baseline_report)
                if not baseline_report.exists():
                    parser.error(f"path does not exist: {baseline_report}")
            try:
                report = release_check(
                    target,
                    large_file_threshold_mb=args.large_file_threshold_mb,
                    secrets_ignores=tuple(args.secrets_ignore),
                    config_path=args.config,
                    local_config_path=args.local_config,
                    load_local_config=not args.no_local_config,
                    baseline_report_path=args.baseline_report,
                )
            except ValueError as exc:
                parser.error(str(exc))
            fail_on = "warn" if args.strict else args.fail_on
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
    if command in {"authorization-draft", "authorization-validate"}:
        output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    elif command == "sandbox-run":
        if args.format == "json":
            output = format_sandbox_run_json(report)
        elif args.format in {"markdown", "md"}:
            output = format_sandbox_run_markdown(report)
        else:
            output = format_sandbox_run_text(report)
    elif command == "sandbox":
        if args.format == "json":
            output = format_sandbox_json(report)
        elif args.format in {"markdown", "md"}:
            output = format_sandbox_markdown(report)
        else:
            output = format_sandbox_text(report)
    elif command == "sandbox-profile":
        if args.format == "json":
            output = format_unknown_repo_profile_json(report)
        elif args.format in {"markdown", "md"}:
            output = format_unknown_repo_profile_markdown(report)
        else:
            output = format_unknown_repo_profile_text(report)
    elif command == "sandbox-approval-draft":
        if args.format == "json":
            output = format_unknown_repo_approval_draft_json(report)
        elif args.format in {"markdown", "md"}:
            output = format_unknown_repo_approval_draft_markdown(report)
        else:
            output = format_unknown_repo_approval_draft_text(report)
    else:
        if args.format == "json":
            output = format_json(report)
        elif args.format in {"markdown", "md"}:
            output = format_markdown(report)
        else:
            output = format_text(report)
    gate_decision = None
    if command == "scan" and (getattr(args, "gate_decision_output", None) or getattr(args, "gate_summary", False)):
        gate_decision = evaluate_gate_decision_from_v3_report(report)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        file_output = format_sandbox_run_json(report) if command == "sandbox-run" else output
        output_path.write_text(file_output, encoding="utf-8")
    if command == "scan" and getattr(args, "gate_decision_output", None) and gate_decision is not None:
        gate_output_path = Path(args.gate_decision_output)
        gate_output_path.parent.mkdir(parents=True, exist_ok=True)
        gate_output_path.write_text(json.dumps(gate_decision, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if command == "scan" and getattr(args, "gate_summary", False) and gate_decision is not None:
        sys.stdout.write(format_gate_summary(report, gate_decision))
    sys.stdout.write(output)
    if command == "sandbox-profile":
        return 1 if report["overall_status"] == "block" else 0
    if command == "sandbox-approval-draft":
        return 1 if report["source_risk_tier"] in {"T4", "T5"} else 0
    if command == "sandbox-run":
        return 0 if report["result"]["status"] == "completed" else 1
    if command == "authorization-validate":
        return 0 if authorization_valid else 1
    return 0 if fail_on is None else determine_exit_code(report, fail_on=fail_on)


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    if not path.exists():
        raise ValueError(f"{label} path does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} JSON parse failed: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _load_argv_json(path: Path) -> list[str]:
    if not path.exists():
        raise ValueError(f"argv JSON path does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"argv JSON parse failed: {exc.msg}") from exc
    if not isinstance(payload, list) or not payload or not all(isinstance(item, str) and item for item in payload):
        raise ValueError("argv JSON must be a non-empty JSON array of strings")
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
