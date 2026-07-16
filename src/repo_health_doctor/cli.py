from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping, Sequence

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
from .sandbox.profiles import SECCOMP_PROFILE_CHOICES, SECCOMP_RUNTIME_DEFAULT
from .gate import (
    build_execution_authorization_draft,
    evaluate_gate_decision_from_v3_report,
    format_gate_summary,
    validate_execution_authorization,
)
from .gate.authorization_discovery import discover_execution_authorization
from .gate.evaluator import ExternalSuiteGateEvidence
from .gate.external_evidence import (
    EXTERNAL_SUITE_EVIDENCE_MAX_BYTES,
    EXTERNAL_SUITE_EVIDENCE_MAX_COUNT,
    validate_external_suite_evidence,
)
from .external_scanner import (
    REAL_SCANNER_ADAPTER_NAMES,
    REAL_SCANNER_DEFAULT_TIMEOUT_SECONDS,
    REAL_SCANNER_MAX_FINDINGS,
    REAL_SCANNER_MAX_FINDINGS_PER_SCANNER,
    REAL_SCANNER_MAX_REPORT_BYTES,
    run_real_scanner_suite_sequential,
)
from .formatters import format_real_scanner_suite


GATE_FAIL_MODES: Mapping[str, frozenset[str]] = {
    "block": frozenset({"block"}),
    "quarantine": frozenset({"quarantine", "block"}),
    "warn": frozenset({"warn", "quarantine", "block"}),
    "unknown": frozenset({"unknown", "warn", "quarantine", "block"}),
}
GATE_CHECK_SCHEMA_VERSION = "0.1-draft"


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
    gate_check_mode = command == "gate-check"
    real_scan_mode = command == "real-scan"
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
            else "repo-health-doctor gate-check"
            if gate_check_mode
            else "repo-health-doctor real-scan"
            if real_scan_mode
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
            else "Run one explicit argv in the sandbox-run v1 locked-down Docker runtime and emit redacted evidence."
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
            else "Run the experimental gate decision and authorization check as one fail-closed command."
            if gate_check_mode
            else "Run selected real scanner adapters and emit a bounded report."
            if real_scan_mode
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
            else "Sandbox-run mode: repo-health-doctor sandbox-run <path> --profile locked-down [--fail-on-gate quarantine] -- COMMAND ARG..."
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
            else "Gate-check mode: repo-health-doctor gate-check <path> --authorization authorization.json --argv-json argv.json [--fail-on-gate unknown]"
            if gate_check_mode
            else "Real-scan mode: repo-health-doctor real-scan <path> [--scanner NAME ...] [--offline] [--fail-on-degraded] [--format text|json|markdown]"
            if real_scan_mode
            else "Policy-only mode: repo-health-doctor validate-policy <path> [--format json|markdown]"
            if validate_mode
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
    if not validate_mode and not list_allows_mode and not diff_reports_mode and not sandbox_mode and not sandbox_run_mode and not sandbox_profile_mode and not sandbox_approval_draft_mode and not authorization_draft_mode and not authorization_validate_mode and not gate_check_mode and not real_scan_mode:
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
    if not validate_mode and not list_allows_mode and not diff_reports_mode and not sandbox_mode and not sandbox_run_mode and not sandbox_profile_mode and not sandbox_approval_draft_mode and not authorization_draft_mode and not authorization_validate_mode and not real_scan_mode:
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
    if not validate_mode and not list_allows_mode and not diff_reports_mode and not release_check_mode and not sandbox_mode and not sandbox_run_mode and not sandbox_profile_mode and not sandbox_approval_draft_mode and not authorization_draft_mode and not authorization_validate_mode and not real_scan_mode:
        parser.add_argument(
            "--public-safety",
            action="store_true",
            help="Enable extra checks for public release safety.",
        )
        parser.add_argument(
            "--fail-on-gate",
            choices=tuple(GATE_FAIL_MODES),
            default="unknown" if gate_check_mode else None,
            help=(
                "Exit with code 2 when the gate decision is UNKNOWN, WARN, QUARANTINE, or BLOCK."
                if gate_check_mode
                else "Exit with code 2 when the gate decision meets the selected threshold."
            ),
        )
        parser.add_argument(
            "--gate-decision-output",
            help="Opt-in sidecar path for a pre-execution gate decision JSON. The default v3 report output is unchanged.",
        )
        if not gate_check_mode:
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
    if gate_check_mode:
        parser.add_argument("--authorization", help="Execution authorization artifact JSON to validate.")
        parser.add_argument("--argv-json", help="JSON array containing the exact argv to validate.")
        parser.add_argument(
            "--no-discover",
            action="store_true",
            help="Do not discover the single repository-root authorization candidate.",
        )
        parser.add_argument(
            "--external-evidence",
            action="append",
            default=[],
            help="Real scanner suite report to validate. Repeat for multiple reports; raw reports are not embedded.",
        )
    if real_scan_mode:
        parser.add_argument(
            "--scanner",
            action="append",
            choices=REAL_SCANNER_ADAPTER_NAMES,
            dest="scanners",
            help="Select a scanner. Repeat the option to select multiple scanners; defaults to all scanners.",
        )
        parser.add_argument(
            "--offline",
            action="store_true",
            help="Skip scanners that can use the network.",
        )
        parser.add_argument(
            "--timeout-seconds",
            "--timeout",
            dest="timeout_seconds",
            type=int,
            default=REAL_SCANNER_DEFAULT_TIMEOUT_SECONDS,
            help="Timeout in seconds for each scanner command.",
        )
        parser.add_argument(
            "--max-findings-per-scanner",
            "--per-scanner-finding-budget",
            dest="max_findings_per_scanner",
            type=int,
            default=REAL_SCANNER_MAX_FINDINGS_PER_SCANNER,
            help="Maximum normalized findings retained for each scanner.",
        )
        parser.add_argument(
            "--max-findings",
            "--suite-finding-budget",
            dest="max_findings",
            type=int,
            default=REAL_SCANNER_MAX_FINDINGS,
            help="Maximum normalized findings retained across the suite.",
        )
        parser.add_argument(
            "--max-report-bytes",
            "--report-byte-budget",
            dest="max_report_bytes",
            type=int,
            default=REAL_SCANNER_MAX_REPORT_BYTES,
            help="Maximum compact JSON report size before findings are truncated.",
        )
        parser.add_argument(
            "--fail-on-degraded",
            action="store_true",
            help="Return exit code 1 when the suite is degraded, including offline skips or truncation.",
        )
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
        parser.add_argument("--approval", help="Legacy sandbox-run approval artifact JSON. If supplied, mismatches block execution.")
        parser.add_argument("--authorization", help="Execution authorization artifact JSON for gate-bound sandbox-run execution.")
        parser.add_argument("--image", default="python:3.12-slim", help="Docker image reference. It must be available locally; sandbox-run uses --pull=never.")
        parser.add_argument(
            "--profile",
            default="locked-down",
            choices=("locked-down", "inspect-only", "dev-permissive", "no-network-default", "no-network-readonly", "network-explicit"),
            help="Sandbox profile. locked-down is the v1 default; dev-permissive and network-explicit fail closed.",
        )
        parser.add_argument(
            "--seccomp",
            default=SECCOMP_RUNTIME_DEFAULT,
            type=_parse_seccomp_profile,
            metavar="{runtime-default,rhd-moby-default-v1}",
            help="Seccomp profile. runtime-default preserves the Docker runtime default.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Generate sandbox-run evidence and Docker argv without invoking Docker.",
        )
        parser.add_argument(
            "--evidence-output",
            help="Write the sandbox-run JSON evidence report to a file. Alias for --output.",
        )
        parser.add_argument(
            "--fail-on-gate",
            choices=tuple(GATE_FAIL_MODES),
            help="Exit with code 2 before Docker when the generated gate decision meets the selected threshold.",
        )
        parser.add_argument(
            "--preserve-workspace",
            action="store_true",
            help="Do not delete the disposable run root. Evidence still redacts the host path.",
        )
        parser.add_argument(
            "--timeout-seconds",
            type=int,
            default=30,
            help="Python-enforced timeout for the Docker command.",
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
    if not diff_reports_mode and not sandbox_mode and not sandbox_run_mode and not sandbox_profile_mode and not sandbox_approval_draft_mode and not authorization_draft_mode and not authorization_validate_mode and not real_scan_mode:
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
    gate_check_argv: list[str] = []
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
    elif raw_args and raw_args[0] == "gate-check":
        command = "gate-check"
        raw_args = raw_args[1:]
    elif raw_args and raw_args[0] == "real-scan":
        command = "real-scan"
        raw_args = raw_args[1:]

    if command in {"sandbox-run", "gate-check"} and "--" in raw_args:
        separator_index = raw_args.index("--")
        trailing_argv = raw_args[separator_index + 1:]
        if command == "sandbox-run":
            sandbox_run_argv = trailing_argv
        else:
            gate_check_argv = trailing_argv
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
            if command == "real-scan":
                parser.error("path does not exist")
            parser.error(f"path does not exist: {target}")
        if command == "real-scan":
            if args.timeout_seconds <= 0:
                parser.error("--timeout-seconds must be greater than 0")
            for option_name in ("max_findings_per_scanner", "max_findings", "max_report_bytes"):
                if getattr(args, option_name) <= 0:
                    parser.error(f"--{option_name.replace('_', '-')} must be greater than 0")
            suite_kwargs = {}
            if args.max_findings_per_scanner != REAL_SCANNER_MAX_FINDINGS_PER_SCANNER:
                suite_kwargs["max_findings_per_scanner"] = args.max_findings_per_scanner
            if args.max_findings != REAL_SCANNER_MAX_FINDINGS:
                suite_kwargs["max_findings"] = args.max_findings
            if args.max_report_bytes != REAL_SCANNER_MAX_REPORT_BYTES:
                suite_kwargs["max_report_bytes"] = args.max_report_bytes
            try:
                report = run_real_scanner_suite_sequential(
                    target,
                    timeout_seconds=args.timeout_seconds,
                    offline=args.offline,
                    scanners=tuple(args.scanners or REAL_SCANNER_ADAPTER_NAMES),
                    **suite_kwargs,
                )
            except ValueError as exc:
                parser.error(str(exc))
            fail_on = None
        elif command == "sandbox":
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
            if args.output and args.evidence_output:
                parser.error("--output and --evidence-output cannot both be used")
            runner = None if args.runner == "docker" else make_fake_runner(args.runner)
            sandbox_gate_decision = None
            sandbox_authorization_validation = None
            if args.fail_on_gate or args.authorization:
                scan_report = diagnose_repo(
                    target,
                    large_file_threshold_mb=DEFAULT_LARGE_FILE_THRESHOLD_MB,
                    secrets_ignores=(),
                    public_safety=True,
                    config_path=None,
                    local_config_path=None,
                    load_local_config=True,
                )
                sandbox_gate_decision = evaluate_gate_decision_from_v3_report(scan_report, repo_root=target)
            if args.authorization:
                try:
                    authorization = _load_json_object(Path(args.authorization), "authorization")
                    sandbox_authorization_validation = validate_execution_authorization(
                        authorization,
                        _mapping(sandbox_gate_decision),
                        sandbox_run_argv,
                    )
                except ValueError as exc:
                    parser.error(str(exc))
            report = run_sandbox_run(
                target,
                approval_path=Path(args.approval) if args.approval else None,
                image=args.image,
                profile_name=args.profile,
                seccomp_profile_name=args.seccomp,
                command_argv=sandbox_run_argv,
                timeout_seconds=args.timeout_seconds,
                runner=runner,
                dry_run=args.dry_run,
                preserve_workspace=args.preserve_workspace,
                gate_decision=sandbox_gate_decision,
                fail_on_gate=args.fail_on_gate,
                authorization_path=Path(args.authorization) if args.authorization else None,
                authorization_validation=sandbox_authorization_validation,
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
        elif command == "gate-check":
            if args.large_file_threshold_mb <= 0:
                parser.error("--large-file-threshold-mb must be greater than 0")
            if len(args.external_evidence) > EXTERNAL_SUITE_EVIDENCE_MAX_COUNT:
                parser.error(
                    f"--external-evidence accepts at most {EXTERNAL_SUITE_EVIDENCE_MAX_COUNT} reports"
                )
            if gate_check_argv and args.argv_json:
                parser.error("--argv-json cannot be combined with trailing argv")
            if args.authorization and not args.argv_json:
                if not gate_check_argv:
                    parser.error("--argv-json is required when --authorization is provided without trailing argv")
            if args.argv_json and not args.authorization:
                parser.error("--authorization is required when --argv-json is provided")
            scan_report = diagnose_repo(
                target,
                large_file_threshold_mb=args.large_file_threshold_mb,
                secrets_ignores=tuple(args.secrets_ignore),
                public_safety=True,
                config_path=args.config,
                local_config_path=args.local_config,
                load_local_config=not args.no_local_config,
            )
            try:
                external_suite_evidence = _load_external_suite_evidence(
                    args.external_evidence,
                    target=target,
                )
            except ValueError as exc:
                parser.error(str(exc))
            gate_decision = evaluate_gate_decision_from_v3_report(
                scan_report,
                repo_root=target,
                external_suite_evidence=external_suite_evidence,
            )
            authorization_validation = None
            if args.authorization:
                try:
                    authorization = _load_json_object(Path(args.authorization), "authorization")
                    argv = gate_check_argv or _load_argv_json(Path(args.argv_json))
                    authorization_validation = validate_execution_authorization(authorization, gate_decision, argv)
                except ValueError as exc:
                    parser.error(str(exc))
            elif gate_check_argv and not args.no_discover:
                discovered = discover_execution_authorization(target)
                if discovered.discovered and discovered.authorization is not None:
                    authorization_validation = validate_execution_authorization(
                        discovered.authorization,
                        gate_decision,
                        gate_check_argv,
                    )
            report = _build_gate_check_report(
                gate_decision,
                fail_on_gate=args.fail_on_gate,
                authorization_validation=authorization_validation,
            )
            fail_on = None
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
    elif command == "gate-check":
        if args.format == "json":
            output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        elif args.format in {"markdown", "md"}:
            output = _format_gate_check_markdown(report)
        else:
            output = _format_gate_check_text(report)
    elif command == "sandbox-approval-draft":
        if args.format == "json":
            output = format_unknown_repo_approval_draft_json(report)
        elif args.format in {"markdown", "md"}:
            output = format_unknown_repo_approval_draft_markdown(report)
        else:
            output = format_unknown_repo_approval_draft_text(report)
    elif command == "real-scan":
        output = format_real_scanner_suite(report, args.format)
    else:
        if args.format == "json":
            output = format_json(report)
        elif args.format in {"markdown", "md"}:
            output = format_markdown(report)
        else:
            output = format_text(report)
    gate_decision = None
    if command == "scan" and (
        getattr(args, "gate_decision_output", None)
        or getattr(args, "gate_summary", False)
        or getattr(args, "fail_on_gate", None)
    ):
        gate_decision = evaluate_gate_decision_from_v3_report(report, repo_root=target)
    sandbox_output_path = getattr(args, "evidence_output", None) if command == "sandbox-run" else None
    if args.output or sandbox_output_path:
        output_path = Path(sandbox_output_path or args.output)
        file_output = format_sandbox_run_json(report) if command == "sandbox-run" else output
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(file_output, encoding="utf-8")
        except OSError:
            if command == "real-scan":
                sys.stderr.write("REAL-SCAN OUTPUT ERROR: unable to write report.\n")
                return 2
            raise
    if command == "gate-check":
        gate_decision = _mapping(report.get("gate_decision"))
    if command in {"scan", "gate-check"} and getattr(args, "gate_decision_output", None) and gate_decision is not None:
        gate_output_path = Path(args.gate_decision_output)
        gate_output_path.parent.mkdir(parents=True, exist_ok=True)
        gate_output_path.write_text(json.dumps(gate_decision, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if command == "scan" and getattr(args, "gate_summary", False) and gate_decision is not None:
        sys.stdout.write(format_gate_summary(report, gate_decision))
    sys.stdout.write(output)
    if command == "sandbox-profile":
        return 1 if report["overall_status"] == "block" else 0
    if command == "real-scan":
        return 1 if args.fail_on_degraded and report.suite_status == "degraded" else 0
    if command == "sandbox-approval-draft":
        return 1 if report["source_risk_tier"] in {"T4", "T5"} else 0
    if command == "sandbox-run":
        return _sandbox_run_exit_code(report)
    if command == "authorization-validate":
        return 0 if authorization_valid else 1
    if command == "gate-check":
        if report.get("status") != "authorized":
            sys.stderr.write(_format_gate_block_stderr(_mapping(report.get("gate_decision")), report))
            return 2
        return 0
    if command == "scan" and gate_decision is not None and getattr(args, "fail_on_gate", None):
        if _gate_matches_fail_on(gate_decision, args.fail_on_gate):
            sys.stderr.write(_format_gate_block_stderr(gate_decision))
            return 2
    return 0 if fail_on is None else determine_exit_code(report, fail_on=fail_on)


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    if not path.exists():
        raise ValueError(f"{label} path does not exist: <path>")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} JSON parse failed: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _load_argv_json(path: Path) -> list[str]:
    if not path.exists():
        raise ValueError("argv JSON path does not exist: <path>")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"argv JSON parse failed: {exc.msg}") from exc
    if not isinstance(payload, list) or not payload or not all(isinstance(item, str) and item for item in payload):
        raise ValueError("argv JSON must be a non-empty JSON array of strings")
    return payload


def _load_external_suite_evidence(
    paths: Sequence[str],
    *,
    target: Path,
) -> tuple[ExternalSuiteGateEvidence, ...]:
    expected_subject = _external_evidence_subject(target)
    seen_fingerprints: set[str] = set()
    evidence: list[ExternalSuiteGateEvidence] = []
    for path_value in paths:
        path = Path(path_value)
        try:
            if not path.is_file():
                raise ValueError("external evidence path is not a regular file: <path>")
            source_size_bytes = path.stat().st_size
            with path.open("rb") as handle:
                raw = handle.read(EXTERNAL_SUITE_EVIDENCE_MAX_BYTES + 1)
        except OSError as exc:
            raise ValueError("external evidence could not be read: <path>") from exc

        measured_size = max(source_size_bytes, len(raw))
        payload: object = None
        if measured_size <= EXTERNAL_SUITE_EVIDENCE_MAX_BYTES:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = None

        validation = validate_external_suite_evidence(
            payload,
            expected_subject=expected_subject,
            source_size_bytes=measured_size,
            seen_fingerprints=seen_fingerprints,
        )
        report = payload if isinstance(payload, Mapping) else {}
        evidence.append(ExternalSuiteGateEvidence(report=report, validation=validation))
        fingerprint = validation.evidence_ref.get("report_fingerprint")
        if isinstance(fingerprint, str):
            seen_fingerprints.add(fingerprint)
    return tuple(evidence)


def _external_evidence_subject(target: Path) -> Mapping[str, object]:
    commit = _git_output(target, ("rev-parse", "HEAD"))
    if commit is not None and (
        len(commit) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        commit = None
    status = _git_output(target, ("status", "--short"))
    dirty_state = "unknown" if status is None else ("dirty" if status else "clean")
    return {"repo_commit": commit, "dirty_state": dirty_state}


def _git_output(target: Path, argv: Sequence[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(target), *argv],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _build_gate_check_report(
    gate_decision: Mapping[str, Any],
    *,
    fail_on_gate: str,
    authorization_validation: Any | None,
) -> dict[str, object]:
    gate_blocked = _gate_matches_fail_on(gate_decision, fail_on_gate)
    auth_payload = authorization_validation.to_dict() if authorization_validation is not None else None
    auth_valid = bool(auth_payload and auth_payload.get("execution_authorized") is True)
    blocking_reasons: list[str] = []
    if gate_blocked:
        blocking_reasons.append(f"gate_verdict_{str(gate_decision.get('verdict', 'unknown'))}")
    if authorization_validation is None:
        blocking_reasons.append("authorization_missing")
    elif not auth_valid:
        blocking_reasons.extend(_string_items(auth_payload.get("blocking_errors") if auth_payload else None))
        if not blocking_reasons:
            blocking_reasons.append("authorization_invalid")
    status = "authorized" if auth_valid and not gate_blocked else "blocked"
    return {
        "report_kind": "gate_check",
        "schema_version": GATE_CHECK_SCHEMA_VERSION,
        "status": status,
        "execution_authorized": status == "authorized",
        "fail_on_gate": fail_on_gate,
        "gate_decision": dict(gate_decision),
        "authorization": auth_payload,
        "blocking_reasons": list(dict.fromkeys(blocking_reasons)),
        "limitations": [
            "experimental_gate_check_contract",
            "gate_decision_is_not_execution_authorization",
            "authorization_must_match_exact_scope_argv_policy_and_gate_decision",
        ],
    }


def _gate_matches_fail_on(gate_decision: Mapping[str, Any], fail_on_gate: str | None) -> bool:
    if fail_on_gate is None:
        return False
    verdict = str(gate_decision.get("verdict", "unknown")).lower()
    return verdict in GATE_FAIL_MODES[fail_on_gate]


def _format_gate_block_stderr(
    gate_decision: Mapping[str, Any],
    gate_check_report: Mapping[str, Any] | None = None,
) -> str:
    explanation = gate_decision.get("explanation") if isinstance(gate_decision.get("explanation"), Mapping) else {}
    key_reasons = _string_items(explanation.get("key_reasons"))
    next_actions = _string_items(explanation.get("next_actions"))
    if not key_reasons:
        key_reasons = ["Gate decision did not authorize execution."]
    if not next_actions:
        next_actions = ["Review gate evidence and obtain explicit authorization before execution."]
    lines = [
        "Repo Health Doctor gate blocked execution.",
        f"Gate decision: {str(gate_decision.get('verdict', 'unknown')).upper()}",
        f"Execution authorized: {'true' if gate_check_report and gate_check_report.get('execution_authorized') is True else 'false'}",
    ]
    blocking_reasons = _string_items(gate_check_report.get("blocking_reasons") if gate_check_report else None)
    if blocking_reasons:
        lines.extend(["", "Blocking reasons:"])
        lines.extend(f"- {item}" for item in blocking_reasons[:6])
    lines.extend(["", "Key reasons:"])
    lines.extend(f"- {item}" for item in key_reasons[:6])
    lines.extend(["", "Next actions:"])
    lines.extend(f"- {item}" for item in next_actions[:6])
    return "\n".join(lines) + "\n"


def _format_gate_check_text(report: Mapping[str, Any]) -> str:
    gate_decision = _mapping(report.get("gate_decision"))
    lines = [
        "Repo Health Doctor Gate Check",
        f"Status: {str(report.get('status', 'blocked')).upper()}",
        f"Gate decision: {str(gate_decision.get('verdict', 'unknown')).upper()}",
        f"Execution authorized: {'true' if report.get('execution_authorized') is True else 'false'}",
        f"Fail-on-gate: {report.get('fail_on_gate', 'unknown')}",
    ]
    evidence_refs = gate_decision.get("evidence_refs")
    if isinstance(evidence_refs, list):
        lines.extend(["", f"Evidence refs: {len(evidence_refs)}"])
        lines.extend(f"- {_format_evidence_ref(item)}" for item in evidence_refs)
    blocking_reasons = _string_items(report.get("blocking_reasons"))
    if blocking_reasons:
        lines.extend(["", "Blocking reasons:"])
        lines.extend(f"- {item}" for item in blocking_reasons)
    return "\n".join(lines) + "\n"


def _format_gate_check_markdown(report: Mapping[str, Any]) -> str:
    gate_decision = _mapping(report.get("gate_decision"))
    lines = [
        "# Repo Health Doctor Gate Check",
        "",
        f"- Status: `{str(report.get('status', 'blocked')).upper()}`",
        f"- Gate decision: `{str(gate_decision.get('verdict', 'unknown')).upper()}`",
        f"- Execution authorized: `{'true' if report.get('execution_authorized') is True else 'false'}`",
        f"- Fail-on-gate: `{report.get('fail_on_gate', 'unknown')}`",
    ]
    evidence_refs = gate_decision.get("evidence_refs")
    if isinstance(evidence_refs, list):
        lines.extend(["", "## Evidence References"])
        lines.extend(f"- `{_format_evidence_ref(item)}`" for item in evidence_refs)
    blocking_reasons = _string_items(report.get("blocking_reasons"))
    if blocking_reasons:
        lines.extend(["", "## Blocking Reasons"])
        lines.extend(f"- `{item}`" for item in blocking_reasons)
    return "\n".join(lines) + "\n"


def _format_evidence_ref(value: object) -> str:
    evidence_ref = _mapping(value)
    fingerprint = evidence_ref.get("report_fingerprint")
    status = str(evidence_ref.get("validation_status", "invalid"))
    reasons = _string_items(evidence_ref.get("reasons"))
    reason_text = ",".join(reasons) if reasons else "none"
    return f"{fingerprint if isinstance(fingerprint, str) else 'fingerprint-unavailable'} status={status} reasons={reason_text}"


def _sandbox_run_exit_code(report: Mapping[str, Any]) -> int:
    sandbox_exit_code = report.get("sandbox_exit_code")
    code = sandbox_exit_code if isinstance(sandbox_exit_code, int) else 1
    if report.get("policy_blocked") is True:
        sys.stderr.write(f"SANDBOX-RUN POLICY BLOCK: {report.get('block_reason') or 'policy_block'}\n")
        return 2
    command_started = report.get("command_started") is True
    command_exit_code = report.get("command_exit_code")
    if not command_started and code != 0:
        sys.stderr.write(f"SANDBOX-RUN ERROR: {report.get('block_reason') or 'sandbox_run_error'}\n")
        return 1
    if command_started and isinstance(command_exit_code, int) and command_exit_code != 0:
        sys.stderr.write(f"SANDBOX-RUN COMMAND EXIT: command exited {command_exit_code}\n")
        return command_exit_code
    return code


def _parse_seccomp_profile(value: str) -> str:
    if value not in SECCOMP_PROFILE_CHOICES:
        raise argparse.ArgumentTypeError("must be runtime-default or rhd-moby-default-v1")
    return value


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


if __name__ == "__main__":
    raise SystemExit(main())
