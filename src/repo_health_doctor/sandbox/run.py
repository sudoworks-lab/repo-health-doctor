from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from ..doctor import TOOL_VERSION
from ..gate.authorization import (
    reserve_execution_authorization,
    validate_execution_authorization_worktree_binding,
)
from .approval import load_sandbox_run_approval, validate_sandbox_run_approval
from .docker import is_digest_pinned
from .docker_runner import (
    DockerRunner,
    FakeDockerRunner,
    SandboxDockerRunner,
    build_docker_run_argv,
    docker_report_fields,
)
from .profiles import (
    PROFILE_LOCKED_DOWN,
    PROFILE_INSPECT_ONLY,
    SECCOMP_RUNTIME_DEFAULT,
    SandboxProfile,
    SeccompProfileSelection,
    get_sandbox_profile,
    materialize_seccomp_profile,
    resolve_seccomp_selection,
)
from .run_workspace import (
    CopyBudget,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILE_COUNT,
    DEFAULT_MAX_TOTAL_BYTES,
    FINGERPRINT_METHOD,
    DisposableWorkspace,
    InventoryResult,
    create_disposable_workspace,
    fingerprint_target,
    inspect_git_worktree,
    snapshot_workspace,
    summarize_workspace_diff,
    target_identity,
)


SANDBOX_RUN_SCHEMA_VERSION = "0.1-draft"
SANDBOX_RUN_REPORT_KIND = "sandbox_run"
DEFAULT_OUTPUT_PREVIEW_CHARS = 4096
STATUS_BLOCKED = "blocked"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_TIMED_OUT = "timed_out"
STATUS_CLEANUP_UNCERTAIN = "cleanup_uncertain"
STATUS_DRY_RUN = "dry_run"
DOCKER_INFRASTRUCTURE_EXIT_CODES = {125}
DEFAULT_SANDBOX_IMAGE = "python:3.12-slim"
SANDBOX_POLICY_BLOCK_EXIT_CODE = 2
SANDBOX_INFRASTRUCTURE_EXIT_CODE = 1
GATE_FAIL_MODES: Mapping[str, frozenset[str]] = {
    "block": frozenset({"block"}),
    "quarantine": frozenset({"quarantine", "block"}),
    "warn": frozenset({"warn", "quarantine", "block"}),
    "unknown": frozenset({"unknown", "warn", "quarantine", "block"}),
}

SECRET_PATTERNS = (
    re.compile(
        r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    re.compile(r"(?i)\b(?:password|token|api[_-]?key|secret)\b\s*[:=]\s*[^\s,;}\]\r\n]+"),
)
_POSIX_HOME_PREFIX = "/" + "home"
_POSIX_USERS_PREFIX = "/" + "Users"
_MNT_PREFIX = "/" + "mnt"
PRIVATE_PATH_PATTERNS = (
    re.compile(_POSIX_HOME_PREFIX + r"/[^/\s]+"),
    re.compile(_POSIX_USERS_PREFIX + r"/[^/\s]+"),
    re.compile(_MNT_PREFIX + r"/[A-Za-z]" + _POSIX_USERS_PREFIX + r"/[^/\s]+"),
    re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+"),
)


def run_sandbox_run(
    target: Path,
    *,
    approval_path: Path | None = None,
    image: str | None = None,
    profile_name: str = PROFILE_LOCKED_DOWN,
    seccomp_profile_name: str = SECCOMP_RUNTIME_DEFAULT,
    command_argv: list[str],
    timeout_seconds: int = 30,
    runner: SandboxDockerRunner | None = None,
    output_preview_chars: int = DEFAULT_OUTPUT_PREVIEW_CHARS,
    dry_run: bool = False,
    preserve_workspace: bool = False,
    copy_budget: CopyBudget | None = None,
    gate_decision: Mapping[str, Any] | None = None,
    fail_on_gate: str | None = None,
    authorization_path: Path | None = None,
    authorization_validation: Any | None = None,
) -> dict[str, Any]:
    target = target.resolve()
    command_argv = _normalize_command_argv(command_argv)
    image = image or DEFAULT_SANDBOX_IMAGE
    profile = get_sandbox_profile(profile_name)
    seccomp = resolve_seccomp_selection(seccomp_profile_name)
    runner = DockerRunner() if runner is None else runner
    limitations: list[str] = []
    next_actions: list[str] = []
    policy_reasons: list[str] = []
    infrastructure_reasons: list[str] = []

    target_inventory = _fingerprint_or_none(target, policy_reasons, limitations)
    base_report = _base_report(
        target=target,
        target_inventory=target_inventory,
        approval_path=approval_path,
        authorization_path=authorization_path,
        image=image,
        profile=profile,
        seccomp=seccomp,
        command_argv=command_argv,
        runner=runner,
        limitations=limitations,
        next_actions=next_actions,
        dry_run=dry_run,
        preserve_workspace=preserve_workspace,
        gate_decision=gate_decision,
        fail_on_gate=fail_on_gate,
        authorization_validation=authorization_validation,
    )

    if not command_argv:
        infrastructure_reasons.append("command_argv_missing")
    if timeout_seconds <= 0:
        infrastructure_reasons.append("timeout_seconds_invalid")
    if not profile.implemented:
        infrastructure_reasons.append(profile.refusal_reason or "profile_not_implemented")
    if profile.name == PROFILE_INSPECT_ONLY and not dry_run:
        policy_reasons.append("inspect_only_profile_requires_dry_run")
    if target_inventory is None:
        policy_reasons.append("target_fingerprint_unavailable")
    gate_block_reason = _gate_block_reason(gate_decision, fail_on_gate)
    authorization_authorized = _authorization_execution_authorized(authorization_validation)
    if gate_block_reason is not None and not authorization_authorized:
        policy_reasons.append(gate_block_reason)
    if authorization_path is not None and not authorization_authorized:
        policy_reasons.extend(_authorization_blocking_reasons(authorization_validation))

    approval_validation = None
    if approval_path is not None and target_inventory is not None and image and command_argv:
        try:
            approval = load_sandbox_run_approval(approval_path)
        except ValueError as exc:
            policy_reasons.append(str(exc))
        else:
            approval_validation = validate_sandbox_run_approval(
                approval,
                target_path=target,
                target_inventory=target_inventory,
                command_argv=command_argv,
                image=image,
                profile=profile,
                timeout_seconds=timeout_seconds,
            )
            policy_reasons.extend(approval_validation.refusal_reasons)
            limitations.extend(approval_validation.limitations)
            limitations.extend(approval_validation.warnings)

    if authorization_path is not None and authorization_authorized and not dry_run:
        authorization_document = _load_authorization_document(authorization_path)
        observed_worktree = inspect_git_worktree(target)
        if authorization_document is None:
            observed_worktree = {
                "git_available": False,
                "repo_identity": None,
                "repo_root_matches_target": False,
                "commit": None,
                "tree_hash": None,
                "dirty_state": "unknown",
            }
        worktree_binding = validate_execution_authorization_worktree_binding(
            authorization_document or {},
            observed_worktree,
        )
        base_report["authorization"]["worktree_binding"] = worktree_binding.to_dict()
        if not worktree_binding.matched:
            policy_reasons.extend(worktree_binding.refusal_reasons)
            base_report["authorization"]["execution_authorized"] = False
            base_report["authorization"]["blocking_errors"] = list(
                dict.fromkeys(
                    [
                        *base_report["authorization"].get("blocking_errors", []),
                        *worktree_binding.refusal_reasons,
                    ]
                )
            )

    if policy_reasons:
        return _policy_blocked_report(
            base_report,
            approval_path=approval_path,
            refusal_reasons=policy_reasons,
            approval_validation=approval_validation,
            next_actions=[
                "Review gate, authorization, copy policy, and approval refusal reasons before retrying.",
                "Do not run the repository-derived command on the host as a fallback.",
            ],
        )

    if infrastructure_reasons:
        return _infrastructure_error_report(
            base_report,
            approval_path=approval_path,
            refusal_reasons=infrastructure_reasons,
            approval_validation=approval_validation,
            next_actions=[
                "Do not fall back to running the repository-derived command directly on the host.",
                "Fix the sandbox-run configuration and retry.",
            ],
        )

    if not dry_run and not runner.docker_available():
        return _infrastructure_error_report(
            base_report,
            approval_path=approval_path,
            refusal_reasons=["docker_unavailable"],
            approval_validation=approval_validation,
            next_actions=[
                "Start or install Docker only if that is appropriate for this host.",
                "Do not fall back to running the repository-derived command directly on the host.",
            ],
        )
    if not dry_run and not runner.image_available_locally(image):
        return _infrastructure_error_report(
            base_report,
            approval_path=approval_path,
            refusal_reasons=["image_unavailable_local_only_policy"],
            approval_validation=approval_validation,
            next_actions=[
                "Preload the exact approved image through a reviewed process, then retry.",
                "Do not pull images implicitly during sandbox-run.",
            ],
        )

    workspace: DisposableWorkspace | None = None
    before_snapshot: InventoryResult | None = None
    after_snapshot: InventoryResult | None = None
    try:
        workspace = create_disposable_workspace(target, copy_budget=copy_budget)
        base_report["disposable_workspace"] = workspace.to_report()
        if not workspace.copy_safety_ok:
            copy_refusals = ["workspace_copy_safety_check_failed"]
            if workspace.copy_budget_exceeded:
                copy_refusals.append("copy_budget_exceeded")
            return _policy_blocked_report(
                base_report,
                approval_path=approval_path,
                refusal_reasons=copy_refusals,
                approval_validation=approval_validation,
                next_actions=[
                    "Remove or review unsupported entries before sandbox execution.",
                    "Do not run the command on the host as a fallback.",
                ],
                workspace=workspace,
                preserve_workspace=preserve_workspace,
            )
        before_snapshot = snapshot_workspace(workspace.workspace)
        seccomp_profile_path = _materialize_seccomp_profile(seccomp, workspace)
        docker_argv = build_docker_run_argv(
            image=image,
            command_argv=command_argv,
            workspace_host_path=workspace.workspace,
            out_host_path=workspace.out,
            profile=profile,
            seccomp_profile_name=seccomp.profile,
            seccomp_profile_path=seccomp_profile_path,
        )
        docker_argv_redacted = [_redact_text(token, target=target, workspace=workspace) for token in docker_argv]
        base_report["docker"] = docker_report_fields(
            image=image,
            profile=profile,
            argv_redacted=docker_argv_redacted,
            runtime=runner.detect_runtime(),
            runner_name=runner.runner_name,
            docker_invoked=bool(runner.docker_invoked and not dry_run),
        )
        if dry_run:
            report = dict(base_report)
            report["authorization"]["single_use_reservation"] = {
                "status": "not_consumed",
                "consumed": False,
                "marker_path_redacted": "<authorization-reservation>" if authorization_path is not None else None,
                "refusal_reason": "dry_run",
            }
            report["result"] = {
                "status": STATUS_DRY_RUN,
                "exit_code": 0,
                "timed_out": False,
                "duration_ms": 0,
            }
            report["workspace_diff"] = summarize_workspace_diff(before_snapshot, before_snapshot)
            report["approval"] = _approval_report(
                approval_path=approval_path,
                approval_validation=approval_validation,
                refusal_reasons=[],
            )
            report["next_actions"] = [
                "Dry-run generated sandbox-run evidence without invoking Docker.",
                "Run without --dry-run only after reviewing the planned boundary.",
            ]
            report["sandbox_exit_code"] = 0
            return _finalize_report(report, workspace=workspace, preserve_workspace=preserve_workspace)
        if authorization_path is not None:
            reservation = reserve_execution_authorization(authorization_path)
            base_report["authorization"]["single_use_reservation"] = reservation.to_dict()
            if not reservation.reserved:
                return _policy_blocked_report(
                    base_report,
                    approval_path=approval_path,
                    refusal_reasons=[reservation.refusal_reason or "authorization_single_use_reservation_rejected"],
                    approval_validation=approval_validation,
                    next_actions=[
                        "Do not retry the authorization after a reservation refusal; obtain a new authorization artifact.",
                        "Do not run the repository-derived command on the host as a fallback.",
                    ],
                    workspace=workspace,
                    preserve_workspace=preserve_workspace,
                )
        run_result = runner.run(docker_argv, timeout_seconds)
        after_snapshot = snapshot_workspace(workspace.workspace)
        output_summary = _build_output_summary(
            run_result.stdout,
            run_result.stderr,
            target=target,
            workspace=workspace,
            limit=output_preview_chars,
        )
        docker_with_result = _docker_report_with_result(
            base_report["docker"],
            run_result,
            output_summary,
            runner=runner,
        )
        status = run_result.status
        if run_result.timed_out:
            status = STATUS_TIMED_OUT
        elif run_result.exit_code not in {0, None}:
            status = STATUS_FAILED
        command_started = not _is_docker_infrastructure_failure(run_result, runner=runner)
        command_exit_code = run_result.exit_code if command_started else None
        sandbox_exit_code = (
            SANDBOX_INFRASTRUCTURE_EXIT_CODE
            if _is_docker_infrastructure_failure(run_result, runner=runner)
            else run_result.exit_code
            if run_result.exit_code is not None
            else SANDBOX_INFRASTRUCTURE_EXIT_CODE
        )
        report = dict(base_report)
        report["docker"] = docker_with_result
        report["workspace_diff"] = summarize_workspace_diff(before_snapshot, after_snapshot)
        report["output_summary"] = output_summary
        report["result"] = {
            "status": status,
            "exit_code": run_result.exit_code,
            "timed_out": run_result.timed_out,
            "duration_ms": run_result.duration_ms,
        }
        report["policy_blocked"] = False
        report["command_started"] = command_started
        report["command_exit_code"] = command_exit_code
        report["sandbox_exit_code"] = sandbox_exit_code
        report["block_reason"] = None
        report["approval"] = _approval_report(
            approval_path=approval_path,
            approval_validation=approval_validation,
            refusal_reasons=[],
        )
        if runner.runner_name.startswith("fake") and not runner.docker_invoked:
            report["limitations"].append(
                "Fake runner mode did not invoke Docker and is only suitable for tests or documentation smoke checks."
            )
        if _is_docker_infrastructure_failure(run_result, runner=runner):
            report["limitations"].extend(_docker_infrastructure_limitations())
            report["next_actions"] = _next_actions_for_docker_infrastructure_failure()
        else:
            report["next_actions"] = _next_actions_for_status(status)
        return _finalize_report(report, workspace=workspace, preserve_workspace=preserve_workspace)
    except Exception as exc:
        report = dict(base_report)
        report["limitations"].append(_redact_text(f"sandbox-run infrastructure error: {exc.__class__.__name__}", target=target, workspace=workspace))
        report["docker"] = _docker_report_with_infrastructure_error(
            report["docker"],
            diagnostic=f"sandbox-run infrastructure error: {exc.__class__.__name__}",
            target=target,
            workspace=workspace,
        )
        report["result"] = {
            "status": STATUS_FAILED,
            "exit_code": None,
            "timed_out": False,
            "duration_ms": 0,
        }
        report["policy_blocked"] = False
        report["command_started"] = False
        report["command_exit_code"] = None
        report["sandbox_exit_code"] = SANDBOX_INFRASTRUCTURE_EXIT_CODE
        report["block_reason"] = "sandbox_run_infrastructure_error"
        report["workspace_diff"] = summarize_workspace_diff(before_snapshot, after_snapshot)
        report["output_summary"] = _empty_output_summary()
        report["approval"] = _approval_report(
            approval_path=approval_path,
            approval_validation=approval_validation,
            refusal_reasons=["sandbox_run_failed_closed"],
        )
        report["next_actions"] = [
            "Treat the sandbox-run evidence as incomplete.",
            "Do not run the repository-derived command directly on the host as a fallback.",
        ]
        return _finalize_report(report, workspace=workspace, preserve_workspace=preserve_workspace)


def make_fake_runner(mode: str) -> FakeDockerRunner:
    mapping = {
        "fake": "success",
        "fake-docker-unavailable": "docker-unavailable",
        "fake-image-unavailable": "image-unavailable",
        "fake-timeout": "timeout",
        "fake-failure": "failure",
    }
    return FakeDockerRunner(mode=mapping[mode])


def _base_report(
    *,
    target: Path,
    target_inventory: InventoryResult | None,
    approval_path: Path | None,
    authorization_path: Path | None,
    image: str,
    profile: SandboxProfile,
    seccomp: SeccompProfileSelection,
    command_argv: list[str],
    runner: SandboxDockerRunner,
    limitations: list[str],
    next_actions: list[str],
    dry_run: bool,
    preserve_workspace: bool,
    gate_decision: Mapping[str, Any] | None,
    fail_on_gate: str | None,
    authorization_validation: Any | None,
) -> dict[str, Any]:
    target_limitations = []
    if target_inventory is not None:
        target_limitations.extend(target_inventory.limitations)
    if image == "latest" or image.endswith(":latest"):
        limitations.append("The approved image uses a latest tag; tag drift limits reproducibility.")
    if image and not is_digest_pinned(image):
        limitations.append("The approved image reference is not digest-pinned.")
    return {
        "schema_version": SANDBOX_RUN_SCHEMA_VERSION,
        "report_kind": SANDBOX_RUN_REPORT_KIND,
        "kind": SANDBOX_RUN_REPORT_KIND,
        "tool": "repo-health-doctor",
        "version": TOOL_VERSION,
        "experimental": False,
        "contract": {
            "stage": "sandbox-run-v1-core",
            "core_execution_backend": True,
            "absolute_safety_claimed": False,
            "malware_proof_claimed": False,
            "safety_proof_claimed": False,
        },
        "run": {
            "run_id": f"rhd-sandbox-run-{uuid4().hex}",
            "started_at": _utc_now(),
            "ended_at": None,
            "duration_ms": 0,
            "dry_run": dry_run,
            "preserve_workspace": preserve_workspace,
        },
        "target": {
            "path_redacted": "<repo>",
            "identity": target_identity(target),
            "fingerprint": target_inventory.fingerprint if target_inventory is not None else None,
            "fingerprint_method": FINGERPRINT_METHOD,
            "fingerprint_limitations": target_limitations,
        },
        "approval": _approval_report(
            approval_path=approval_path,
            approval_validation=None,
            refusal_reasons=[],
        ),
        "gate": _gate_report(gate_decision, fail_on_gate),
        "authorization": _authorization_report(
            authorization_path=authorization_path,
            authorization_validation=authorization_validation,
        ),
        "sandbox_profile": profile.to_report(),
        "seccomp": seccomp.to_report(),
        "command": {
            "argv_redacted": [_redact_text(token, target=target, workspace=None) for token in command_argv],
            "shell": _command_uses_explicit_shell(command_argv),
            "shell_wrapped_by_runner": False,
            "cwd": "/workspace",
        },
        "docker": docker_report_fields(
            image=image,
            profile=profile,
            runner_name=runner.runner_name,
            docker_invoked=False,
        ),
        "disposable_workspace": _workspace_not_created(),
        "workspace_diff": summarize_workspace_diff(None, None),
        "result": {
            "status": STATUS_BLOCKED,
            "exit_code": None,
            "timed_out": False,
            "duration_ms": 0,
        },
        "policy_blocked": False,
        "command_started": False,
        "command_exit_code": None,
        "sandbox_exit_code": SANDBOX_INFRASTRUCTURE_EXIT_CODE,
        "block_reason": None,
        "output_summary": _empty_output_summary(),
        "env_policy": {
            "host_environment_inherited": False,
            "injected_env_keys": sorted(profile.env),
            "values_recorded": False,
        },
        "cleanup_policy": {
            "default": "cleanup_run_root",
            "preserve_workspace": preserve_workspace,
            "delete_scope": "sandbox_run_root_only",
        },
        "boundary_statement": _boundary_statement(),
        "limitations": list(dict.fromkeys(limitations)),
        "next_actions": next_actions,
        "safety_statement": _safety_statement(),
    }


def _materialize_seccomp_profile(
    seccomp: SeccompProfileSelection,
    workspace: DisposableWorkspace,
) -> Path | None:
    if seccomp.profile == SECCOMP_RUNTIME_DEFAULT:
        return None
    destination = workspace.root / f"{seccomp.profile}.json"
    return materialize_seccomp_profile(seccomp.profile, destination)


def _policy_blocked_report(
    report: dict[str, Any],
    *,
    approval_path: Path | None,
    refusal_reasons: list[str],
    approval_validation: Any,
    next_actions: list[str],
    workspace: DisposableWorkspace | None = None,
    preserve_workspace: bool = False,
) -> dict[str, Any]:
    report = dict(report)
    reasons = list(dict.fromkeys(refusal_reasons))
    report["approval"] = _approval_report(
        approval_path=approval_path,
        approval_validation=approval_validation,
        refusal_reasons=reasons,
    )
    report["result"] = {
        "status": STATUS_BLOCKED,
        "exit_code": SANDBOX_POLICY_BLOCK_EXIT_CODE,
        "timed_out": False,
        "duration_ms": 0,
    }
    report["policy_blocked"] = True
    report["command_started"] = False
    report["command_exit_code"] = None
    report["sandbox_exit_code"] = SANDBOX_POLICY_BLOCK_EXIT_CODE
    report["block_reason"] = reasons[0] if reasons else "policy_block"
    report["next_actions"] = next_actions
    return _finalize_report(report, workspace=workspace, preserve_workspace=preserve_workspace)


def _infrastructure_error_report(
    report: dict[str, Any],
    *,
    approval_path: Path | None,
    refusal_reasons: list[str],
    approval_validation: Any,
    next_actions: list[str],
    workspace: DisposableWorkspace | None = None,
    preserve_workspace: bool = False,
) -> dict[str, Any]:
    report = dict(report)
    reasons = list(dict.fromkeys(refusal_reasons))
    report["approval"] = _approval_report(
        approval_path=approval_path,
        approval_validation=approval_validation,
        refusal_reasons=reasons,
    )
    report["result"] = {
        "status": STATUS_FAILED,
        "exit_code": SANDBOX_INFRASTRUCTURE_EXIT_CODE,
        "timed_out": False,
        "duration_ms": 0,
    }
    report["policy_blocked"] = False
    report["command_started"] = False
    report["command_exit_code"] = None
    report["sandbox_exit_code"] = SANDBOX_INFRASTRUCTURE_EXIT_CODE
    report["block_reason"] = reasons[0] if reasons else "sandbox_run_infrastructure_error"
    report["docker"] = _docker_report_with_infrastructure_error(
        report["docker"],
        diagnostic=report["block_reason"] or "sandbox-run infrastructure error",
        target=Path("."),
        workspace=workspace,
    )
    report["next_actions"] = next_actions
    return _finalize_report(report, workspace=workspace, preserve_workspace=preserve_workspace)


def _finalize_report(
    report: dict[str, Any],
    *,
    workspace: DisposableWorkspace | None,
    preserve_workspace: bool,
) -> dict[str, Any]:
    cleanup_status = "not_started"
    if workspace is not None:
        if preserve_workspace:
            workspace.cleanup_status = "preserved"
        else:
            workspace.cleanup()
        cleanup_status = workspace.cleanup_status
        report["disposable_workspace"] = workspace.to_report()
    if cleanup_status == "failed":
        report["result"]["status"] = STATUS_CLEANUP_UNCERTAIN
        report["sandbox_exit_code"] = SANDBOX_INFRASTRUCTURE_EXIT_CODE
        report["block_reason"] = "workspace_cleanup_failed"
        report["limitations"].append("Disposable workspace cleanup failed; treat the result as fail-closed evidence.")
        report["next_actions"] = [
            "Inspect and remove the disposable workspace manually before retrying.",
            "Do not treat this sandbox-run report as clean execution evidence.",
        ]
    run = report.get("run")
    if isinstance(run, dict):
        run["ended_at"] = _utc_now()
        if isinstance(report.get("result"), dict):
            run["duration_ms"] = report["result"].get("duration_ms", 0)
    report["limitations"] = list(dict.fromkeys(report["limitations"]))
    report["next_actions"] = list(dict.fromkeys(report["next_actions"]))
    report["safety_statement"] = _safety_statement()
    return _redact_report(report)


def _approval_report(
    *,
    approval_path: Path | None,
    approval_validation: Any,
    refusal_reasons: list[str],
) -> dict[str, Any]:
    validation_reasons = list(approval_validation.refusal_reasons) if approval_validation is not None else []
    reasons = list(dict.fromkeys([*validation_reasons, *refusal_reasons]))
    return {
        "approved": bool(approval_validation.approved) if approval_validation is not None else False,
        "artifact_path_redacted": "<approval>" if approval_path is not None else None,
        "matched": bool(approval_validation.matched) if approval_validation is not None else False,
        "refusal_reasons": reasons,
    }


def _gate_report(gate_decision: Mapping[str, Any] | None, fail_on_gate: str | None) -> dict[str, Any]:
    verdict = str(gate_decision.get("verdict", "unknown")).lower() if gate_decision is not None else None
    return {
        "evaluated": gate_decision is not None,
        "fail_on_gate": fail_on_gate,
        "verdict": verdict,
        "execution_authorized": False if gate_decision is not None else None,
        "decision_kind": gate_decision.get("decision_kind") if gate_decision is not None else None,
        "schema_version": gate_decision.get("schema_version") if gate_decision is not None else None,
        "policy_blocked": _gate_block_reason(gate_decision, fail_on_gate) is not None,
    }


def _authorization_report(
    *,
    authorization_path: Path | None,
    authorization_validation: Any | None,
) -> dict[str, Any]:
    payload = authorization_validation.to_dict() if authorization_validation is not None else None
    return {
        "artifact_path_redacted": "<authorization>" if authorization_path is not None else None,
        "validated": authorization_validation is not None,
        "execution_authorized": _authorization_execution_authorized(authorization_validation),
        "blocking_errors": _authorization_blocking_reasons(authorization_validation),
        "warnings": _string_items(payload.get("warnings") if isinstance(payload, Mapping) else None),
        "worktree_binding": {
            "checked": False,
            "status": "not_attempted",
            "matched": False,
            "repo_matches": False,
            "commit_matches": False,
            "tree_matches": False,
            "dirty_state": "not_checked",
            "refusal_reasons": [],
            "observed_values_recorded": False,
        },
        "single_use_reservation": {
            "status": "not_attempted",
            "consumed": False,
            "marker_path_redacted": "<authorization-reservation>" if authorization_path is not None else None,
            "refusal_reason": None,
        },
    }


def _gate_block_reason(gate_decision: Mapping[str, Any] | None, fail_on_gate: str | None) -> str | None:
    if gate_decision is None or fail_on_gate is None:
        return None
    verdict = str(gate_decision.get("verdict", "unknown")).lower()
    if verdict in GATE_FAIL_MODES[fail_on_gate]:
        return f"gate_verdict_{verdict}"
    return None


def _authorization_execution_authorized(authorization_validation: Any | None) -> bool:
    return bool(
        authorization_validation is not None
        and getattr(authorization_validation, "execution_authorized", False) is True
    )


def _authorization_blocking_reasons(authorization_validation: Any | None) -> list[str]:
    if authorization_validation is None:
        return ["authorization_missing"]
    payload = authorization_validation.to_dict()
    reasons = _string_items(payload.get("blocking_errors") if isinstance(payload, Mapping) else None)
    return reasons or ["authorization_invalid"]


def _load_authorization_document(path: Path) -> Mapping[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _command_uses_explicit_shell(command_argv: list[str]) -> bool:
    if len(command_argv) < 2:
        return False
    executable = Path(command_argv[0]).name
    return executable in {"sh", "bash"} and command_argv[1] in {"-c", "-lc"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _string_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _fingerprint_or_none(
    target: Path,
    refusal_reasons: list[str],
    limitations: list[str],
) -> InventoryResult | None:
    try:
        inventory = fingerprint_target(target)
    except OSError:
        limitations.append("Target fingerprint could not be computed.")
        return None
    if inventory.errors:
        refusal_reasons.append("target_fingerprint_inventory_error")
        limitations.extend(inventory.limitations)
    return inventory


def _normalize_command_argv(command_argv: list[str]) -> list[str]:
    normalized = list(command_argv)
    if normalized and normalized[0] == "--":
        normalized = normalized[1:]
    return normalized


def _build_output_summary(
    stdout: str,
    stderr: str,
    *,
    target: Path,
    workspace: DisposableWorkspace | None,
    limit: int,
) -> dict[str, Any]:
    stdout_redacted, stdout_truncated = _bounded_redacted_preview(stdout, target=target, workspace=workspace, limit=limit)
    stderr_redacted, stderr_truncated = _bounded_redacted_preview(stderr, target=target, workspace=workspace, limit=limit)
    return {
        "stdout_preview_redacted": stdout_redacted,
        "stderr_preview_redacted": stderr_redacted,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "redaction_applied": True,
        "redaction_failure": None,
        "raw_stdout_stderr_persisted": False,
    }


def _empty_output_summary() -> dict[str, Any]:
    return {
        "stdout_preview_redacted": "",
        "stderr_preview_redacted": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "redaction_applied": True,
        "redaction_failure": None,
        "raw_stdout_stderr_persisted": False,
    }


def _docker_report_with_result(
    docker_report: dict[str, Any],
    run_result: Any,
    output_summary: dict[str, Any],
    *,
    runner: SandboxDockerRunner,
) -> dict[str, Any]:
    report = dict(docker_report)
    report["invoked"] = bool(runner.docker_invoked)
    report["docker_invoked"] = bool(runner.docker_invoked)
    report["exit_code"] = run_result.exit_code
    report["stdout_preview_redacted"] = output_summary["stdout_preview_redacted"]
    report["stderr_preview_redacted"] = output_summary["stderr_preview_redacted"]
    report["failure_class"] = None
    report["diagnostic_redacted"] = None
    if run_result.timed_out:
        report["failure_class"] = "timeout"
        report["diagnostic_redacted"] = (
            "Docker runner timed out before complete bounded evidence was available."
            if runner.docker_invoked
            else "Sandbox runner timed out before complete bounded evidence was available."
        )
    elif _is_docker_infrastructure_failure(run_result, runner=runner):
        report["failure_class"] = "docker_infrastructure_failure"
        report["diagnostic_redacted"] = (
            "Docker run failed before the approved command could be confirmed as executed "
            f"(exit code {run_result.exit_code}). Review bounded redacted Docker stderr/stdout previews before retrying."
        )
    elif run_result.exit_code not in {0, None}:
        report["failure_class"] = "sandbox_command_or_runner_failure"
        report["diagnostic_redacted"] = (
            "Docker run returned a nonzero exit code after invocation; review bounded redacted output previews before "
            "inferring whether the approved command started."
            if runner.docker_invoked
            else "Sandbox runner returned a nonzero exit code; review bounded redacted output previews."
        )
    return report


def _docker_report_with_infrastructure_error(
    docker_report: dict[str, Any],
    *,
    diagnostic: str,
    target: Path,
    workspace: DisposableWorkspace | None,
) -> dict[str, Any]:
    report = dict(docker_report)
    report["failure_class"] = "sandbox_run_infrastructure_error"
    report["diagnostic_redacted"] = _redact_text(diagnostic, target=target, workspace=workspace)
    return report


def _is_docker_infrastructure_failure(run_result: Any, *, runner: SandboxDockerRunner) -> bool:
    if not runner.docker_invoked or run_result.timed_out:
        return False
    return run_result.exit_code in DOCKER_INFRASTRUCTURE_EXIT_CODES or run_result.exit_code is None


def _docker_infrastructure_limitations() -> list[str]:
    return [
        "Docker infrastructure failed before the approved command could be confirmed as executed.",
        "Docker diagnostics are bounded and redacted; raw Docker stdout/stderr was not persisted.",
    ]


def _bounded_redacted_preview(
    value: str,
    *,
    target: Path,
    workspace: DisposableWorkspace | None,
    limit: int,
) -> tuple[str, bool]:
    redacted = _redact_text(value, target=target, workspace=workspace)
    truncated = len(redacted) > limit
    if truncated:
        redacted = redacted[:limit] + "\n<redacted-preview-truncated>"
    return redacted, truncated


def _redact_text(
    value: str,
    *,
    target: Path,
    workspace: DisposableWorkspace | None,
) -> str:
    redacted = value.replace(str(target), "<repo>")
    if workspace is not None:
        redacted = redacted.replace(str(workspace.workspace), "<disposable-workspace>")
        redacted = redacted.replace(str(workspace.out), "<sandbox-out>")
        redacted = redacted.replace(str(workspace.root), "<sandbox-run-root>")
    for pattern in PRIVATE_PATH_PATTERNS:
        redacted = pattern.sub("<host-private-path>", redacted)
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("<redacted-secret>", redacted)
    return redacted


def _redact_report(value: Any) -> Any:
    if isinstance(value, str):
        for pattern in PRIVATE_PATH_PATTERNS:
            value = pattern.sub("<host-private-path>", value)
        for pattern in SECRET_PATTERNS:
            value = pattern.sub("<redacted-secret>", value)
        return value
    if isinstance(value, list):
        return [_redact_report(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_report(item) for key, item in value.items()}
    return value


def _workspace_not_created() -> dict[str, Any]:
    return {
        "created": False,
        "cleanup": "not_started",
        "copy_policy": "not_started",
        "excluded_path_categories": [],
        "files_copied": 0,
        "total_bytes_copied": 0,
        "copy_safety_ok": False,
        "unsafe_symlink_count": 0,
        "copy_error_count": 0,
        "copy_budget": {
            "max_file_count": DEFAULT_MAX_FILE_COUNT,
            "max_total_bytes": DEFAULT_MAX_TOTAL_BYTES,
            "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
            "files_copied": 0,
            "total_bytes_copied": 0,
            "copy_budget_exceeded": False,
            "copy_budget_exceeded_reason": None,
        },
        "symlink_policy": {
            "follow_symlinks": False,
            "absolute_symlinks": "skip",
            "outside_repo_symlinks": "skip",
            "copied_symlink_count": 0,
            "unsafe_symlink_count": 0,
        },
        "special_file_policy": {
            "copy_special_files": False,
            "unsupported_entry_count": 0,
        },
        "source_path_redacted": "<repo>",
        "workspace_path_redacted": None,
        "out_path_redacted": None,
    }


def _boundary_statement() -> dict[str, list[str]]:
    return {
        "what_was_constrained": [
            "The command is passed to Docker as argv; sandbox-run does not add implicit shell wrapping.",
            "Gate, authorization, and optional legacy approval checks can block before Docker is invoked.",
            "The original repository is copied to a disposable workspace and is not mounted directly as writable.",
            "The locked-down profile disables container networking and avoids Docker socket, host HOME, credential, and SSH-agent mounts.",
        ],
        "what_was_not_guaranteed": [
            "Docker isolation is not complete malware containment.",
            "A successful sandbox run is not proof that the repository is safe.",
            "A successful sandbox run is not unrestricted execution authorization.",
            "The report contains bounded redacted output previews, not raw exhaustive execution logs.",
        ],
    }


def _safety_statement() -> str:
    return (
        "Sandbox-run v1 is repo-health-doctor's practical strong isolation runtime for "
        "unknown-repository command execution evidence. It is not proof that the repository "
        "is safe, is not unrestricted execution authorization, and Docker isolation has limitations."
    )


def _next_actions_for_status(status: str) -> list[str]:
    if status == STATUS_COMPLETED:
        return [
            "Review the bounded output preview and workspace diff summary.",
            "Do not treat successful execution as proof of safety or unrestricted authorization.",
            "Use gate evidence and human review before any further execution.",
        ]
    if status == STATUS_TIMED_OUT:
        return [
            "Treat timeout as incomplete evidence.",
            "Review whether a shorter, safer, or more specific approved command is needed.",
        ]
    return [
        "Treat the sandbox-run report as non-authorizing evidence.",
        "Review refusal reasons, limitations, and approval binding before retrying.",
    ]


def _next_actions_for_docker_infrastructure_failure() -> list[str]:
    return [
        "Treat this as failed sandbox-run infrastructure evidence, not as command completion.",
        "Review docker.diagnostic_redacted and bounded redacted Docker stderr/stdout previews before retrying.",
        "Do not run the repository-derived command directly on the host as a fallback.",
    ]
