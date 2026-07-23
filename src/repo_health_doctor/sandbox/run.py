from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from ..control_file import (
    BoundedJsonDocument,
    ControlFileReadError,
    control_file_matches,
    load_bounded_json_document,
)
from ..doctor import TOOL_VERSION
from ..gate.authorization import (
    gate_decision_fingerprint,
    reserve_execution_authorization,
    validate_execution_authorization,
    validate_execution_authorization_snapshot_binding,
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
from .image_binding import is_digest_pinned_authorization_reference, is_safe_docker_image_token
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
    DEFAULT_MAX_DIRECTORY_COUNT,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_RELATIVE_PATH_BYTES,
    DEFAULT_MAX_TOTAL_BYTES,
    FINGERPRINT_METHOD,
    DisposableWorkspace,
    InventoryResult,
    create_verified_snapshot,
    fingerprint_target,
    snapshot_workspace,
    summarize_workspace_diff,
    target_identity,
    verify_verified_snapshot,
)


SANDBOX_RUN_SCHEMA_VERSION = "0.1-draft"
SANDBOX_RUN_REPORT_KIND = "sandbox_run"
DEFAULT_OUTPUT_PREVIEW_CHARS = 4096
STATUS_BLOCKED = "blocked"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_TIMED_OUT = "timed_out"
STATUS_OUTPUT_BUDGET_EXCEEDED = "output_budget_exceeded"
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
    authorization_control_document: BoundedJsonDocument | None = None,
    prepared_workspace: DisposableWorkspace | None = None,
) -> dict[str, Any]:
    """Own the prepared snapshot until a report is returned.

    Interruptions and other BaseException paths still attempt workspace cleanup.
    """
    workspace = (
        prepared_workspace
        if prepared_workspace is not None
        else create_verified_snapshot(target, copy_budget=copy_budget)
    )
    completed = False
    try:
        report = _run_sandbox_run(
            target,
            approval_path=approval_path,
            image=image,
            profile_name=profile_name,
            seccomp_profile_name=seccomp_profile_name,
            command_argv=command_argv,
            timeout_seconds=timeout_seconds,
            runner=runner,
            output_preview_chars=output_preview_chars,
            dry_run=dry_run,
            preserve_workspace=preserve_workspace,
            copy_budget=copy_budget,
            gate_decision=gate_decision,
            fail_on_gate=fail_on_gate,
            authorization_path=authorization_path,
            authorization_validation=authorization_validation,
            authorization_control_document=authorization_control_document,
            prepared_workspace=workspace,
        )
        completed = True
        return report
    finally:
        if not completed:
            workspace.cleanup()


def _run_sandbox_run(
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
    authorization_control_document: BoundedJsonDocument | None = None,
    prepared_workspace: DisposableWorkspace | None = None,
) -> dict[str, Any]:
    target = Path(os.path.abspath(target))
    command_argv = _normalize_command_argv(command_argv)
    image = image if image is not None else DEFAULT_SANDBOX_IMAGE
    profile = get_sandbox_profile(profile_name)
    seccomp = resolve_seccomp_selection(seccomp_profile_name)
    runner = DockerRunner() if runner is None else runner
    require_real_authorization = not dry_run and runner.runner_name == "docker"
    limitations: list[str] = []
    next_actions: list[str] = []
    policy_reasons: list[str] = []
    infrastructure_reasons: list[str] = []
    workspace = (
        prepared_workspace
        if prepared_workspace is not None
        else create_verified_snapshot(target, copy_budget=copy_budget)
    )
    if Path(os.path.abspath(workspace.source_root)) != target:
        workspace.refusal_reasons.append("prepared_snapshot_source_mismatch")
    target_inventory = (
        snapshot_workspace(workspace.workspace)
        if workspace.copy_safety_ok
        else None
    )
    snapshot = workspace.verified_snapshot
    snapshot_id = snapshot.snapshot_id if snapshot is not None else None
    repository_identity = (
        snapshot.source_identity_redacted if snapshot is not None else None
    )
    source_commit = snapshot.source_commit if snapshot is not None else None
    source_tree = snapshot.source_tree if snapshot is not None else None
    manifest_fingerprint = (
        snapshot.manifest_fingerprint if snapshot is not None else None
    )
    if not workspace.copy_safety_ok:
        policy_reasons.extend(
            [
                "workspace_copy_safety_check_failed",
                *workspace.refusal_reasons,
            ]
        )
        if workspace.copy_budget_exceeded:
            policy_reasons.append("copy_budget_exceeded")
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
        require_image_binding=require_real_authorization,
        workspace=workspace,
    )
    runtime_authorization_control = (
        _load_authorization_control_document(authorization_path)
        if authorization_path is not None
        else None
    )
    authorization_document = (
        runtime_authorization_control.payload
        if runtime_authorization_control is not None
        and isinstance(runtime_authorization_control.payload, Mapping)
        else None
    )
    authorization_control_matches = (
        authorization_control_document is None
        or (
            runtime_authorization_control is not None
            and control_file_matches(
                authorization_control_document,
                runtime_authorization_control,
            )
        )
    )
    if authorization_path is not None and not authorization_control_matches:
        policy_reasons.append("authorization_control_file_changed")

    if require_real_authorization and authorization_path is not None:
        if authorization_document is None or not authorization_control_matches:
            authorization_validation = None
        else:
            runtime_image_id = (
                runner.image_id(image)
                if is_digest_pinned_authorization_reference(image)
                else None
            )
            authorization_validation = validate_execution_authorization(
                authorization_document,
                gate_decision if isinstance(gate_decision, Mapping) else {},
                command_argv,
                runtime_image_reference=image,
                runtime_image_id=runtime_image_id,
                expected_repository_identity=repository_identity,
                expected_commit=source_commit,
                expected_tree=source_tree,
                expected_snapshot_id=snapshot_id,
                expected_manifest_fingerprint=manifest_fingerprint,
            )
        base_report["authorization"] = _authorization_report(
            authorization_path=authorization_path,
            authorization_validation=authorization_validation,
            require_image_binding=True,
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
    if not is_safe_docker_image_token(image):
        policy_reasons.append("image_reference_invalid")
    elif require_real_authorization and not is_digest_pinned_authorization_reference(image):
        policy_reasons.append("image_digest_pinned_required")
    gate_block_reason = _gate_block_reason(gate_decision, fail_on_gate)
    authorization_authorized = _authorization_execution_authorized(
        authorization_validation,
        require_image_binding=require_real_authorization,
    )
    if require_real_authorization:
        if gate_decision is None:
            policy_reasons.append("gate_decision_required")
        if fail_on_gate is None:
            policy_reasons.append("gate_threshold_required")
        if authorization_path is None:
            policy_reasons.append("authorization_required")
        elif not authorization_authorized:
            policy_reasons.extend(
                _authorization_blocking_reasons(
                    authorization_validation,
                    require_image_binding=True,
                )
            )
    if gate_block_reason is not None:
        policy_reasons.append(gate_block_reason)
    if authorization_path is not None and not authorization_authorized and not require_real_authorization:
        policy_reasons.extend(_authorization_blocking_reasons(authorization_validation))

    subject_consistency = _subject_consistency_report(
        repository_identity=repository_identity,
        commit=source_commit,
        tree=source_tree,
        source_kind=snapshot.source_kind if snapshot is not None else None,
        snapshot_id=snapshot_id,
        manifest_fingerprint=manifest_fingerprint,
        gate_decision=gate_decision,
        authorization=authorization_document,
    )
    base_report["subject_consistency"] = subject_consistency
    if (
        not dry_run
        and gate_decision is not None
        and not subject_consistency["gate_matches"]
    ):
        policy_reasons.append("snapshot_subject_mismatch")
    if (
        not dry_run
        and authorization_path is not None
        and not subject_consistency["authorization_matches"]
    ):
        policy_reasons.append("snapshot_subject_mismatch")
    if require_real_authorization and not subject_consistency["consistent"]:
        policy_reasons.append("snapshot_subject_mismatch")

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

    if authorization_path is not None and authorization_authorized:
        snapshot_binding = validate_execution_authorization_snapshot_binding(
            authorization_document or {},
            gate_decision or {},
            repository_identity=repository_identity,
            commit=source_commit,
            tree=source_tree,
            snapshot_id=snapshot_id,
            manifest_fingerprint=manifest_fingerprint,
        )
        base_report["authorization"]["snapshot_binding"] = (
            snapshot_binding.to_dict()
        )
        if not snapshot_binding.matched:
            policy_reasons.extend(snapshot_binding.refusal_reasons)
            base_report["authorization"]["execution_authorized"] = False
            base_report["authorization"]["blocking_errors"] = list(
                dict.fromkeys(
                    [
                        *base_report["authorization"].get("blocking_errors", []),
                        *snapshot_binding.refusal_reasons,
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
            workspace=workspace,
            preserve_workspace=preserve_workspace,
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
            workspace=workspace,
            preserve_workspace=preserve_workspace,
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
            workspace=workspace,
            preserve_workspace=preserve_workspace,
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
            workspace=workspace,
            preserve_workspace=preserve_workspace,
        )

    before_snapshot: InventoryResult | None = None
    after_snapshot: InventoryResult | None = None
    try:
        base_report["disposable_workspace"] = workspace.to_report()
        before_snapshot = snapshot_workspace(workspace.workspace)
        if not verify_verified_snapshot(workspace):
            return _policy_blocked_report(
                base_report,
                approval_path=approval_path,
                refusal_reasons=["snapshot_integrity_verification_failed"],
                approval_validation=approval_validation,
                next_actions=[
                    "Discard the invalid snapshot and repeat bounded intake.",
                    "Do not invoke Docker or run the command on the host.",
                ],
                workspace=workspace,
                preserve_workspace=preserve_workspace,
            )
        seccomp_profile_path = _materialize_seccomp_profile(seccomp, workspace)
        docker_argv = build_docker_run_argv(
            image=image,
            command_argv=command_argv,
            workspace_host_path=workspace.workspace,
            out_host_path=workspace.out,
            profile=profile,
            seccomp_profile_name=seccomp.profile,
            seccomp_profile_path=seccomp_profile_path,
            container_tracking_label=uuid4().hex,
            cidfile_path=workspace.root / "container.cid",
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
        base_report["docker"]["container_tracking_enabled"] = not dry_run and runner.runner_name == "docker"
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
            reservation_control = _load_authorization_control_document(
                authorization_path
            )
            if (
                runtime_authorization_control is None
                or reservation_control is None
                or not control_file_matches(
                    runtime_authorization_control,
                    reservation_control,
                )
            ):
                return _policy_blocked_report(
                    base_report,
                    approval_path=approval_path,
                    refusal_reasons=["authorization_control_file_changed"],
                    approval_validation=authorization_validation,
                    next_actions=[
                        "Obtain a new authorization artifact and repeat validation.",
                        "Do not run the repository-derived command on the host as a fallback.",
                    ],
                    workspace=workspace,
                    preserve_workspace=preserve_workspace,
                )
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
            post_reservation_control = _load_authorization_control_document(
                authorization_path
            )
            if (
                runtime_authorization_control is None
                or post_reservation_control is None
                or not control_file_matches(
                    runtime_authorization_control,
                    post_reservation_control,
                )
            ):
                return _policy_blocked_report(
                    base_report,
                    approval_path=approval_path,
                    refusal_reasons=["authorization_control_file_changed"],
                    approval_validation=authorization_validation,
                    next_actions=[
                        "The consumed authorization changed; obtain a new authorization artifact.",
                        "Do not run the repository-derived command on the host as a fallback.",
                    ],
                    workspace=workspace,
                    preserve_workspace=preserve_workspace,
                )
        if not verify_verified_snapshot(workspace):
            return _policy_blocked_report(
                base_report,
                approval_path=approval_path,
                refusal_reasons=["snapshot_integrity_verification_failed"],
                approval_validation=approval_validation,
                next_actions=[
                    "Discard the invalid snapshot and repeat bounded intake.",
                    "Do not invoke Docker or run the command on the host.",
                ],
                workspace=workspace,
                preserve_workspace=preserve_workspace,
            )
        run_result = runner.run(docker_argv, timeout_seconds)
        snapshot_integrity_after = verify_verified_snapshot(workspace)
        after_snapshot = snapshot_workspace(workspace.workspace)
        output_summary = _build_output_summary(
            run_result.stdout,
            run_result.stderr,
            target=target,
            workspace=workspace,
            limit=output_preview_chars,
            stdout_bytes=run_result.stdout_bytes,
            stderr_bytes=run_result.stderr_bytes,
            total_output_bytes=run_result.total_output_bytes,
            stdout_budget_exceeded=run_result.stdout_truncated,
            stderr_budget_exceeded=run_result.stderr_truncated,
            output_budget_exceeded=run_result.output_budget_exceeded,
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
        elif run_result.output_budget_exceeded:
            status = STATUS_OUTPUT_BUDGET_EXCEEDED
        elif run_result.exit_code not in {0, None}:
            status = STATUS_FAILED
        command_start_state = getattr(run_result, "command_start_state", "unknown")
        command_started = command_start_state == "confirmed"
        command_exit_code = run_result.exit_code if command_started else None
        if run_result.output_budget_exceeded:
            sandbox_exit_code = SANDBOX_POLICY_BLOCK_EXIT_CODE
        elif _is_docker_infrastructure_failure(run_result, runner=runner):
            sandbox_exit_code = SANDBOX_INFRASTRUCTURE_EXIT_CODE
        elif run_result.exit_code is not None:
            sandbox_exit_code = run_result.exit_code
        else:
            sandbox_exit_code = SANDBOX_INFRASTRUCTURE_EXIT_CODE
        report = dict(base_report)
        report["docker"] = docker_with_result
        report["workspace_diff"] = summarize_workspace_diff(before_snapshot, after_snapshot)
        report["runtime_write_budget"] = _runtime_write_budget_report(before_snapshot, after_snapshot)
        report["output_summary"] = output_summary
        report["result"] = {
            "status": status,
            "exit_code": run_result.exit_code,
            "timed_out": run_result.timed_out,
            "duration_ms": run_result.duration_ms,
        }
        report["policy_blocked"] = False
        report["command_started"] = command_started
        report["command_start_state"] = command_start_state
        report["command_exit_code"] = command_exit_code
        report["sandbox_exit_code"] = sandbox_exit_code
        report["block_reason"] = None
        report["verified_snapshot"]["integrity_after_execution"] = (
            "verified" if snapshot_integrity_after else "mismatch"
        )
        if not snapshot_integrity_after:
            report["result"]["status"] = STATUS_FAILED
            report["sandbox_exit_code"] = SANDBOX_INFRASTRUCTURE_EXIT_CODE
            report["block_reason"] = "snapshot_integrity_verification_failed"
            report["limitations"].append(
                "The Docker workspace no longer matched the approved snapshot."
            )
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
    require_image_binding: bool,
    workspace: DisposableWorkspace,
) -> dict[str, Any]:
    target_limitations = []
    if target_inventory is not None:
        target_limitations.extend(target_inventory.limitations)
    if image == "latest" or image.endswith(":latest"):
        limitations.append("The approved image uses a latest tag; tag drift limits reproducibility.")
    if image and not is_digest_pinned(image):
        limitations.append("The approved image reference is not digest-pinned.")
    verified_snapshot = (
        workspace.verified_snapshot.to_report()
        if workspace.verified_snapshot is not None
        else {
            "schema_version": "1.0",
            "snapshot_id": None,
            "manifest_fingerprint": None,
            "integrity_status": "invalid",
            "limitations": [],
            "refusal_reasons": list(workspace.refusal_reasons),
        }
    )
    verified_snapshot["integrity_after_execution"] = "not_checked"
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
        "verified_snapshot": verified_snapshot,
        "subject_consistency": _subject_consistency_report(
            repository_identity=(
                workspace.verified_snapshot.source_identity_redacted
                if workspace.verified_snapshot is not None
                else None
            ),
            commit=(
                workspace.verified_snapshot.source_commit
                if workspace.verified_snapshot is not None
                else None
            ),
            tree=(
                workspace.verified_snapshot.source_tree
                if workspace.verified_snapshot is not None
                else None
            ),
            source_kind=(
                workspace.verified_snapshot.source_kind
                if workspace.verified_snapshot is not None
                else None
            ),
            snapshot_id=(
                workspace.verified_snapshot.snapshot_id
                if workspace.verified_snapshot is not None
                else None
            ),
            manifest_fingerprint=(
                workspace.verified_snapshot.manifest_fingerprint
                if workspace.verified_snapshot is not None
                else None
            ),
            gate_decision=gate_decision,
            authorization=None,
        ),
        "approval": _approval_report(
            approval_path=approval_path,
            approval_validation=None,
            refusal_reasons=[],
        ),
        "gate": _gate_report(gate_decision, fail_on_gate),
        "authorization": _authorization_report(
            authorization_path=authorization_path,
            authorization_validation=authorization_validation,
            require_image_binding=require_image_binding,
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
        "command_start_state": "not_started",
        "command_exit_code": None,
        "sandbox_exit_code": SANDBOX_INFRASTRUCTURE_EXIT_CODE,
        "block_reason": None,
        "output_summary": _empty_output_summary(),
        "runtime_write_budget": _runtime_write_budget_report(None, None),
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
    docker = report.get("docker")
    if isinstance(docker, dict) and docker.get("container_tracking_enabled") is True:
        cleanup_status = docker.get("cleanup_status")
        if cleanup_status != "ok" and report.get("result", {}).get("status") != STATUS_BLOCKED:
            report["result"]["status"] = STATUS_CLEANUP_UNCERTAIN
            report["sandbox_exit_code"] = SANDBOX_INFRASTRUCTURE_EXIT_CODE
            report["block_reason"] = "container_cleanup_failed"
            report["limitations"].append(
                "Container cleanup could not be confirmed; treat the result as fail-closed evidence."
            )
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
        "decision_fingerprint": (
            gate_decision_fingerprint(gate_decision)
            if gate_decision is not None
            else None
        ),
        "subject": (
            dict(gate_decision.get("subject"))
            if gate_decision is not None
            and isinstance(gate_decision.get("subject"), Mapping)
            else {}
        ),
        "policy_version": (
            gate_decision.get("policy", {}).get("policy_version")
            if gate_decision is not None
            and isinstance(gate_decision.get("policy"), Mapping)
            else None
        ),
        "policy_blocked": _gate_block_reason(gate_decision, fail_on_gate) is not None,
    }


def _subject_consistency_report(
    *,
    repository_identity: str | None,
    commit: str | None,
    tree: str | None,
    source_kind: str | None,
    snapshot_id: str | None,
    manifest_fingerprint: str | None,
    gate_decision: Mapping[str, Any] | None,
    authorization: Mapping[str, Any] | None,
) -> dict[str, Any]:
    gate_subject = (
        gate_decision.get("subject")
        if isinstance(gate_decision, Mapping)
        and isinstance(gate_decision.get("subject"), Mapping)
        else {}
    )
    authorization_subject = (
        authorization.get("subject")
        if isinstance(authorization, Mapping)
        and isinstance(authorization.get("subject"), Mapping)
        else {}
    )
    actual_fields = {
        "repository_identity": repository_identity,
        "commit": commit,
        "tree": tree,
        "snapshot_id": snapshot_id,
        "manifest_fingerprint": manifest_fingerprint,
    }
    gate_fields = {
        "repository_identity": gate_subject.get("repo"),
        "commit": gate_subject.get("commit"),
        "tree": gate_subject.get("tree_hash"),
        "snapshot_id": gate_subject.get("snapshot_id"),
        "manifest_fingerprint": gate_subject.get("manifest_fingerprint"),
    }
    authorization_fields = {
        "repository_identity": authorization_subject.get("repo"),
        "commit": authorization_subject.get("commit"),
        "tree": authorization_subject.get("tree_hash"),
        "snapshot_id": authorization_subject.get("snapshot_id"),
        "manifest_fingerprint": authorization_subject.get(
            "manifest_fingerprint"
        ),
    }
    field_resolved = {
        "repository_identity": _is_sha256_fingerprint(repository_identity),
        "commit": isinstance(commit, str) and bool(commit),
        "tree": isinstance(tree, str) and bool(tree),
        "snapshot_id": _is_sha256_fingerprint(snapshot_id),
        "manifest_fingerprint": _is_sha256_fingerprint(manifest_fingerprint),
    }
    snapshot_resolved = source_kind == "git_commit" and all(
        field_resolved.values()
    )
    gate_field_matches = {
        key: value == actual_fields[key]
        for key, value in gate_fields.items()
    }
    authorization_field_matches = {
        key: value == actual_fields[key]
        for key, value in authorization_fields.items()
    }
    gate_matches = gate_decision is None or (
        gate_subject.get("binding_kind") == "snapshot_bound"
        and all(gate_field_matches.values())
    )
    authorization_matches = authorization is None or (
        all(authorization_field_matches.values())
    )
    return {
        "consistent": bool(
            snapshot_resolved and gate_matches and authorization_matches
        ),
        "scan_snapshot_id": snapshot_id,
        "gate_snapshot_id": gate_fields["snapshot_id"],
        "authorization_snapshot_id": authorization_fields["snapshot_id"],
        "workspace_snapshot_id": snapshot_id,
        "evidence_snapshot_id": snapshot_id,
        "scan_manifest_fingerprint": manifest_fingerprint,
        "gate_manifest_fingerprint": gate_fields["manifest_fingerprint"],
        "authorization_manifest_fingerprint": authorization_fields[
            "manifest_fingerprint"
        ],
        "workspace_manifest_fingerprint": manifest_fingerprint,
        "evidence_manifest_fingerprint": manifest_fingerprint,
        "actual_source_kind_is_git_commit": source_kind == "git_commit",
        "runtime_fields_resolved": field_resolved,
        "gate_field_matches": gate_field_matches,
        "authorization_field_matches": authorization_field_matches,
        "gate_matches": gate_matches,
        "authorization_matches": authorization_matches,
        "missing_or_unresolved": not snapshot_resolved,
    }


def _is_sha256_fingerprint(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _authorization_report(
    *,
    authorization_path: Path | None,
    authorization_validation: Any | None,
    require_image_binding: bool,
) -> dict[str, Any]:
    payload = authorization_validation.to_dict() if authorization_validation is not None else None
    return {
        "artifact_path_redacted": "<authorization>" if authorization_path is not None else None,
        "validated": authorization_validation is not None,
        "execution_authorized": _authorization_execution_authorized(
            authorization_validation,
            require_image_binding=require_image_binding,
        ),
        "blocking_errors": _authorization_blocking_reasons(
            authorization_validation,
            require_image_binding=require_image_binding,
        ),
        "warnings": _string_items(payload.get("warnings") if isinstance(payload, Mapping) else None),
        "snapshot_binding": {
            "checked": False,
            "status": "not_attempted",
            "matched": False,
            "snapshot_id_matches": False,
            "manifest_fingerprint_matches": False,
            "gate_matches": False,
            "refusal_reasons": [],
            "observed_values_recorded": False,
        },
        "worktree_binding": {
            "checked": False,
            "status": "superseded_by_snapshot_binding",
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


def _authorization_execution_authorized(
    authorization_validation: Any | None,
    *,
    require_image_binding: bool = False,
) -> bool:
    basic_authorized = bool(
        authorization_validation is not None
        and getattr(authorization_validation, "execution_authorized", False) is True
    )
    if not basic_authorized:
        return False
    if not require_image_binding:
        return True
    return bool(
        getattr(authorization_validation, "image_binding_present", False) is True
        and getattr(authorization_validation, "image_reference_matches", False) is True
        and getattr(authorization_validation, "image_id_matches", False) is True
    )


def _authorization_blocking_reasons(
    authorization_validation: Any | None,
    *,
    require_image_binding: bool = False,
) -> list[str]:
    if authorization_validation is None:
        return ["authorization_missing"]
    payload = authorization_validation.to_dict()
    reasons = _string_items(payload.get("blocking_errors") if isinstance(payload, Mapping) else None)
    if require_image_binding and not (
        getattr(authorization_validation, "image_binding_present", False) is True
        and getattr(authorization_validation, "image_reference_matches", False) is True
        and getattr(authorization_validation, "image_id_matches", False) is True
    ):
        reasons.append("authorization_image_binding_required")
    return list(dict.fromkeys(reasons or ["authorization_invalid"]))


def _load_authorization_control_document(
    path: Path,
) -> BoundedJsonDocument | None:
    try:
        document = load_bounded_json_document(
            path,
            label="authorization",
        )
    except ControlFileReadError:
        return None
    return document if isinstance(document.payload, Mapping) else None


def _load_authorization_document(path: Path) -> Mapping[str, Any] | None:
    document = _load_authorization_control_document(path)
    return (
        document.payload
        if document is not None and isinstance(document.payload, Mapping)
        else None
    )


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
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
    total_output_bytes: int = 0,
    stdout_budget_exceeded: bool = False,
    stderr_budget_exceeded: bool = False,
    output_budget_exceeded: bool = False,
) -> dict[str, Any]:
    stdout_redacted, stdout_truncated = _bounded_redacted_preview(stdout, target=target, workspace=workspace, limit=limit)
    stderr_redacted, stderr_truncated = _bounded_redacted_preview(stderr, target=target, workspace=workspace, limit=limit)
    return {
        "stdout_preview_redacted": stdout_redacted,
        "stderr_preview_redacted": stderr_redacted,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "total_output_bytes": total_output_bytes,
        "stdout_byte_budget": 64 * 1024,
        "stderr_byte_budget": 64 * 1024,
        "total_byte_budget": 128 * 1024,
        "preview_char_budget": limit,
        "read_chunk_bytes": 8192,
        "output_budget_exceeded": output_budget_exceeded,
        "stdout_budget_exceeded": stdout_budget_exceeded,
        "stderr_budget_exceeded": stderr_budget_exceeded,
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
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "total_output_bytes": 0,
        "stdout_byte_budget": 64 * 1024,
        "stderr_byte_budget": 64 * 1024,
        "total_byte_budget": 128 * 1024,
        "preview_char_budget": DEFAULT_OUTPUT_PREVIEW_CHARS,
        "read_chunk_bytes": 8192,
        "output_budget_exceeded": False,
        "stdout_budget_exceeded": False,
        "stderr_budget_exceeded": False,
        "redaction_applied": True,
        "redaction_failure": None,
        "raw_stdout_stderr_persisted": False,
    }


def _runtime_write_budget_report(
    before: InventoryResult | None,
    after: InventoryResult | None,
) -> dict[str, Any]:
    observed_bytes = None
    observed_files = None
    exceeded = None
    if before is not None and after is not None:
        observed_bytes = max(0, after.total_bytes - before.total_bytes)
        observed_files = max(0, after.file_count - before.file_count)
        exceeded = observed_bytes > 0 or observed_files > 0
    return {
        "enforcement": "host_backed_writes_removed_from_real_runtime",
        "polling_watchdog": False,
        "poll_interval_ms": None,
        "scan_budget": None,
        "overshoot_limitation": "No polling overshoot: /workspace is read-only and /out is a kernel-bounded tmpfs.",
        "paths": {
            "workspace": {
                "host_backed": True,
                "mount": "bind",
                "read_only": True,
                "max_bytes": 0,
                "max_files": 0,
                "observed_bytes": observed_bytes,
                "observed_files": observed_files,
                "exceeded": exceeded,
            },
            "out": {
                "host_backed": False,
                "mount": "tmpfs",
                "read_only": False,
                "max_bytes": 64 * 1024 * 1024,
                "max_files": 4096,
                "observed_bytes": None,
                "observed_files": None,
                "exceeded": None,
                "kernel_enforced": True,
            },
        },
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
    report["stdout_bytes"] = run_result.stdout_bytes
    report["stderr_bytes"] = run_result.stderr_bytes
    report["total_output_bytes"] = run_result.total_output_bytes
    report["stdout_truncated"] = run_result.stdout_truncated
    report["stderr_truncated"] = run_result.stderr_truncated
    report["output_budget_exceeded"] = run_result.output_budget_exceeded
    report["cleanup_attempted"] = run_result.cleanup_attempted
    report["cleanup_status"] = run_result.container_cleanup_status
    report["cleanup_failure_class"] = run_result.cleanup_failure_class
    report["command_start_state"] = run_result.command_start_state
    report["failure_class"] = None
    report["diagnostic_redacted"] = None
    if run_result.output_budget_exceeded:
        report["failure_class"] = "output_budget_exceeded"
        report["diagnostic_redacted"] = "Docker output exceeded the bounded byte budget; the client and tracked container were stopped."
    elif run_result.timed_out:
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
            "max_directory_count": DEFAULT_MAX_DIRECTORY_COUNT,
            "max_depth": DEFAULT_MAX_DEPTH,
            "max_total_bytes": DEFAULT_MAX_TOTAL_BYTES,
            "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
            "max_relative_path_bytes": DEFAULT_MAX_RELATIVE_PATH_BYTES,
            "files_copied": 0,
            "directories_examined": 0,
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
