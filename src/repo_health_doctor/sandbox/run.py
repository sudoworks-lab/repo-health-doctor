from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..doctor import TOOL_VERSION
from .approval import load_sandbox_run_approval, validate_sandbox_run_approval
from .docker import is_digest_pinned
from .docker_runner import (
    DockerRunner,
    FakeDockerRunner,
    SandboxDockerRunner,
    build_docker_run_argv,
    docker_report_fields,
)
from .profiles import PROFILE_NO_NETWORK_DEFAULT, SandboxProfile, get_sandbox_profile
from .run_workspace import (
    FINGERPRINT_METHOD,
    DisposableWorkspace,
    InventoryResult,
    create_disposable_workspace,
    fingerprint_target,
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
DOCKER_INFRASTRUCTURE_EXIT_CODES = {125}

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
    approval_path: Path | None,
    image: str | None,
    profile_name: str = PROFILE_NO_NETWORK_DEFAULT,
    command_argv: list[str],
    timeout_seconds: int = 30,
    runner: SandboxDockerRunner | None = None,
    output_preview_chars: int = DEFAULT_OUTPUT_PREVIEW_CHARS,
) -> dict[str, Any]:
    target = target.resolve()
    command_argv = _normalize_command_argv(command_argv)
    image = image or ""
    profile = get_sandbox_profile(profile_name)
    runner = DockerRunner() if runner is None else runner
    limitations: list[str] = []
    next_actions: list[str] = []
    refusal_reasons: list[str] = []

    target_inventory = _fingerprint_or_none(target, refusal_reasons, limitations)
    base_report = _base_report(
        target=target,
        target_inventory=target_inventory,
        approval_path=approval_path,
        image=image,
        profile=profile,
        command_argv=command_argv,
        runner=runner,
        limitations=limitations,
        next_actions=next_actions,
    )

    if not command_argv:
        refusal_reasons.append("command_argv_missing")
    if not image:
        refusal_reasons.append("image_missing")
    if timeout_seconds <= 0:
        refusal_reasons.append("timeout_seconds_invalid")
    if not profile.implemented:
        refusal_reasons.append(profile.refusal_reason or "profile_not_implemented")
    if target_inventory is None:
        refusal_reasons.append("target_fingerprint_unavailable")

    approval_validation = None
    if approval_path is None:
        refusal_reasons.append("approval_missing")
    elif target_inventory is not None and image and command_argv:
        try:
            approval = load_sandbox_run_approval(approval_path)
        except ValueError as exc:
            refusal_reasons.append(str(exc))
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
            refusal_reasons.extend(approval_validation.refusal_reasons)
            limitations.extend(approval_validation.limitations)
            limitations.extend(approval_validation.warnings)

    if refusal_reasons:
        return _blocked_report(
            base_report,
            approval_path=approval_path,
            refusal_reasons=refusal_reasons,
            approval_validation=approval_validation,
            next_actions=[
                "Provide a valid sandbox-run approval artifact for the exact target, image, profile, network mode, timeout, resource limits, and command.",
                "Review the sandbox-run report limitations before retrying.",
            ],
        )

    if not runner.docker_available():
        return _blocked_report(
            base_report,
            approval_path=approval_path,
            refusal_reasons=["docker_unavailable"],
            approval_validation=approval_validation,
            next_actions=[
                "Start or install Docker only if that is appropriate for this host.",
                "Do not fall back to running the repository-derived command directly on the host.",
            ],
        )
    if not runner.image_available_locally(image):
        return _blocked_report(
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
        workspace = create_disposable_workspace(target)
        base_report["disposable_workspace"] = workspace.to_report()
        if not workspace.copy_safety_ok:
            return _blocked_report(
                base_report,
                approval_path=approval_path,
                refusal_reasons=["workspace_copy_safety_check_failed"],
                approval_validation=approval_validation,
                next_actions=[
                    "Remove or review unsupported entries before sandbox execution.",
                    "Do not run the command on the host as a fallback.",
                ],
                workspace=workspace,
            )
        before_snapshot = snapshot_workspace(workspace.workspace)
        docker_argv = build_docker_run_argv(
            image=image,
            command_argv=command_argv,
            workspace_host_path=workspace.workspace,
            profile=profile,
        )
        docker_argv_redacted = [_redact_text(token, target=target, workspace=workspace) for token in docker_argv]
        base_report["docker"] = docker_report_fields(
            image=image,
            profile=profile,
            argv_redacted=docker_argv_redacted,
            runtime=runner.detect_runtime(),
            runner_name=runner.runner_name,
            docker_invoked=runner.docker_invoked,
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
        return _finalize_report(report, workspace=workspace)
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
        return _finalize_report(report, workspace=workspace)


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
    image: str,
    profile: SandboxProfile,
    command_argv: list[str],
    runner: SandboxDockerRunner,
    limitations: list[str],
    next_actions: list[str],
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
        "experimental": True,
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
        "sandbox_profile": profile.to_report(),
        "command": {
            "argv_redacted": [_redact_text(token, target=target, workspace=None) for token in command_argv],
            "shell": False,
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
        "output_summary": _empty_output_summary(),
        "boundary_statement": _boundary_statement(),
        "limitations": list(dict.fromkeys(limitations)),
        "next_actions": next_actions,
        "safety_statement": _safety_statement(),
    }


def _blocked_report(
    report: dict[str, Any],
    *,
    approval_path: Path | None,
    refusal_reasons: list[str],
    approval_validation: Any,
    next_actions: list[str],
    workspace: DisposableWorkspace | None = None,
) -> dict[str, Any]:
    report = dict(report)
    report["approval"] = _approval_report(
        approval_path=approval_path,
        approval_validation=approval_validation,
        refusal_reasons=refusal_reasons,
    )
    report["result"] = {
        "status": STATUS_BLOCKED,
        "exit_code": None,
        "timed_out": False,
        "duration_ms": 0,
    }
    report["next_actions"] = next_actions
    return _finalize_report(report, workspace=workspace)


def _finalize_report(report: dict[str, Any], *, workspace: DisposableWorkspace | None) -> dict[str, Any]:
    cleanup_status = "not_started"
    if workspace is not None:
        workspace.cleanup()
        cleanup_status = workspace.cleanup_status
        report["disposable_workspace"] = workspace.to_report()
    if cleanup_status == "failed":
        report["result"]["status"] = STATUS_CLEANUP_UNCERTAIN
        report["limitations"].append("Disposable workspace cleanup failed; treat the result as fail-closed evidence.")
        report["next_actions"] = [
            "Inspect and remove the disposable workspace manually before retrying.",
            "Do not treat this sandbox-run report as clean completed evidence.",
        ]
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
        "copy_safety_ok": False,
        "unsafe_symlink_count": 0,
        "copy_error_count": 0,
        "source_path_redacted": "<repo>",
        "workspace_path_redacted": None,
    }


def _boundary_statement() -> dict[str, list[str]]:
    return {
        "what_was_constrained": [
            "The approved command argv is compared exactly before execution.",
            "The requested Docker image, profile, network mode, timeout, resource limits, and target fingerprint must match the approval.",
            "The original repository is copied to a disposable workspace and is not mounted directly as writable.",
            "The default profile disables container networking and avoids Docker socket, host HOME, credential, and SSH-agent mounts.",
        ],
        "what_was_not_guaranteed": [
            "Docker isolation is not complete malware containment.",
            "A completed sandbox run is not proof that the repository is safe.",
            "A completed sandbox run is not unrestricted execution authorization.",
            "The report contains bounded redacted output previews, not raw exhaustive execution logs.",
        ],
    }


def _safety_statement() -> str:
    return (
        "Sandbox-run is an experimental add-on to reduce direct host execution risk. "
        "A sandbox run is not proof that the repository is safe, is not unrestricted "
        "execution authorization, and Docker isolation has limitations."
    )


def _next_actions_for_status(status: str) -> list[str]:
    if status == STATUS_COMPLETED:
        return [
            "Review the bounded output preview and workspace diff summary.",
            "Do not treat completion as proof of safety or unrestricted authorization.",
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
