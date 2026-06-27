"""Fail-closed readiness gate for external scanner execution plans."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


ALLOWED_SCANNERS = {"zizmor-style", "zizmor-style-github-actions"}
ALLOWED_MODES = {"local_static_no_network"}
READINESS_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_EXTERNAL_SCANNER_EXECUTION_READINESS = "external_scanner_execution_readiness"
FORBIDDEN_COMMAND_PREFIXES = {("sh", "-c"), ("bash", "-c"), ("/bin/sh", "-c"), ("/bin/bash", "-c")}
FORBIDDEN_MOUNT_MARKERS = (
    "docker.sock",
    "<docker-socket>",
    "<host-home>",
    "<credentials>",
    ".ssh",
    ".aws",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "git-credentials",
)


@dataclass(frozen=True)
class ScannerExecutionReadinessResult:
    ready: bool
    execution_authorized: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    required_approvals: tuple[str, ...]
    approval_present: bool
    scanner_executed: bool
    network_allowed: bool
    target_code_execution_allowed: bool
    docker_allowed: bool
    raw_output_retention: bool
    raw_output_discard_required: bool
    requires_human_approval: bool
    binary_trust_status: str
    version_pin_status: str
    binary_hash_status: str
    policy_version: str | None
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": READINESS_SCHEMA_VERSION,
            "report_kind": REPORT_KIND_EXTERNAL_SCANNER_EXECUTION_READINESS,
            "ready": self.ready,
            "execution_authorized": self.execution_authorized,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "required_approvals": list(self.required_approvals),
            "approval_present": self.approval_present,
            "scanner_executed": self.scanner_executed,
            "network_allowed": self.network_allowed,
            "target_code_execution_allowed": self.target_code_execution_allowed,
            "docker_allowed": self.docker_allowed,
            "raw_output_retention": self.raw_output_retention,
            "raw_output_discard_required": self.raw_output_discard_required,
            "requires_human_approval": self.requires_human_approval,
            "binary_trust_status": self.binary_trust_status,
            "version_pin_status": self.version_pin_status,
            "binary_hash_status": self.binary_hash_status,
            "policy_version": self.policy_version,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
        }


def evaluate_scanner_execution_readiness(
    plan: Mapping[str, Any],
    *,
    approval: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
) -> ScannerExecutionReadinessResult:
    """Evaluate whether a scanner execution plan is ready to be attempted.

    A ready result is still not a live execution authorization report:
    ``execution_authorized`` remains false.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(plan, Mapping):
        errors.append("readiness_plan_must_be_object")
        plan = {}

    scanner_name = _string(plan.get("scanner_name") or _nested(plan, "scanner", "name"))
    scanner_mode = _string(plan.get("scanner_mode") or _nested(plan, "scanner", "mode"))
    scanner_argv = plan.get("scanner_argv")
    docker_argv = plan.get("docker_argv")
    mounts = _list_of_mappings(plan.get("mounts"))
    limitations = tuple(_string_items(plan.get("limitations")))
    residual_risks = tuple(_string_items(plan.get("residual_risks")))
    approval_present = isinstance(approval, Mapping)
    required_approvals = ("human_scanner_execution_approval",)

    if not approval_present:
        errors.append("approval_missing")
    if scanner_name not in ALLOWED_SCANNERS:
        errors.append("scanner_not_allowlisted")
    if scanner_mode not in ALLOWED_MODES:
        errors.append("unsupported_scanner_mode")
    if plan.get("requires_human_approval") is not True:
        errors.append("requires_human_approval_must_be_true")
    if plan.get("scanner_executed") is True:
        errors.append("scanner_executed_before_readiness")
    if plan.get("network_allowed") is True or plan.get("network_mode") not in {None, "none"}:
        errors.append("network_allowed_must_be_false_for_target_scan")
    if plan.get("target_code_execution_allowed") is not False:
        errors.append("target_code_execution_allowed_must_be_false")
    if plan.get("raw_output_retention") is not False:
        errors.append("raw_output_retention_must_be_false")
    if plan.get("raw_output_discard_required") is not True:
        errors.append("raw_output_discard_required_must_be_true")
    if not limitations:
        errors.append("limitations_empty")
    if not residual_risks:
        errors.append("residual_risks_empty")

    binary_trust_status = _string(plan.get("binary_trust_status")) or "unknown"
    version_pin_status = _string(plan.get("version_pin_status")) or "unknown"
    binary_hash_status = _string(plan.get("binary_hash_status")) or "unknown"
    if binary_trust_status not in {"verified", "attested"}:
        errors.append("binary_trust_not_verified")
    if version_pin_status != "pinned":
        errors.append("version_pin_not_confirmed")
    if binary_hash_status != "verified":
        errors.append("binary_hash_not_verified")

    _validate_argv(scanner_argv, "scanner", errors)
    _validate_argv(docker_argv, "docker", errors)
    _validate_mounts(mounts, errors)
    _validate_approval(plan, approval, errors, warnings)

    policy_version = None
    if isinstance(policy, Mapping):
        policy_version = _string(policy.get("policy_version"))
    elif isinstance(plan.get("policy_version"), str):
        policy_version = str(plan["policy_version"])

    return ScannerExecutionReadinessResult(
        ready=not errors,
        execution_authorized=False,
        blocking_errors=tuple(_dedupe(errors)),
        warnings=tuple(_dedupe(warnings)),
        required_approvals=required_approvals,
        approval_present=approval_present,
        scanner_executed=plan.get("scanner_executed") is True,
        network_allowed=plan.get("network_allowed") is True or plan.get("network_mode") not in {None, "none"},
        target_code_execution_allowed=plan.get("target_code_execution_allowed") is True,
        docker_allowed=plan.get("docker_allowed") is True,
        raw_output_retention=plan.get("raw_output_retention") is True,
        raw_output_discard_required=plan.get("raw_output_discard_required") is True,
        requires_human_approval=plan.get("requires_human_approval") is True,
        binary_trust_status=binary_trust_status,
        version_pin_status=version_pin_status,
        binary_hash_status=binary_hash_status,
        policy_version=policy_version,
        limitations=limitations,
        residual_risks=residual_risks,
    )


def _validate_argv(value: object, label: str, errors: list[str]) -> None:
    if isinstance(value, str):
        errors.append(f"{label}_shell_string_command_forbidden")
        return
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        errors.append(f"{label}_argv_must_be_nonempty_string_list")
        return
    lowered = tuple(item.lower() for item in value[:2])
    if lowered in FORBIDDEN_COMMAND_PREFIXES:
        errors.append(f"{label}_shell_interpreter_command_forbidden")


def _validate_mounts(mounts: list[Mapping[str, Any]], errors: list[str]) -> None:
    for mount in mounts:
        rendered = " ".join(str(mount.get(field, "")) for field in ("source", "target", "type"))
        if "docker.sock" in rendered or "<docker-socket>" in rendered:
            errors.append("docker_socket_mount_forbidden")
        if "<host-home>" in rendered:
            errors.append("host_home_mount_forbidden")
        if "<credentials>" in rendered:
            errors.append("credential_mount_forbidden")
        if any(
            marker in rendered
            for marker in FORBIDDEN_MOUNT_MARKERS
            if marker not in {"docker.sock", "<docker-socket>", "<host-home>", "<credentials>"}
        ):
            errors.append("credential_mount_forbidden")
        if mount.get("read_only") is not True:
            errors.append("target_mount_must_be_read_only")


def _validate_approval(
    plan: Mapping[str, Any],
    approval: Mapping[str, Any] | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(approval, Mapping):
        return
    if approval.get("approval_state") != "accepted":
        errors.append("approval_invalid")
    if approval.get("scanner_name") != plan.get("scanner_name"):
        errors.append("approval_scanner_mismatch")
    if approval.get("scope") != plan.get("scope"):
        errors.append("approval_scope_mismatch")
    if approval.get("scanner_argv") != plan.get("scanner_argv"):
        errors.append("approval_command_mismatch")
    expires_at = _string(approval.get("expires_at"))
    if not expires_at:
        errors.append("approval_expiry_missing")
        return
    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        errors.append("approval_expiry_invalid")
        return
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        errors.append("approval_expired")
    if approval.get("approval_artifact_generated") is True:
        warnings.append("approval_artifact_generation_not_performed_by_readiness_gate")


def _nested(value: Mapping[str, Any], section: str, field: str) -> object:
    item = value.get(section)
    return item.get(field) if isinstance(item, Mapping) else None


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _list_of_mappings(value: object) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
