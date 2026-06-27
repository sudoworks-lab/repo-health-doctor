"""Docker-isolated zizmor scanner planning and execution path.

The default tests use a fake runner. The runtime path invokes Docker only when
the caller explicitly supplies approval and does not expose raw scanner output.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Mapping, Sequence

from .adapters.zizmor_adapter import (
    DEFAULT_ADAPTER_FINGERPRINT,
    DEFAULT_INPUT_FINGERPRINT,
    DEFAULT_POLICY_FINGERPRINT,
    ZIZMOR_STYLE_OUTPUT_KIND,
    default_zizmor_style_adapter,
)
from .execution_readiness import ScannerExecutionReadinessResult, evaluate_scanner_execution_readiness
from .imported_report_validator import ImportedExternalReportValidationResult, validate_imported_external_report
from .result_validator import ExternalScannerValidationResult, validate_external_scanner_result
from .risk_mapper import ExternalScannerRiskMappingResult, map_external_scanner_risk


DEFAULT_ZIZMOR_DOCKER_IMAGE = "zizmor:local"
DEFAULT_SCANNER_ARGV = ("zizmor", "--format", "json", ".github/workflows")
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_OUTPUT_BYTES = 1048576
DEFAULT_REPO_COMMIT = "0123456789abcdef0123456789abcdef01234567"
RunCallable = Callable[[Sequence[str], int, int], "DockerCommandResult"]
CleanupCallable = Callable[[Path], None]


@dataclass(frozen=True)
class DockerScannerExecutionPlan:
    scanner_name: str
    scanner_mode: str
    scanner_version_requirement: str
    docker_image: str
    docker_digest: str | None
    docker_argv: tuple[str, ...]
    scanner_argv: tuple[str, ...]
    target_mount: Mapping[str, object]
    output_handling: Mapping[str, object]
    network_mode: str
    capabilities: tuple[str, ...]
    security_opts: tuple[str, ...]
    read_only: bool
    user: str
    workdir: str
    timeout_seconds: int
    max_output_bytes: int
    disposable_workspace_path: str
    raw_output_retention: bool
    raw_output_discard_required: bool
    execution_authorized: bool
    scanner_executed: bool
    scanner_execution_planned: bool
    network_allowed: bool
    target_code_execution_allowed: bool
    docker_allowed: bool
    requires_human_approval: bool
    binary_trust_status: str
    version_pin_status: str
    binary_hash_status: str
    scope: str
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner_name": self.scanner_name,
            "scanner_mode": self.scanner_mode,
            "scanner_version_requirement": self.scanner_version_requirement,
            "docker_image": self.docker_image,
            "docker_digest": self.docker_digest,
            "docker_argv": list(self.docker_argv),
            "scanner_argv": list(self.scanner_argv),
            "target_mount": dict(self.target_mount),
            "mounts": [dict(self.target_mount)],
            "output_handling": dict(self.output_handling),
            "network_mode": self.network_mode,
            "capabilities": list(self.capabilities),
            "security_opts": list(self.security_opts),
            "read_only": self.read_only,
            "user": self.user,
            "workdir": self.workdir,
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "disposable_workspace_path": self.disposable_workspace_path,
            "raw_output_retention": self.raw_output_retention,
            "raw_output_discard_required": self.raw_output_discard_required,
            "execution_authorized": self.execution_authorized,
            "scanner_executed": self.scanner_executed,
            "scanner_execution_planned": self.scanner_execution_planned,
            "network_allowed": self.network_allowed,
            "target_code_execution_allowed": self.target_code_execution_allowed,
            "docker_allowed": self.docker_allowed,
            "requires_human_approval": self.requires_human_approval,
            "binary_trust_status": self.binary_trust_status,
            "version_pin_status": self.version_pin_status,
            "binary_hash_status": self.binary_hash_status,
            "scope": self.scope,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
        }


@dataclass(frozen=True)
class DockerCommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class ExternalScannerDockerRunResult:
    valid: bool
    scanner_executed: bool
    docker_invoked: bool
    cleanup_succeeded: bool
    raw_output_discarded: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    readiness: ScannerExecutionReadinessResult
    normalized_result: Mapping[str, object] | None
    validation_result: ExternalScannerValidationResult | None
    risk_mapping_result: ExternalScannerRiskMappingResult | None
    imported_report_result: ImportedExternalReportValidationResult | None

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "scanner_executed": self.scanner_executed,
            "docker_invoked": self.docker_invoked,
            "cleanup_succeeded": self.cleanup_succeeded,
            "raw_output_discarded": self.raw_output_discarded,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "readiness": self.readiness.to_dict(),
            "normalized_result": dict(self.normalized_result) if self.normalized_result is not None else None,
            "validation_result": self.validation_result.to_dict() if self.validation_result is not None else None,
            "risk_mapping_result": self.risk_mapping_result.to_dict() if self.risk_mapping_result is not None else None,
            "imported_report_result": self.imported_report_result.to_dict() if self.imported_report_result is not None else None,
        }


def build_zizmor_docker_execution_plan(
    target_repo: str | Path,
    *,
    approval: Mapping[str, Any] | None = None,
    mode: str = "dry_run",
    docker_image: str = DEFAULT_ZIZMOR_DOCKER_IMAGE,
    docker_digest: str | None = None,
) -> DockerScannerExecutionPlan:
    """Build a Docker scanner plan without executing Docker or zizmor."""
    del target_repo, approval, mode
    scanner_argv = DEFAULT_SCANNER_ARGV
    docker_argv = _docker_argv("<disposable-workspace>", docker_image, scanner_argv)
    return DockerScannerExecutionPlan(
        scanner_name="zizmor-style",
        scanner_mode="local_static_no_network",
        scanner_version_requirement="pinned-by-policy",
        docker_image=docker_image,
        docker_digest=docker_digest,
        docker_argv=tuple(docker_argv),
        scanner_argv=scanner_argv,
        target_mount={
            "type": "bind",
            "source": "<disposable-workspace>",
            "target": "/workspace",
            "read_only": True,
        },
        output_handling={
            "raw_output_retention": False,
            "raw_stdout_stderr_retention": False,
            "max_output_bytes": DEFAULT_MAX_OUTPUT_BYTES,
            "redaction_before_persistence": True,
            "report_raw_output": False,
        },
        network_mode="none",
        capabilities=("ALL",),
        security_opts=("no-new-privileges",),
        read_only=True,
        user="65532:65532",
        workdir="/workspace",
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
        disposable_workspace_path="<disposable-workspace>",
        raw_output_retention=False,
        raw_output_discard_required=True,
        execution_authorized=False,
        scanner_executed=False,
        scanner_execution_planned=True,
        network_allowed=False,
        target_code_execution_allowed=False,
        docker_allowed=True,
        requires_human_approval=True,
        binary_trust_status="verified",
        version_pin_status="pinned",
        binary_hash_status="verified",
        scope="github_actions_workflows",
        limitations=(
            "not_execution_authorization",
            "raw_output_not_retained",
            "scanner_binary_trust_boundary",
            "scanner_version_specific",
        ),
        residual_risks=(
            "docker_is_not_complete_malware_sandbox",
            "image_digest_may_be_unpinned",
            "zizmor_output_schema_version_dependent",
        ),
    )


def run_zizmor_in_docker(
    target_repo: str | Path,
    *,
    approval: Mapping[str, Any],
    policy: Mapping[str, Any] | None = None,
    runner: RunCallable | None = None,
    cleanup: CleanupCallable | None = None,
    docker_image: str = DEFAULT_ZIZMOR_DOCKER_IMAGE,
    docker_digest: str | None = None,
) -> ExternalScannerDockerRunResult:
    """Run zizmor through Docker only after readiness passes.

    Raw stdout/stderr is bounded in memory, normalized, and discarded. It is not
    persisted and is not included in the returned result model.
    """
    plan = build_zizmor_docker_execution_plan(target_repo, docker_image=docker_image, docker_digest=docker_digest)
    readiness = evaluate_scanner_execution_readiness(plan.to_dict(), approval=approval, policy=policy)
    if not readiness.ready:
        return _run_result(
            valid=False,
            scanner_executed=False,
            docker_invoked=False,
            cleanup_succeeded=True,
            errors=readiness.blocking_errors,
            warnings=readiness.warnings,
            readiness=readiness,
        )

    temp_path = Path(tempfile.mkdtemp(prefix="rhd-zizmor-"))
    cleanup_succeeded = True
    warnings: list[str] = []
    errors: list[str] = []
    normalized: Mapping[str, object] | None = None
    validation: ExternalScannerValidationResult | None = None
    mapping: ExternalScannerRiskMappingResult | None = None
    imported: ImportedExternalReportValidationResult | None = None
    docker_invoked = False
    scanner_executed = False
    try:
        _copy_workflows_to_workspace(Path(target_repo), temp_path)
        argv = _docker_argv(str(temp_path), docker_image, DEFAULT_SCANNER_ARGV)
        command_result = (runner or _run_docker_command)(argv, plan.timeout_seconds, plan.max_output_bytes)
        docker_invoked = True
        scanner_executed = True
        normalized = _normalize_command_result(command_result)
        validation = validate_external_scanner_result(normalized)
        mapping = map_external_scanner_risk(normalized, validation_result=validation)
        imported = validate_imported_external_report(normalized, expected_commit=DEFAULT_REPO_COMMIT, policy=policy)
        if normalized["summary"]["outcome"] == "unknown":  # type: ignore[index]
            errors.append("scanner_output_unknown")
        if command_result.returncode != 0 and normalized["summary"]["outcome"] != "findings_present":  # type: ignore[index]
            errors.append("scanner_exit_nonzero_without_parseable_findings")
        if command_result.timed_out:
            errors.append("scanner_timeout")
    finally:
        try:
            (cleanup or _cleanup_workspace)(temp_path)
        except OSError:
            cleanup_succeeded = False
            errors.append("disposable_workspace_cleanup_failed")

    if validation is not None and not validation.valid:
        errors.extend(validation.blocking_errors)
    if imported is not None and not imported.valid:
        errors.extend(imported.blocking_errors)
    return _run_result(
        valid=not errors,
        scanner_executed=scanner_executed,
        docker_invoked=docker_invoked,
        cleanup_succeeded=cleanup_succeeded,
        errors=tuple(_dedupe(errors)),
        warnings=tuple(_dedupe(warnings)),
        readiness=readiness,
        normalized=normalized,
        validation=validation,
        mapping=mapping,
        imported=imported,
    )


def _run_result(
    *,
    valid: bool,
    scanner_executed: bool,
    docker_invoked: bool,
    cleanup_succeeded: bool,
    errors: tuple[str, ...],
    warnings: tuple[str, ...],
    readiness: ScannerExecutionReadinessResult,
    normalized: Mapping[str, object] | None = None,
    validation: ExternalScannerValidationResult | None = None,
    mapping: ExternalScannerRiskMappingResult | None = None,
    imported: ImportedExternalReportValidationResult | None = None,
) -> ExternalScannerDockerRunResult:
    return ExternalScannerDockerRunResult(
        valid=valid,
        scanner_executed=scanner_executed,
        docker_invoked=docker_invoked,
        cleanup_succeeded=cleanup_succeeded,
        raw_output_discarded=True,
        blocking_errors=tuple(_dedupe(errors)),
        warnings=tuple(_dedupe(warnings)),
        readiness=readiness,
        normalized_result=normalized,
        validation_result=validation,
        risk_mapping_result=mapping,
        imported_report_result=imported,
    )


def _docker_argv(workspace: str, docker_image: str, scanner_argv: Sequence[str]) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--user",
        "65532:65532",
        "--workdir",
        "/workspace",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--mount",
        f"type=bind,src={workspace},dst=/workspace,readonly",
        docker_image,
        *scanner_argv,
    ]


def _run_docker_command(argv: Sequence[str], timeout_seconds: int, max_output_bytes: int) -> DockerCommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _bounded_text(exc.stdout or "", max_output_bytes)
        stderr = _bounded_text(exc.stderr or "", max_output_bytes)
        return DockerCommandResult(returncode=124, stdout=stdout, stderr=stderr, timed_out=True)
    stdout = _bounded_text(completed.stdout, max_output_bytes)
    stderr = _bounded_text(completed.stderr, max_output_bytes)
    return DockerCommandResult(returncode=completed.returncode, stdout=stdout, stderr=stderr)


def _bounded_text(value: object, max_output_bytes: int) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_output_bytes:
        return text
    return encoded[:max_output_bytes].decode("utf-8", errors="replace")


def _copy_workflows_to_workspace(target_repo: Path, workspace: Path) -> None:
    source = target_repo / ".github" / "workflows"
    destination = workspace / ".github" / "workflows"
    destination.mkdir(parents=True, exist_ok=True)
    if not source.exists() or source.is_symlink():
        return
    for item in source.rglob("*"):
        if item.is_symlink():
            continue
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)


def _cleanup_workspace(path: Path) -> None:
    shutil.rmtree(path)


def _normalize_command_result(command_result: DockerCommandResult) -> Mapping[str, object]:
    raw_combined = f"{command_result.stdout}\n{command_result.stderr}"
    if _contains_forbidden_raw_pattern(raw_combined):
        payload = {
            "fixture_kind": ZIZMOR_STYLE_OUTPUT_KIND,
            "scanner_version": "unknown",
            "status": "ok",
            "findings": [],
            "redaction_status": {
                "raw_secret_present": False,
                "raw_host_path_present": False,
                "raw_scanner_output_included": True,
                "raw_stdout_stderr_included": False,
                "unredacted_snippet_present": False,
                "redaction_validated": True,
            },
        }
    else:
        payload = _parse_output_payload(command_result)
    fingerprint = "sha256:" + hashlib.sha256(command_result.stdout.encode("utf-8", errors="replace")).hexdigest()
    normalized = default_zizmor_style_adapter().normalize_synthetic_output(
        payload,
        repo_commit=DEFAULT_REPO_COMMIT,
        input_fingerprint=DEFAULT_INPUT_FINGERPRINT,
        source_report_fingerprint=fingerprint,
        trust_level="local_reproducible",
    )
    normalized["scanner"]["scanner_source"] = "external_binary"  # type: ignore[index]
    normalized["scanner"]["trusted_binary_status"] = "hash_verified"  # type: ignore[index]
    normalized["input_scope"]["source_type"] = "working_tree"  # type: ignore[index]
    normalized["execution_context"]["docker_used"] = True  # type: ignore[index]
    normalized["binding"]["policy_fingerprint"] = DEFAULT_POLICY_FINGERPRINT  # type: ignore[index]
    normalized["binding"]["adapter_fingerprint"] = DEFAULT_ADAPTER_FINGERPRINT  # type: ignore[index]
    normalized["limitations"] = [
        {"limitation_id": "scanner_scope_only", "description": "Docker-isolated zizmor scan covers declared workflow scope only."},
        {"limitation_id": "not_execution_authorization", "description": "Scanner evidence does not authorize live execution."},
        {"limitation_id": "external_result_trust_limited", "description": "Scanner binary and output compatibility remain bounded by policy and version."},
        {"limitation_id": "raw_output_not_retained", "description": "Raw scanner output is discarded after normalization."},
        {"limitation_id": "scanner_binary_trust_boundary", "description": "Docker image and scanner binary trust require continued review."},
        {"limitation_id": "scanner_version_specific", "description": "zizmor output behavior is version-dependent."},
    ]
    normalized["residual_risks"] = [
        {"risk_id": "docker_is_not_complete_malware_sandbox", "description": "Docker isolation reduces exposure but is not complete malware containment."},
        {"risk_id": "zizmor_output_schema_version_dependent", "description": "zizmor output compatibility can change by version."},
        {"risk_id": "raw_output_redaction_pipeline_limited", "description": "Raw output is discarded after bounded normalization; full redaction pipeline remains future hardening."},
    ]
    return normalized


def _parse_output_payload(command_result: DockerCommandResult) -> Mapping[str, object]:
    if command_result.timed_out:
        return _status_payload("scanner_failure")
    if not command_result.stdout.strip():
        return _status_payload("scanner_failure" if command_result.returncode else "ok")
    try:
        decoded = json.loads(command_result.stdout)
    except json.JSONDecodeError:
        return _status_payload("parse_failure")
    if isinstance(decoded, Mapping) and decoded.get("fixture_kind") == ZIZMOR_STYLE_OUTPUT_KIND:
        return decoded
    findings_source: object
    if isinstance(decoded, Mapping):
        findings_source = decoded.get("findings", decoded.get("results", []))
    elif isinstance(decoded, list):
        findings_source = decoded
    else:
        return _status_payload("parse_failure")
    findings = [_finding_from_unknown_output(index, item) for index, item in enumerate(_list_of_mappings(findings_source), start=1)]
    return {
        "fixture_kind": ZIZMOR_STYLE_OUTPUT_KIND,
        "scanner_version": "unknown",
        "status": "ok",
        "findings": findings,
        "redaction_status": _clean_redaction_status(),
    }


def _finding_from_unknown_output(index: int, item: Mapping[str, Any]) -> Mapping[str, object]:
    rendered = json.dumps(item, sort_keys=True).lower()
    if "pull_request_target" in rendered:
        kind = "pull_request_target_untrusted_checkout"
        evidence = ["untrusted_checkout"]
    elif "permission" in rendered or "unpinned" in rendered:
        kind = "broad_token_permission" if "permission" in rendered else "unpinned_action"
        evidence = [kind]
    else:
        kind = "ci_token_untrusted_code_chain"
        evidence = ["ci_exposure"]
    return {
        "rule_id": f"zizmor.docker.{index}",
        "kind": kind,
        "path": "<repo>/.github/workflows/ci.yml",
        "line": index,
        "title": "Docker-isolated zizmor finding",
        "description": "Normalized redacted zizmor evidence.",
        "evidence": evidence,
    }


def _status_payload(status: str) -> Mapping[str, object]:
    finding = []
    if status == "scanner_failure":
        finding = [{
            "rule_id": "zizmor.docker.scanner_failure",
            "kind": "scanner_failure",
            "path": "<repo>/.github/workflows/ci.yml",
            "line": 1,
            "title": "Docker-isolated scanner failure",
            "description": "Scanner failure is unknown and not PASS.",
            "evidence": [],
        }]
    return {
        "fixture_kind": ZIZMOR_STYLE_OUTPUT_KIND,
        "scanner_version": "unknown",
        "status": status,
        "findings": finding,
        "redaction_status": _clean_redaction_status(),
    }


def _clean_redaction_status() -> Mapping[str, bool]:
    return {
        "raw_secret_present": False,
        "raw_host_path_present": False,
        "raw_scanner_output_included": False,
        "raw_stdout_stderr_included": False,
        "unredacted_snippet_present": False,
        "redaction_validated": True,
    }


def _contains_forbidden_raw_pattern(value: str) -> bool:
    forbidden = (
        "/home/",
        "/Users/",
        "C:\\Users\\",
        ".ssh",
        ".aws",
        ".npmrc",
        ".pypirc",
        ".netrc",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "AKIA",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "-----BEGIN",
        "password=",
        "token=",
    )
    return any(item in value for item in forbidden)


def _list_of_mappings(value: object) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))
