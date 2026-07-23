"""Real Gitleaks external scanner adapter.

The adapter invokes a locally installed Gitleaks binary only. It does not use a
shell, network, Docker, target-code execution, or raw report retention.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable, Iterable, Mapping, Sequence

from ...sandbox.run_workspace import (
    DisposableWorkspace,
    create_static_scan_snapshot,
    verify_verified_snapshot,
)
from ..result_validator import (
    EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
    REPORT_KIND_EXTERNAL_SCANNER_RESULT,
    validate_external_scanner_result,
)
from .base import ExternalScannerAdapterCapability


ADAPTER_VERSION = "0.1"
GITLEAKS_SCANNER_NAME = "gitleaks"
GITLEAKS_CATEGORY = "secret_detection"
GITLEAKS_MODE = "local_static_no_network"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_POLICY_FINGERPRINT = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
DEFAULT_ADAPTER_FINGERPRINT = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
VERSION_PATTERN = re.compile(r"^(?:gitleaks\s+)?v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9._-]+)?$")

LIMITATIONS = (
    "scanner_scope_only",
    "not_execution_authorization",
    "external_result_trust_limited",
    "raw_output_not_retained",
    "scanner_binary_trust_boundary",
    "scanner_version_specific",
)
POSIX_HOME_MARKER = "/" + "home" + "/"
POSIX_USERS_MARKER = "/" + "users" + "/"

RunnerCallable = Callable[[Sequence[str], int], "GitleaksCommandResult"]


@dataclass(frozen=True)
class GitleaksCommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class GitleaksExitInterpretation:
    returncode: int
    status: str
    outcome: str
    consume_report: bool
    unknown_reason: str | None
    blocking_error: str | None


@dataclass(frozen=True)
class GitleaksRunResult:
    valid: bool
    scanner_executed: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    normalized_result: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "scanner_executed": self.scanner_executed,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "normalized_result": dict(self.normalized_result),
        }


class GitleaksAdapter:
    def capability(self) -> ExternalScannerAdapterCapability:
        return ExternalScannerAdapterCapability(
            scanner_name=GITLEAKS_SCANNER_NAME,
            scanner_category=GITLEAKS_CATEGORY,
            supported_mode=GITLEAKS_MODE,
            allowed_input_paths=("<repo>",),
            requires_network=False,
            executes_target_code=False,
            docker_needed=False,
            raw_output_retention=False,
            expected_output_kind="gitleaks_json_array",
            limitations=LIMITATIONS,
            residual_risks=(
                "gitleaks_rule_coverage_limited",
                "gitleaks_binary_unattested",
                "dirty_worktree_may_not_match_commit",
            ),
        )

    def build_scan_argv(self, repo_path: str | Path, report_path: str | Path) -> tuple[str, ...]:
        return build_gitleaks_scan_argv(repo_path, report_path)


def default_gitleaks_adapter() -> GitleaksAdapter:
    return GitleaksAdapter()


def build_gitleaks_scan_argv(repo_path: str | Path, report_path: str | Path) -> tuple[str, ...]:
    return (
        "gitleaks",
        "git",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--redact",
        "--exit-code",
        "2",
        "--no-banner",
        "--log-level",
        "error",
        str(repo_path),
    )


def interpret_gitleaks_exit_code(returncode: int) -> GitleaksExitInterpretation:
    if returncode == 0:
        return GitleaksExitInterpretation(returncode, "completed_no_findings", "no_findings_in_scope", True, None, None)
    if returncode == 2:
        return GitleaksExitInterpretation(returncode, "completed_with_findings", "findings_present", True, None, None)
    if returncode == 1:
        return GitleaksExitInterpretation(returncode, "tool_error", "unknown", False, "unknown", "scan_error")
    if returncode == 126:
        return GitleaksExitInterpretation(returncode, "tool_interface_error", "unknown", False, "unknown", "tool_interface_error")
    return GitleaksExitInterpretation(returncode, "tool_unknown_error", "unknown", False, "unknown", "tool_unknown_error")


def run_gitleaks_scan(
    repo_path: str | Path,
    *,
    runner: RunnerCallable | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    _verified_workspace: DisposableWorkspace | None = None,
) -> GitleaksRunResult:
    if _verified_workspace is None:
        workspace = create_static_scan_snapshot(Path(repo_path))
        try:
            if workspace.verified_snapshot is None:
                normalized = _unknown_result(
                    scanner_version="unknown",
                    repo_commit=None,
                    dirty_state="unknown",
                    unknown_reason="snapshot_intake_refused",
                    scanner_completed=False,
                )
                return _run_result(
                    False,
                    False,
                    ("snapshot_intake_refused",),
                    (),
                    normalized,
                )
            return run_gitleaks_scan(
                workspace.workspace,
                runner=runner,
                timeout_seconds=timeout_seconds,
                _verified_workspace=workspace,
            )
        finally:
            workspace.cleanup()
    target_repo = Path(repo_path)
    verified_snapshot = _verified_workspace.verified_snapshot
    if (
        verified_snapshot is None
        or target_repo.resolve() != _verified_workspace.workspace.resolve()
        or not verify_verified_snapshot(_verified_workspace)
    ):
        normalized = _unknown_result(
            scanner_version="unknown",
            repo_commit=None,
            dirty_state="unknown",
            unknown_reason="snapshot_intake_refused",
            scanner_completed=False,
        )
        return _run_result(
            False,
            False,
            ("snapshot_intake_refused",),
            (),
            normalized,
        )
    active_runner = runner or _run_command
    repo_commit, dirty_state = _repo_commit_and_dirty_state(verified_snapshot)
    version_result = _run_preflight(active_runner, timeout_seconds)
    if version_result is None or version_result.returncode != 0 or version_result.timed_out:
        normalized = _unknown_result(
            scanner_version="unknown",
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="scanner_unavailable",
            scanner_completed=False,
        )
        return _run_result(False, False, ("scanner_unavailable",), (), normalized)

    scanner_version = _version_text(version_result.stdout, version_result.stderr)
    try:
        return _run_scan_pipeline(
            active_runner,
            target_repo,
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            timeout_seconds=timeout_seconds,
        )
    except Exception:
        # Fail-closed: any unexpected error (tempdir creation, report read I/O,
        # normalization, or validation) is converted into a normalized
        # quarantine result instead of letting a raw exception escape the
        # adapter and rely on the caller to treat it as "block".
        normalized = _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="adapter_error",
            scanner_completed=False,
        )
        return _run_result(False, True, ("adapter_internal_error",), (), normalized)


def _run_scan_pipeline(
    active_runner: RunnerCallable,
    target_repo: Path,
    *,
    scanner_version: str,
    repo_commit: str | None,
    dirty_state: str,
    timeout_seconds: int,
) -> GitleaksRunResult:
    with tempfile.TemporaryDirectory(prefix="rhd-gitleaks-") as temp_dir:
        report_path = Path(temp_dir) / "gitleaks-report.json"
        argv = build_gitleaks_scan_argv(target_repo, report_path)
        scan_result = _run_scan(active_runner, argv, timeout_seconds)
        if scan_result is None:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="scanner_unavailable",
                scanner_completed=False,
            )
            return _run_result(False, True, ("scanner_unavailable",), (), normalized)
        if scan_result.timed_out:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="timeout",
                scanner_completed=False,
                timeout_occurred=True,
            )
            return _run_result(False, True, ("scanner_timeout",), (), normalized)

        interpretation = interpret_gitleaks_exit_code(scan_result.returncode)
        if not interpretation.consume_report:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason=interpretation.unknown_reason or "unknown",
                scanner_completed=False,
            )
            return _run_result(False, True, tuple(item for item in (interpretation.blocking_error,) if item), (), normalized)

        if not report_path.exists():
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="parse_failure",
                scanner_completed=False,
            )
            return _run_result(False, True, ("missing_report",), (), normalized)

        report_bytes = report_path.read_bytes()
        parsed = _parse_gitleaks_report(report_bytes)
        if parsed is None:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="parse_failure",
                scanner_completed=False,
                source_report_fingerprint=_sha256_bytes(report_bytes),
            )
            return _run_result(False, True, ("parse_failure",), (), normalized)
        if _exit_code_report_mismatch(interpretation.status, parsed):
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="parse_failure",
                scanner_completed=False,
                source_report_fingerprint=_sha256_bytes(report_bytes),
            )
            return _run_result(False, True, ("report_exit_code_mismatch",), (), normalized)
        if interpretation.status == "completed_no_findings" and (repo_commit is None or dirty_state != "clean"):
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="scope_ambiguous",
                scanner_completed=True,
                source_report_fingerprint=_sha256_bytes(report_bytes),
            )
            return _run_result(False, True, ("dirty_worktree_scope_ambiguous",), (), normalized)

        normalized = _normalized_result(
            parsed,
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            source_report_fingerprint=_sha256_bytes(report_bytes),
            outcome=interpretation.outcome,
        )
        validation = validate_external_scanner_result(normalized)
        if not validation.valid:
            return _run_result(False, True, validation.blocking_errors, validation.warnings, normalized)
        return _run_result(True, True, (), (), normalized)


def normalize_gitleaks_json_array(
    report: Sequence[Mapping[str, Any]],
    *,
    scanner_version: str = "unknown",
    repo_commit: str | None = None,
    dirty_state: str = "unknown",
    outcome: str | None = None,
) -> Mapping[str, object]:
    if not all(_is_minimal_gitleaks_finding(item) for item in report):
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="parse_failure",
            scanner_completed=False,
            source_report_fingerprint=_fingerprint_json_array(report),
        )
    effective_outcome = outcome or ("findings_present" if report else "no_findings_in_scope")
    if effective_outcome == "no_findings_in_scope" and (repo_commit is None or dirty_state != "clean"):
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="scope_ambiguous",
            scanner_completed=True,
            source_report_fingerprint=_fingerprint_json_array(report),
        )
    return _normalized_result(
        report,
        scanner_version=scanner_version,
        repo_commit=repo_commit,
        dirty_state=dirty_state,
        source_report_fingerprint=_fingerprint_json_array(report),
        outcome=effective_outcome,
    )


def _run_preflight(runner: RunnerCallable, timeout_seconds: int) -> GitleaksCommandResult | None:
    try:
        return runner(("gitleaks", "version"), timeout_seconds)
    except (FileNotFoundError, OSError):
        return None


def _run_scan(runner: RunnerCallable, argv: Sequence[str], timeout_seconds: int) -> GitleaksCommandResult | None:
    try:
        return runner(argv, timeout_seconds)
    except (FileNotFoundError, OSError):
        return None


def _run_command(argv: Sequence[str], timeout_seconds: int) -> GitleaksCommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return GitleaksCommandResult(
            returncode=124,
            stdout=_bounded_text(exc.stdout or ""),
            stderr=_bounded_text(exc.stderr or ""),
            timed_out=True,
        )
    return GitleaksCommandResult(
        returncode=completed.returncode,
        stdout=_bounded_text(completed.stdout),
        stderr=_bounded_text(completed.stderr),
    )


def _repo_commit_and_dirty_state(
    snapshot: object,
) -> tuple[str | None, str]:
    if (
        not hasattr(snapshot, "source_kind")
        or getattr(snapshot, "source_kind") != "git_commit"
        or not isinstance(getattr(snapshot, "source_commit", None), str)
    ):
        return None, "unknown"
    return str(getattr(snapshot, "source_commit")), "clean"


def _parse_gitleaks_report(report_bytes: bytes) -> tuple[Mapping[str, Any], ...] | None:
    try:
        decoded = json.loads(report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, list):
        return None
    if not all(isinstance(item, Mapping) for item in decoded):
        return None
    if not all(_is_minimal_gitleaks_finding(item) for item in decoded):
        return None
    return tuple(decoded)


def _is_minimal_gitleaks_finding(finding: Mapping[str, Any]) -> bool:
    required_string_fields = ("RuleID", "File")
    if any(not isinstance(finding.get(field), str) or not finding.get(field) for field in required_string_fields):
        return False
    for field in ("StartLine", "EndLine", "StartColumn", "EndColumn"):
        value = finding.get(field)
        if value is not None and not isinstance(value, int):
            return False
    if "Tags" in finding and not isinstance(finding.get("Tags"), list):
        return False
    return True


def _exit_code_report_mismatch(status: str, report: Sequence[Mapping[str, Any]]) -> bool:
    return (status == "completed_no_findings" and bool(report)) or (status == "completed_with_findings" and not report)


def _normalized_result(
    report: Sequence[Mapping[str, Any]],
    *,
    scanner_version: str,
    repo_commit: str | None,
    dirty_state: str,
    source_report_fingerprint: str,
    outcome: str,
) -> Mapping[str, object]:
    findings = [_normalized_finding(index, finding) for index, finding in enumerate(report, start=1)]
    nodes = [_normalized_node(index, finding) for index, finding in enumerate(report, start=1)]
    finding_count = len(findings)
    risk_effect = "T5_candidate" if finding_count else "none"
    gate_effects = ["blocks_live_execution"] if finding_count else ["evidence_only"]
    rules_fired = ["RISK001"] if any(item["secondary_category"] == "secret_like_value" for item in findings) else []
    return {
        "schema_version": EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_EXTERNAL_SCANNER_RESULT,
        "scanner": {
            "name": GITLEAKS_SCANNER_NAME,
            "version": scanner_version,
            "adapter_version": ADAPTER_VERSION,
            "category": GITLEAKS_CATEGORY,
            "mode": GITLEAKS_MODE,
            "scanner_source": "external_binary",
            "trusted_binary_status": "unverified",
            "unsupported_version": False,
        },
        "input_scope": {
            "scope": "repo",
            "source_type": "git_commit",
            "repo_commit": repo_commit,
            "dirty_state": dirty_state,
            "input_fingerprint": _input_fingerprint(repo_commit, dirty_state),
            "included_paths": ["<repo>"],
            "excluded_paths": [],
        },
        "execution_context": {
            "network_used": False,
            "target_code_executed": False,
            "docker_used": False,
            "scanner_downloaded_dependencies": False,
            "raw_output_available": False,
            "raw_output_retained": False,
            "timeout_occurred": False,
            "scanner_completed": True,
        },
        "trust_level": "local_reproducible",
        "execution_authorized": False,
        "findings": findings,
        "evidence_nodes": nodes,
        "evidence_edges": [],
        "summary": {
            "outcome": outcome,
            "finding_count": finding_count,
            "highest_risk_tier_effect": risk_effect,
            "gate_effects": gate_effects,
        },
        "mapping_result": {
            "risk_tier_effect": risk_effect,
            "gate_effects": gate_effects,
            "rules_fired": rules_fired,
            "risk_lowering_allowed": False,
        },
        "redaction_status": _redaction_status(),
        "limitations": _limitations(),
        "residual_risks": _residual_risks(dirty_state),
        "binding": {
            "repo_commit": repo_commit,
            "input_fingerprint": _input_fingerprint(repo_commit, dirty_state),
            "source_report_fingerprint": source_report_fingerprint,
            "policy_fingerprint": DEFAULT_POLICY_FINGERPRINT,
            "adapter_fingerprint": DEFAULT_ADAPTER_FINGERPRINT,
        },
    }


def _unknown_result(
    *,
    scanner_version: str,
    repo_commit: str | None,
    dirty_state: str,
    unknown_reason: str,
    scanner_completed: bool,
    timeout_occurred: bool = False,
    source_report_fingerprint: str | None = None,
) -> Mapping[str, object]:
    return {
        "schema_version": EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_EXTERNAL_SCANNER_RESULT,
        "scanner": {
            "name": GITLEAKS_SCANNER_NAME,
            "version": scanner_version,
            "adapter_version": ADAPTER_VERSION,
            "category": GITLEAKS_CATEGORY,
            "mode": GITLEAKS_MODE,
            "scanner_source": "external_binary",
            "trusted_binary_status": "unverified",
            "unsupported_version": False,
        },
        "input_scope": {
            "scope": "repo",
            "source_type": "git_commit",
            "repo_commit": repo_commit,
            "dirty_state": dirty_state,
            "input_fingerprint": _input_fingerprint(repo_commit, dirty_state),
            "included_paths": ["<repo>"],
            "excluded_paths": [],
        },
        "execution_context": {
            "network_used": False,
            "target_code_executed": False,
            "docker_used": False,
            "scanner_downloaded_dependencies": False,
            "raw_output_available": False,
            "raw_output_retained": False,
            "timeout_occurred": timeout_occurred,
            "scanner_completed": scanner_completed,
        },
        "trust_level": "local_reproducible",
        "execution_authorized": False,
        "findings": [],
        "evidence_nodes": [],
        "evidence_edges": [],
        "summary": {
            "outcome": "unknown",
            "unknown_reason": unknown_reason,
            "finding_count": 0,
            "highest_risk_tier_effect": "T5_candidate",
            "gate_effects": ["quarantine"],
        },
        "mapping_result": {
            "risk_tier_effect": "T5_candidate",
            "gate_effects": ["quarantine"],
            "rules_fired": [],
            "risk_lowering_allowed": False,
        },
        "redaction_status": _redaction_status(),
        "limitations": _limitations(),
        "residual_risks": _residual_risks(dirty_state),
        "binding": {
            "repo_commit": repo_commit,
            "input_fingerprint": _input_fingerprint(repo_commit, dirty_state),
            "source_report_fingerprint": source_report_fingerprint,
            "policy_fingerprint": DEFAULT_POLICY_FINGERPRINT,
            "adapter_fingerprint": DEFAULT_ADAPTER_FINGERPRINT,
        },
    }


def _normalized_finding(index: int, finding: Mapping[str, Any]) -> Mapping[str, object]:
    rule_id = _string_field(finding, "RuleID", f"gitleaks.finding.{index}")
    file_path = _relative_repo_path(_string_field(finding, "File", "<repo>"))
    start_line = _positive_int(finding.get("StartLine"))
    start_column = _positive_int(finding.get("StartColumn"))
    return {
        "finding_id": f"gitleaks-{index}",
        "scanner_rule_id": rule_id,
        "primary_category": "secret",
        "secondary_category": "secret_like_value",
        "scanner_severity": "secret",
        "normalized_severity": "block",
        "confidence": "medium",
        "title": f"Gitleaks finding {rule_id}",
        "redacted_description": "Gitleaks reported a secret candidate; raw secret, match, and rule metadata omitted.",
        "location": {"path": file_path, "line": start_line, "column": start_column},
        "evidence": _safe_evidence(finding),
        "risk_mapping": {"risk_tier_effect": "raise_to_T5", "rule_ids": ["RISK001"]},
        "gate_effect": "blocks_live_execution",
    }


def _normalized_node(index: int, finding: Mapping[str, Any]) -> Mapping[str, object]:
    return {
        "node_id": f"gitleaks-node-{index}",
        "primary_category": "secret",
        "secondary_category": "secret_like_value",
        "title": f"Gitleaks finding {_string_field(finding, 'RuleID', str(index))}",
        "redacted_summary": "Gitleaks reported a secret candidate; raw secret, match, and rule metadata omitted.",
        "location": {
            "path": _relative_repo_path(_string_field(finding, "File", "<repo>")),
            "line": _positive_int(finding.get("StartLine")),
            "column": _positive_int(finding.get("StartColumn")),
        },
        "confidence": "medium",
    }


def _safe_evidence(finding: Mapping[str, Any]) -> list[str]:
    evidence = [
        f"rule_id:{_string_field(finding, 'RuleID', 'unknown')}",
        f"description:{_metadata_state(finding, 'Description')}",
        f"file:{_relative_repo_path(_string_field(finding, 'File', '<repo>'))}",
        f"start_line:{_field_value(finding.get('StartLine'))}",
        f"end_line:{_field_value(finding.get('EndLine'))}",
        f"start_column:{_field_value(finding.get('StartColumn'))}",
        f"end_column:{_field_value(finding.get('EndColumn'))}",
        f"commit:{_string_field(finding, 'Commit', 'unknown')}",
        f"fingerprint:{_safe_fingerprint(_string_field(finding, 'Fingerprint', 'unknown'))}",
        f"tags:{_tags_state(finding.get('Tags'))}",
        f"entropy:{_field_value(finding.get('Entropy'))}",
        f"secret_redacted:{_secret_redacted_state(finding)}",
    ]
    return evidence


def _metadata_state(finding: Mapping[str, Any], field: str) -> str:
    return "present_omitted" if field in finding else "unknown"


def _tags_state(value: Any) -> str:
    if value is None:
        return "unknown"
    if not isinstance(value, list):
        return "invalid_omitted"
    return f"present_count:{len(value)}"


def _secret_redacted_state(finding: Mapping[str, Any]) -> str:
    if "Secret" not in finding:
        return "unknown"
    # Do not inspect the raw Secret field value; even redacted values stay out
    # of normalized evidence.
    return "unknown"


def _redaction_status() -> Mapping[str, bool]:
    return {
        "raw_secret_present": False,
        "raw_host_path_present": False,
        "raw_scanner_output_included": False,
        "raw_stdout_stderr_included": False,
        "unredacted_snippet_present": False,
        "redaction_validated": True,
    }


def _limitations() -> list[Mapping[str, str]]:
    return [
        {"limitation_id": "scanner_scope_only", "description": "Gitleaks scanner reached only the configured repository scope."},
        {"limitation_id": "not_execution_authorization", "description": "Gitleaks evidence does not authorize execution or prove safety."},
        {"limitation_id": "external_result_trust_limited", "description": "Only rules and configuration detectable by this Gitleaks run are represented."},
        {"limitation_id": "raw_output_not_retained", "description": "Raw Gitleaks JSON, stdout, and stderr are not retained in normalized output."},
        {"limitation_id": "scanner_binary_trust_boundary", "description": "The local Gitleaks binary is outside repo-health-doctor's trust boundary."},
        {"limitation_id": "scanner_version_specific", "description": "Gitleaks behavior and JSON shape are version-specific."},
    ]


def _residual_risks(dirty_state: str) -> list[Mapping[str, str]]:
    risks = [
        {"risk_id": "no_findings_not_safety_proof", "description": "No finding is not proof of safety."},
        {"risk_id": "gitleaks_rules_config_only", "description": "Only secrets detectable by the active Gitleaks rules and configuration are represented."},
        {"risk_id": "scanner_scope_only", "description": "Files outside the reached scanner scope are not covered."},
    ]
    if dirty_state == "dirty":
        risks.append({
            "risk_id": "dirty_worktree_not_clean_commit_evidence",
            "description": "The scan was bound to HEAD with a dirty working tree and is not clean commit-only evidence.",
        })
    return risks


def _run_result(
    valid: bool,
    scanner_executed: bool,
    blocking_errors: tuple[str, ...],
    warnings: tuple[str, ...],
    normalized: Mapping[str, object],
) -> GitleaksRunResult:
    return GitleaksRunResult(
        valid=valid,
        scanner_executed=scanner_executed,
        blocking_errors=tuple(_dedupe(blocking_errors)),
        warnings=tuple(_dedupe(warnings)),
        normalized_result=normalized,
    )


def _version_text(stdout: str, stderr: str) -> str:
    value = (stdout or stderr).strip().splitlines()
    candidate = value[0].strip() if value and value[0].strip() else ""
    return candidate if VERSION_PATTERN.fullmatch(candidate) else "unknown"


def _input_fingerprint(repo_commit: str | None, dirty_state: str) -> str:
    return _sha256_text(f"repo_commit={repo_commit or 'unknown'}\ndirty_state={dirty_state}\n")


def _fingerprint_json_array(report: Sequence[Mapping[str, Any]]) -> str:
    payload = json.dumps(list(report), sort_keys=True, separators=(",", ":"))
    return _sha256_text(payload)


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bounded_text(value: object, max_bytes: int = 131072) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="replace")


def _relative_repo_path(path: str) -> str:
    clean = path.replace("\\", "/")
    if _looks_like_host_path(clean):
        return "<repo>/<redacted-host-path>"
    clean = clean.lstrip("/")
    if not clean or clean == "<repo>":
        return "<repo>"
    if clean.startswith("<repo>/"):
        return clean
    return f"<repo>/{clean}"


def _safe_fingerprint(value: str) -> str:
    normalized = value.replace("\\", "/")
    if _looks_like_host_path(normalized) or ":/" in normalized or re.search(r"[A-Za-z]:/", normalized):
        return "redacted-host-path:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return value


def _looks_like_host_path(value: str) -> bool:
    lowered = value.lower()
    return (
        value.startswith("/")
        or (len(value) >= 3 and value[1] == ":" and value[2] == "/")
        or lowered.startswith("home/")
        or lowered.startswith("users/")
        or POSIX_HOME_MARKER in lowered
        or POSIX_USERS_MARKER in lowered
    )


def _string_field(data: Mapping[str, Any], key: str, default: str) -> str:
    value = data.get(key)
    return value if isinstance(value, str) and value else default


def _positive_int(value: object) -> int | None:
    return value if isinstance(value, int) and value > 0 else None


def _field_value(value: object) -> str:
    if isinstance(value, (int, float, str)) and value != "":
        return str(value)
    return "unknown"


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
