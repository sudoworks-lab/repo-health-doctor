"""Real Trivy external scanner adapter.

The adapter invokes a locally installed Trivy binary only. It runs filesystem
scans, may use network/cache for Trivy databases, and does not retain raw
scanner reports, stdout, stderr, secret matches, or code snippets.
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

from ..result_validator import (
    EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
    REPORT_KIND_EXTERNAL_SCANNER_RESULT,
    validate_external_scanner_result,
)
from .base import ExternalScannerAdapterCapability


ADAPTER_VERSION = "0.1"
TRIVY_SCANNER_NAME = "trivy"
TRIVY_SCANNER_CATEGORY = "custom_static"
TRIVY_SCANNER_MODE = "local_static_network"
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_POLICY_FINGERPRINT = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
DEFAULT_ADAPTER_FINGERPRINT = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
DEFAULT_TRIVY_SCANNERS = ("vuln", "misconfig")
UNSAFE_TRIVY_VERSIONS = frozenset({"0.69.4", "0.69.5", "0.69.6"})

VERSION_PATTERN = re.compile(r"\bv?(\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9._-]+)?)\b")
LOCAL_IP_PATTERN = re.compile(r"(?<!\d)(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)")
URL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

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
SECRET_MARKERS = (
    "akia",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "sk-",
    "password=",
    "secret=",
    "token=",
    "api_key",
    "access_key",
    "authorization",
    "bearer ",
    "-----begin",
)

RunnerCallable = Callable[[Sequence[str], int], "TrivyCommandResult"]


@dataclass(frozen=True)
class TrivyCommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class TrivyExitInterpretation:
    returncode: int
    status: str
    outcome: str
    consume_report: bool
    unknown_reason: str | None
    blocking_error: str | None


@dataclass(frozen=True)
class TrivyVersionAssessment:
    version: str
    supported_for_live_scan: bool
    unsupported_version: bool
    blocking_error: str | None
    unknown_reason: str | None


@dataclass(frozen=True)
class TrivyRunResult:
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


class TrivyAdapter:
    def capability(self) -> ExternalScannerAdapterCapability:
        return ExternalScannerAdapterCapability(
            scanner_name=TRIVY_SCANNER_NAME,
            scanner_category=TRIVY_SCANNER_CATEGORY,
            supported_mode=TRIVY_SCANNER_MODE,
            allowed_input_paths=("<repo>",),
            requires_network=True,
            executes_target_code=False,
            docker_needed=False,
            raw_output_retention=False,
            expected_output_kind="trivy_json_object",
            limitations=LIMITATIONS + (
                "default_live_scan_may_download_or_update_trivy_databases",
                "default_live_scan_uses_vuln_and_misconfig_scanners_only",
                "no_findings_not_safety_proof",
            ),
            residual_risks=(
                "trivy_database_cache_freshness_limited",
                "trivy_scanner_coverage_limited",
                "trivy_binary_unattested",
                "dirty_worktree_may_not_match_commit",
            ),
        )

    def build_scan_argv(
        self,
        repo_path: str | Path,
        report_path: str | Path,
        cache_dir: str | Path | None = None,
    ) -> tuple[str, ...]:
        return build_trivy_scan_argv(repo_path, report_path, cache_dir)


def default_trivy_adapter() -> TrivyAdapter:
    return TrivyAdapter()


def build_trivy_scan_argv(
    repo_path: str | Path,
    report_path: str | Path,
    cache_dir: str | Path | None = None,
) -> tuple[str, ...]:
    argv = [
        "trivy",
        "fs",
        "--scanners",
        ",".join(DEFAULT_TRIVY_SCANNERS),
        "--format",
        "json",
        "--output",
        str(report_path),
        "--exit-code",
        "1",
    ]
    if cache_dir is not None:
        argv.extend(("--cache-dir", str(cache_dir)))
    argv.append(str(repo_path))
    return tuple(argv)


def interpret_trivy_exit_code(returncode: int) -> TrivyExitInterpretation:
    if returncode == 0:
        return TrivyExitInterpretation(returncode, "completed_no_findings", "no_findings_in_scope", True, None, None)
    if returncode == 1:
        return TrivyExitInterpretation(returncode, "completed_with_findings", "findings_present", True, None, None)
    if returncode == 127:
        return TrivyExitInterpretation(returncode, "tool_unavailable", "unknown", False, "scanner_unavailable", "scanner_unavailable")
    if 2 <= returncode <= 126:
        return TrivyExitInterpretation(returncode, "tool_error", "unknown", False, "unknown", "tool_error")
    return TrivyExitInterpretation(returncode, "tool_unknown_error", "unknown", False, "unknown", "tool_unknown_error")


def assess_trivy_version(stdout: str, stderr: str) -> TrivyVersionAssessment:
    version = _version_text(stdout, stderr)
    if version == "unknown":
        return TrivyVersionAssessment("unknown", False, True, "tool_unsafe_or_untrusted", "unsupported_version")
    if _version_core(version) in UNSAFE_TRIVY_VERSIONS:
        return TrivyVersionAssessment(version, False, True, "tool_unsafe_or_untrusted", "unsupported_version")
    return TrivyVersionAssessment(version, True, False, None, None)


def run_trivy_scan(
    repo_path: str | Path,
    *,
    runner: RunnerCallable | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> TrivyRunResult:
    target_repo = Path(repo_path)
    active_runner = runner or _run_command
    repo_commit, dirty_state = _repo_commit_and_dirty_state(target_repo)
    version_result = _run_preflight(active_runner, timeout_seconds)
    if version_result is None or version_result.returncode != 0 or version_result.timed_out:
        unknown_reason = "timeout" if version_result is not None and version_result.timed_out else "scanner_unavailable"
        blocking_error = "scanner_timeout" if unknown_reason == "timeout" else "scanner_unavailable"
        normalized = _unknown_result(
            scanner_version="unknown",
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason=unknown_reason,
            scanner_completed=False,
            timeout_occurred=unknown_reason == "timeout",
            network_used=False,
            scanner_downloaded_dependencies=False,
        )
        return _run_result(False, False, (blocking_error,), (), normalized)

    version_assessment = assess_trivy_version(version_result.stdout, version_result.stderr)
    if not version_assessment.supported_for_live_scan:
        normalized = _unknown_result(
            scanner_version=version_assessment.version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason=version_assessment.unknown_reason or "unsupported_version",
            scanner_completed=False,
            network_used=False,
            scanner_downloaded_dependencies=False,
            unsupported_version=version_assessment.unsupported_version,
        )
        return _run_result(False, False, tuple(item for item in (version_assessment.blocking_error,) if item), (), normalized)

    scanner_version = version_assessment.version
    with tempfile.TemporaryDirectory(prefix="rhd-trivy-") as temp_dir:
        report_path = Path(temp_dir) / "trivy-report.json"
        cache_dir = Path(temp_dir) / "trivy-cache"
        argv = build_trivy_scan_argv(target_repo, report_path, cache_dir)
        scan_result = _run_scan(active_runner, argv, timeout_seconds)
        if scan_result is None:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="scanner_unavailable",
                scanner_completed=False,
                network_used=False,
                scanner_downloaded_dependencies=False,
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
                network_used=True,
                scanner_downloaded_dependencies=True,
            )
            return _run_result(False, True, ("scanner_timeout",), (), normalized)

        interpretation = interpret_trivy_exit_code(scan_result.returncode)
        if not interpretation.consume_report:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason=interpretation.unknown_reason or "unknown",
                scanner_completed=False,
                network_used=True,
                scanner_downloaded_dependencies=True,
            )
            return _run_result(False, True, tuple(item for item in (interpretation.blocking_error,) if item), (), normalized)

        if not report_path.exists():
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="parse_failure",
                scanner_completed=False,
                network_used=True,
                scanner_downloaded_dependencies=True,
            )
            return _run_result(False, True, ("missing_report",), (), normalized)

        report_bytes = report_path.read_bytes()
        parsed = _parse_trivy_report(report_bytes)
        if parsed is None:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="parse_failure",
                scanner_completed=False,
                network_used=True,
                scanner_downloaded_dependencies=True,
            )
            return _run_result(False, True, ("parse_failure",), (), normalized)
        if _exit_code_report_mismatch(interpretation.status, parsed):
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="parse_failure",
                scanner_completed=False,
                network_used=True,
                scanner_downloaded_dependencies=True,
                source_report_fingerprint=_fingerprint_trivy_report(parsed),
            )
            return _run_result(False, True, ("report_exit_code_mismatch",), (), normalized)
        if interpretation.status == "completed_no_findings" and (repo_commit is None or dirty_state != "clean"):
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="scope_ambiguous",
                scanner_completed=True,
                network_used=True,
                scanner_downloaded_dependencies=True,
                source_report_fingerprint=_fingerprint_trivy_report(parsed),
            )
            return _run_result(False, True, ("dirty_worktree_scope_ambiguous",), (), normalized)

        normalized = _normalized_result(
            parsed,
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            source_report_fingerprint=_fingerprint_trivy_report(parsed),
            outcome=interpretation.outcome,
        )
        validation = validate_external_scanner_result(normalized)
        if not validation.valid:
            return _run_result(False, True, validation.blocking_errors, validation.warnings, normalized)
        return _run_result(True, True, (), validation.warnings, normalized)


def normalize_trivy_json_object(
    report: object,
    *,
    scanner_version: str = "unknown",
    repo_commit: str | None = None,
    dirty_state: str = "unknown",
    outcome: str | None = None,
) -> Mapping[str, object]:
    if not isinstance(report, Mapping) or not _is_minimal_trivy_report(report):
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="parse_failure",
            scanner_completed=False,
            network_used=True,
            scanner_downloaded_dependencies=True,
        )
    effective_outcome = outcome or ("findings_present" if _issue_records(report) else "no_findings_in_scope")
    if effective_outcome not in {"no_findings_in_scope", "findings_present"}:
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="parse_failure",
            scanner_completed=False,
            network_used=True,
            scanner_downloaded_dependencies=True,
            source_report_fingerprint=_fingerprint_trivy_report(report),
        )
    if _exit_code_report_mismatch(_outcome_to_status(effective_outcome), report):
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="parse_failure",
            scanner_completed=False,
            network_used=True,
            scanner_downloaded_dependencies=True,
            source_report_fingerprint=_fingerprint_trivy_report(report),
        )
    if effective_outcome == "no_findings_in_scope" and (repo_commit is None or dirty_state != "clean"):
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="scope_ambiguous",
            scanner_completed=True,
            network_used=True,
            scanner_downloaded_dependencies=True,
            source_report_fingerprint=_fingerprint_trivy_report(report),
        )
    return _normalized_result(
        report,
        scanner_version=scanner_version,
        repo_commit=repo_commit,
        dirty_state=dirty_state,
        source_report_fingerprint=_fingerprint_trivy_report(report),
        outcome=effective_outcome,
    )


def _run_preflight(runner: RunnerCallable, timeout_seconds: int) -> TrivyCommandResult | None:
    try:
        return runner(("trivy", "--version"), timeout_seconds)
    except (FileNotFoundError, OSError):
        return None


def _run_scan(runner: RunnerCallable, argv: Sequence[str], timeout_seconds: int) -> TrivyCommandResult | None:
    try:
        return runner(argv, timeout_seconds)
    except (FileNotFoundError, OSError):
        return None


def _run_command(argv: Sequence[str], timeout_seconds: int) -> TrivyCommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return TrivyCommandResult(
            returncode=124,
            stdout=_bounded_text(exc.stdout or ""),
            stderr=_bounded_text(exc.stderr or ""),
            timed_out=True,
        )
    return TrivyCommandResult(
        returncode=completed.returncode,
        stdout=_bounded_text(completed.stdout),
        stderr=_bounded_text(completed.stderr),
    )


def _repo_commit_and_dirty_state(repo_path: Path) -> tuple[str | None, str]:
    commit = _git_output(repo_path, ("rev-parse", "HEAD"))
    status = _git_output(repo_path, ("status", "--short"))
    dirty_state = "unknown" if status is None else ("dirty" if status.strip() else "clean")
    return commit, dirty_state


def _git_output(repo_path: Path, args: Sequence[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def _parse_trivy_report(report_bytes: bytes) -> Mapping[str, Any] | None:
    try:
        decoded = json.loads(report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, Mapping):
        return None
    if not _is_minimal_trivy_report(decoded):
        return None
    return decoded


def _is_minimal_trivy_report(report: Mapping[str, Any]) -> bool:
    results = report.get("Results")
    if not isinstance(results, list):
        return False
    for result in results:
        if not isinstance(result, Mapping):
            return False
        for field in ("Target", "Class", "Type"):
            value = result.get(field)
            if value is not None and not isinstance(value, str):
                return False
        for field, predicate in (
            ("Vulnerabilities", _is_minimal_vulnerability),
            ("Misconfigurations", _is_minimal_misconfiguration),
            ("Secrets", _is_minimal_secret),
            ("Licenses", _is_minimal_license),
        ):
            values = result.get(field, [])
            if values is None:
                continue
            if not isinstance(values, list):
                return False
            if not all(predicate(item) for item in values):
                return False
    return True


def _is_minimal_vulnerability(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if not isinstance(value.get("VulnerabilityID"), str) or not value.get("VulnerabilityID"):
        return False
    for field in ("PkgName", "InstalledVersion", "FixedVersion", "Severity"):
        field_value = value.get(field)
        if field_value is not None and not isinstance(field_value, str):
            return False
    if "References" in value and not isinstance(value.get("References"), list):
        return False
    return True


def _is_minimal_misconfiguration(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if not _string_or_missing(value.get("ID")) and not _string_or_missing(value.get("AVDID")):
        return False
    if not (isinstance(value.get("ID"), str) and value.get("ID")) and not (isinstance(value.get("AVDID"), str) and value.get("AVDID")):
        return False
    for field in ("ID", "AVDID", "Type", "Severity", "Status", "Title"):
        field_value = value.get(field)
        if field_value is not None and not isinstance(field_value, str):
            return False
    if "CauseMetadata" in value and not isinstance(value.get("CauseMetadata"), Mapping):
        return False
    return True


def _is_minimal_secret(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if not isinstance(value.get("RuleID"), str) or not value.get("RuleID"):
        return False
    for field in ("RuleID", "Category", "Severity", "Title"):
        field_value = value.get(field)
        if field_value is not None and not isinstance(field_value, str):
            return False
    for field in ("StartLine", "EndLine", "StartColumn", "EndColumn"):
        field_value = value.get(field)
        if field_value is not None and not isinstance(field_value, int):
            return False
    return True


def _is_minimal_license(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if not (isinstance(value.get("Name"), str) and value.get("Name")) and not (isinstance(value.get("PkgName"), str) and value.get("PkgName")):
        return False
    for field in ("Name", "PkgName", "Severity", "Category"):
        field_value = value.get(field)
        if field_value is not None and not isinstance(field_value, str):
            return False
    return True


def _string_or_missing(value: object) -> bool:
    return value is None or isinstance(value, str)


def _exit_code_report_mismatch(status: str, report: Mapping[str, Any]) -> bool:
    issue_count = len(_issue_records(report))
    return (status == "completed_no_findings" and issue_count > 0) or (status == "completed_with_findings" and issue_count == 0)


def _outcome_to_status(outcome: str) -> str:
    if outcome == "no_findings_in_scope":
        return "completed_no_findings"
    if outcome == "findings_present":
        return "completed_with_findings"
    return outcome


def _normalized_result(
    report: Mapping[str, Any],
    *,
    scanner_version: str,
    repo_commit: str | None,
    dirty_state: str,
    source_report_fingerprint: str,
    outcome: str,
) -> Mapping[str, object]:
    records = _issue_records(report)
    findings = [_normalized_finding(index, record) for index, record in enumerate(records, start=1)]
    nodes = [_normalized_node(index, record) for index, record in enumerate(records, start=1)]
    finding_count = len(findings)
    risk_effect, gate_effects, rules_fired = _summary_mapping(findings)
    return {
        "schema_version": EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_EXTERNAL_SCANNER_RESULT,
        "scanner": {
            "name": TRIVY_SCANNER_NAME,
            "version": scanner_version,
            "adapter_version": ADAPTER_VERSION,
            "category": TRIVY_SCANNER_CATEGORY,
            "mode": TRIVY_SCANNER_MODE,
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
            "network_used": True,
            "target_code_executed": False,
            "docker_used": False,
            "scanner_downloaded_dependencies": True,
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
    network_used: bool,
    scanner_downloaded_dependencies: bool,
    unsupported_version: bool = False,
    source_report_fingerprint: str | None = None,
) -> Mapping[str, object]:
    return {
        "schema_version": EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_EXTERNAL_SCANNER_RESULT,
        "scanner": {
            "name": TRIVY_SCANNER_NAME,
            "version": scanner_version,
            "adapter_version": ADAPTER_VERSION,
            "category": TRIVY_SCANNER_CATEGORY,
            "mode": TRIVY_SCANNER_MODE,
            "scanner_source": "external_binary",
            "trusted_binary_status": "unverified",
            "unsupported_version": unsupported_version,
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
            "network_used": network_used,
            "target_code_executed": False,
            "docker_used": False,
            "scanner_downloaded_dependencies": scanner_downloaded_dependencies,
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
            "rules_fired": ["RISK018"] if unsupported_version else [],
            "risk_lowering_allowed": False,
        },
        "redaction_status": _redaction_status(),
        "limitations": _limitations(),
        "residual_risks": _residual_risks(dirty_state, unsupported_version=unsupported_version),
        "binding": {
            "repo_commit": repo_commit,
            "input_fingerprint": _input_fingerprint(repo_commit, dirty_state),
            "source_report_fingerprint": source_report_fingerprint,
            "policy_fingerprint": DEFAULT_POLICY_FINGERPRINT,
            "adapter_fingerprint": DEFAULT_ADAPTER_FINGERPRINT,
        },
    }


def _summary_mapping(findings: Sequence[Mapping[str, object]]) -> tuple[str, list[str], list[str]]:
    if not findings:
        return "none", ["evidence_only"], []
    secondaries = {item.get("secondary_category") for item in findings}
    rules: list[str] = []
    if "verified_secret" in secondaries:
        rules.append("RISK001")
    if "known_critical_vulnerability" in secondaries:
        rules.append("RISK014")
    if "low_security_posture" in secondaries:
        rules.append("RISK016")
    if "verified_secret" in secondaries:
        return "raise_to_T5", ["blocks_live_execution"], rules
    if "known_critical_vulnerability" in secondaries:
        return "raise_to_T3", ["raises_risk"], rules
    if "low_security_posture" in secondaries:
        return "raise_to_T2", ["requires_human_review"], rules
    return "T5_candidate", ["requires_human_review"], rules


def _normalized_finding(index: int, record: Mapping[str, Any]) -> Mapping[str, object]:
    kind = _string_field(record, "kind", "unknown")
    issue = _mapping_field(record, "issue")
    result = _mapping_field(record, "result")
    target = _result_target(result)
    if kind == "vulnerability":
        profile = _vulnerability_profile(_string_field(issue, "Severity", "UNKNOWN"))
        rule_id = _safe_token(issue.get("VulnerabilityID"), f"trivy.vulnerability.{index}")
        return {
            "finding_id": f"trivy-{index}",
            "scanner_rule_id": rule_id,
            "primary_category": "vulnerability",
            "secondary_category": profile["secondary_category"],
            "scanner_severity": profile["scanner_severity"],
            "normalized_severity": profile["normalized_severity"],
            "confidence": "high",
            "title": f"Trivy vulnerability {rule_id}",
            "redacted_description": "Trivy reported a vulnerable package; raw description, URLs, vendor metadata, and dependency tree omitted.",
            "location": {"path": target, "line": None, "column": None},
            "evidence": _vulnerability_evidence(result, issue),
            "risk_mapping": {"risk_tier_effect": profile["risk_tier_effect"], "rule_ids": profile["rule_ids"]},
            "gate_effect": profile["gate_effect"],
        }
    if kind == "misconfiguration":
        rule_id = _misconfiguration_id(issue, index)
        return {
            "finding_id": f"trivy-{index}",
            "scanner_rule_id": rule_id,
            "primary_category": "repo_posture",
            "secondary_category": "low_security_posture",
            "scanner_severity": _severity_token(issue.get("Severity")),
            "normalized_severity": _normalized_misconfig_severity(issue.get("Severity")),
            "confidence": "high",
            "title": f"Trivy misconfiguration {rule_id}",
            "redacted_description": "Trivy reported a misconfiguration; raw message, code, cause metadata, and remediation prose omitted.",
            "location": {"path": target, "line": _cause_line(issue), "column": None},
            "evidence": _misconfiguration_evidence(result, issue),
            "risk_mapping": {"risk_tier_effect": "raise_to_T2", "rule_ids": ["RISK016"]},
            "gate_effect": "requires_human_review",
        }
    if kind == "secret":
        rule_id = _safe_token(issue.get("RuleID"), f"trivy.secret.{index}")
        return {
            "finding_id": f"trivy-{index}",
            "scanner_rule_id": rule_id,
            "primary_category": "secret",
            "secondary_category": "verified_secret",
            "scanner_severity": _severity_token(issue.get("Severity")),
            "normalized_severity": "block",
            "confidence": "high",
            "title": f"Trivy secret finding {rule_id}",
            "redacted_description": "Trivy reported a secret candidate; raw secret value, match text, and code snippet omitted.",
            "location": {"path": target, "line": _positive_int(issue.get("StartLine")), "column": _positive_int(issue.get("StartColumn"))},
            "evidence": _secret_evidence(result, issue),
            "risk_mapping": {"risk_tier_effect": "raise_to_T5", "rule_ids": ["RISK001"]},
            "gate_effect": "blocks_live_execution",
        }
    rule_id = _safe_token(issue.get("Name") or issue.get("PkgName"), f"trivy.license.{index}")
    return {
        "finding_id": f"trivy-{index}",
        "scanner_rule_id": rule_id,
        "primary_category": "repo_posture",
        "secondary_category": "low_security_posture",
        "scanner_severity": _severity_token(issue.get("Severity")),
        "normalized_severity": "warn",
        "confidence": "medium",
        "title": f"Trivy license finding {rule_id}",
        "redacted_description": "Trivy reported a license issue; raw license metadata omitted.",
        "location": {"path": target, "line": None, "column": None},
        "evidence": _license_evidence(result, issue),
        "risk_mapping": {"risk_tier_effect": "raise_to_T2", "rule_ids": ["RISK016"]},
        "gate_effect": "requires_human_review",
    }


def _normalized_node(index: int, record: Mapping[str, Any]) -> Mapping[str, object]:
    finding = _normalized_finding(index, record)
    return {
        "node_id": f"trivy-node-{index}",
        "primary_category": finding["primary_category"],
        "secondary_category": finding["secondary_category"],
        "title": finding["title"],
        "redacted_summary": finding["redacted_description"],
        "location": finding["location"],
        "confidence": finding["confidence"],
    }


def _vulnerability_evidence(result: Mapping[str, Any], issue: Mapping[str, Any]) -> list[str]:
    return _common_evidence(result, "vulnerability") + [
        f"vulnerability_id:{_safe_token(issue.get('VulnerabilityID'), 'unknown')}",
        f"package_name:{_safe_token(issue.get('PkgName'), 'unknown')}",
        f"installed_version:{_safe_token(issue.get('InstalledVersion'), 'unknown')}",
        f"fixed_versions_count:{_fixed_versions_count(issue.get('FixedVersion'))}",
        f"severity:{_severity_token(issue.get('Severity'))}",
        f"primary_identifier:{_safe_token(issue.get('VulnerabilityID'), 'unknown')}",
    ]


def _misconfiguration_evidence(result: Mapping[str, Any], issue: Mapping[str, Any]) -> list[str]:
    return _common_evidence(result, "misconfiguration") + [
        f"misconfiguration_id:{_misconfiguration_id(issue, 0)}",
        f"misconfiguration_type:{_safe_token(issue.get('Type'), 'unknown')}",
        f"severity:{_severity_token(issue.get('Severity'))}",
        f"status:{_safe_token(issue.get('Status'), 'unknown')}",
        f"title:{'present_omitted' if isinstance(issue.get('Title'), str) else 'unknown'}",
    ]


def _secret_evidence(result: Mapping[str, Any], issue: Mapping[str, Any]) -> list[str]:
    return _common_evidence(result, "secret") + [
        f"secret_rule_id:{_safe_token(issue.get('RuleID'), 'unknown')}",
        f"secret_category:{_safe_token(issue.get('Category'), 'unknown')}",
        f"severity:{_severity_token(issue.get('Severity'))}",
        f"start_line:{_field_value(issue.get('StartLine'))}",
        f"end_line:{_field_value(issue.get('EndLine'))}",
        "secret_value:redacted",
    ]


def _license_evidence(result: Mapping[str, Any], issue: Mapping[str, Any]) -> list[str]:
    return _common_evidence(result, "license") + [
        f"license_name:{_safe_token(issue.get('Name'), 'unknown')}",
        f"package_name:{_safe_token(issue.get('PkgName'), 'unknown')}",
        f"severity:{_severity_token(issue.get('Severity'))}",
    ]


def _common_evidence(result: Mapping[str, Any], scanner_category: str) -> list[str]:
    return [
        f"target:{_result_target(result)}",
        f"class:{_safe_token(result.get('Class'), 'unknown')}",
        f"type:{_safe_token(result.get('Type'), 'unknown')}",
        f"scanner_category:{scanner_category}",
        f"scanner_categories:{_scanner_categories(result)}",
    ]


def _issue_records(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    for result in _mappings(report.get("Results")):
        for issue in _mappings(result.get("Vulnerabilities")):
            records.append({"kind": "vulnerability", "result": result, "issue": issue})
        for issue in _mappings(result.get("Misconfigurations")):
            records.append({"kind": "misconfiguration", "result": result, "issue": issue})
        for issue in _mappings(result.get("Secrets")):
            records.append({"kind": "secret", "result": result, "issue": issue})
        for issue in _mappings(result.get("Licenses")):
            records.append({"kind": "license", "result": result, "issue": issue})
    return records


def _scanner_categories(result: Mapping[str, Any]) -> str:
    categories = []
    if _mappings(result.get("Vulnerabilities")):
        categories.append("vulnerability")
    if _mappings(result.get("Misconfigurations")):
        categories.append("misconfiguration")
    if _mappings(result.get("Secrets")):
        categories.append("secret")
    if _mappings(result.get("Licenses")):
        categories.append("license")
    return ",".join(categories) if categories else "none"


def _vulnerability_profile(severity: str) -> Mapping[str, Any]:
    normalized = severity.strip().upper()
    if normalized == "CRITICAL":
        return {
            "secondary_category": "known_critical_vulnerability",
            "scanner_severity": "critical",
            "normalized_severity": "block",
            "risk_tier_effect": "raise_to_T3",
            "gate_effect": "raises_risk",
            "rule_ids": ["RISK014"],
        }
    if normalized in {"HIGH", "MEDIUM"}:
        return _noncritical_vulnerability_profile(normalized.lower(), "warn")
    if normalized == "LOW":
        return _noncritical_vulnerability_profile("low", "info")
    return _noncritical_vulnerability_profile("unknown", "warn")


def _noncritical_vulnerability_profile(scanner_severity: str, normalized_severity: str) -> Mapping[str, Any]:
    return {
        "secondary_category": "unknown",
        "scanner_severity": scanner_severity,
        "normalized_severity": normalized_severity,
        "risk_tier_effect": "T5_candidate",
        "gate_effect": "requires_human_review",
        "rule_ids": [],
    }


def _normalized_misconfig_severity(value: object) -> str:
    severity = _severity_token(value)
    if severity in {"critical", "high", "medium"}:
        return "warn"
    if severity == "low":
        return "info"
    return "unknown"


def _severity_token(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    normalized = value.strip().lower()
    return normalized if normalized in {"unknown", "low", "medium", "high", "critical"} else "unknown"


def _misconfiguration_id(issue: Mapping[str, Any], index: int) -> str:
    return _safe_token(issue.get("ID") or issue.get("AVDID"), f"trivy.misconfiguration.{index}")


def _fixed_versions_count(value: object) -> int:
    if not isinstance(value, str) or not value.strip():
        return 0
    return len([item for item in value.split(",") if item.strip()])


def _cause_line(issue: Mapping[str, Any]) -> int | None:
    cause = issue.get("CauseMetadata")
    if not isinstance(cause, Mapping):
        return None
    return _positive_int(cause.get("StartLine"))


def _result_target(result: Mapping[str, Any]) -> str:
    value = result.get("Target")
    return _relative_repo_path(value if isinstance(value, str) and value else "<repo>")


def _limitations() -> list[Mapping[str, str]]:
    return [
        {
            "limitation_id": "scanner_scope_only",
            "description": "Trivy filesystem scan coverage is limited to scanner types, ecosystems, manifests, IaC files, secret rules, and repository paths reached by this run.",
        },
        {
            "limitation_id": "not_execution_authorization",
            "description": "Trivy evidence does not authorize execution or prove repository safety.",
        },
        {
            "limitation_id": "external_result_trust_limited",
            "description": "Results depend on Trivy database freshness, cache state, scanner version, supported detectors, and local binary provenance.",
        },
        {
            "limitation_id": "raw_output_not_retained",
            "description": "Raw Trivy JSON, stdout, stderr, secret match text, code snippets, descriptions, references, and vendor metadata are not retained in normalized output.",
        },
        {
            "limitation_id": "scanner_binary_trust_boundary",
            "description": "The local Trivy binary is outside repo-health-doctor's trust boundary and is checked only by version preflight and known-unsafe version denylist.",
        },
        {
            "limitation_id": "scanner_version_specific",
            "description": "Trivy command behavior, database behavior, exit codes, detectors, and JSON shape are version-specific.",
        },
    ]


def _residual_risks(dirty_state: str, *, unsupported_version: bool = False) -> list[Mapping[str, str]]:
    risks = [
        {"risk_id": "no_findings_not_safety_proof", "description": "No Trivy finding is not proof that vulnerabilities, misconfigurations, secrets, or license issues are absent."},
        {"risk_id": "trivy_default_scanners_limited", "description": "The default live command enables vulnerability and misconfiguration scanners only; secret and license findings may be absent unless supplied by another Trivy report."},
        {"risk_id": "trivy_scanner_coverage_limited", "description": "Only issues detectable by Trivy's supported scanners, ecosystems, manifests, IaC parsers, secret rules, and database coverage are represented."},
        {"risk_id": "trivy_database_cache_freshness_limited", "description": "Live scans may depend on vulnerability, Java, misconfiguration, and check database freshness and temporary cache behavior."},
        {"risk_id": "trivy_default_live_scan_network_or_cache", "description": "Default live Trivy scans may download or update databases and use a temporary cache directory."},
        {"risk_id": "trivy_secret_values_not_retained", "description": "Secret scanner findings omit raw values and code snippets; human review in the target repository may be needed to confirm details."},
    ]
    if unsupported_version:
        risks.append({
            "risk_id": "unsupported_scanner_version",
            "description": "The Trivy version is unknown or denylisted and cannot be used for live scan evidence.",
        })
    if dirty_state == "dirty":
        risks.append({
            "risk_id": "dirty_worktree_not_clean_commit_evidence",
            "description": "The scan was bound to HEAD with a dirty working tree and is not clean commit-only evidence.",
        })
    return risks


def _redaction_status() -> Mapping[str, bool]:
    return {
        "raw_secret_present": False,
        "raw_host_path_present": False,
        "raw_scanner_output_included": False,
        "raw_stdout_stderr_included": False,
        "unredacted_snippet_present": False,
        "redaction_validated": True,
    }


def _run_result(
    valid: bool,
    scanner_executed: bool,
    blocking_errors: tuple[str, ...],
    warnings: tuple[str, ...],
    normalized: Mapping[str, object],
) -> TrivyRunResult:
    return TrivyRunResult(
        valid=valid,
        scanner_executed=scanner_executed,
        blocking_errors=tuple(_dedupe(blocking_errors)),
        warnings=tuple(_dedupe(warnings)),
        normalized_result=normalized,
    )


def _version_text(stdout: str, stderr: str) -> str:
    candidate_text = (stdout or stderr).strip()
    match = VERSION_PATTERN.search(candidate_text)
    return match.group(1) if match else "unknown"


def _version_core(version: str) -> str:
    value = version.strip().lower().lstrip("v")
    return re.split(r"[-+]", value, maxsplit=1)[0]


def _input_fingerprint(repo_commit: str | None, dirty_state: str) -> str:
    return _sha256_text(f"repo_commit={repo_commit or 'unknown'}\ndirty_state={dirty_state}\n")


def _fingerprint_trivy_report(report: Mapping[str, Any]) -> str:
    payload = json.dumps(_fingerprint_projection(report), sort_keys=True, separators=(",", ":"))
    return _sha256_text(payload)


def _fingerprint_projection(report: Mapping[str, Any]) -> Mapping[str, object]:
    results: list[Mapping[str, object]] = []
    for result in _mappings(report.get("Results")):
        results.append({
            "target": _result_target(result),
            "class": _safe_token(result.get("Class"), "unknown"),
            "type": _safe_token(result.get("Type"), "unknown"),
            "vulnerabilities": [
                {
                    "id": _safe_token(issue.get("VulnerabilityID"), "unknown"),
                    "package": _safe_token(issue.get("PkgName"), "unknown"),
                    "installed_version": _safe_token(issue.get("InstalledVersion"), "unknown"),
                    "fixed_versions_count": _fixed_versions_count(issue.get("FixedVersion")),
                    "severity": _severity_token(issue.get("Severity")),
                }
                for issue in _mappings(result.get("Vulnerabilities"))
            ],
            "misconfigurations": [
                {
                    "id": _misconfiguration_id(issue, 0),
                    "type": _safe_token(issue.get("Type"), "unknown"),
                    "severity": _severity_token(issue.get("Severity")),
                    "status": _safe_token(issue.get("Status"), "unknown"),
                    "title_present": isinstance(issue.get("Title"), str),
                    "line": _cause_line(issue),
                }
                for issue in _mappings(result.get("Misconfigurations"))
            ],
            "secrets": [
                {
                    "rule_id": _safe_token(issue.get("RuleID"), "unknown"),
                    "category": _safe_token(issue.get("Category"), "unknown"),
                    "severity": _severity_token(issue.get("Severity")),
                    "start_line": _positive_int(issue.get("StartLine")),
                    "end_line": _positive_int(issue.get("EndLine")),
                }
                for issue in _mappings(result.get("Secrets"))
            ],
            "licenses": [
                {
                    "name": _safe_token(issue.get("Name"), "unknown"),
                    "package": _safe_token(issue.get("PkgName"), "unknown"),
                    "severity": _severity_token(issue.get("Severity")),
                }
                for issue in _mappings(result.get("Licenses"))
            ],
        })
    return {"Results": results}


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


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
    if _looks_sensitive_value(clean):
        return "<repo>/<redacted-sensitive-path>"
    clean = clean.lstrip("/")
    if not clean or clean == "<repo>":
        return "<repo>"
    if clean.startswith("<repo>/"):
        return clean
    return f"<repo>/{clean}"


def _safe_token(value: object, default: str, max_length: int = 160) -> str:
    if not isinstance(value, str) or not value.strip():
        return default
    candidate = value.strip().replace("\\", "/")
    if _looks_like_host_path(candidate) or _looks_sensitive_value(candidate):
        return "redacted"
    if not re.fullmatch(r"[A-Za-z0-9@._/+~:,-]{1,160}", candidate):
        return "redacted"
    if len(candidate) > max_length:
        return candidate[:max_length]
    return candidate


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


def _looks_sensitive_value(value: str) -> bool:
    lowered = value.lower()
    return bool(URL_PATTERN.search(value)) or bool(LOCAL_IP_PATTERN.search(value)) or any(marker in lowered for marker in SECRET_MARKERS)


def _field_value(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _safe_token(value, "redacted")
    return "invalid_omitted"


def _positive_int(value: object) -> int | None:
    return value if isinstance(value, int) and value > 0 else None


def _string_field(data: Mapping[str, Any], key: str, default: str) -> str:
    value = data.get(key)
    return value if isinstance(value, str) and value else default


def _mapping_field(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    return value if isinstance(value, Mapping) else {}


def _mappings(value: object) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
