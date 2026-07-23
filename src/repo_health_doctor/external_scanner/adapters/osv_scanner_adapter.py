"""Real OSV-Scanner external scanner adapter.

The adapter invokes a locally installed OSV-Scanner binary only. The default
scan mode can contact OSV.dev, does not execute target code, and does not
retain raw scanner reports, stdout, or stderr.
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
OSV_SCANNER_NAME = "osv-scanner"
OSV_SCANNER_CATEGORY = "vulnerability"
OSV_SCANNER_MODE = "local_static_network"
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_POLICY_FINGERPRINT = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
DEFAULT_ADAPTER_FINGERPRINT = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
VERSION_PATTERN = re.compile(r"\bv?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9._-]+)?\b")

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
    "token=",
    "-----begin",
)

RunnerCallable = Callable[[Sequence[str], int], "OsvScannerCommandResult"]


@dataclass(frozen=True)
class OsvScannerCommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class OsvScannerExitInterpretation:
    returncode: int
    status: str
    outcome: str
    consume_report: bool
    unknown_reason: str | None
    blocking_error: str | None


@dataclass(frozen=True)
class OsvScannerRunResult:
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


class OsvScannerAdapter:
    def capability(self) -> ExternalScannerAdapterCapability:
        return ExternalScannerAdapterCapability(
            scanner_name=OSV_SCANNER_NAME,
            scanner_category=OSV_SCANNER_CATEGORY,
            supported_mode=OSV_SCANNER_MODE,
            allowed_input_paths=("<repo>",),
            requires_network=True,
            executes_target_code=False,
            docker_needed=False,
            raw_output_retention=False,
            expected_output_kind="osv_scanner_json_object",
            limitations=LIMITATIONS + (
                "default_live_scan_may_query_osv_dev_api",
                "no_vulnerabilities_not_safety_proof",
                "no_packages_found_not_safety_proof",
            ),
            residual_risks=(
                "osv_ecosystem_lockfile_extractor_scope_limited",
                "osv_database_advisory_availability_limited",
                "osv_binary_unattested",
                "dirty_worktree_may_not_match_commit",
            ),
        )

    def build_scan_argv(self, repo_path: str | Path, report_path: str | Path) -> tuple[str, ...]:
        return build_osv_scan_argv(repo_path, report_path)


def default_osv_scanner_adapter() -> OsvScannerAdapter:
    return OsvScannerAdapter()


def build_osv_scan_argv(repo_path: str | Path, report_path: str | Path) -> tuple[str, ...]:
    return (
        "osv-scanner",
        "scan",
        "source",
        "--recursive",
        "--format",
        "json",
        "--output-file",
        str(report_path),
        str(repo_path),
    )


def interpret_osv_exit_code(returncode: int) -> OsvScannerExitInterpretation:
    if returncode == 0:
        return OsvScannerExitInterpretation(
            returncode,
            "completed_no_vulnerabilities",
            "no_findings_in_scope",
            True,
            None,
            None,
        )
    if returncode == 1:
        return OsvScannerExitInterpretation(
            returncode,
            "completed_with_vulnerabilities",
            "findings_present",
            True,
            None,
            None,
        )
    if returncode == 127:
        return OsvScannerExitInterpretation(returncode, "tool_error", "unknown", False, "unknown", "tool_error")
    if returncode == 128:
        return OsvScannerExitInterpretation(
            returncode,
            "no_packages_found",
            "unknown",
            False,
            "scope_ambiguous",
            "no_packages_found",
        )
    return OsvScannerExitInterpretation(
        returncode,
        "tool_unknown_error",
        "unknown",
        False,
        "unknown",
        "tool_unknown_error",
    )


def run_osv_scan(
    repo_path: str | Path,
    *,
    runner: RunnerCallable | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    _verified_workspace: DisposableWorkspace | None = None,
) -> OsvScannerRunResult:
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
                    network_used=False,
                )
                return _run_result(
                    False,
                    False,
                    ("snapshot_intake_refused",),
                    (),
                    normalized,
                )
            return run_osv_scan(
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
            network_used=False,
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
        )
        return _run_result(False, False, (blocking_error,), (), normalized)

    scanner_version = _version_text(version_result.stdout, version_result.stderr)
    with tempfile.TemporaryDirectory(prefix="rhd-osv-scanner-") as temp_dir:
        report_path = Path(temp_dir) / "osv-scanner-report.json"
        argv = build_osv_scan_argv(target_repo, report_path)
        scan_result = _run_scan(active_runner, argv, timeout_seconds)
        if scan_result is None:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="scanner_unavailable",
                scanner_completed=False,
                network_used=False,
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
            )
            return _run_result(False, True, ("scanner_timeout",), (), normalized)

        interpretation = interpret_osv_exit_code(scan_result.returncode)
        if not interpretation.consume_report:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason=interpretation.unknown_reason or "unknown",
                scanner_completed=False,
                network_used=True,
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
            )
            return _run_result(False, True, ("missing_report",), (), normalized)

        report_bytes = report_path.read_bytes()
        parsed = _parse_osv_report(report_bytes)
        if parsed is None:
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="parse_failure",
                scanner_completed=False,
                network_used=True,
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
                network_used=True,
                source_report_fingerprint=_sha256_bytes(report_bytes),
            )
            return _run_result(False, True, ("report_exit_code_mismatch",), (), normalized)
        if interpretation.status == "completed_no_vulnerabilities" and (repo_commit is None or dirty_state != "clean"):
            normalized = _unknown_result(
                scanner_version=scanner_version,
                repo_commit=repo_commit,
                dirty_state=dirty_state,
                unknown_reason="scope_ambiguous",
                scanner_completed=True,
                network_used=True,
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
        return _run_result(True, True, (), validation.warnings, normalized)


def normalize_osv_json_object(
    report: object,
    *,
    scanner_version: str = "unknown",
    repo_commit: str | None = None,
    dirty_state: str = "unknown",
    outcome: str | None = None,
) -> Mapping[str, object]:
    if not isinstance(report, Mapping) or not _is_minimal_osv_report(report):
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="parse_failure",
            scanner_completed=False,
            network_used=True,
            source_report_fingerprint=_fingerprint_json_object(report) if isinstance(report, Mapping) else None,
        )
    effective_outcome = outcome or ("findings_present" if _vulnerability_records(report) else "no_findings_in_scope")
    if effective_outcome not in {"no_findings_in_scope", "findings_present"}:
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="parse_failure",
            scanner_completed=False,
            network_used=True,
            source_report_fingerprint=_fingerprint_json_object(report),
        )
    if _exit_code_report_mismatch(_outcome_to_status(effective_outcome), report):
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="parse_failure",
            scanner_completed=False,
            network_used=True,
            source_report_fingerprint=_fingerprint_json_object(report),
        )
    if effective_outcome == "no_findings_in_scope" and (repo_commit is None or dirty_state != "clean"):
        return _unknown_result(
            scanner_version=scanner_version,
            repo_commit=repo_commit,
            dirty_state=dirty_state,
            unknown_reason="scope_ambiguous",
            scanner_completed=True,
            network_used=True,
            source_report_fingerprint=_fingerprint_json_object(report),
        )
    return _normalized_result(
        report,
        scanner_version=scanner_version,
        repo_commit=repo_commit,
        dirty_state=dirty_state,
        source_report_fingerprint=_fingerprint_json_object(report),
        outcome=effective_outcome,
    )


def _run_preflight(runner: RunnerCallable, timeout_seconds: int) -> OsvScannerCommandResult | None:
    try:
        return runner(("osv-scanner", "--version"), timeout_seconds)
    except (FileNotFoundError, OSError):
        return None


def _run_scan(runner: RunnerCallable, argv: Sequence[str], timeout_seconds: int) -> OsvScannerCommandResult | None:
    try:
        return runner(argv, timeout_seconds)
    except (FileNotFoundError, OSError):
        return None


def _run_command(argv: Sequence[str], timeout_seconds: int) -> OsvScannerCommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return OsvScannerCommandResult(
            returncode=124,
            stdout=_bounded_text(exc.stdout or ""),
            stderr=_bounded_text(exc.stderr or ""),
            timed_out=True,
        )
    return OsvScannerCommandResult(
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


def _parse_osv_report(report_bytes: bytes) -> Mapping[str, Any] | None:
    try:
        decoded = json.loads(report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, Mapping):
        return None
    if not _is_minimal_osv_report(decoded):
        return None
    return decoded


def _is_minimal_osv_report(report: Mapping[str, Any]) -> bool:
    results = report.get("results")
    if not isinstance(results, list):
        return False
    for result in results:
        if not isinstance(result, Mapping):
            return False
        source = result.get("source", {})
        if source is not None and not isinstance(source, Mapping):
            return False
        if isinstance(source, Mapping):
            for field in ("path", "type"):
                value = source.get(field)
                if value is not None and not isinstance(value, str):
                    return False
        packages = result.get("packages")
        if not isinstance(packages, list):
            return False
        for package in packages:
            if not _is_minimal_package(package):
                return False
    return True


def _is_minimal_package(package: object) -> bool:
    if not isinstance(package, Mapping):
        return False
    package_meta = package.get("package")
    if not isinstance(package_meta, Mapping):
        return False
    if not isinstance(package_meta.get("name"), str) or not isinstance(package_meta.get("ecosystem"), str):
        return False
    version = package_meta.get("version")
    if version is not None and not isinstance(version, str):
        return False
    vulnerabilities = package.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return False
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, Mapping):
            return False
        if not isinstance(vulnerability.get("id"), str) or not vulnerability.get("id"):
            return False
        if "aliases" in vulnerability and not isinstance(vulnerability.get("aliases"), list):
            return False
        if "severity" in vulnerability and not isinstance(vulnerability.get("severity"), list):
            return False
        if "database_specific" in vulnerability and not isinstance(vulnerability.get("database_specific"), Mapping):
            return False
        if "affected" in vulnerability and not isinstance(vulnerability.get("affected"), list):
            return False
        if "references" in vulnerability and not isinstance(vulnerability.get("references"), list):
            return False
    if "groups" in package and not isinstance(package.get("groups"), list):
        return False
    return True


def _exit_code_report_mismatch(status: str, report: Mapping[str, Any]) -> bool:
    vulnerability_count = len(_vulnerability_records(report))
    return (
        (status == "completed_no_vulnerabilities" and vulnerability_count > 0)
        or (status == "completed_with_vulnerabilities" and vulnerability_count == 0)
    )


def _outcome_to_status(outcome: str) -> str:
    if outcome == "no_findings_in_scope":
        return "completed_no_vulnerabilities"
    if outcome == "findings_present":
        return "completed_with_vulnerabilities"
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
    records = _vulnerability_records(report)
    findings = [_normalized_finding(index, record) for index, record in enumerate(records, start=1)]
    nodes = [_normalized_node(index, record) for index, record in enumerate(records, start=1)]
    finding_count = len(findings)
    has_critical = any(item["secondary_category"] == "known_critical_vulnerability" for item in findings)
    if finding_count and has_critical:
        risk_effect = "raise_to_T3"
        gate_effects = ["raises_risk"]
        rules_fired = ["RISK014"]
    elif finding_count:
        risk_effect = "T5_candidate"
        gate_effects = ["requires_human_review"]
        rules_fired = []
    else:
        risk_effect = "none"
        gate_effects = ["evidence_only"]
        rules_fired = []
    return {
        "schema_version": EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_EXTERNAL_SCANNER_RESULT,
        "scanner": {
            "name": OSV_SCANNER_NAME,
            "version": scanner_version,
            "adapter_version": ADAPTER_VERSION,
            "category": OSV_SCANNER_CATEGORY,
            "mode": OSV_SCANNER_MODE,
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
    network_used: bool,
    source_report_fingerprint: str | None = None,
) -> Mapping[str, object]:
    return {
        "schema_version": EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_EXTERNAL_SCANNER_RESULT,
        "scanner": {
            "name": OSV_SCANNER_NAME,
            "version": scanner_version,
            "adapter_version": ADAPTER_VERSION,
            "category": OSV_SCANNER_CATEGORY,
            "mode": OSV_SCANNER_MODE,
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
            "network_used": network_used,
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


def _normalized_finding(index: int, record: Mapping[str, Any]) -> Mapping[str, object]:
    vulnerability = _mapping_field(record, "vulnerability")
    package_meta = _mapping_field(record, "package")
    source = _mapping_field(record, "source")
    profile = _severity_profile(vulnerability)
    vuln_id = _safe_token(vulnerability.get("id"), f"osv.vulnerability.{index}")
    source_path = _source_path(source)
    return {
        "finding_id": f"osv-{index}",
        "scanner_rule_id": vuln_id,
        "primary_category": "vulnerability",
        "secondary_category": profile["secondary_category"],
        "scanner_severity": profile["scanner_severity"],
        "normalized_severity": profile["normalized_severity"],
        "confidence": "high",
        "title": f"OSV-Scanner vulnerability {vuln_id}",
        "redacted_description": "OSV-Scanner reported a vulnerable package; advisory prose, URLs, credits, and raw database metadata omitted.",
        "location": {"path": source_path, "line": None, "column": None},
        "evidence": _safe_evidence(record),
        "risk_mapping": {"risk_tier_effect": profile["risk_tier_effect"], "rule_ids": profile["rule_ids"]},
        "gate_effect": profile["gate_effect"],
    }


def _normalized_node(index: int, record: Mapping[str, Any]) -> Mapping[str, object]:
    vulnerability = _mapping_field(record, "vulnerability")
    source = _mapping_field(record, "source")
    profile = _severity_profile(vulnerability)
    vuln_id = _safe_token(vulnerability.get("id"), str(index))
    return {
        "node_id": f"osv-node-{index}",
        "primary_category": "vulnerability",
        "secondary_category": profile["secondary_category"],
        "title": f"OSV-Scanner vulnerability {vuln_id}",
        "redacted_summary": "OSV-Scanner reported a vulnerable package; raw advisory metadata omitted.",
        "location": {
            "path": _source_path(source),
            "line": None,
            "column": None,
        },
        "confidence": "high",
    }


def _safe_evidence(record: Mapping[str, Any]) -> list[str]:
    vulnerability = _mapping_field(record, "vulnerability")
    package_meta = _mapping_field(record, "package")
    source = _mapping_field(record, "source")
    return [
        f"source_type:{_safe_token(source.get('type'), 'unknown')}",
        f"source_path:{_source_path(source)}",
        f"package_name:{_safe_token(package_meta.get('name'), 'unknown')}",
        f"package_version:{_safe_token(package_meta.get('version'), 'unknown')}",
        f"package_ecosystem:{_safe_token(package_meta.get('ecosystem'), 'unknown')}",
        f"vulnerability_id:{_safe_token(vulnerability.get('id'), 'unknown')}",
        f"aliases_count:{_aliases_count(vulnerability)}",
        f"group_ids:{_group_ids_summary(record.get('groups'))}",
        f"severity:{_severity_summary(vulnerability)}",
        f"fixed_versions_count:{_fixed_versions_count(vulnerability)}",
    ]


def _vulnerability_records(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    for result in _mappings(report.get("results")):
        source = result.get("source") if isinstance(result.get("source"), Mapping) else {}
        for package in _mappings(result.get("packages")):
            package_meta = package.get("package") if isinstance(package.get("package"), Mapping) else {}
            groups = package.get("groups") if isinstance(package.get("groups"), list) else []
            for vulnerability in _mappings(package.get("vulnerabilities")):
                records.append({
                    "source": source,
                    "package": package_meta,
                    "vulnerability": vulnerability,
                    "groups": groups,
                })
    return records


def _severity_profile(vulnerability: Mapping[str, Any]) -> Mapping[str, Any]:
    database_severity = _database_specific_severity(vulnerability.get("database_specific"))
    score = _cvss_score(vulnerability.get("severity"))
    if database_severity == "CRITICAL" or (score is not None and score >= 9.0):
        return {
            "secondary_category": "known_critical_vulnerability",
            "scanner_severity": "critical",
            "normalized_severity": "block",
            "risk_tier_effect": "raise_to_T3",
            "gate_effect": "raises_risk",
            "rule_ids": ["RISK014"],
        }
    if database_severity == "HIGH" or (score is not None and score >= 7.0):
        scanner_severity = "high" if database_severity == "HIGH" else f"cvss:{score}"
        return _noncritical_profile(scanner_severity, "warn")
    if database_severity == "MODERATE" or database_severity == "MEDIUM" or (score is not None and score >= 4.0):
        scanner_severity = "medium" if database_severity in {"MODERATE", "MEDIUM"} else f"cvss:{score}"
        return _noncritical_profile(scanner_severity, "warn")
    if database_severity == "LOW" or score is not None:
        scanner_severity = "low" if database_severity == "LOW" else f"cvss:{score}"
        return _noncritical_profile(scanner_severity, "info")
    return _noncritical_profile("unknown", "warn")


def _noncritical_profile(scanner_severity: str, normalized_severity: str) -> Mapping[str, Any]:
    return {
        "secondary_category": "unknown",
        "scanner_severity": scanner_severity,
        "normalized_severity": normalized_severity,
        "risk_tier_effect": "T5_candidate",
        "gate_effect": "requires_human_review",
        "rule_ids": [],
    }


def _database_specific_severity(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    severity = value.get("severity")
    if not isinstance(severity, str):
        return None
    normalized = severity.strip().upper()
    return normalized if normalized in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"} else None


def _severity_summary(vulnerability: Mapping[str, Any]) -> str:
    database_severity = _database_specific_severity(vulnerability.get("database_specific"))
    score = _cvss_score(vulnerability.get("severity"))
    if database_severity and score is not None:
        return f"database:{database_severity.lower()},cvss:{score}"
    if database_severity:
        return f"database:{database_severity.lower()}"
    if score is not None:
        return f"cvss:{score}"
    return "unknown"


def _aliases_count(vulnerability: Mapping[str, Any]) -> int:
    aliases = vulnerability.get("aliases")
    return len(aliases) if isinstance(aliases, list) else 0


def _group_ids_summary(groups: object) -> str:
    group_ids: list[str] = []
    for group in groups if isinstance(groups, list) else []:
        if isinstance(group, str):
            group_ids.append(_safe_token(group, "redacted"))
        elif isinstance(group, Mapping):
            ids = group.get("ids")
            if isinstance(ids, list):
                group_ids.extend(_safe_token(item, "redacted") for item in ids)
    safe_ids = [item for item in _dedupe(group_ids) if item != "redacted"]
    if not safe_ids:
        return "none"
    if len(safe_ids) > 5:
        return f"present_count:{len(safe_ids)}"
    return ",".join(safe_ids)


def _fixed_versions_count(vulnerability: Mapping[str, Any]) -> int:
    count = 0
    for affected in _mappings(vulnerability.get("affected")):
        for range_item in _mappings(affected.get("ranges")):
            for event in _mappings(range_item.get("events")):
                if isinstance(event.get("fixed"), str) and event.get("fixed"):
                    count += 1
    return count


def _limitations() -> list[Mapping[str, str]]:
    return [
        {
            "limitation_id": "scanner_scope_only",
            "description": "OSV-Scanner coverage is limited to supported ecosystems, lockfiles, manifests, SBOMs, and extractors reached by this scan.",
        },
        {
            "limitation_id": "not_execution_authorization",
            "description": "OSV-Scanner evidence does not authorize execution or prove repository safety.",
        },
        {
            "limitation_id": "external_result_trust_limited",
            "description": "Results depend on OSV.dev database coverage, advisory availability, extractor behavior, and the local scanner binary.",
        },
        {
            "limitation_id": "raw_output_not_retained",
            "description": "Raw OSV-Scanner JSON, stdout, stderr, advisory prose, URL lists, credits, and database objects are not retained in normalized output.",
        },
        {
            "limitation_id": "scanner_binary_trust_boundary",
            "description": "The local OSV-Scanner binary is outside repo-health-doctor's trust boundary.",
        },
        {
            "limitation_id": "scanner_version_specific",
            "description": "OSV-Scanner command behavior, exit codes, extractor coverage, and JSON shape are version-specific.",
        },
    ]


def _residual_risks(dirty_state: str) -> list[Mapping[str, str]]:
    risks = [
        {"risk_id": "no_findings_not_safety_proof", "description": "No vulnerabilities is not proof that dependencies are vulnerability-free or safe to execute."},
        {"risk_id": "no_packages_found_not_safety_proof", "description": "No packages found is incomplete evidence, not a safety proof."},
        {"risk_id": "osv_ecosystem_lockfile_extractor_scope_limited", "description": "Only package ecosystems, manifests, lockfiles, SBOMs, and source extractors supported by OSV-Scanner are covered."},
        {"risk_id": "osv_database_advisory_availability_limited", "description": "Results depend on OSV.dev database freshness and advisory availability."},
        {"risk_id": "osv_default_live_scan_network_query", "description": "Default live OSV-Scanner scans can query the OSV.dev API with package, version, ecosystem, and hash metadata."},
    ]
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
) -> OsvScannerRunResult:
    return OsvScannerRunResult(
        valid=valid,
        scanner_executed=scanner_executed,
        blocking_errors=tuple(_dedupe(blocking_errors)),
        warnings=tuple(_dedupe(warnings)),
        normalized_result=normalized,
    )


def _version_text(stdout: str, stderr: str) -> str:
    candidate_text = (stdout or stderr).strip()
    match = VERSION_PATTERN.search(candidate_text)
    return match.group(0) if match else "unknown"


def _input_fingerprint(repo_commit: str | None, dirty_state: str) -> str:
    return _sha256_text(f"repo_commit={repo_commit or 'unknown'}\ndirty_state={dirty_state}\n")


def _fingerprint_json_object(report: Mapping[str, Any]) -> str:
    payload = json.dumps(dict(report), sort_keys=True, separators=(",", ":"))
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
    if _looks_sensitive_path(clean):
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
    lowered = candidate.lower()
    if _looks_like_host_path(candidate) or "://" in lowered or any(marker in lowered for marker in SECRET_MARKERS):
        return "redacted"
    if not re.fullmatch(r"[A-Za-z0-9@._/+~:-]{1,160}", candidate):
        return "redacted"
    if len(candidate) > max_length:
        return candidate[:max_length]
    return candidate


def _source_path(source: Mapping[str, Any]) -> str:
    value = source.get("path")
    return _relative_repo_path(value if isinstance(value, str) and value else "<repo>")


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


def _looks_sensitive_path(value: str) -> bool:
    lowered = value.lower()
    return "://" in lowered or any(marker in lowered for marker in SECRET_MARKERS)


def _mapping_field(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    return value if isinstance(value, Mapping) else {}


def _mappings(value: object) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _cvss_score(severity: object) -> float | None:
    for item in _mappings(severity):
        score = item.get("score")
        if isinstance(score, str) and score.startswith("CVSS:3."):
            return _cvss_v3_base_score(score)
        try:
            return float(score) if score is not None else None
        except (TypeError, ValueError):
            return None
    return None


def _cvss_v3_base_score(vector: str) -> float | None:
    metrics = _cvss_metrics(vector)
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if (set(metrics) & required) != required:
        return None
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope = metrics["S"]
        pr = {
            "N": 0.85,
            "L": 0.62 if scope == "U" else 0.68,
            "H": 0.27 if scope == "U" else 0.5,
        }[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
        c = impact_values[metrics["C"]]
        i = impact_values[metrics["I"]]
        a = impact_values[metrics["A"]]
    except KeyError:
        return None
    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    elif scope == "C":
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        return None
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _round_up_1(min(impact + exploitability, 10))
    return _round_up_1(min(1.08 * (impact + exploitability), 10))


def _cvss_metrics(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part or part.startswith("CVSS:"):
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    return metrics


def _round_up_1(value: float) -> float:
    scaled = int(value * 100000)
    return ((scaled + 9999) // 10000) / 10.0


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
