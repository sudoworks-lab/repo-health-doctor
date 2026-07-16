"""Models and sequential runner for the explicit real scanner suite.

The suite only invokes the existing adapters when its runner is called. It
does not install scanners, retain raw output, or authorize execution.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .adapters import (
    ExternalScannerAdapterCapability,
    GitleaksRunResult,
    OsvScannerRunResult,
    TrivyRunResult,
    default_gitleaks_adapter,
    default_osv_scanner_adapter,
    default_trivy_adapter,
    run_gitleaks_scan,
    run_osv_scan,
    run_trivy_scan,
)


SUITE_REPORT_KIND = "real_scanner_suite"
SUITE_SCHEMA_VERSION = "0.1-draft"
REAL_SCANNER_ADAPTER_NAMES = ("gitleaks", "osv-scanner", "trivy")

REAL_SCANNER_SUITE_LIMITATIONS = (
    "real_scanner_execution_is_explicit_not_default_cli",
    "scanner_unavailable_is_fail_closed_not_pass",
    "no_findings_not_safety_proof",
    "raw_scanner_output_not_retained",
    "network_cache_and_privacy_limitations_apply",
)

_NETWORK_SCANNERS = frozenset({"osv-scanner", "trivy"})
REAL_SCANNER_DEFAULT_TIMEOUT_SECONDS = 120
REAL_SCANNER_MAX_FINDINGS_PER_SCANNER = 100
REAL_SCANNER_MAX_FINDINGS = 300
REAL_SCANNER_MAX_REPORT_BYTES = 256 * 1024
REAL_SCANNER_MAX_TEXT_FIELD_CHARS = 1024
_DEFAULT_TIMEOUT_SECONDS = REAL_SCANNER_DEFAULT_TIMEOUT_SECONDS
_RunResult = GitleaksRunResult | OsvScannerRunResult | TrivyRunResult
_ScannerRunner = Callable[[Sequence[str], int], object]
_ScannerFunction = Callable[..., _RunResult]


@dataclass(frozen=True)
class RealScannerSuiteEntry:
    scanner_name: str
    executed: bool
    valid: bool
    status: str
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    risk_summary: Mapping[str, object]
    normalized_result: Mapping[str, object]
    finding_count: int
    omitted_finding_count: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner_name": self.scanner_name,
            "executed": self.executed,
            "valid": self.valid,
            "status": self.status,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "risk_summary": dict(self.risk_summary),
            "normalized_result": dict(self.normalized_result),
            "finding_count": self.finding_count,
            "omitted_finding_count": self.omitted_finding_count,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class RealScannerSuiteReport:
    suite_status: str
    entries: tuple[RealScannerSuiteEntry, ...]
    limitations: tuple[str, ...]
    execution_authorized: bool
    report_fingerprint: str
    generated_at: str
    subject: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SUITE_SCHEMA_VERSION,
            "report_kind": SUITE_REPORT_KIND,
            "suite_status": self.suite_status,
            "entries": [entry.to_dict() for entry in self.entries],
            "limitations": list(self.limitations),
            "execution_authorized": self.execution_authorized,
            "report_fingerprint": self.report_fingerprint,
            "generated_at": self.generated_at,
            "subject": dict(self.subject),
        }


def default_real_scanner_adapters() -> tuple[object, ...]:
    return (
        default_gitleaks_adapter(),
        default_osv_scanner_adapter(),
        default_trivy_adapter(),
    )


def run_real_scanner_suite(
    repo_path: str | Path,
    *,
    runner: _ScannerRunner | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    offline: bool = False,
    scanners: Sequence[str] = REAL_SCANNER_ADAPTER_NAMES,
    max_findings_per_scanner: int = REAL_SCANNER_MAX_FINDINGS_PER_SCANNER,
    max_findings: int = REAL_SCANNER_MAX_FINDINGS,
    max_report_bytes: int = REAL_SCANNER_MAX_REPORT_BYTES,
) -> RealScannerSuiteReport:
    """Run the selected scanners one at a time and aggregate bounded results.

    ``runner`` is passed to each adapter, which makes unavailable, timeout, and
    other runner behavior deterministic in unit tests. An exception from one
    adapter is converted to one unknown entry so later scanners still run.
    """

    requested_scanners = tuple(scanners)
    unknown_scanners = tuple(name for name in requested_scanners if name not in REAL_SCANNER_ADAPTER_NAMES)
    if unknown_scanners:
        raise ValueError(f"unknown scanner: {unknown_scanners[0]}")
    _validate_budget("max_findings_per_scanner", max_findings_per_scanner)
    _validate_budget("max_findings", max_findings)
    _validate_budget("max_report_bytes", max_report_bytes)

    entries: list[RealScannerSuiteEntry] = []
    suite_findings_used = 0
    per_scanner_budget_exceeded = False
    suite_finding_budget_exceeded = False
    for scanner_name in requested_scanners:
        if offline and scanner_name in _NETWORK_SCANNERS:
            entries.append(_skipped_offline_entry(scanner_name))
            continue

        try:
            result = _scanner_function(scanner_name)(
                repo_path,
                runner=runner,
                timeout_seconds=timeout_seconds,
            )
        except Exception:
            entries.append(_runner_error_entry(scanner_name))
            continue
        original_finding_count = _result_finding_count(result.normalized_result)
        remaining_suite_budget = max(0, max_findings - suite_findings_used)
        allowed_findings = min(max_findings_per_scanner, remaining_suite_budget)
        per_scanner_budget_exceeded = per_scanner_budget_exceeded or original_finding_count > max_findings_per_scanner
        suite_finding_budget_exceeded = suite_finding_budget_exceeded or original_finding_count > remaining_suite_budget
        entry = _entry_from_run_result(scanner_name, result, max_findings=allowed_findings)
        entries.append(entry)
        suite_findings_used += entry.finding_count

    status = "completed" if all(entry.valid and entry.status == "completed" for entry in entries) else "degraded"
    limitations = list(REAL_SCANNER_SUITE_LIMITATIONS)
    if per_scanner_budget_exceeded:
        limitations.append("per_scanner_finding_budget_exceeded")
    if suite_finding_budget_exceeded:
        limitations.append("suite_finding_budget_exceeded")
    if status == "degraded":
        limitations.append("suite_degraded_requires_review")
    if offline and any(entry.status == "skipped_offline" for entry in entries):
        limitations.append("offline_network_scanners_skipped")

    entries, byte_budget_exceeded = _apply_report_byte_budget(
        entries,
        max_report_bytes=max_report_bytes,
        limitations=limitations,
        generated_at="2000-01-01T00:00:00+00:00",
        subject=_subject_from_entries(entries),
    )
    if byte_budget_exceeded:
        limitations.append("report_byte_budget_exceeded")
        limitations.append("report_truncated")
    if byte_budget_exceeded or any(entry.truncated for entry in entries):
        status = "degraded"

    generated_at = datetime.now(timezone.utc).isoformat()
    subject = _subject_from_entries(entries)
    report_without_fingerprint = {
        "schema_version": SUITE_SCHEMA_VERSION,
        "report_kind": SUITE_REPORT_KIND,
        "suite_status": status,
        "entries": [entry.to_dict() for entry in entries],
        "limitations": limitations,
        "execution_authorized": False,
        "generated_at": generated_at,
        "subject": subject,
    }
    fingerprint = _fingerprint(report_without_fingerprint)
    return RealScannerSuiteReport(
        suite_status=status,
        entries=tuple(entries),
        limitations=tuple(limitations),
        execution_authorized=False,
        report_fingerprint=fingerprint,
        generated_at=generated_at,
        subject=subject,
    )


def run_real_scanner_suite_sequential(
    repo_path: str | Path,
    *,
    runner: _ScannerRunner | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    offline: bool = False,
    scanners: Sequence[str] = REAL_SCANNER_ADAPTER_NAMES,
    max_findings_per_scanner: int = REAL_SCANNER_MAX_FINDINGS_PER_SCANNER,
    max_findings: int = REAL_SCANNER_MAX_FINDINGS,
    max_report_bytes: int = REAL_SCANNER_MAX_REPORT_BYTES,
) -> RealScannerSuiteReport:
    """Explicit name for the suite's sequential execution contract."""

    return run_real_scanner_suite(
        repo_path,
        runner=runner,
        timeout_seconds=timeout_seconds,
        offline=offline,
        scanners=scanners,
        max_findings_per_scanner=max_findings_per_scanner,
        max_findings=max_findings,
        max_report_bytes=max_report_bytes,
    )


def real_scanner_capabilities() -> tuple[ExternalScannerAdapterCapability, ...]:
    return tuple(adapter.capability() for adapter in default_real_scanner_adapters())


def real_scanner_inventory() -> tuple[Mapping[str, object], ...]:
    return tuple(_inventory_item(capability) for capability in real_scanner_capabilities())


def _inventory_item(capability: ExternalScannerAdapterCapability) -> Mapping[str, object]:
    return {
        "scanner_name": capability.scanner_name,
        "scanner_category": capability.scanner_category,
        "supported_mode": capability.supported_mode,
        "allowed_input_paths": list(capability.allowed_input_paths),
        "requires_network": capability.requires_network,
        "executes_target_code": capability.executes_target_code,
        "docker_needed": capability.docker_needed,
        "raw_output_retention": capability.raw_output_retention,
        "expected_output_kind": capability.expected_output_kind,
        "default_cli_execution": False,
        "unavailable_result": "fail_closed_unknown_not_pass",
        "no_findings_result": "limited_evidence_not_safety_proof",
        "limitations": list(capability.limitations),
        "residual_risks": list(capability.residual_risks),
    }


def _scanner_function(scanner_name: str) -> _ScannerFunction:
    functions: Mapping[str, _ScannerFunction] = {
        "gitleaks": run_gitleaks_scan,
        "osv-scanner": run_osv_scan,
        "trivy": run_trivy_scan,
    }
    return functions[scanner_name]


def _entry_from_run_result(
    scanner_name: str,
    result: _RunResult,
    *,
    max_findings: int | None = None,
    truncation_warning: str = "finding_budget_exceeded",
) -> RealScannerSuiteEntry:
    normalized = _bounded_mapping(result.normalized_result)
    status = "completed" if result.valid else "unknown"
    summary = _mapping_value(normalized, "summary")
    mapping_result = _mapping_value(normalized, "mapping_result")
    original_finding_count = _result_finding_count(normalized)
    findings = normalized.get("findings")
    finding_records = list(findings) if isinstance(findings, list) else []
    retained_finding_count = original_finding_count
    if max_findings is not None:
        retained_finding_count = min(original_finding_count, max_findings)
        normalized = _truncate_normalized_result(normalized, retained_finding_count)
    omitted_finding_count = max(0, original_finding_count - retained_finding_count)
    warnings = list(result.warnings)
    if omitted_finding_count and truncation_warning not in warnings:
        warnings.append(truncation_warning)
    finding_count = min(len(finding_records), retained_finding_count)
    if not finding_records and retained_finding_count:
        finding_count = retained_finding_count
    risk_summary = {
        "outcome": _string_value(summary.get("outcome"), "unknown"),
        "highest_risk_tier_effect": _string_value(summary.get("highest_risk_tier_effect"), "unknown"),
        "risk_tier_effect": _string_value(mapping_result.get("risk_tier_effect"), "unknown"),
        "gate_effects": _string_list(mapping_result.get("gate_effects")),
        "risk_lowering_allowed": mapping_result.get("risk_lowering_allowed") is True,
    }
    return RealScannerSuiteEntry(
        scanner_name=scanner_name,
        executed=result.scanner_executed,
        valid=result.valid,
        status=status,
        blocking_errors=tuple(result.blocking_errors),
        warnings=tuple(warnings),
        risk_summary=risk_summary,
        normalized_result=normalized,
        finding_count=finding_count,
        omitted_finding_count=omitted_finding_count,
        truncated=omitted_finding_count > 0,
    )


def _validate_budget(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be greater than 0")


def _result_finding_count(normalized: Mapping[str, object]) -> int:
    findings = normalized.get("findings")
    list_count = len(findings) if isinstance(findings, list) else 0
    summary_count = _nonnegative_int(_mapping_value(normalized, "summary").get("finding_count"))
    return max(list_count, summary_count)


def _bounded_mapping(normalized: Mapping[str, object]) -> dict[str, object]:
    bounded = _bounded_json_value(deepcopy(dict(normalized)))
    return bounded if isinstance(bounded, dict) else {}


def _bounded_json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _bounded_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_bounded_json_value(item) for item in value]
    if isinstance(value, str) and len(value) > REAL_SCANNER_MAX_TEXT_FIELD_CHARS:
        return value[:REAL_SCANNER_MAX_TEXT_FIELD_CHARS] + "<truncated>"
    return value


def _truncate_normalized_result(normalized: Mapping[str, object], keep_findings: int) -> dict[str, object]:
    bounded = _bounded_mapping(normalized)
    findings = bounded.get("findings")
    if isinstance(findings, list):
        bounded["findings"] = findings[:keep_findings]
    evidence_nodes = bounded.get("evidence_nodes")
    if isinstance(evidence_nodes, list):
        bounded["evidence_nodes"] = evidence_nodes[:keep_findings]
    summary = bounded.get("summary")
    if isinstance(summary, Mapping):
        summary_copy = dict(summary)
        summary_copy["finding_count"] = keep_findings
        bounded["summary"] = summary_copy
    return bounded


def _truncate_entry(entry: RealScannerSuiteEntry, keep_findings: int, warning: str) -> RealScannerSuiteEntry:
    removed = max(0, entry.finding_count - keep_findings)
    warnings = list(entry.warnings)
    if warning not in warnings:
        warnings.append(warning)
    return replace(
        entry,
        warnings=tuple(warnings),
        normalized_result=_truncate_normalized_result(entry.normalized_result, keep_findings),
        finding_count=keep_findings,
        omitted_finding_count=entry.omitted_finding_count + removed,
        truncated=True,
    )


def _apply_report_byte_budget(
    entries: list[RealScannerSuiteEntry],
    *,
    max_report_bytes: int,
    limitations: Sequence[str],
    generated_at: str,
    subject: Mapping[str, object],
) -> tuple[list[RealScannerSuiteEntry], bool]:
    status = "completed" if all(entry.valid and entry.status == "completed" for entry in entries) else "degraded"
    if any(entry.truncated for entry in entries):
        status = "degraded"
    placeholder_fingerprint = "sha256:" + "0" * 64
    if _report_json_size(entries, status, limitations, generated_at, subject, placeholder_fingerprint) <= max_report_bytes:
        return entries, False

    byte_limitations = tuple(limitations) + ("report_byte_budget_exceeded", "report_truncated")
    while _report_json_size(entries, status, byte_limitations, generated_at, subject, placeholder_fingerprint) > max_report_bytes:
        candidate_indexes = [index for index, entry in enumerate(entries) if entry.finding_count > 0]
        if not candidate_indexes:
            if entries:
                entries[0] = replace(
                    entries[0],
                    warnings=tuple(dict.fromkeys((*entries[0].warnings, "report_byte_budget_exceeded"))),
                    truncated=True,
                )
            break
        index = candidate_indexes[-1]
        entries[index] = _truncate_entry(entries[index], entries[index].finding_count - 1, "report_byte_budget_exceeded")
        status = "degraded"
    return entries, True


def _report_json_size(
    entries: Sequence[RealScannerSuiteEntry],
    status: str,
    limitations: Sequence[str],
    generated_at: str,
    subject: Mapping[str, object],
    report_fingerprint: str,
) -> int:
    payload = {
        "schema_version": SUITE_SCHEMA_VERSION,
        "report_kind": SUITE_REPORT_KIND,
        "suite_status": status,
        "entries": [entry.to_dict() for entry in entries],
        "limitations": list(limitations),
        "execution_authorized": False,
        "report_fingerprint": report_fingerprint,
        "generated_at": generated_at,
        "subject": dict(subject),
    }
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _skipped_offline_entry(scanner_name: str) -> RealScannerSuiteEntry:
    normalized = _suite_unknown_result(scanner_name, "skipped_offline")
    return RealScannerSuiteEntry(
        scanner_name=scanner_name,
        executed=False,
        valid=False,
        status="skipped_offline",
        blocking_errors=(),
        warnings=("scanner_skipped_offline",),
        risk_summary=_risk_summary(normalized),
        normalized_result=normalized,
        finding_count=0,
        omitted_finding_count=0,
        truncated=False,
    )


def _runner_error_entry(scanner_name: str) -> RealScannerSuiteEntry:
    normalized = _suite_unknown_result(scanner_name, "runner_error")
    return RealScannerSuiteEntry(
        scanner_name=scanner_name,
        executed=False,
        valid=False,
        status="unknown",
        blocking_errors=("suite_runner_error",),
        warnings=(),
        risk_summary=_risk_summary(normalized),
        normalized_result=normalized,
        finding_count=0,
        omitted_finding_count=0,
        truncated=False,
    )


def _risk_summary(normalized: Mapping[str, object]) -> Mapping[str, object]:
    summary = _mapping_value(normalized, "summary")
    mapping_result = _mapping_value(normalized, "mapping_result")
    return {
        "outcome": _string_value(summary.get("outcome"), "unknown"),
        "highest_risk_tier_effect": _string_value(summary.get("highest_risk_tier_effect"), "unknown"),
        "risk_tier_effect": _string_value(mapping_result.get("risk_tier_effect"), "unknown"),
        "gate_effects": _string_list(mapping_result.get("gate_effects")),
        "risk_lowering_allowed": mapping_result.get("risk_lowering_allowed") is True,
    }


def _suite_unknown_result(scanner_name: str, reason: str) -> Mapping[str, object]:
    capability = next(capability for capability in real_scanner_capabilities() if capability.scanner_name == scanner_name)
    return {
        "schema_version": SUITE_SCHEMA_VERSION,
        "report_kind": "external_scanner_result",
        "scanner": {
            "name": scanner_name,
            "version": "unknown",
            "adapter_version": "unknown",
            "category": capability.scanner_category,
            "mode": capability.supported_mode,
            "scanner_source": "external_binary",
            "trusted_binary_status": "unverified",
            "unsupported_version": False,
        },
        "input_scope": {
            "scope": "repo",
            "source_type": "git_commit",
            "repo_commit": None,
            "dirty_state": "unknown",
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
            "timeout_occurred": reason == "timeout",
            "scanner_completed": False,
        },
        "trust_level": "local_reproducible",
        "execution_authorized": False,
        "findings": [],
        "evidence_nodes": [],
        "evidence_edges": [],
        "summary": {
            "outcome": "unknown",
            "unknown_reason": reason,
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
        "redaction_status": {
            "raw_secret_present": False,
            "raw_host_path_present": False,
            "raw_scanner_output_included": False,
            "raw_stdout_stderr_included": False,
            "unredacted_snippet_present": False,
            "redaction_validated": True,
        },
    }


def _subject_from_entries(entries: Sequence[RealScannerSuiteEntry]) -> Mapping[str, object]:
    for entry in entries:
        input_scope = _mapping_value(entry.normalized_result, "input_scope")
        if input_scope:
            return {
                "repo_commit": input_scope.get("repo_commit"),
                "dirty_state": _string_value(input_scope.get("dirty_state"), "unknown"),
            }
    return {"repo_commit": None, "dirty_state": "unknown"}


def _mapping_value(value: Mapping[str, object], key: str) -> Mapping[str, object]:
    nested = value.get(key)
    return nested if isinstance(nested, Mapping) else {}


def _nonnegative_int(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _string_value(value: object, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def _string_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str)]


def _fingerprint(value: Mapping[str, object]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
