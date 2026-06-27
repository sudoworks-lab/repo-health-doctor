"""Validate imported external scanner result evidence.

The validator is intentionally static. It validates caller-supplied
JSON-compatible mappings and returns a fail-closed result model. It never runs
or installs an external scanner, contacts a network, starts Docker, calls a
remote API, executes target code, captures observers, persists raw scanner
output, or authorizes live execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_EXTERNAL_SCANNER_RESULT = "external_scanner_result"

ALLOWED_OUTCOMES = {
    "no_findings_in_scope",
    "findings_present",
    "block",
    "unknown",
    "not_applicable",
}
LOW_TRUST_LEVELS = {"untrusted_import", "schema_validated_import"}
SAFE_NO_FINDING_GATE_EFFECTS = {"evidence_only"}
GATE_EFFECT_ORDER = {
    "evidence_only": 0,
    "raises_risk": 1,
    "requires_human_review": 2,
    "blocks_live_execution": 3,
    "requires_dedicated_vm": 4,
    "quarantine": 5,
}

TOP_LEVEL_FIELDS = {
    "schema_version",
    "report_kind",
    "scanner",
    "input_scope",
    "execution_context",
    "trust_level",
    "execution_authorized",
    "findings",
    "evidence_nodes",
    "evidence_edges",
    "summary",
    "mapping_result",
    "redaction_status",
    "limitations",
    "residual_risks",
    "binding",
}
SCANNER_FIELDS = {
    "name",
    "version",
    "adapter_version",
    "category",
    "mode",
    "scanner_source",
    "trusted_binary_status",
    "unsupported_version",
}
EXECUTION_CONTEXT_FIELDS = {
    "network_used",
    "target_code_executed",
    "docker_used",
    "scanner_downloaded_dependencies",
    "raw_output_available",
    "raw_output_retained",
    "timeout_occurred",
    "scanner_completed",
}
SUMMARY_FIELDS = {
    "outcome",
    "unknown_reason",
    "finding_count",
    "highest_risk_tier_effect",
    "gate_effects",
}
SUMMARY_REQUIRED_FIELDS = {
    "outcome",
    "finding_count",
    "highest_risk_tier_effect",
    "gate_effects",
}
MAPPING_RESULT_FIELDS = {
    "risk_tier_effect",
    "gate_effects",
    "rules_fired",
    "risk_lowering_allowed",
}
REDACTION_STATUS_FIELDS = {
    "raw_secret_present",
    "raw_host_path_present",
    "raw_scanner_output_included",
    "raw_stdout_stderr_included",
    "unredacted_snippet_present",
    "redaction_validated",
}
LIMITATION_FIELDS = {"limitation_id", "description"}
RESIDUAL_RISK_FIELDS = {"risk_id", "description"}

RAW_HOST_PATH = re.compile(
    r"(?:^|[\s\"'=])(?:/(?:home|Users)/|/mnt/[A-Za-z]/Users/|[A-Za-z]:\\Users\\)"
)


@dataclass(frozen=True)
class ExternalScannerValidationResult:
    valid: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    fired_invariants: tuple[str, ...]
    highest_gate_effect: str
    execution_authorized: bool
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "fired_invariants": list(self.fired_invariants),
            "highest_gate_effect": self.highest_gate_effect,
            "execution_authorized": self.execution_authorized,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
        }


def load_external_scanner_result_schema() -> Mapping[str, Any]:
    schema_path = Path(__file__).resolve().parents[3] / "schemas" / "external-scanner-result.schema.json"
    with schema_path.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, Mapping):
        raise ValueError("external scanner result schema is not an object")
    return schema


def validate_external_scanner_result(data: Mapping[str, Any]) -> ExternalScannerValidationResult:
    """Validate supplied external scanner result data.

    The return value is deliberately not an execution decision. Even a valid
    no-finding result is not safety proof and does not authorize live execution.
    """
    blocking_errors: list[str] = []
    warnings: list[str] = []
    fired_invariants: list[str] = []

    try:
        schema = load_external_scanner_result_schema()
    except (OSError, json.JSONDecodeError, ValueError):
        schema = {}
        _block(blocking_errors, fired_invariants, "schema_contract_unavailable")
    if schema and schema.get("additionalProperties") is not False:
        _block(blocking_errors, fired_invariants, "schema_top_level_must_be_closed")

    if not isinstance(data, Mapping):
        return _result(
            blocking_errors=("schema_input_must_be_object",),
            warnings=(),
            fired_invariants=("schema_input_must_be_object",),
            highest_gate_effect="quarantine",
            execution_authorized=False,
            limitations=(),
            residual_risks=("unknown_or_unsupported_external_scanner_result",),
        )

    _validate_schema_shape(data, blocking_errors, fired_invariants)
    _validate_semantics(data, blocking_errors, warnings, fired_invariants)
    _validate_redaction(data, blocking_errors, fired_invariants)

    limitations = _limitation_ids(data.get("limitations"))
    residual_risks = _residual_risk_ids(data.get("residual_risks"))
    highest_gate_effect = _highest_gate_effect(data, bool(blocking_errors))
    return _result(
        blocking_errors=tuple(_dedupe(blocking_errors)),
        warnings=tuple(_dedupe(warnings)),
        fired_invariants=tuple(_dedupe(fired_invariants)),
        highest_gate_effect=highest_gate_effect,
        execution_authorized=data.get("execution_authorized") is True,
        limitations=tuple(limitations),
        residual_risks=tuple(residual_risks),
    )


def _result(
    *,
    blocking_errors: tuple[str, ...],
    warnings: tuple[str, ...],
    fired_invariants: tuple[str, ...],
    highest_gate_effect: str,
    execution_authorized: bool,
    limitations: tuple[str, ...],
    residual_risks: tuple[str, ...],
) -> ExternalScannerValidationResult:
    return ExternalScannerValidationResult(
        valid=not blocking_errors,
        blocking_errors=blocking_errors,
        warnings=warnings,
        fired_invariants=fired_invariants,
        highest_gate_effect=highest_gate_effect,
        execution_authorized=execution_authorized,
        limitations=limitations,
        residual_risks=residual_risks,
    )


def _block(errors: list[str], invariants: list[str], invariant: str) -> None:
    errors.append(invariant)
    invariants.append(invariant)


def _warn(warnings: list[str], invariants: list[str], invariant: str) -> None:
    warnings.append(invariant)
    invariants.append(invariant)


def _validate_schema_shape(data: Mapping[str, Any], errors: list[str], invariants: list[str]) -> None:
    if set(data) != TOP_LEVEL_FIELDS:
        _block(errors, invariants, "schema_top_level_required_or_unknown_field")
    if data.get("schema_version") != EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION:
        _block(errors, invariants, "schema_version_unsupported")
    if data.get("report_kind") != REPORT_KIND_EXTERNAL_SCANNER_RESULT:
        _block(errors, invariants, "report_kind_unsupported")
    if data.get("execution_authorized") is not False:
        _block(errors, invariants, "execution_authorized_must_be_false")

    scanner = _mapping(data.get("scanner"), SCANNER_FIELDS, "scanner", errors, invariants)
    if scanner is not None:
        if not isinstance(scanner.get("unsupported_version"), bool):
            _block(errors, invariants, "scanner_unsupported_version_must_be_boolean")
        if scanner.get("mode") not in {
            "imported_report",
            "local_static_no_network",
            "local_static_network",
            "remote_api",
            "local_dynamic_sandbox",
        }:
            _block(errors, invariants, "scanner_mode_invalid")

    execution = _mapping(data.get("execution_context"), EXECUTION_CONTEXT_FIELDS, "execution_context", errors, invariants)
    if execution is not None:
        for field in EXECUTION_CONTEXT_FIELDS:
            if not isinstance(execution.get(field), bool):
                _block(errors, invariants, f"execution_context_{field}_must_be_boolean")

    summary = _mapping(data.get("summary"), SUMMARY_FIELDS, "summary", errors, invariants, allow_missing={"unknown_reason"})
    if summary is not None:
        missing = SUMMARY_REQUIRED_FIELDS - set(summary)
        if missing:
            _block(errors, invariants, "summary_required_field_missing")
        outcome = summary.get("outcome")
        if outcome == "pass":
            _block(errors, invariants, "outcome_pass_is_forbidden")
        elif outcome not in ALLOWED_OUTCOMES:
            _block(errors, invariants, "outcome_invalid")
        if outcome == "unknown" and "unknown_reason" not in summary:
            _block(errors, invariants, "unknown_reason_missing")
        if not isinstance(summary.get("gate_effects"), list):
            _block(errors, invariants, "summary_gate_effects_invalid")

    mapping_result = _mapping(data.get("mapping_result"), MAPPING_RESULT_FIELDS, "mapping_result", errors, invariants)
    if mapping_result is not None:
        if mapping_result.get("risk_lowering_allowed") is not False:
            _block(errors, invariants, "risk_lowering_allowed_must_be_false")
        if not isinstance(mapping_result.get("gate_effects"), list):
            _block(errors, invariants, "mapping_result_gate_effects_invalid")
        if not isinstance(mapping_result.get("rules_fired"), list):
            _block(errors, invariants, "mapping_result_rules_fired_invalid")

    redaction = _mapping(data.get("redaction_status"), REDACTION_STATUS_FIELDS, "redaction_status", errors, invariants)
    if redaction is not None:
        for field in REDACTION_STATUS_FIELDS:
            if not isinstance(redaction.get(field), bool):
                _block(errors, invariants, f"redaction_status_{field}_must_be_boolean")

    if not isinstance(data.get("findings"), list):
        _block(errors, invariants, "findings_must_be_array")
    if not isinstance(data.get("evidence_nodes"), list):
        _block(errors, invariants, "evidence_nodes_must_be_array")
    if not isinstance(data.get("evidence_edges"), list):
        _block(errors, invariants, "evidence_edges_must_be_array")
    if not isinstance(data.get("limitations"), list):
        _block(errors, invariants, "limitations_must_be_array")
    if not isinstance(data.get("residual_risks"), list):
        _block(errors, invariants, "residual_risks_must_be_array")


def _validate_semantics(
    data: Mapping[str, Any],
    errors: list[str],
    warnings: list[str],
    invariants: list[str],
) -> None:
    scanner = data.get("scanner") if isinstance(data.get("scanner"), Mapping) else {}
    execution = data.get("execution_context") if isinstance(data.get("execution_context"), Mapping) else {}
    summary = data.get("summary") if isinstance(data.get("summary"), Mapping) else {}
    mapping_result = data.get("mapping_result") if isinstance(data.get("mapping_result"), Mapping) else {}
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []

    outcome = summary.get("outcome")
    if outcome == "no_findings_in_scope":
        _warn(warnings, invariants, "no_findings_in_scope_is_not_safety_proof")

    if execution.get("scanner_completed") is False and outcome == "no_findings_in_scope":
        _block(errors, invariants, "scanner_incomplete_claims_no_findings")
    if any(isinstance(item, Mapping) and item.get("primary_category") == "scanner_failure" for item in findings) and outcome == "no_findings_in_scope":
        _block(errors, invariants, "scanner_failure_claims_no_findings")
    if scanner.get("mode") == "local_static_no_network" and execution.get("network_used") is True:
        _block(errors, invariants, "local_static_no_network_used_network")
    if scanner.get("mode") == "local_static_no_network" and execution.get("target_code_executed") is True:
        _block(errors, invariants, "local_static_no_network_executed_target_code")
    if scanner.get("mode") == "imported_report" and execution.get("raw_output_retained") is True:
        _block(errors, invariants, "imported_report_raw_output_retained")
    if scanner.get("unsupported_version") is True and outcome == "no_findings_in_scope":
        _block(errors, invariants, "unsupported_version_claims_no_findings")
    if outcome == "unknown" and "unknown_reason" not in summary:
        _block(errors, invariants, "unknown_reason_missing")
    if isinstance(data.get("limitations"), list) and not data["limitations"]:
        _block(errors, invariants, "limitations_empty")
    if data.get("execution_authorized") is True:
        _block(errors, invariants, "external_result_cannot_authorize_execution")

    if data.get("trust_level") in LOW_TRUST_LEVELS and outcome == "no_findings_in_scope":
        _warn(warnings, invariants, "low_trust_no_finding_import_cannot_lower_risk")
        safe_mapping = (
            mapping_result.get("risk_lowering_allowed") is False
            and mapping_result.get("risk_tier_effect") == "none"
            and summary.get("highest_risk_tier_effect") == "none"
            and set(_string_items(mapping_result.get("gate_effects"))).issubset(SAFE_NO_FINDING_GATE_EFFECTS)
            and set(_string_items(summary.get("gate_effects"))).issubset(SAFE_NO_FINDING_GATE_EFFECTS)
        )
        if not safe_mapping:
            _block(errors, invariants, "low_trust_no_finding_attempts_to_lower_or_clear_risk")


def _validate_redaction(data: Mapping[str, Any], errors: list[str], invariants: list[str]) -> None:
    redaction = data.get("redaction_status") if isinstance(data.get("redaction_status"), Mapping) else {}
    redaction_blockers = {
        "raw_secret_present": "raw_secret_present",
        "raw_host_path_present": "raw_host_path_present",
        "raw_scanner_output_included": "raw_scanner_output_included",
        "raw_stdout_stderr_included": "raw_stdout_stderr_included",
        "unredacted_snippet_present": "unredacted_snippet_present",
    }
    for field, invariant in redaction_blockers.items():
        if redaction.get(field) is True:
            _block(errors, invariants, invariant)
    if redaction and redaction.get("redaction_validated") is not True:
        _block(errors, invariants, "redaction_not_validated")

    if any(RAW_HOST_PATH.search(value) for value in _iter_strings(data)):
        _block(errors, invariants, "raw_host_path_pattern_present")


def _mapping(
    value: Any,
    expected_fields: set[str],
    label: str,
    errors: list[str],
    invariants: list[str],
    *,
    allow_missing: set[str] | None = None,
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        _block(errors, invariants, f"{label}_must_be_object")
        return None
    allowed = set(expected_fields)
    required = allowed - set(allow_missing or set())
    if not required.issubset(value) or not set(value).issubset(allowed):
        _block(errors, invariants, f"{label}_required_or_unknown_field")
    return value


def _string_items(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def _limitation_ids(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    ids: list[str] = []
    for item in value:
        if isinstance(item, Mapping) and set(item) == LIMITATION_FIELDS and isinstance(item.get("limitation_id"), str):
            ids.append(item["limitation_id"])
    return ids


def _residual_risk_ids(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    ids: list[str] = []
    for item in value:
        if isinstance(item, Mapping) and set(item) == RESIDUAL_RISK_FIELDS and isinstance(item.get("risk_id"), str):
            ids.append(item["risk_id"])
    return ids


def _highest_gate_effect(data: Mapping[str, Any], has_blocking_errors: bool) -> str:
    if has_blocking_errors:
        return "quarantine"
    effects: list[str] = []
    summary = data.get("summary")
    mapping_result = data.get("mapping_result")
    if isinstance(summary, Mapping):
        effects.extend(_string_items(summary.get("gate_effects")))
    if isinstance(mapping_result, Mapping):
        effects.extend(_string_items(mapping_result.get("gate_effects")))
    if not effects:
        return "evidence_only"
    return max(effects, key=lambda item: GATE_EFFECT_ORDER.get(item, -1))


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
