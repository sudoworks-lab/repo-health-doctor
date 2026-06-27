"""Validate imported external scanner reports without running scanners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .result_validator import ExternalScannerValidationResult, validate_external_scanner_result
from .risk_mapper import ExternalScannerRiskMappingResult, map_external_scanner_risk


@dataclass(frozen=True)
class ImportedExternalReportValidationResult:
    valid: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    fired_invariants: tuple[str, ...]
    fired_rules: tuple[str, ...]
    highest_risk_tier_effect: str
    gate_effects: tuple[str, ...]
    trust_level: str | None
    commit_bound: bool
    commit_mismatch: bool
    cannot_lower_risk: bool
    execution_authorized: bool
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]
    report_summary: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "fired_invariants": list(self.fired_invariants),
            "fired_rules": list(self.fired_rules),
            "highest_risk_tier_effect": self.highest_risk_tier_effect,
            "gate_effects": list(self.gate_effects),
            "trust_level": self.trust_level,
            "commit_bound": self.commit_bound,
            "commit_mismatch": self.commit_mismatch,
            "cannot_lower_risk": self.cannot_lower_risk,
            "execution_authorized": self.execution_authorized,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
            "report_summary": dict(self.report_summary),
        }


def validate_imported_external_report(
    data: Mapping[str, Any],
    *,
    expected_commit: str | None = None,
    policy: Mapping[str, Any] | None = None,
) -> ImportedExternalReportValidationResult:
    """Validate imported external scanner evidence as a report-only input.

    This is not a scanner runner and not an execution authorization path. It
    validates caller-supplied JSON-compatible data, applies the external scanner
    semantic/redaction validator, maps risk, and checks imported-report binding.
    """
    validation = validate_external_scanner_result(data)
    mapping = map_external_scanner_risk(data, validation_result=validation, policy=policy)

    blocking_errors = list(validation.blocking_errors)
    warnings = list(validation.warnings)
    fired_invariants = list(validation.fired_invariants)

    scanner = _mapping(data.get("scanner"))
    binding = _mapping(data.get("binding"))
    input_scope = _mapping(data.get("input_scope"))
    summary = _mapping(data.get("summary"))

    mode = scanner.get("mode") if scanner else None
    if mode != "imported_report":
        _block(blocking_errors, fired_invariants, "imported_report_mode_required")

    binding_commit = _string_value(binding, "repo_commit")
    input_commit = _string_value(input_scope, "repo_commit")
    commit_bound = bool(binding_commit and input_commit and binding_commit == input_commit)
    commit_mismatch = False
    if binding_commit and input_commit and binding_commit != input_commit:
        commit_mismatch = True
        _block(blocking_errors, fired_invariants, "binding_commit_mismatch")
    if expected_commit is not None and binding_commit != expected_commit:
        commit_mismatch = True
        _block(blocking_errors, fired_invariants, "expected_commit_mismatch")
    if not commit_bound:
        warnings.append("imported_report_commit_binding_not_confirmed")

    if not validation.limitations:
        _block(blocking_errors, fired_invariants, "imported_report_limitations_missing")
    if not validation.residual_risks:
        _block(blocking_errors, fired_invariants, "imported_report_residual_risks_missing")
    if validation.execution_authorized or data.get("execution_authorized") is True:
        _block(blocking_errors, fired_invariants, "imported_report_cannot_authorize_execution")

    report_summary = {
        "outcome": summary.get("outcome") if summary else None,
        "finding_count": summary.get("finding_count") if summary else None,
        "scanner_name": scanner.get("name") if scanner else None,
        "scanner_mode": mode,
        "repo_commit": binding_commit,
        "expected_commit": expected_commit,
        "risk_lowering_allowed": False,
        "live_execution_authorized": False,
    }
    return ImportedExternalReportValidationResult(
        valid=not blocking_errors,
        blocking_errors=tuple(_dedupe(blocking_errors)),
        warnings=tuple(_dedupe(warnings)),
        fired_invariants=tuple(_dedupe(fired_invariants)),
        fired_rules=tuple(rule.rule_id for rule in mapping.fired_rules),
        highest_risk_tier_effect=mapping.highest_risk_tier_effect,
        gate_effects=mapping.gate_effects,
        trust_level=data.get("trust_level") if isinstance(data.get("trust_level"), str) else None,
        commit_bound=commit_bound,
        commit_mismatch=commit_mismatch,
        cannot_lower_risk=mapping.cannot_lower_risk,
        execution_authorized=False,
        limitations=mapping.limitations,
        residual_risks=mapping.residual_risks,
        report_summary=report_summary,
    )


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_value(value: Mapping[str, Any], field: str) -> str | None:
    item = value.get(field)
    return item if isinstance(item, str) and item else None


def _block(errors: list[str], invariants: list[str], invariant: str) -> None:
    errors.append(invariant)
    invariants.append(invariant)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
