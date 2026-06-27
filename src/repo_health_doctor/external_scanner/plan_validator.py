"""Validate local no-network external scanner plans without executing them."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping


EXTERNAL_SCANNER_PLAN_SCHEMA_VERSION = "0.1-draft"
PLAN_KIND_EXTERNAL_SCANNER_NO_NETWORK = "external_scanner_no_network_plan"

TOP_LEVEL_FIELDS = {
    "schema_version",
    "plan_kind",
    "scanner",
    "input_scope",
    "execution_constraints",
    "approval",
    "failure_policy",
    "limitations",
    "residual_risks",
    "execution_authorized",
    "scanner_execution_planned",
    "scanner_executed",
}
SCANNER_FIELDS = {
    "name",
    "mode",
    "version_pin_required",
    "version_pin",
    "binary_hash_required",
    "binary_hash",
    "binary_trust_requirement",
    "allowed_input_scope",
}
EXECUTION_CONSTRAINT_FIELDS = {
    "network_allowed",
    "target_code_execution_allowed",
    "docker_allowed",
    "timeout_seconds",
    "max_output_bytes",
    "raw_output_retention",
    "redaction_before_persistence",
}
APPROVAL_FIELDS = {"requires_human_approval", "approval_artifact_generated", "approval_reference"}
FAILURE_POLICY_FIELDS = {"failure_effect", "scanner_unavailable_effect", "parse_failure_effect"}


@dataclass(frozen=True)
class ExternalScannerPlanValidationResult:
    valid: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    fired_invariants: tuple[str, ...]
    scanner_name: str | None
    scanner_mode: str | None
    execution_authorized: bool
    scanner_execution_planned: bool
    scanner_executed: bool
    requires_human_approval: bool
    network_allowed: bool
    target_code_execution_allowed: bool
    raw_output_retention: bool
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "fired_invariants": list(self.fired_invariants),
            "scanner_name": self.scanner_name,
            "scanner_mode": self.scanner_mode,
            "execution_authorized": self.execution_authorized,
            "scanner_execution_planned": self.scanner_execution_planned,
            "scanner_executed": self.scanner_executed,
            "requires_human_approval": self.requires_human_approval,
            "network_allowed": self.network_allowed,
            "target_code_execution_allowed": self.target_code_execution_allowed,
            "raw_output_retention": self.raw_output_retention,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
        }


def load_external_scanner_plan_schema() -> Mapping[str, Any]:
    schema_path = Path(__file__).resolve().parents[3] / "schemas" / "external-scanner-plan.schema.json"
    with schema_path.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, Mapping):
        raise ValueError("external scanner plan schema is not an object")
    return schema


def validate_external_scanner_plan(data: Mapping[str, Any]) -> ExternalScannerPlanValidationResult:
    """Validate a no-network scanner plan without executing scanners."""
    errors: list[str] = []
    warnings: list[str] = []
    invariants: list[str] = []
    try:
        schema = load_external_scanner_plan_schema()
    except (OSError, json.JSONDecodeError, ValueError):
        schema = {}
        _block(errors, invariants, "plan_schema_unavailable")
    if schema and schema.get("additionalProperties") is not False:
        _block(errors, invariants, "plan_schema_top_level_must_be_closed")

    if not isinstance(data, Mapping):
        return _result(
            errors=("plan_input_must_be_object",),
            warnings=(),
            invariants=("plan_input_must_be_object",),
            scanner_name=None,
            scanner_mode=None,
            execution_authorized=False,
            scanner_execution_planned=False,
            scanner_executed=False,
            requires_human_approval=False,
            network_allowed=False,
            target_code_execution_allowed=False,
            raw_output_retention=False,
            limitations=(),
            residual_risks=("unknown_or_unsupported_external_scanner_plan",),
        )

    if set(data) != TOP_LEVEL_FIELDS:
        _block(errors, invariants, "plan_top_level_required_or_unknown_field")
    if data.get("schema_version") != EXTERNAL_SCANNER_PLAN_SCHEMA_VERSION:
        _block(errors, invariants, "plan_schema_version_unsupported")
    if data.get("plan_kind") != PLAN_KIND_EXTERNAL_SCANNER_NO_NETWORK:
        _block(errors, invariants, "plan_kind_unsupported")

    scanner = _mapping(data.get("scanner"), SCANNER_FIELDS, "scanner", errors, invariants)
    constraints = _mapping(data.get("execution_constraints"), EXECUTION_CONSTRAINT_FIELDS, "execution_constraints", errors, invariants)
    approval = _mapping(data.get("approval"), APPROVAL_FIELDS, "approval", errors, invariants)
    _mapping(data.get("failure_policy"), FAILURE_POLICY_FIELDS, "failure_policy", errors, invariants)

    if data.get("execution_authorized") is not False:
        _block(errors, invariants, "plan_execution_authorized_must_be_false")
    if data.get("scanner_execution_planned") is not True:
        _block(errors, invariants, "scanner_execution_planned_must_be_true")
    if data.get("scanner_executed") is not False:
        _block(errors, invariants, "scanner_executed_must_be_false")
    if scanner.get("mode") != "local_static_no_network":
        _block(errors, invariants, "scanner_mode_must_be_local_static_no_network")
    if constraints.get("network_allowed") is not False:
        _block(errors, invariants, "network_allowed_must_be_false")
    if constraints.get("target_code_execution_allowed") is not False:
        _block(errors, invariants, "target_code_execution_allowed_must_be_false")
    if constraints.get("docker_allowed") is not False:
        _block(errors, invariants, "docker_allowed_must_be_false")
    if constraints.get("raw_output_retention") is not False:
        _block(errors, invariants, "raw_output_retention_must_be_false")
    if constraints.get("redaction_before_persistence") is not True:
        _block(errors, invariants, "redaction_before_persistence_required")
    if approval.get("requires_human_approval") is not True:
        _block(errors, invariants, "requires_human_approval_must_be_true")
    if approval.get("approval_artifact_generated") is not False:
        _block(errors, invariants, "approval_artifact_generated_must_be_false")

    limitations = _string_items(data.get("limitations"))
    residual_risks = _string_items(data.get("residual_risks"))
    if not limitations:
        _block(errors, invariants, "plan_limitations_empty")
    if not residual_risks:
        _block(errors, invariants, "plan_residual_risks_empty")
    if scanner.get("version_pin_required") is not True:
        warnings.append("scanner_version_pin_required_not_confirmed")
    if scanner.get("binary_hash_required") is not True:
        warnings.append("scanner_binary_hash_required_not_confirmed")

    return _result(
        errors=tuple(_dedupe(errors)),
        warnings=tuple(_dedupe(warnings)),
        invariants=tuple(_dedupe(invariants)),
        scanner_name=scanner.get("name") if isinstance(scanner.get("name"), str) else None,
        scanner_mode=scanner.get("mode") if isinstance(scanner.get("mode"), str) else None,
        execution_authorized=data.get("execution_authorized") is True,
        scanner_execution_planned=data.get("scanner_execution_planned") is True,
        scanner_executed=data.get("scanner_executed") is True,
        requires_human_approval=approval.get("requires_human_approval") is True,
        network_allowed=constraints.get("network_allowed") is True,
        target_code_execution_allowed=constraints.get("target_code_execution_allowed") is True,
        raw_output_retention=constraints.get("raw_output_retention") is True,
        limitations=tuple(limitations),
        residual_risks=tuple(residual_risks),
    )


def _result(
    *,
    errors: tuple[str, ...],
    warnings: tuple[str, ...],
    invariants: tuple[str, ...],
    scanner_name: str | None,
    scanner_mode: str | None,
    execution_authorized: bool,
    scanner_execution_planned: bool,
    scanner_executed: bool,
    requires_human_approval: bool,
    network_allowed: bool,
    target_code_execution_allowed: bool,
    raw_output_retention: bool,
    limitations: tuple[str, ...],
    residual_risks: tuple[str, ...],
) -> ExternalScannerPlanValidationResult:
    return ExternalScannerPlanValidationResult(
        valid=not errors,
        blocking_errors=errors,
        warnings=warnings,
        fired_invariants=invariants,
        scanner_name=scanner_name,
        scanner_mode=scanner_mode,
        execution_authorized=execution_authorized,
        scanner_execution_planned=scanner_execution_planned,
        scanner_executed=scanner_executed,
        requires_human_approval=requires_human_approval,
        network_allowed=network_allowed,
        target_code_execution_allowed=target_code_execution_allowed,
        raw_output_retention=raw_output_retention,
        limitations=limitations,
        residual_risks=residual_risks,
    )


def _mapping(
    value: object,
    expected_fields: set[str],
    label: str,
    errors: list[str],
    invariants: list[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _block(errors, invariants, f"{label}_must_be_object")
        return {}
    if set(value) != expected_fields:
        _block(errors, invariants, f"{label}_required_or_unknown_field")
    return value


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _block(errors: list[str], invariants: list[str], invariant: str) -> None:
    errors.append(invariant)
    invariants.append(invariant)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
