"""Validate future evidence model candidates.

The validator is intentionally static. It validates supplied JSON-compatible
mappings and never runs scanners, contacts networks, starts Docker, executes
target code, persists raw output, or authorizes execution.
"""

from __future__ import annotations

from typing import Any, Mapping
import re

from .models import EvidenceValidationResult


EVIDENCE_SCHEMA_VERSION = "0.1-draft"
EVIDENCE_KIND = "repo_health_evidence"

TOP_LEVEL_FIELDS = {
    "evidence_id",
    "schema_version",
    "evidence_kind",
    "source",
    "subject",
    "classification",
    "finding",
    "raw_handling",
    "trust",
    "effects",
    "residual_risks",
}
SOURCE_FIELDS = {"tool_name", "tool_version", "adapter_name", "adapter_version", "execution_mode"}
LEGACY_SUBJECT_FIELDS = {
    "repo_identity",
    "commit",
    "tree_hash",
    "path_scope",
    "binding_kind",
}
SUBJECT_FIELDS = LEGACY_SUBJECT_FIELDS | {
    "snapshot_id",
    "manifest_fingerprint",
}
CLASSIFICATION_FIELDS = {"category", "subcategory", "severity", "confidence", "confidence_reason"}
FINDING_FIELDS = {"present", "count", "locations", "redacted_summary"}
RAW_HANDLING_FIELDS = {
    "raw_output_retained",
    "raw_stdout_retained",
    "raw_stderr_retained",
    "redaction_status",
    "redaction_failures",
}
TRUST_FIELDS = {"level", "commit_bound", "signature_verified", "binary_attested", "limitations"}
EFFECTS_FIELDS = {"can_lower_risk", "can_authorize_execution", "recommended_gate_effect"}

EXECUTION_MODES = {
    "native_static",
    "imported_report",
    "local_no_network",
    "docker_isolated",
    "sandbox_observer",
    "synthetic_fixture",
}
TRUST_LEVELS = {
    "untrusted_import",
    "schema_validated",
    "redaction_validated",
    "commit_bound",
    "policy_bound",
    "docker_isolated_reproduced",
    "attested_binary_reproduced",
}
LOW_TRUST_LEVELS = {"untrusted_import", "schema_validated"}
CATEGORIES = {
    "secret",
    "known_vulnerability",
    "sbom",
    "ci_cd",
    "runtime_behavior",
    "repo_posture",
    "sandbox_observation",
    "external_scanner",
    "approval",
    "limitation",
}
SEVERITIES = {"info", "warn", "block", "unknown"}
CONFIDENCES = {"low", "medium", "high", "unknown"}
GATE_EFFECTS = {"evidence_only", "requires_human_review", "allow_limited", "warn", "quarantine", "block"}
BINDING_KINDS = {
    "unbound",
    "path_bound",
    "commit_bound",
    "tree_bound",
    "snapshot_bound",
    "synthetic",
}

RAW_HOST_PATH = re.compile(r"(?:^|[\s\"'=])(?:/(?:home|Users)/|/mnt/[A-Za-z]/Users/|[A-Za-z]:\\Users\\)")


def validate_evidence(data: Mapping[str, Any]) -> EvidenceValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(data, Mapping):
        return EvidenceValidationResult(
            valid=False,
            blocking_errors=("evidence_must_be_object",),
            warnings=(),
            limitations=(),
            residual_risks=("invalid_evidence_input",),
        )

    if set(data) != TOP_LEVEL_FIELDS:
        errors.append("evidence_top_level_required_or_unknown_field")
    if data.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        errors.append("evidence_schema_version_unsupported")
    if data.get("evidence_kind") != EVIDENCE_KIND:
        errors.append("evidence_kind_unsupported")
    if not _non_empty_string(data.get("evidence_id")):
        errors.append("evidence_id_required")

    source = _mapping(data.get("source"), SOURCE_FIELDS, "source", errors)
    subject_value = data.get("subject")
    subject = subject_value if isinstance(subject_value, Mapping) else None
    if subject is None:
        errors.append("subject_must_be_object")
    elif frozenset(subject) not in {
        frozenset(LEGACY_SUBJECT_FIELDS),
        frozenset(SUBJECT_FIELDS),
    }:
        errors.append("subject_required_or_unknown_field")
    classification = _mapping(data.get("classification"), CLASSIFICATION_FIELDS, "classification", errors)
    finding = _mapping(data.get("finding"), FINDING_FIELDS, "finding", errors)
    raw_handling = _mapping(data.get("raw_handling"), RAW_HANDLING_FIELDS, "raw_handling", errors)
    trust = _mapping(data.get("trust"), TRUST_FIELDS, "trust", errors)
    effects = _mapping(data.get("effects"), EFFECTS_FIELDS, "effects", errors)

    if source is not None:
        if source.get("execution_mode") not in EXECUTION_MODES:
            errors.append("source_execution_mode_invalid")
        _require_strings(source, ("tool_name", "tool_version", "adapter_name", "adapter_version"), errors, "source")

    if subject is not None:
        if subject.get("binding_kind") not in BINDING_KINDS:
            errors.append("subject_binding_kind_invalid")
        if not isinstance(subject.get("path_scope"), list):
            errors.append("subject_path_scope_must_be_array")
        if not _non_empty_string(subject.get("repo_identity")):
            errors.append("subject_repo_identity_required")
        if subject.get("binding_kind") == "snapshot_bound":
            if not _fingerprint(subject.get("snapshot_id")):
                errors.append("subject_snapshot_id_invalid")
            if not _fingerprint(subject.get("manifest_fingerprint")):
                errors.append("subject_manifest_fingerprint_invalid")

    if classification is not None:
        if classification.get("category") not in CATEGORIES:
            errors.append("classification_category_invalid")
        if classification.get("severity") not in SEVERITIES:
            errors.append("classification_severity_invalid")
        if classification.get("confidence") not in CONFIDENCES:
            errors.append("classification_confidence_invalid")
        _require_strings(classification, ("subcategory", "confidence_reason"), errors, "classification")

    if finding is not None:
        present = finding.get("present")
        count = finding.get("count")
        if not isinstance(present, bool):
            errors.append("finding_present_must_be_boolean")
        if not isinstance(count, int) or count < 0:
            errors.append("finding_count_invalid")
        if present is False and count != 0:
            errors.append("finding_absent_count_must_be_zero")
        if present is True and count <= 0:
            errors.append("finding_present_count_must_be_positive")
        if not isinstance(finding.get("locations"), list):
            errors.append("finding_locations_must_be_array")
        if not isinstance(finding.get("redacted_summary"), str):
            errors.append("finding_redacted_summary_must_be_string")

    if raw_handling is not None:
        for field in ("raw_output_retained", "raw_stdout_retained", "raw_stderr_retained"):
            if raw_handling.get(field) is True:
                errors.append(f"{field}_must_be_false")
            elif raw_handling.get(field) is not False:
                errors.append(f"{field}_must_be_boolean_false")
        if raw_handling.get("redaction_status") == "failed":
            errors.append("redaction_status_failed")
        if not isinstance(raw_handling.get("redaction_failures"), list):
            errors.append("redaction_failures_must_be_array")

    limitations: tuple[str, ...] = ()
    if trust is not None:
        if trust.get("level") not in TRUST_LEVELS:
            errors.append("trust_level_invalid")
        for field in ("commit_bound", "signature_verified", "binary_attested"):
            if not isinstance(trust.get(field), bool):
                errors.append(f"trust_{field}_must_be_boolean")
        limitations = tuple(_string_items(trust.get("limitations")))
        if not limitations:
            errors.append("limitations_empty")

    if effects is not None:
        if effects.get("can_authorize_execution") is not False:
            errors.append("effects_can_authorize_execution_must_be_false")
        if not isinstance(effects.get("can_lower_risk"), bool):
            errors.append("effects_can_lower_risk_must_be_boolean")
        if effects.get("recommended_gate_effect") not in GATE_EFFECTS:
            errors.append("effects_recommended_gate_effect_invalid")
        no_finding = finding is not None and finding.get("present") is False
        low_trust = trust is not None and trust.get("level") in LOW_TRUST_LEVELS
        if no_finding and effects.get("can_lower_risk") is True:
            errors.append("no_finding_cannot_lower_risk")
        if low_trust and effects.get("can_lower_risk") is True:
            errors.append("low_trust_cannot_lower_risk")

    residual_risks = tuple(_string_items(data.get("residual_risks")))
    if not isinstance(data.get("residual_risks"), list):
        errors.append("residual_risks_must_be_array")

    if _contains_raw_host_path(data):
        errors.append("raw_host_path_pattern_present")

    if finding is not None and finding.get("present") is False:
        warnings.append("no_finding_is_not_safety_proof")
    if subject is not None and subject.get("binding_kind") == "unbound":
        warnings.append("evidence_subject_unbound")
    if raw_handling is not None and raw_handling.get("redaction_status") == "unknown":
        warnings.append("redaction_status_unknown")

    return EvidenceValidationResult(
        valid=not errors,
        blocking_errors=tuple(_dedupe(errors)),
        warnings=tuple(_dedupe(warnings)),
        limitations=limitations,
        residual_risks=residual_risks,
    )


def _mapping(value: Any, fields: set[str], name: str, errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{name}_must_be_object")
        return None
    if set(value) != fields:
        errors.append(f"{name}_required_or_unknown_field")
    return value


def _require_strings(data: Mapping[str, Any], fields: tuple[str, ...], errors: list[str], prefix: str) -> None:
    for field in fields:
        if not _non_empty_string(data.get(field)):
            errors.append(f"{prefix}_{field}_required")


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _fingerprint(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _string_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _contains_raw_host_path(value: Any) -> bool:
    if isinstance(value, str):
        return bool(RAW_HOST_PATH.search(value))
    if isinstance(value, Mapping):
        return any(_contains_raw_host_path(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_raw_host_path(item) for item in value)
    return False


def _dedupe(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
