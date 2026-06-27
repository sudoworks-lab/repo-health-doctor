"""Validate future gate decision candidates.

This module formalizes the candidate data shape only. It does not implement a
gate evaluator and it never authorizes execution.
"""

from __future__ import annotations

from typing import Any, Mapping

from .decision import GateDecisionValidationResult


GATE_DECISION_SCHEMA_VERSION = "0.1-draft"
DECISION_KIND = "repo_health_gate_decision"

TOP_LEVEL_FIELDS = {
    "decision_kind",
    "schema_version",
    "subject",
    "verdict",
    "execution_authorized",
    "confidence",
    "confidence_reason",
    "explanation",
    "evidence_summary",
    "required_actions",
    "limitations",
    "policy",
    "residual_risks",
}
SUBJECT_FIELDS = {"repo", "commit", "tree_hash", "binding_kind"}
EXPLANATION_FIELDS = {"summary", "key_reasons", "next_actions"}
EVIDENCE_SUMMARY_FIELDS = {
    "findings_count",
    "blocking_evidence",
    "warning_evidence",
    "missing_evidence",
    "degraded_observers",
}
POLICY_FIELDS = {"policy_version", "fail_closed"}

VERDICTS = {"allow_limited", "warn", "quarantine", "block", "unknown"}
CONFIDENCES = {"low", "medium", "high", "unknown"}
BINDING_KINDS = {"unbound", "path_bound", "commit_bound", "tree_bound", "synthetic"}


def validate_gate_decision(data: Mapping[str, Any]) -> GateDecisionValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(data, Mapping):
        return GateDecisionValidationResult(
            valid=False,
            blocking_errors=("gate_decision_must_be_object",),
            warnings=(),
            limitations=(),
            residual_risks=("invalid_gate_decision_input",),
        )

    if set(data) != TOP_LEVEL_FIELDS:
        errors.append("gate_decision_top_level_required_or_unknown_field")
    if data.get("schema_version") != GATE_DECISION_SCHEMA_VERSION:
        errors.append("gate_decision_schema_version_unsupported")
    if data.get("decision_kind") != DECISION_KIND:
        errors.append("decision_kind_unsupported")
    if data.get("verdict") not in VERDICTS:
        errors.append("verdict_invalid")
    if data.get("execution_authorized") is not False:
        errors.append("execution_authorized_must_be_false")
    if data.get("confidence") not in CONFIDENCES:
        errors.append("confidence_invalid")
    if not isinstance(data.get("confidence_reason"), str) or not data.get("confidence_reason"):
        errors.append("confidence_reason_required")
    explanation = _mapping(data.get("explanation"), EXPLANATION_FIELDS, "explanation", errors)
    if explanation is not None:
        if not isinstance(explanation.get("summary"), str) or not explanation.get("summary"):
            errors.append("explanation_summary_required")
        if not _string_items(explanation.get("key_reasons")):
            errors.append("explanation_key_reasons_required")
        if not _string_items(explanation.get("next_actions")):
            errors.append("explanation_next_actions_required")

    subject = _mapping(data.get("subject"), SUBJECT_FIELDS, "subject", errors)
    if subject is not None:
        if not isinstance(subject.get("repo"), str) or not subject.get("repo"):
            errors.append("subject_repo_required")
        if subject.get("binding_kind") not in BINDING_KINDS:
            errors.append("subject_binding_kind_invalid")

    evidence_summary = _mapping(data.get("evidence_summary"), EVIDENCE_SUMMARY_FIELDS, "evidence_summary", errors)
    if evidence_summary is not None:
        if not isinstance(evidence_summary.get("findings_count"), int) or evidence_summary.get("findings_count") < 0:
            errors.append("evidence_summary_findings_count_invalid")
        for field in ("blocking_evidence", "warning_evidence", "missing_evidence", "degraded_observers"):
            if not isinstance(evidence_summary.get(field), list):
                errors.append(f"evidence_summary_{field}_must_be_array")

    policy = _mapping(data.get("policy"), POLICY_FIELDS, "policy", errors)
    if policy is not None and not isinstance(policy.get("fail_closed"), bool):
        errors.append("policy_fail_closed_must_be_boolean")

    if not isinstance(data.get("required_actions"), list):
        errors.append("required_actions_must_be_array")
    limitations = tuple(_string_items(data.get("limitations")))
    if not limitations:
        errors.append("limitations_empty")
    residual_risks = tuple(_string_items(data.get("residual_risks")))
    if not isinstance(data.get("residual_risks"), list):
        errors.append("residual_risks_must_be_array")

    if data.get("verdict") == "allow_limited" and data.get("execution_authorized") is False:
        warnings.append("allow_limited_is_not_execution_authorization")
    if evidence_summary is not None and evidence_summary.get("missing_evidence"):
        warnings.append("missing_evidence_present")
    if subject is not None and subject.get("binding_kind") == "unbound":
        warnings.append("gate_decision_subject_unbound")

    return GateDecisionValidationResult(
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


def _string_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _dedupe(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
