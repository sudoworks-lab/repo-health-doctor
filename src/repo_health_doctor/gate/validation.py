"""Validate future gate decision candidates.

This module formalizes the candidate data shape only. It does not implement a
gate evaluator and it never authorizes execution.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from .decision import GateDecisionValidationResult


GATE_DECISION_SCHEMA_VERSION = "0.1-draft"
DECISION_KIND = "repo_health_gate_decision"

REQUIRED_TOP_LEVEL_FIELDS = {
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
TOP_LEVEL_FIELDS = REQUIRED_TOP_LEVEL_FIELDS | {"evidence_refs"}
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
EXTERNAL_EVIDENCE_REF_FIELDS = {
    "report_kind",
    "report_fingerprint",
    "generated_at",
    "subject",
    "size_bytes",
    "truncated",
    "validation_status",
    "reasons",
}
SANDBOX_EVIDENCE_REF_FIELDS = {
    "report_kind",
    "report_fingerprint",
    "run_id",
    "gate_decision_fingerprint",
    "validation_status",
    "reasons",
}
EVIDENCE_REF_SUBJECT_FIELDS = {"repo_commit", "dirty_state"}
EVIDENCE_REF_REASONS = {
    "external_evidence_invalid",
    "external_evidence_fingerprint_mismatch",
    "external_evidence_stale",
    "external_evidence_subject_mismatch",
    "external_evidence_over_budget",
    "external_evidence_duplicate",
    "external_evidence_truncated",
}
SANDBOX_EVIDENCE_REF_REASONS = {
    "sandbox_evidence_invalid",
    "sandbox_evidence_fingerprint_mismatch",
    "sandbox_evidence_stale",
    "sandbox_evidence_subject_mismatch",
    "sandbox_evidence_policy_mismatch",
    "sandbox_evidence_over_budget",
    "sandbox_evidence_duplicate",
    "sandbox_evidence_truncated",
}

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

    if not REQUIRED_TOP_LEVEL_FIELDS.issubset(data) or set(data) - TOP_LEVEL_FIELDS:
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

    if "evidence_refs" in data:
        _validate_evidence_refs(data.get("evidence_refs"), errors)

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


def _validate_evidence_refs(value: object, errors: list[str]) -> None:
    if not isinstance(value, list) or not value or len(value) > 16:
        errors.append("evidence_refs_invalid")
        return
    for item in value:
        if not isinstance(item, Mapping):
            errors.append("evidence_ref_must_be_object")
            continue
        if item.get("report_kind") == "sandbox_run":
            evidence_ref = _mapping(
                item,
                SANDBOX_EVIDENCE_REF_FIELDS,
                "evidence_ref",
                errors,
            )
            if evidence_ref is not None:
                _validate_sandbox_evidence_ref(evidence_ref, errors)
            continue
        evidence_ref = _mapping(
            item,
            EXTERNAL_EVIDENCE_REF_FIELDS,
            "evidence_ref",
            errors,
        )
        if evidence_ref is None:
            continue
        if evidence_ref.get("report_kind") not in {"real_scanner_suite", None}:
            errors.append("evidence_ref_report_kind_invalid")
        fingerprint = evidence_ref.get("report_fingerprint")
        if fingerprint is not None and (
            not isinstance(fingerprint, str)
            or not fingerprint.startswith("sha256:")
            or len(fingerprint) != 71
            or any(character not in "0123456789abcdef" for character in fingerprint[7:])
        ):
            errors.append("evidence_ref_fingerprint_invalid")
        generated_at = evidence_ref.get("generated_at")
        if generated_at is not None and not _is_timestamp(generated_at):
            errors.append("evidence_ref_generated_at_invalid")
        ref_subject = evidence_ref.get("subject")
        if not isinstance(ref_subject, Mapping) or set(ref_subject) - EVIDENCE_REF_SUBJECT_FIELDS:
            errors.append("evidence_ref_subject_invalid")
        elif ref_subject:
            repo_commit = ref_subject.get("repo_commit")
            if repo_commit is not None and (
                not isinstance(repo_commit, str)
                or len(repo_commit) not in {40, 64}
                or any(character not in "0123456789abcdef" for character in repo_commit)
            ):
                errors.append("evidence_ref_subject_repo_commit_invalid")
            if ref_subject.get("dirty_state") not in {
                "clean",
                "dirty",
                "unknown",
                "not_applicable",
            }:
                errors.append("evidence_ref_subject_dirty_state_invalid")
        size_bytes = evidence_ref.get("size_bytes")
        if size_bytes is not None and (
            not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or size_bytes < 0
        ):
            errors.append("evidence_ref_size_bytes_invalid")
        if not isinstance(evidence_ref.get("truncated"), bool):
            errors.append("evidence_ref_truncated_invalid")
        if evidence_ref.get("validation_status") not in {"valid", "invalid"}:
            errors.append("evidence_ref_validation_status_invalid")
        reasons = evidence_ref.get("reasons")
        if (
            not isinstance(reasons, list)
            or len(reasons) > len(EVIDENCE_REF_REASONS)
            or any(not isinstance(reason, str) for reason in reasons)
            or len(reasons) != len(set(reasons))
            or any(reason not in EVIDENCE_REF_REASONS for reason in reasons)
        ):
            errors.append("evidence_ref_reasons_invalid")


def _validate_sandbox_evidence_ref(
    evidence_ref: Mapping[str, Any],
    errors: list[str],
) -> None:
    for field in ("report_fingerprint", "gate_decision_fingerprint"):
        fingerprint = evidence_ref.get(field)
        if fingerprint is not None and not _is_fingerprint(fingerprint):
            errors.append(f"evidence_ref_{field}_invalid")
    run_id = evidence_ref.get("run_id")
    if run_id is not None and (
        not isinstance(run_id, str)
        or not run_id
        or len(run_id) > 128
        or any(not (character.isalnum() or character in "._:-") for character in run_id)
    ):
        errors.append("evidence_ref_run_id_invalid")
    if evidence_ref.get("validation_status") not in {"valid", "invalid"}:
        errors.append("evidence_ref_validation_status_invalid")
    reasons = evidence_ref.get("reasons")
    if (
        not isinstance(reasons, list)
        or len(reasons) > len(SANDBOX_EVIDENCE_REF_REASONS)
        or any(not isinstance(reason, str) for reason in reasons)
        or len(reasons) != len(set(reasons))
        or any(reason not in SANDBOX_EVIDENCE_REF_REASONS for reason in reasons)
    ):
        errors.append("evidence_ref_reasons_invalid")


def _is_fingerprint(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


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
