"""Bounded validation for caller-supplied sandbox-run evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import re
from typing import Any, Collection, Mapping

from ..evidence.sandbox_run import (
    DECISION_BINDING_MISMATCH,
    DECISION_INVALID,
    DECISION_OVER_BUDGET,
    DECISION_STALE,
    DECISION_TRUNCATED,
    normalize_sandbox_run_evidence,
    sandbox_run_report_fingerprint,
)


SANDBOX_EVIDENCE_MAX_BYTES = 256 * 1024
SANDBOX_EVIDENCE_MAX_TOTAL_BYTES = 1024 * 1024
SANDBOX_EVIDENCE_MAX_COUNT = 16
SANDBOX_EVIDENCE_MAX_AGE_SECONDS = 24 * 60 * 60
SANDBOX_EVIDENCE_MAX_FUTURE_SKEW_SECONDS = 5 * 60

SANDBOX_EVIDENCE_INVALID = "sandbox_evidence_invalid"
SANDBOX_EVIDENCE_FINGERPRINT_MISMATCH = "sandbox_evidence_fingerprint_mismatch"
SANDBOX_EVIDENCE_STALE = "sandbox_evidence_stale"
SANDBOX_EVIDENCE_SUBJECT_MISMATCH = "sandbox_evidence_subject_mismatch"
SANDBOX_EVIDENCE_POLICY_MISMATCH = "sandbox_evidence_policy_mismatch"
SANDBOX_EVIDENCE_OVER_BUDGET = "sandbox_evidence_over_budget"
SANDBOX_EVIDENCE_DUPLICATE = "sandbox_evidence_duplicate"
SANDBOX_EVIDENCE_TRUNCATED = "sandbox_evidence_truncated"

_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SANDBOX_REQUIRED_FIELDS = {
    "schema_version",
    "report_kind",
    "kind",
    "tool",
    "version",
    "experimental",
    "contract",
    "run",
    "target",
    "approval",
    "gate",
    "authorization",
    "sandbox_profile",
    "seccomp",
    "command",
    "docker",
    "disposable_workspace",
    "workspace_diff",
    "result",
    "policy_blocked",
    "command_started",
    "command_exit_code",
    "sandbox_exit_code",
    "block_reason",
    "output_summary",
    "env_policy",
    "cleanup_policy",
    "boundary_statement",
    "limitations",
    "next_actions",
    "safety_statement",
}
_SANDBOX_ALLOWED_FIELDS = _SANDBOX_REQUIRED_FIELDS | {"report_fingerprint"}
_SANDBOX_OBJECT_FIELDS = {
    "contract",
    "run",
    "target",
    "approval",
    "gate",
    "authorization",
    "sandbox_profile",
    "seccomp",
    "command",
    "docker",
    "disposable_workspace",
    "workspace_diff",
    "result",
    "output_summary",
    "env_policy",
    "cleanup_policy",
    "boundary_statement",
}


@dataclass(frozen=True)
class SandboxRunEvidenceValidationResult:
    """Validated normalized evidence plus a bounded gate reference."""

    valid: bool
    status: str
    reasons: tuple[str, ...]
    validation_errors: tuple[str, ...]
    normalized_evidence: Mapping[str, object]
    evidence_ref: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "status": self.status,
            "reasons": list(self.reasons),
            "validation_errors": list(self.validation_errors),
            "normalized_evidence": dict(self.normalized_evidence),
            "evidence_ref": dict(self.evidence_ref),
        }


def validate_sandbox_run_evidence(
    data: object,
    *,
    expected_subject: Mapping[str, object] | None = None,
    expected_policy_version: str | None = None,
    now: datetime | None = None,
    max_age_seconds: int = SANDBOX_EVIDENCE_MAX_AGE_SECONDS,
    max_bytes: int = SANDBOX_EVIDENCE_MAX_BYTES,
    source_size_bytes: int | None = None,
    total_over_budget: bool = False,
    seen_fingerprints: Collection[str] = (),
) -> SandboxRunEvidenceValidationResult:
    """Validate one source report without retaining it in the gate reference."""

    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be greater than 0")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be greater than 0")
    if source_size_bytes is not None and (
        not isinstance(source_size_bytes, int)
        or isinstance(source_size_bytes, bool)
        or source_size_bytes < 0
    ):
        raise ValueError("source_size_bytes must be a non-negative integer")

    source = data if isinstance(data, Mapping) else None
    normalized = normalize_sandbox_run_evidence(data)
    validation_errors: list[str] = []
    reasons: list[str] = []

    computed_fingerprint: str | None = None
    if source is not None:
        _validate_source_shape(source, validation_errors)
        try:
            computed_fingerprint = sandbox_run_report_fingerprint(source)
        except (TypeError, ValueError):
            validation_errors.append("report_not_json_serializable")
    else:
        validation_errors.append("schema_input_must_be_object")

    claimed_fingerprint = source.get("report_fingerprint") if source is not None else None
    fingerprint_mismatch = False
    if claimed_fingerprint is not None:
        if not isinstance(claimed_fingerprint, str) or not _FINGERPRINT.fullmatch(claimed_fingerprint):
            validation_errors.append("report_fingerprint_invalid")
        elif computed_fingerprint is not None:
            fingerprint_mismatch = not hmac.compare_digest(claimed_fingerprint, computed_fingerprint)

    decision_signals = _string_list(normalized.get("decision_signals"))
    if DECISION_INVALID in decision_signals:
        validation_errors.append("sandbox_report_shape_invalid")

    run_id = normalized.get("run_id")
    if not isinstance(run_id, str) or not _SAFE_RUN_ID.fullmatch(run_id):
        validation_errors.append("run_id_invalid")
        run_id = None

    gate = normalized.get("gate")
    gate_fingerprint = gate.get("decision_fingerprint") if isinstance(gate, Mapping) else None
    if not isinstance(gate_fingerprint, str) or not _FINGERPRINT.fullmatch(gate_fingerprint):
        validation_errors.append("gate_decision_fingerprint_invalid")
        gate_fingerprint = None

    generated_at = _parse_timestamp(normalized.get("generated_at"))
    stale = False
    if generated_at is None:
        validation_errors.append("generated_at_invalid")
    else:
        current = now or datetime.now(timezone.utc)
        current = current.replace(tzinfo=timezone.utc) if current.tzinfo is None else current.astimezone(timezone.utc)
        age_seconds = (current - generated_at).total_seconds()
        stale = age_seconds > max_age_seconds
        if age_seconds < -SANDBOX_EVIDENCE_MAX_FUTURE_SKEW_SECONDS:
            validation_errors.append("generated_at_in_future")

    subject = normalized.get("subject")
    subject_mismatch = expected_subject is not None and (
        not isinstance(subject, Mapping) or not _mapping_matches(subject, expected_subject)
    )
    policy = normalized.get("policy")
    policy_version = policy.get("version") if isinstance(policy, Mapping) else None
    policy_mismatch = expected_policy_version is not None and policy_version != expected_policy_version
    over_budget = total_over_budget or (
        source_size_bytes is not None and source_size_bytes > max_bytes
    )
    duplicate = computed_fingerprint is not None and computed_fingerprint in seen_fingerprints
    truncated = DECISION_TRUNCATED in decision_signals

    if validation_errors or fingerprint_mismatch:
        reasons.append(SANDBOX_EVIDENCE_INVALID)
    if fingerprint_mismatch:
        reasons.append(SANDBOX_EVIDENCE_FINGERPRINT_MISMATCH)
    if stale:
        reasons.append(SANDBOX_EVIDENCE_STALE)
    if subject_mismatch:
        reasons.append(SANDBOX_EVIDENCE_SUBJECT_MISMATCH)
    if policy_mismatch:
        reasons.append(SANDBOX_EVIDENCE_POLICY_MISMATCH)
    if over_budget:
        reasons.append(SANDBOX_EVIDENCE_OVER_BUDGET)
    if duplicate:
        reasons.append(SANDBOX_EVIDENCE_DUPLICATE)
    if truncated:
        reasons.append(SANDBOX_EVIDENCE_TRUNCATED)

    reasons = _dedupe(reasons)
    validation_errors = _dedupe(validation_errors)
    normalized_with_validation = dict(normalized)
    validated_signals = list(decision_signals)
    if SANDBOX_EVIDENCE_INVALID in reasons or SANDBOX_EVIDENCE_DUPLICATE in reasons or SANDBOX_EVIDENCE_POLICY_MISMATCH in reasons:
        validated_signals.append(DECISION_INVALID)
    if SANDBOX_EVIDENCE_STALE in reasons:
        validated_signals.append(DECISION_STALE)
    if SANDBOX_EVIDENCE_SUBJECT_MISMATCH in reasons:
        validated_signals.append(DECISION_BINDING_MISMATCH)
    if SANDBOX_EVIDENCE_OVER_BUDGET in reasons:
        validated_signals.append(DECISION_OVER_BUDGET)
    if SANDBOX_EVIDENCE_TRUNCATED in reasons:
        validated_signals.append(DECISION_TRUNCATED)
    normalized_with_validation["decision_signals"] = _dedupe(validated_signals)

    valid = not reasons
    evidence_ref = {
        "report_kind": "sandbox_run",
        "report_fingerprint": computed_fingerprint,
        "run_id": run_id,
        "gate_decision_fingerprint": gate_fingerprint,
        "validation_status": "valid" if valid else "invalid",
        "reasons": list(reasons),
    }
    return SandboxRunEvidenceValidationResult(
        valid=valid,
        status="valid" if valid else "invalid",
        reasons=tuple(reasons),
        validation_errors=tuple(validation_errors),
        normalized_evidence=normalized_with_validation,
        evidence_ref=evidence_ref,
    )


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _validate_source_shape(source: Mapping[str, Any], errors: list[str]) -> None:
    if not _SANDBOX_REQUIRED_FIELDS.issubset(source) or set(source) - _SANDBOX_ALLOWED_FIELDS:
        errors.append("schema_top_level_required_or_unknown_field")
    if source.get("schema_version") != "0.1-draft":
        errors.append("schema_version_unsupported")
    if source.get("report_kind") != "sandbox_run" or source.get("kind") != "sandbox_run":
        errors.append("report_kind_unsupported")
    if source.get("tool") != "repo-health-doctor":
        errors.append("tool_invalid")
    if not isinstance(source.get("experimental"), bool):
        errors.append("experimental_must_be_boolean")
    for field in _SANDBOX_OBJECT_FIELDS:
        if not isinstance(source.get(field), Mapping):
            errors.append(f"{field}_must_be_object")
    for field in ("policy_blocked", "command_started"):
        if not isinstance(source.get(field), bool):
            errors.append(f"{field}_must_be_boolean")
    command_exit_code = source.get("command_exit_code")
    if command_exit_code is not None and (
        not isinstance(command_exit_code, int) or isinstance(command_exit_code, bool)
    ):
        errors.append("command_exit_code_invalid")
    block_reason = source.get("block_reason")
    if block_reason is not None and not isinstance(block_reason, str):
        errors.append("block_reason_invalid")
    if not isinstance(source.get("sandbox_exit_code"), int) or isinstance(
        source.get("sandbox_exit_code"), bool
    ):
        errors.append("sandbox_exit_code_invalid")
    for field in ("limitations", "next_actions"):
        value = source.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            errors.append(f"{field}_invalid")
    if not isinstance(source.get("safety_statement"), str):
        errors.append("safety_statement_invalid")
    output_summary = source.get("output_summary")
    if isinstance(output_summary, Mapping) and output_summary.get("raw_stdout_stderr_persisted") is not False:
        errors.append("raw_stdout_stderr_persisted_must_be_false")


def _mapping_matches(actual: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    return all(actual.get(field) == expected.get(field) for field in ("repo", "commit", "tree_hash", "binding_kind"))


def _string_list(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
