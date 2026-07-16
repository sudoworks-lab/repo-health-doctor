"""Bounded validation for imported real scanner suite evidence.

This module validates caller-supplied JSON-compatible mappings only.  It does
not read files, run scanners, change a gate verdict, or authorize execution.
Validation results expose a bounded reference and never retain the raw report.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Collection, Mapping

from ..external_scanner.real_scanner_suite import REAL_SCANNER_MAX_REPORT_BYTES


EXTERNAL_SUITE_EVIDENCE_MAX_BYTES = REAL_SCANNER_MAX_REPORT_BYTES
EXTERNAL_SUITE_EVIDENCE_MAX_AGE_SECONDS = 24 * 60 * 60
EXTERNAL_SUITE_EVIDENCE_MAX_FUTURE_SKEW_SECONDS = 5 * 60

EXTERNAL_EVIDENCE_INVALID = "external_evidence_invalid"
EXTERNAL_EVIDENCE_FINGERPRINT_MISMATCH = "external_evidence_fingerprint_mismatch"
EXTERNAL_EVIDENCE_STALE = "external_evidence_stale"
EXTERNAL_EVIDENCE_SUBJECT_MISMATCH = "external_evidence_subject_mismatch"
EXTERNAL_EVIDENCE_OVER_BUDGET = "external_evidence_over_budget"
EXTERNAL_EVIDENCE_DUPLICATE = "external_evidence_duplicate"
EXTERNAL_EVIDENCE_TRUNCATED = "external_evidence_truncated"

_SUITE_SCHEMA_VERSION = "0.1-draft"
_SUITE_REPORT_KIND = "real_scanner_suite"
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "report_kind",
    "suite_status",
    "entries",
    "limitations",
    "execution_authorized",
    "report_fingerprint",
    "generated_at",
    "subject",
}
_ENTRY_FIELDS = {
    "scanner_name",
    "executed",
    "valid",
    "status",
    "blocking_errors",
    "warnings",
    "risk_summary",
    "normalized_result",
    "finding_count",
    "omitted_finding_count",
    "truncated",
}
_RISK_SUMMARY_FIELDS = {
    "outcome",
    "highest_risk_tier_effect",
    "risk_tier_effect",
    "gate_effects",
    "risk_lowering_allowed",
}
_SUBJECT_FIELDS = {"repo_commit", "dirty_state"}
_ENTRY_STATUSES = {"completed", "unknown", "skipped_offline"}
_DIRTY_STATES = {"clean", "dirty", "unknown", "not_applicable"}
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


@dataclass(frozen=True)
class ExternalSuiteEvidenceValidationResult:
    """Machine-readable result that deliberately omits the raw suite report."""

    valid: bool
    status: str
    reasons: tuple[str, ...]
    validation_errors: tuple[str, ...]
    evidence_ref: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "status": self.status,
            "reasons": list(self.reasons),
            "validation_errors": list(self.validation_errors),
            "evidence_ref": dict(self.evidence_ref),
        }


def external_suite_report_fingerprint(report: Mapping[str, Any]) -> str:
    """Return the canonical fingerprint used by real scanner suite reports."""

    payload = dict(report)
    payload.pop("report_fingerprint", None)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_external_suite_evidence(
    data: object,
    *,
    expected_subject: Mapping[str, object] | None = None,
    now: datetime | None = None,
    max_age_seconds: int = EXTERNAL_SUITE_EVIDENCE_MAX_AGE_SECONDS,
    max_bytes: int = EXTERNAL_SUITE_EVIDENCE_MAX_BYTES,
    source_size_bytes: int | None = None,
    seen_fingerprints: Collection[str] = (),
) -> ExternalSuiteEvidenceValidationResult:
    """Validate one suite report without retaining it in the result.

    ``source_size_bytes`` should be the byte size measured before JSON parsing
    when a caller loads a file.  The compact JSON size is used by pure-mapping
    callers that omit it.  Duplicate detection is scoped to fingerprints the
    caller has already accepted or encountered in the current bounded batch.
    """

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

    validation_errors: list[str] = []
    report = data if isinstance(data, Mapping) else None
    if report is None:
        validation_errors.append("schema_input_must_be_object")
    else:
        _validate_schema_shape(report, validation_errors)

    encoded_size: int | None = source_size_bytes
    if encoded_size is None:
        try:
            encoded_size = len(
                json.dumps(
                    data,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            )
        except (TypeError, ValueError):
            validation_errors.append("schema_input_must_be_json_serializable")

    claimed_fingerprint = report.get("report_fingerprint") if report is not None else None
    fingerprint_mismatch = False
    if (
        report is not None
        and isinstance(claimed_fingerprint, str)
        and _SHA256.fullmatch(claimed_fingerprint)
    ):
        try:
            computed_fingerprint = external_suite_report_fingerprint(report)
        except (TypeError, ValueError):
            computed_fingerprint = None
        if computed_fingerprint is not None:
            fingerprint_mismatch = not hmac.compare_digest(claimed_fingerprint, computed_fingerprint)

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)
    generated_at = _parse_generated_at(report.get("generated_at") if report is not None else None)
    stale = False
    if generated_at is not None:
        age_seconds = (current - generated_at).total_seconds()
        stale = age_seconds > max_age_seconds
        if age_seconds < -EXTERNAL_SUITE_EVIDENCE_MAX_FUTURE_SKEW_SECONDS:
            validation_errors.append("generated_at_in_future")

    subject = report.get("subject") if report is not None else None
    subject_mismatch = expected_subject is not None and (
        not isinstance(subject, Mapping) or not _subject_matches(subject, expected_subject)
    )
    over_budget = encoded_size is not None and encoded_size > max_bytes
    duplicate = (
        isinstance(claimed_fingerprint, str)
        and _SHA256.fullmatch(claimed_fingerprint) is not None
        and claimed_fingerprint in seen_fingerprints
    )
    truncated = _is_truncated(report)

    reasons: list[str] = []
    if validation_errors or fingerprint_mismatch:
        reasons.append(EXTERNAL_EVIDENCE_INVALID)
    if fingerprint_mismatch:
        reasons.append(EXTERNAL_EVIDENCE_FINGERPRINT_MISMATCH)
    if stale:
        reasons.append(EXTERNAL_EVIDENCE_STALE)
    if subject_mismatch:
        reasons.append(EXTERNAL_EVIDENCE_SUBJECT_MISMATCH)
    if over_budget:
        reasons.append(EXTERNAL_EVIDENCE_OVER_BUDGET)
    if duplicate:
        reasons.append(EXTERNAL_EVIDENCE_DUPLICATE)
    if truncated:
        reasons.append(EXTERNAL_EVIDENCE_TRUNCATED)

    reasons = _dedupe(reasons)
    validation_errors = _dedupe(validation_errors)
    valid = not reasons
    evidence_ref = _evidence_ref(
        report,
        claimed_fingerprint=claimed_fingerprint,
        generated_at=generated_at,
        encoded_size=encoded_size,
        truncated=truncated,
        status="valid" if valid else "invalid",
        reasons=reasons,
    )
    return ExternalSuiteEvidenceValidationResult(
        valid=valid,
        status="valid" if valid else "invalid",
        reasons=tuple(reasons),
        validation_errors=tuple(validation_errors),
        evidence_ref=evidence_ref,
    )


def _validate_schema_shape(data: Mapping[str, Any], errors: list[str]) -> None:
    if set(data) != _TOP_LEVEL_FIELDS:
        errors.append("schema_top_level_required_or_unknown_field")
    if data.get("schema_version") != _SUITE_SCHEMA_VERSION:
        errors.append("schema_version_unsupported")
    if data.get("report_kind") != _SUITE_REPORT_KIND:
        errors.append("report_kind_unsupported")
    if data.get("suite_status") not in {"completed", "degraded"}:
        errors.append("suite_status_invalid")
    if data.get("execution_authorized") is not False:
        errors.append("execution_authorized_must_be_false")
    if not isinstance(data.get("report_fingerprint"), str) or not _SHA256.fullmatch(
        data["report_fingerprint"]
    ):
        errors.append("report_fingerprint_invalid")
    if _parse_generated_at(data.get("generated_at")) is None:
        errors.append("generated_at_invalid")

    limitations = data.get("limitations")
    if not _nonempty_string_list(limitations):
        errors.append("limitations_invalid")

    subject = data.get("subject")
    if not isinstance(subject, Mapping):
        errors.append("subject_must_be_object")
    else:
        if set(subject) != _SUBJECT_FIELDS:
            errors.append("subject_required_or_unknown_field")
        repo_commit = subject.get("repo_commit")
        if repo_commit is not None and (
            not isinstance(repo_commit, str) or not _GIT_COMMIT.fullmatch(repo_commit)
        ):
            errors.append("subject_repo_commit_invalid")
        if subject.get("dirty_state") not in _DIRTY_STATES:
            errors.append("subject_dirty_state_invalid")

    entries = data.get("entries")
    if not isinstance(entries, list):
        errors.append("entries_must_be_array")
        return
    for entry in entries:
        _validate_entry(entry, errors)


def _validate_entry(value: object, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("entry_must_be_object")
        return
    if set(value) != _ENTRY_FIELDS:
        errors.append("entry_required_or_unknown_field")
    if not _nonempty_string(value.get("scanner_name")):
        errors.append("entry_scanner_name_invalid")
    for field in ("executed", "valid", "truncated"):
        if not isinstance(value.get(field), bool):
            errors.append(f"entry_{field}_must_be_boolean")
    if value.get("status") not in _ENTRY_STATUSES:
        errors.append("entry_status_invalid")
    for field in ("blocking_errors", "warnings"):
        if not _string_list(value.get(field)):
            errors.append(f"entry_{field}_invalid")
    for field in ("finding_count", "omitted_finding_count"):
        item = value.get(field)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            errors.append(f"entry_{field}_invalid")
    if not isinstance(value.get("normalized_result"), Mapping):
        errors.append("entry_normalized_result_must_be_object")

    risk_summary = value.get("risk_summary")
    if not isinstance(risk_summary, Mapping):
        errors.append("entry_risk_summary_must_be_object")
    else:
        if set(risk_summary) != _RISK_SUMMARY_FIELDS:
            errors.append("entry_risk_summary_required_or_unknown_field")
        for field in ("outcome", "highest_risk_tier_effect", "risk_tier_effect"):
            if not isinstance(risk_summary.get(field), str):
                errors.append(f"entry_risk_summary_{field}_invalid")
        if not _string_list(risk_summary.get("gate_effects")):
            errors.append("entry_risk_summary_gate_effects_invalid")
        if risk_summary.get("risk_lowering_allowed") is not False:
            errors.append("entry_risk_lowering_allowed_must_be_false")

    omitted = value.get("omitted_finding_count")
    if (
        isinstance(omitted, int)
        and not isinstance(omitted, bool)
        and omitted > 0
        and value.get("truncated") is not True
    ):
        errors.append("entry_truncation_inconsistent")


def _parse_generated_at(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _subject_matches(actual: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    return all(actual.get(field) == expected.get(field) for field in _SUBJECT_FIELDS if field in expected)


def _is_truncated(data: Mapping[str, Any] | None) -> bool:
    if data is None:
        return False
    limitations = data.get("limitations")
    if isinstance(limitations, list) and any(
        item in {"report_truncated", "report_byte_budget_exceeded"}
        for item in limitations
    ):
        return True
    entries = data.get("entries")
    if not isinstance(entries, list):
        return False
    return any(
        isinstance(entry, Mapping)
        and (
            entry.get("truncated") is True
            or (
                isinstance(entry.get("omitted_finding_count"), int)
                and not isinstance(entry.get("omitted_finding_count"), bool)
                and entry["omitted_finding_count"] > 0
            )
        )
        for entry in entries
    )


def _evidence_ref(
    report: Mapping[str, Any] | None,
    *,
    claimed_fingerprint: object,
    generated_at: datetime | None,
    encoded_size: int | None,
    truncated: bool,
    status: str,
    reasons: list[str],
) -> Mapping[str, object]:
    subject = report.get("subject") if report is not None else None
    bounded_subject: Mapping[str, object] = {}
    if isinstance(subject, Mapping):
        repo_commit = subject.get("repo_commit")
        dirty_state = subject.get("dirty_state")
        if (
            repo_commit is None
            or isinstance(repo_commit, str) and _GIT_COMMIT.fullmatch(repo_commit)
        ) and dirty_state in _DIRTY_STATES:
            bounded_subject = {"repo_commit": repo_commit, "dirty_state": dirty_state}
    return {
        "report_kind": _SUITE_REPORT_KIND
        if report is not None and report.get("report_kind") == _SUITE_REPORT_KIND
        else None,
        "report_fingerprint": claimed_fingerprint
        if isinstance(claimed_fingerprint, str) and _SHA256.fullmatch(claimed_fingerprint)
        else None,
        "generated_at": generated_at.isoformat() if generated_at is not None else None,
        "subject": dict(bounded_subject),
        "size_bytes": encoded_size,
        "truncated": truncated,
        "validation_status": status,
        "reasons": list(reasons),
    }


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _nonempty_string_list(value: object) -> bool:
    return _string_list(value) and bool(value) and all(value)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
