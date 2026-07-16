"""Execution authorization artifact helpers.

Gate decisions never authorize execution. This module validates a separate
human-controlled authorization artifact against an exact gate decision, argv,
scope, policy version, and expiry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping, Sequence


AUTHORIZATION_KIND = "repo_health_execution_authorization"
AUTHORIZATION_SCHEMA_VERSION = "0.1-draft"
TOP_LEVEL_FIELDS = {
    "authorization_kind",
    "schema_version",
    "approved",
    "approved_by",
    "approved_at",
    "expires_at",
    "approved_scope",
    "approved_argv",
    "approved_policy_version",
    "based_on_gate_decision",
    "subject",
    "limitations",
    "residual_risks",
}
BASED_ON_FIELDS = {"decision_kind", "schema_version", "verdict", "fingerprint"}
SUBJECT_FIELDS = {"repo", "commit", "tree_hash"}
DISALLOWED_GATE_VERDICTS = {"block", "quarantine", "unknown"}
AUTHORIZATION_REFUSAL_REASONS = frozenset(
    {
        "authorization_must_be_object",
        "authorization_top_level_required_or_unknown_field",
        "authorization_kind_unsupported",
        "authorization_schema_version_unsupported",
        "approval_missing",
        "approved_must_be_boolean",
        "limitations_empty",
        "residual_risks_empty",
        "approved_scope_mismatch",
        "approved_argv_mismatch",
        "approved_policy_version_mismatch",
        "based_on_gate_decision_required_or_unknown_field",
        "based_on_gate_decision_mismatch",
        "authorization_subject_required_or_unknown_field",
        "authorization_subject_mismatch",
        "expires_at_required",
        "expires_at_invalid",
        "authorization_expired",
        "approved_by_required",
        "approved_at_required",
        "approved_at_invalid",
        "gate_verdict_block_cannot_be_authorized",
        "gate_verdict_quarantine_cannot_be_authorized",
        "gate_verdict_unknown_cannot_be_authorized",
        "gate_verdict_invalid_for_authorization",
        "authorization_contains_forbidden_raw_pattern",
        "authorization_contains_raw_host_path",
    }
)
FORBIDDEN_PATTERNS = (
    "/home/",
    "/Users/",
    "C:\\Users\\",
    ".ssh",
    ".aws",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "AKIA",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "sk-",
    "-----BEGIN",
    "password=",
    "token=",
)
RAW_HOST_PATH = re.compile(r"(?:^|[\s\"'=])(?:/(?:home|Users)/|/mnt/[A-Za-z]/Users/|[A-Za-z]:\\Users\\)")


@dataclass(frozen=True)
class ExecutionAuthorizationValidationResult:
    valid: bool
    approved: bool
    execution_authorized: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    scope_matches: bool
    argv_matches: bool
    policy_matches: bool
    not_expired: bool
    based_on_gate_decision_matches: bool
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "approved": self.approved,
            "execution_authorized": self.execution_authorized,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "scope_matches": self.scope_matches,
            "argv_matches": self.argv_matches,
            "policy_matches": self.policy_matches,
            "not_expired": self.not_expired,
            "based_on_gate_decision_matches": self.based_on_gate_decision_matches,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
        }


def build_execution_authorization_draft(
    gate_decision: Mapping[str, Any],
    argv: Sequence[str],
    *,
    expires_at: str | None = None,
) -> Mapping[str, Any]:
    """Build a non-approved execution authorization draft.

    The draft is intentionally not executable: ``approved`` is false and the
    validator will return ``execution_authorized=false`` until a human-controlled
    approved artifact exactly matches the decision and argv.
    """
    subject = _gate_subject(gate_decision)
    limitations = [
        "draft_only_not_approved",
        "not_execution_authorization_until_human_approved",
        "argv_scope_policy_and_gate_decision_must_match_exactly",
    ]
    if not expires_at:
        limitations.append("expires_at_must_be_set_before_approval")
    return {
        "authorization_kind": AUTHORIZATION_KIND,
        "schema_version": AUTHORIZATION_SCHEMA_VERSION,
        "approved": False,
        "approved_by": None,
        "approved_at": None,
        "expires_at": expires_at,
        "approved_scope": subject,
        "approved_argv": list(argv),
        "approved_policy_version": _policy_version(gate_decision),
        "based_on_gate_decision": _gate_reference(gate_decision),
        "subject": {
            "repo": subject["repo"],
            "commit": subject["commit"],
            "tree_hash": subject["tree_hash"],
        },
        "limitations": limitations,
        "residual_risks": [
            "human approval required before execution",
            "authorization is only valid for the exact reviewed command and scope",
        ],
    }


def validate_execution_authorization(
    authorization: Mapping[str, Any],
    gate_decision: Mapping[str, Any],
    argv: Sequence[str],
    *,
    now: datetime | None = None,
) -> ExecutionAuthorizationValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(authorization, Mapping):
        return _result(
            approved=False,
            errors=("authorization_must_be_object",),
            warnings=(),
            scope_matches=False,
            argv_matches=False,
            policy_matches=False,
            not_expired=False,
            based_on_gate_decision_matches=False,
            limitations=(),
            residual_risks=("invalid_authorization_input",),
        )
    if set(authorization) != TOP_LEVEL_FIELDS:
        errors.append("authorization_top_level_required_or_unknown_field")
    if authorization.get("authorization_kind") != AUTHORIZATION_KIND:
        errors.append("authorization_kind_unsupported")
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA_VERSION:
        errors.append("authorization_schema_version_unsupported")

    approved = authorization.get("approved") is True
    if not approved:
        errors.append("approval_missing")
    if authorization.get("approved") not in {True, False}:
        errors.append("approved_must_be_boolean")

    limitations = tuple(_string_items(authorization.get("limitations")))
    residual_risks = tuple(_string_items(authorization.get("residual_risks")))
    if not limitations:
        errors.append("limitations_empty")
    if not residual_risks:
        errors.append("residual_risks_empty")

    gate_subject = _gate_subject(gate_decision)
    approved_scope = _mapping(authorization.get("approved_scope"))
    scope_matches = approved_scope == gate_subject
    if not scope_matches:
        errors.append("approved_scope_mismatch")

    approved_argv = authorization.get("approved_argv")
    argv_list = list(argv)
    argv_matches = isinstance(approved_argv, list) and approved_argv == argv_list and all(isinstance(item, str) and item for item in approved_argv)
    if not argv_matches:
        errors.append("approved_argv_mismatch")

    policy_matches = authorization.get("approved_policy_version") == _policy_version(gate_decision)
    if not policy_matches:
        errors.append("approved_policy_version_mismatch")

    based_on = _mapping(authorization.get("based_on_gate_decision"))
    if set(based_on) != BASED_ON_FIELDS:
        errors.append("based_on_gate_decision_required_or_unknown_field")
    based_on_gate_decision_matches = based_on == _gate_reference(gate_decision)
    if not based_on_gate_decision_matches:
        errors.append("based_on_gate_decision_mismatch")

    subject = _mapping(authorization.get("subject"))
    if set(subject) != SUBJECT_FIELDS:
        errors.append("authorization_subject_required_or_unknown_field")
    if subject != {key: gate_subject[key] for key in ("repo", "commit", "tree_hash")}:
        errors.append("authorization_subject_mismatch")

    not_expired = _not_expired(authorization.get("expires_at"), now=now, errors=errors)
    _approved_metadata_valid(authorization, errors)

    verdict = gate_decision.get("verdict")
    if verdict in DISALLOWED_GATE_VERDICTS:
        errors.append(f"gate_verdict_{verdict}_cannot_be_authorized")
    elif verdict == "warn":
        warnings.append("warn_verdict_authorization_requires_explicit_human_acceptance")
    elif verdict != "allow_limited":
        errors.append("gate_verdict_invalid_for_authorization")

    if _contains_forbidden_pattern(authorization):
        errors.append("authorization_contains_forbidden_raw_pattern")
    if _contains_raw_host_path(authorization):
        errors.append("authorization_contains_raw_host_path")

    return _result(
        approved=approved,
        errors=tuple(_dedupe(errors)),
        warnings=tuple(_dedupe(warnings)),
        scope_matches=scope_matches,
        argv_matches=argv_matches,
        policy_matches=policy_matches,
        not_expired=not_expired,
        based_on_gate_decision_matches=based_on_gate_decision_matches,
        limitations=limitations,
        residual_risks=residual_risks,
    )


def gate_decision_fingerprint(gate_decision: Mapping[str, Any]) -> str:
    payload = json.dumps(gate_decision, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _result(
    *,
    approved: bool,
    errors: tuple[str, ...],
    warnings: tuple[str, ...],
    scope_matches: bool,
    argv_matches: bool,
    policy_matches: bool,
    not_expired: bool,
    based_on_gate_decision_matches: bool,
    limitations: tuple[str, ...],
    residual_risks: tuple[str, ...],
) -> ExecutionAuthorizationValidationResult:
    valid = not errors
    return ExecutionAuthorizationValidationResult(
        valid=valid,
        approved=approved,
        execution_authorized=valid and approved,
        blocking_errors=errors,
        warnings=warnings,
        scope_matches=scope_matches,
        argv_matches=argv_matches,
        policy_matches=policy_matches,
        not_expired=not_expired,
        based_on_gate_decision_matches=based_on_gate_decision_matches,
        limitations=limitations,
        residual_risks=residual_risks,
    )


def _gate_subject(gate_decision: Mapping[str, Any]) -> Mapping[str, Any]:
    subject = gate_decision.get("subject") if isinstance(gate_decision.get("subject"), Mapping) else {}
    return {
        "repo": str(subject.get("repo", "<repo>")),
        "commit": subject.get("commit") if isinstance(subject.get("commit"), str) else None,
        "tree_hash": subject.get("tree_hash") if isinstance(subject.get("tree_hash"), str) else None,
        "binding_kind": str(subject.get("binding_kind", "unbound")),
    }


def _gate_reference(gate_decision: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "decision_kind": gate_decision.get("decision_kind"),
        "schema_version": gate_decision.get("schema_version"),
        "verdict": gate_decision.get("verdict"),
        "fingerprint": gate_decision_fingerprint(gate_decision),
    }


def _policy_version(gate_decision: Mapping[str, Any]) -> str | None:
    policy = gate_decision.get("policy") if isinstance(gate_decision.get("policy"), Mapping) else {}
    return policy.get("policy_version") if isinstance(policy.get("policy_version"), str) else None


def _not_expired(value: object, *, now: datetime | None, errors: list[str]) -> bool:
    expires_at = value if isinstance(value, str) and value else None
    if expires_at is None:
        errors.append("expires_at_required")
        return False
    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        errors.append("expires_at_invalid")
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if expires <= current:
        errors.append("authorization_expired")
        return False
    return True


def _approved_metadata_valid(authorization: Mapping[str, Any], errors: list[str]) -> None:
    approved_by = authorization.get("approved_by")
    approved_at = authorization.get("approved_at")
    if authorization.get("approved") is True:
        if not isinstance(approved_by, str) or not approved_by:
            errors.append("approved_by_required")
        if not isinstance(approved_at, str) or not approved_at:
            errors.append("approved_at_required")
            return
        try:
            datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
        except ValueError:
            errors.append("approved_at_invalid")


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _contains_forbidden_pattern(value: object) -> bool:
    if isinstance(value, str):
        return any(pattern in value for pattern in FORBIDDEN_PATTERNS)
    if isinstance(value, Mapping):
        return any(_contains_forbidden_pattern(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_pattern(item) for item in value)
    return False


def _contains_raw_host_path(value: object) -> bool:
    if isinstance(value, str):
        return bool(RAW_HOST_PATH.search(value))
    if isinstance(value, Mapping):
        return any(_contains_raw_host_path(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_raw_host_path(item) for item in value)
    return False


def _dedupe(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
