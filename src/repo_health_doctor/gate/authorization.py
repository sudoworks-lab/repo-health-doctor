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
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from ..sandbox.image_binding import (
    is_digest_pinned_authorization_reference,
    is_full_local_image_id,
)


AUTHORIZATION_KIND = "repo_health_execution_authorization"
LEGACY_AUTHORIZATION_SCHEMA_VERSION = "0.1-draft"
AUTHORIZATION_SCHEMA_VERSION = "0.2-draft"
AUTHORIZATION_SCHEMA_VERSIONS = frozenset(
    {LEGACY_AUTHORIZATION_SCHEMA_VERSION, AUTHORIZATION_SCHEMA_VERSION}
)
BASE_TOP_LEVEL_FIELDS = {
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
APPROVED_IMAGE_FIELDS = {"requested_reference", "resolved_image_id"}
TOP_LEVEL_FIELDS_BY_VERSION = {
    LEGACY_AUTHORIZATION_SCHEMA_VERSION: frozenset(BASE_TOP_LEVEL_FIELDS),
    AUTHORIZATION_SCHEMA_VERSION: frozenset(BASE_TOP_LEVEL_FIELDS | {"approved_image"}),
}
TOP_LEVEL_FIELDS = TOP_LEVEL_FIELDS_BY_VERSION[AUTHORIZATION_SCHEMA_VERSION]
BASED_ON_FIELDS = {"decision_kind", "schema_version", "verdict", "fingerprint"}
SUBJECT_FIELDS = {"repo", "commit", "tree_hash"}
DISALLOWED_GATE_VERDICTS = {"block", "quarantine", "unknown"}
AUTHORIZATION_WORKTREE_BINDING_MISMATCH_REASON = "authorization_worktree_binding_mismatch"
AUTHORIZATION_WORKTREE_BINDING_UNRESOLVED_REASON = "authorization_worktree_binding_unresolved"
AUTHORIZATION_WORKTREE_NOT_GIT_REASON = "authorization_worktree_not_git"
AUTHORIZATION_WORKTREE_DIRTY_REASON = "authorization_worktree_dirty"
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
        "authorization_approved_image_invalid",
        "approved_image_reference_mismatch",
        "approved_image_digest_unpinned",
        "runtime_image_id_unresolved",
        "approved_image_id_mismatch",
        AUTHORIZATION_WORKTREE_BINDING_MISMATCH_REASON,
        AUTHORIZATION_WORKTREE_BINDING_UNRESOLVED_REASON,
        AUTHORIZATION_WORKTREE_NOT_GIT_REASON,
        AUTHORIZATION_WORKTREE_DIRTY_REASON,
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
AUTHORIZATION_RESERVATION_SUFFIX = ".reserved"
AUTHORIZATION_RESERVATION_KIND = "single_use_execution_authorization_reservation"
AUTHORIZATION_RESERVATION_EXISTS_REASON = "authorization_single_use_reservation_exists"
AUTHORIZATION_RESERVATION_WRITE_FAILURE_REASON = "authorization_single_use_reservation_write_failed"
WORKTREE_BINDING_MATCHED = "matched"
WORKTREE_BINDING_MISMATCH = "mismatch"
WORKTREE_BINDING_UNRESOLVED = "unresolved"
WORKTREE_BINDING_DIRTY = "dirty"


@dataclass(frozen=True)
class ExecutionAuthorizationWorktreeBinding:
    status: str
    repo_matches: bool
    commit_matches: bool
    tree_matches: bool
    dirty_state: str
    refusal_reasons: tuple[str, ...]

    @property
    def matched(self) -> bool:
        return self.status == WORKTREE_BINDING_MATCHED

    def to_dict(self) -> dict[str, object]:
        return {
            "checked": True,
            "status": self.status,
            "matched": self.matched,
            "repo_matches": self.repo_matches,
            "commit_matches": self.commit_matches,
            "tree_matches": self.tree_matches,
            "dirty_state": self.dirty_state,
            "refusal_reasons": list(self.refusal_reasons),
            "observed_values_recorded": False,
        }


def validate_execution_authorization_worktree_binding(
    authorization: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> ExecutionAuthorizationWorktreeBinding:
    """Compare direct Git observations with the approved authorization subject."""
    subject = authorization.get("subject")
    scope = authorization.get("approved_scope")
    if not isinstance(subject, Mapping) or not isinstance(scope, Mapping):
        return ExecutionAuthorizationWorktreeBinding(
            status=WORKTREE_BINDING_UNRESOLVED,
            repo_matches=False,
            commit_matches=False,
            tree_matches=False,
            dirty_state="unknown",
            refusal_reasons=(AUTHORIZATION_WORKTREE_BINDING_UNRESOLVED_REASON,),
        )
    if scope.get("binding_kind") not in {"commit_bound", "tree_bound"}:
        return ExecutionAuthorizationWorktreeBinding(
            status=WORKTREE_BINDING_UNRESOLVED,
            repo_matches=False,
            commit_matches=False,
            tree_matches=False,
            dirty_state="unknown",
            refusal_reasons=(AUTHORIZATION_WORKTREE_BINDING_UNRESOLVED_REASON,),
        )

    repo_root_matches_target = observed.get("repo_root_matches_target") is True
    observed_repo = observed.get("repo_identity")
    expected_repo = subject.get("repo")
    if expected_repo == "<repo>":
        repo_matches = repo_root_matches_target
    else:
        repo_matches = (
            isinstance(expected_repo, str)
            and isinstance(observed_repo, str)
            and expected_repo == observed_repo
            and repo_root_matches_target
        )

    observed_commit = observed.get("commit")
    expected_commit = subject.get("commit")
    commit_matches = (
        isinstance(expected_commit, str)
        and isinstance(observed_commit, str)
        and expected_commit == observed_commit
    )
    observed_tree = observed.get("tree_hash")
    tree_matches = _tree_hash_matches(subject.get("tree_hash"), observed_tree)
    dirty_state = observed.get("dirty_state")
    if dirty_state not in {"clean", "dirty", "unknown"}:
        dirty_state = "unknown"

    reasons: list[str] = []
    if observed.get("git_available") is not True:
        reasons.extend(
            (
                AUTHORIZATION_WORKTREE_NOT_GIT_REASON,
                AUTHORIZATION_WORKTREE_BINDING_UNRESOLVED_REASON,
            )
        )
        status = WORKTREE_BINDING_UNRESOLVED
    elif observed_commit is None or observed_tree is None:
        reasons.append(AUTHORIZATION_WORKTREE_BINDING_UNRESOLVED_REASON)
        status = WORKTREE_BINDING_UNRESOLVED
    elif dirty_state == "unknown":
        reasons.append(AUTHORIZATION_WORKTREE_BINDING_UNRESOLVED_REASON)
        status = WORKTREE_BINDING_UNRESOLVED
    elif dirty_state == "dirty":
        reasons.append(AUTHORIZATION_WORKTREE_DIRTY_REASON)
        status = WORKTREE_BINDING_DIRTY
    elif not (repo_matches and commit_matches and tree_matches):
        reasons.append(AUTHORIZATION_WORKTREE_BINDING_MISMATCH_REASON)
        status = WORKTREE_BINDING_MISMATCH
    else:
        status = WORKTREE_BINDING_MATCHED

    return ExecutionAuthorizationWorktreeBinding(
        status=status,
        repo_matches=repo_matches,
        commit_matches=commit_matches,
        tree_matches=tree_matches,
        dirty_state=dirty_state,
        refusal_reasons=tuple(dict.fromkeys(reasons)),
    )


def _tree_hash_matches(expected: object, observed: object) -> bool:
    if not isinstance(expected, str) or not isinstance(observed, str):
        return False
    return expected == observed or expected == f"sha256:{observed}"


@dataclass(frozen=True)
class ExecutionAuthorizationReservation:
    reserved: bool
    reservation_path: Path
    refusal_reason: str | None = None

    @property
    def consumed(self) -> bool:
        return self.reserved or self.refusal_reason in {
            AUTHORIZATION_RESERVATION_EXISTS_REASON,
            AUTHORIZATION_RESERVATION_WRITE_FAILURE_REASON,
        }

    def to_dict(self) -> dict[str, object]:
        if self.reserved:
            status = "reserved"
        elif self.refusal_reason == AUTHORIZATION_RESERVATION_EXISTS_REASON:
            status = "already_reserved"
        elif self.refusal_reason == AUTHORIZATION_RESERVATION_WRITE_FAILURE_REASON:
            status = "write_failed"
        else:
            status = "rejected"
        return {
            "status": status,
            "consumed": self.consumed,
            "marker_path_redacted": "<authorization-reservation>",
            "refusal_reason": self.refusal_reason,
        }


def authorization_reservation_path(authorization_path: Path) -> Path:
    """Return the persistent local marker path for one authorization artifact."""
    return authorization_path.with_name(
        authorization_path.name + AUTHORIZATION_RESERVATION_SUFFIX
    )


def reserve_execution_authorization(
    authorization_path: Path,
) -> ExecutionAuthorizationReservation:
    """Atomically consume an approved authorization immediately before execution.

    The marker is intentionally persistent. A partial marker or a failed marker
    write is still a fail-closed reservation and must not be removed to permit
    reuse.
    """
    reservation_path = authorization_reservation_path(authorization_path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    payload = (
        json.dumps(
            {
                "reservation_kind": AUTHORIZATION_RESERVATION_KIND,
                "schema_version": AUTHORIZATION_SCHEMA_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    file_descriptor: int | None = None
    try:
        file_descriptor = os.open(reservation_path, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError("reservation marker write made no progress")
            view = view[written:]
        os.fsync(file_descriptor)
    except FileExistsError:
        return ExecutionAuthorizationReservation(
            reserved=False,
            reservation_path=reservation_path,
            refusal_reason=AUTHORIZATION_RESERVATION_EXISTS_REASON,
        )
    except OSError:
        return ExecutionAuthorizationReservation(
            reserved=False,
            reservation_path=reservation_path,
            refusal_reason=AUTHORIZATION_RESERVATION_WRITE_FAILURE_REASON,
        )
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
    return ExecutionAuthorizationReservation(
        reserved=True,
        reservation_path=reservation_path,
    )


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
    image_binding_present: bool
    image_reference_matches: bool
    image_id_matches: bool
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
            "image_binding_present": self.image_binding_present,
            "image_reference_matches": self.image_reference_matches,
            "image_id_matches": self.image_id_matches,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
        }


def build_execution_authorization_draft(
    gate_decision: Mapping[str, Any],
    argv: Sequence[str],
    *,
    expires_at: str | None = None,
    approved_image: Mapping[str, Any] | None = None,
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
    if approved_image is None:
        limitations.append("authorization_not_image_bound")
    draft: dict[str, Any] = {
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
    if approved_image is not None:
        draft["approved_image"] = dict(approved_image)
    return draft


def validate_execution_authorization(
    authorization: Mapping[str, Any],
    gate_decision: Mapping[str, Any],
    argv: Sequence[str],
    *,
    now: datetime | None = None,
    runtime_image_reference: str | None = None,
    runtime_image_id: str | None = None,
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
            image_binding_present=False,
            image_reference_matches=False,
            image_id_matches=False,
            limitations=(),
            residual_risks=("invalid_authorization_input",),
        )
    schema_version = authorization.get("schema_version")
    allowed_fields = TOP_LEVEL_FIELDS_BY_VERSION.get(
        schema_version, frozenset(BASE_TOP_LEVEL_FIELDS)
    )
    if not BASE_TOP_LEVEL_FIELDS.issubset(authorization) or set(authorization) - allowed_fields:
        errors.append("authorization_top_level_required_or_unknown_field")
    if authorization.get("authorization_kind") != AUTHORIZATION_KIND:
        errors.append("authorization_kind_unsupported")
    if schema_version not in AUTHORIZATION_SCHEMA_VERSIONS:
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

    image_binding_present = "approved_image" in authorization
    image_reference_matches = False
    image_id_matches = False
    if image_binding_present and schema_version == AUTHORIZATION_SCHEMA_VERSION:
        image_reference_matches, image_id_matches = _validate_image_binding(
            authorization.get("approved_image"),
            runtime_image_reference=runtime_image_reference,
            runtime_image_id=runtime_image_id,
            errors=errors,
        )
    elif not image_binding_present:
        if "authorization_not_image_bound" not in limitations:
            limitations = tuple((*limitations, "authorization_not_image_bound"))

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
        image_binding_present=image_binding_present,
        image_reference_matches=image_reference_matches,
        image_id_matches=image_id_matches,
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
    image_binding_present: bool,
    image_reference_matches: bool,
    image_id_matches: bool,
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
        image_binding_present=image_binding_present,
        image_reference_matches=image_reference_matches,
        image_id_matches=image_id_matches,
        limitations=limitations,
        residual_risks=residual_risks,
    )


def _validate_image_binding(
    approved_image: object,
    *,
    runtime_image_reference: str | None,
    runtime_image_id: str | None,
    errors: list[str],
) -> tuple[bool, bool]:
    if not isinstance(approved_image, Mapping) or set(approved_image) != APPROVED_IMAGE_FIELDS:
        errors.append("authorization_approved_image_invalid")
        return False, False

    requested_reference = approved_image.get("requested_reference")
    resolved_image_id = approved_image.get("resolved_image_id")
    if not is_digest_pinned_authorization_reference(requested_reference):
        errors.append("approved_image_digest_unpinned")
    reference_matches = (
        isinstance(requested_reference, str)
        and runtime_image_reference == requested_reference
    )
    if not reference_matches:
        errors.append("approved_image_reference_mismatch")

    if runtime_image_id is None or not is_full_local_image_id(runtime_image_id):
        errors.append("runtime_image_id_unresolved")
        image_id_matches = False
    else:
        image_id_matches = runtime_image_id == resolved_image_id
        if not image_id_matches:
            errors.append("approved_image_id_mismatch")
    if not is_full_local_image_id(resolved_image_id):
        errors.append("approved_image_id_mismatch")
        image_id_matches = False
    return reference_matches, image_id_matches


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
