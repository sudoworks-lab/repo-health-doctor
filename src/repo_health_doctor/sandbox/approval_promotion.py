from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping

from .workspace import GENERIC_SECRET_PATTERNS


COMMAND_APPROVAL_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_COMMAND_APPROVAL = "sandbox_unknown_repo_command_approval"
REPORT_KIND_COMMAND_APPROVAL_VALIDATION = "sandbox_unknown_repo_command_approval_validation"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40,64}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ARTIFACT_FIELDS = {"schema_version", "report_kind", "approval_id", "approved", "approval_status", "approval_scope", "repo_scope", "source_approval_draft", "source_profile_report", "source_risk_tier", "command", "image_lock_binding", "behavior_policy_binding", "candidate_key", "exact_match_key", "lifecycle", "human_review_requirements", "revocation", "t3_exception", "limitations", "residual_risks"}
_SCOPE_FIELDS = {"scope", "phase", "kind"}
_REPO_FIELDS = {"repository_identity", "commit", "path", "working_tree_status"}
_DRAFT_FIELDS = {"schema_version", "report_kind", "candidate_key", "exact_match_key"}
_PROFILE_FIELDS = {"schema_version", "report_kind", "repository_identity"}
_COMMAND_FIELDS = {"phase", "kind", "cwd", "argv", "env_allowlist", "shell", "network_policy"}
_IMAGE_FIELDS = {"schema_version", "report_kind", "lock_id", "registry_digest", "expected_image_id", "platform", "tool_versions", "pull_policy"}
_POLICY_FIELDS = {"schema_version", "report_kind", "policy_id", "binding_fingerprint"}
_LIFECYCLE_FIELDS = {"created_at", "expires_at", "created_by", "reviewed_by", "reviewed_at", "review_rationale", "review_evidence_handle"}
_REVOCATION_FIELDS = {"state", "invalidation_conditions"}
_T3_FIELDS = {"exception_rationale", "exception_scope", "phase1_required", "phase1_5_required", "subprocess_allowlist", "stronger_isolation_required", "expiry", "reviewers", "network_none_required", "shell_false_required", "disallowed_if_direct_url_or_vcs_or_credential_or_obfuscation"}


def _mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} schema mismatch or unknown field")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError(f"{label} timestamp is invalid")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _safe_label(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _safe_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512 or "\n" in value:
        raise ValueError(f"{label} is invalid")
    if any(pattern.search(value) for pattern in GENERIC_SECRET_PATTERNS) or re.search(r"(?:^|\s)/(?:home|Users)/", value):
        raise ValueError(f"{label} contains an unsafe value")
    return value


def _safe_list(value: Any, label: str, *, nonempty: bool = True, pattern: re.Pattern[str] = _LABEL) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value) or not all(isinstance(item, str) and pattern.fullmatch(item) for item in value):
        raise ValueError(f"{label} is invalid")
    return value


def validate_unknown_repo_command_approval(artifact: Mapping[str, Any], *, now: datetime | None = None) -> None:
    """Statically validate a human-authored approval artifact; never authorize execution."""
    rendered = json.dumps(artifact, ensure_ascii=False, sort_keys=True)
    if any(pattern.search(rendered) for pattern in GENERIC_SECRET_PATTERNS) or re.search(r"(?:^|[\s\"])/(?:home|Users)/", rendered):
        raise ValueError("approval artifact contains an unsafe value")
    _mapping(artifact, _ARTIFACT_FIELDS, "command approval")
    if artifact.get("schema_version") != COMMAND_APPROVAL_SCHEMA_VERSION:
        raise ValueError("approval schema_version is unsupported")
    if artifact.get("report_kind") != REPORT_KIND_COMMAND_APPROVAL:
        raise ValueError("approval report_kind is unsupported")
    if artifact.get("approved") is not True or artifact.get("approval_status") != "approved_human_reviewed":
        raise ValueError("approval artifact must be explicitly human approved")
    _safe_label(artifact.get("approval_id"), "approval_id")

    scope = _mapping(artifact.get("approval_scope"), _SCOPE_FIELDS, "approval_scope")
    command = _mapping(artifact.get("command"), _COMMAND_FIELDS, "command")
    if scope.get("scope") != "single_command" or scope.get("phase") not in {"phase2_install_probe", "phase3_runtime_probe"} or scope.get("phase") != command.get("phase"):
        raise ValueError("approval scope phase is invalid")
    if scope.get("kind") != command.get("kind") or not _safe_label(command.get("kind"), "command kind"):
        raise ValueError("approval scope kind is invalid")
    if not isinstance(command.get("cwd"), str) or not (command["cwd"] == "/workspace" or command["cwd"].startswith("/workspace/")):
        raise ValueError("command cwd is invalid")
    if not isinstance(command.get("argv"), list) or not command["argv"] or not all(isinstance(item, str) and item and not item.startswith("/") for item in command["argv"]):
        raise ValueError("command argv is invalid")
    if not isinstance(command.get("env_allowlist"), list) or not all(isinstance(item, str) and _ENV.fullmatch(item) for item in command["env_allowlist"]):
        raise ValueError("command env_allowlist is invalid")
    if command.get("shell") is not False or command.get("network_policy") != "none":
        raise ValueError("command attempts to relax shell or network boundary")

    repo = _mapping(artifact.get("repo_scope"), _REPO_FIELDS, "repo_scope")
    if not _SHA256.fullmatch(str(repo.get("repository_identity"))) or not _COMMIT.fullmatch(str(repo.get("commit"))) or repo.get("path") != "<repo>" or repo.get("working_tree_status") != "clean_verified":
        raise ValueError("repo scope is invalid or dirty")
    draft = _mapping(artifact.get("source_approval_draft"), _DRAFT_FIELDS, "source approval draft")
    profile = _mapping(artifact.get("source_profile_report"), _PROFILE_FIELDS, "source profile report")
    if draft.get("schema_version") != "0.1-draft" or draft.get("report_kind") != "sandbox_approval_draft" or profile.get("schema_version") != "0.1-draft" or profile.get("report_kind") != "sandbox_unknown_repo_profile" or profile.get("repository_identity") != repo["repository_identity"]:
        raise ValueError("source report binding is invalid")
    tier = artifact.get("source_risk_tier")
    if tier not in {"T1", "T2", "T3"}:
        raise ValueError("source risk tier is not promotable")
    for field in ("candidate_key", "exact_match_key"):
        if not _SHA256.fullmatch(str(artifact.get(field))) or artifact[field] != draft.get(field):
            raise ValueError("candidate key binding is invalid")
    if artifact["candidate_key"] != artifact["exact_match_key"]:
        raise ValueError("exact match key is invalid")

    image = _mapping(artifact.get("image_lock_binding"), _IMAGE_FIELDS, "image lock binding")
    if image.get("schema_version") != "0.1-draft" or image.get("report_kind") != "sandbox_image_lock" or image.get("pull_policy") != "never":
        raise ValueError("image lock binding is invalid")
    _safe_label(image.get("lock_id"), "image lock id")
    digest, image_id = image.get("registry_digest"), image.get("expected_image_id")
    if (digest is None) == (image_id is None) or (digest is not None and not _SHA256.fullmatch(str(digest))) or (image_id is not None and not _SHA256.fullmatch(str(image_id))):
        raise ValueError("image identity binding is invalid")
    platform = _mapping(image.get("platform"), {"os", "architecture"}, "image platform")
    if platform.get("os") != "linux" or platform.get("architecture") not in {"amd64", "arm64"}:
        raise ValueError("image platform is invalid")
    tools = image.get("tool_versions")
    if not isinstance(tools, Mapping) or not tools or not all(isinstance(value, str) and _LABEL.fullmatch(value) for value in tools.values()):
        raise ValueError("image tool versions are invalid")

    policy = _mapping(artifact.get("behavior_policy_binding"), _POLICY_FIELDS, "behavior policy binding")
    if policy.get("schema_version") != "0.1-draft" or policy.get("report_kind") != "sandbox_command_behavior_policy" or not _safe_label(policy.get("policy_id"), "behavior policy id") or not _SHA256.fullmatch(str(policy.get("binding_fingerprint"))):
        raise ValueError("behavior policy binding is invalid")

    lifecycle = _mapping(artifact.get("lifecycle"), _LIFECYCLE_FIELDS, "approval lifecycle")
    created, expires, reviewed = (_timestamp(lifecycle.get("created_at"), "created_at"), _timestamp(lifecycle.get("expires_at"), "expires_at"), _timestamp(lifecycle.get("reviewed_at"), "reviewed_at"))
    if reviewed < created or expires <= reviewed or expires <= (now or datetime.now(timezone.utc)):
        raise ValueError("approval lifecycle is expired or invalid")
    for field in ("created_by", "reviewed_by", "review_evidence_handle"):
        _safe_label(lifecycle.get(field), field)
    _safe_text(lifecycle.get("review_rationale"), "review_rationale")
    _safe_list(artifact.get("human_review_requirements"), "human_review_requirements")
    revocation = _mapping(artifact.get("revocation"), _REVOCATION_FIELDS, "revocation")
    if revocation.get("state") != "active":
        raise ValueError("approval is revoked or inactive")
    _safe_list(revocation.get("invalidation_conditions"), "invalidation_conditions")

    t3_exception = artifact.get("t3_exception")
    if tier == "T3":
        exception = _mapping(t3_exception, _T3_FIELDS, "t3_exception")
        for field in ("exception_scope",):
            _safe_label(exception.get(field), field)
        _safe_text(exception.get("exception_rationale"), "exception_rationale")
        if exception.get("phase1_required") is not True or exception.get("phase1_5_required") is not True or exception.get("stronger_isolation_required") is not True or exception.get("network_none_required") is not True or exception.get("shell_false_required") is not True or exception.get("disallowed_if_direct_url_or_vcs_or_credential_or_obfuscation") is not True:
            raise ValueError("t3 exception safety metadata is invalid")
        if _timestamp(exception.get("expiry"), "t3 exception expiry") != expires:
            raise ValueError("t3 exception expiry does not match approval")
        _safe_list(exception.get("subprocess_allowlist"), "t3 subprocess_allowlist", nonempty=False)
        reviewers = _safe_list(exception.get("reviewers"), "t3 reviewers")
        if lifecycle["reviewed_by"] not in reviewers:
            raise ValueError("t3 reviewers do not include reviewed_by")
    elif t3_exception is not None:
        raise ValueError("t3 exception is not valid for this tier")
    _safe_list(artifact.get("limitations"), "limitations")
    _safe_list(artifact.get("residual_risks"), "residual_risks")


def validate_unknown_repo_command_approval_report(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Return only a static validation result; it never creates or uses an approval."""
    try:
        validate_unknown_repo_command_approval(artifact)
    except ValueError:
        return {
            "schema_version": COMMAND_APPROVAL_SCHEMA_VERSION,
            "report_kind": REPORT_KIND_COMMAND_APPROVAL_VALIDATION,
            "approval_schema_version": "unvalidated",
            "verdict": "block",
            "valid": False,
            "blockers": ["invalid_or_unsupported_command_approval"],
            "warnings": [],
            "binding_summary": {},
            "limitations": ["Static validation failed closed; no approval was created, promoted, or used."],
            "residual_risks": ["unknown_or_unsupported_approval_input"],
            "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        }
    return {
        "schema_version": COMMAND_APPROVAL_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_COMMAND_APPROVAL_VALIDATION,
        "approval_schema_version": artifact["schema_version"],
        "verdict": "pass",
        "valid": True,
        "blockers": [],
        "warnings": ["static_approval_validation_is_not_runner_authorization"],
        "binding_summary": {
            "phase": artifact["command"]["phase"],
            "risk_tier": artifact["source_risk_tier"],
            "image_identity_kind": "registry_digest" if artifact["image_lock_binding"]["registry_digest"] is not None else "local_full_image_id",
            "behavior_policy_bound": True,
            "working_tree_clean_verified": True,
        },
        "limitations": ["This report validates a supplied artifact only; it does not create, promote, or authorize an approval."],
        "residual_risks": ["runner_and_live_gates_remain_unimplemented"],
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }
