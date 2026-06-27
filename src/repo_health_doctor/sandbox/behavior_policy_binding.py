"""Static binding verifier for approvals, behavior policies, and observer evidence.

The verifier consumes supplied in-memory mappings only.  It does not create
approvals, connect a runner, contact Docker, capture observer data, or execute
commands.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from .approval_promotion import (
    COMMAND_APPROVAL_SCHEMA_VERSION,
    REPORT_KIND_COMMAND_APPROVAL,
    validate_unknown_repo_command_approval,
)
from .behavior_policy import (
    BEHAVIOR_POLICY_SCHEMA_VERSION,
    REPORT_KIND_BEHAVIOR_POLICY,
    behavior_policy_binding_fingerprint,
    evaluate_behavior_policy,
    validate_behavior_policy,
)
from .lock_binding import (
    LOCK_BINDING_SCHEMA_VERSION,
    REPORT_KIND_IMAGE_LOCK_BINDING_VALIDATION,
)
from .observer_evidence import (
    NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION,
    REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE,
    validate_normalized_observer_evidence,
)
from .workspace import GENERIC_SECRET_PATTERNS


BEHAVIOR_POLICY_BINDING_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_BEHAVIOR_POLICY_BINDING_VALIDATION = "sandbox_behavior_policy_binding_validation"

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOME_PATH = re.compile(r"(?:^|[\s\"'])/(?:home|Users)/")
_CANDIDATE_MATERIAL_FIELDS = {
    "candidate_key",
    "exact_match_key",
    "phase",
    "kind",
    "cwd",
    "argv_fingerprint",
    "shell",
    "network_policy",
    "behavior_policy_schema_version",
    "behavior_policy_report_kind",
    "behavior_policy_id",
    "behavior_policy_binding_fingerprint",
    "normalized_observer_evidence_schema_version",
    "normalized_observer_evidence_report_kind",
    "evidence_id",
}


def _contains_unsafe_value(value: Any) -> bool:
    try:
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return True
    return bool(_HOME_PATH.search(rendered)) or any(pattern.search(rendered) for pattern in GENERIC_SECRET_PATTERNS)


def _exact_mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} schema mismatch or unknown field")
    return value


def _argv_fingerprint(argv: Any) -> str:
    if not isinstance(argv, list):
        raise ValueError("policy argv is invalid")
    raw = json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _validate_optional_image_lock_result(result: Mapping[str, Any] | None) -> None:
    if result is None:
        return
    required = {
        "schema_version",
        "report_kind",
        "verdict",
        "binding_status",
        "approval_reference",
        "image_lock_reference",
        "behavior_policy_reference",
        "checked_fields",
        "mismatches",
        "blockers",
        "warnings",
        "limitations",
        "residual_risks",
        "redaction_status",
        "execution_permitted",
        "runner_connected",
        "docker_contacted",
    }
    report = _exact_mapping(result, required, "image lock binding validation result")
    if (
        report["schema_version"] != LOCK_BINDING_SCHEMA_VERSION
        or report["report_kind"] != REPORT_KIND_IMAGE_LOCK_BINDING_VALIDATION
        or report["verdict"] != "pass"
        or report["execution_permitted"] is not False
        or report["runner_connected"] is not False
        or report["docker_contacted"] is not False
    ):
        raise ValueError("image lock binding validation result is not an eligible static pass")


def _validate_candidate_material(
    material: Mapping[str, Any],
    approval: Mapping[str, Any],
    policy: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> None:
    document = _exact_mapping(material, _CANDIDATE_MATERIAL_FIELDS, "candidate key material")
    command = approval["command"]
    expected = {
        "candidate_key": approval["candidate_key"],
        "exact_match_key": approval["exact_match_key"],
        "phase": command["phase"],
        "kind": command["kind"],
        "cwd": command["cwd"],
        "argv_fingerprint": _argv_fingerprint(command["argv"]),
        "shell": False,
        "network_policy": "none",
        "behavior_policy_schema_version": policy["schema_version"],
        "behavior_policy_report_kind": policy["report_kind"],
        "behavior_policy_id": policy["policy_id"],
        "behavior_policy_binding_fingerprint": behavior_policy_binding_fingerprint(policy),
        "normalized_observer_evidence_schema_version": evidence["schema_version"],
        "normalized_observer_evidence_report_kind": evidence["report_kind"],
        "evidence_id": evidence["evidence_id"],
    }
    if document != expected:
        raise ValueError("candidate key material does not exactly bind supplied inputs")
    if not _SHA256.fullmatch(str(document["candidate_key"])) or document["candidate_key"] != document["exact_match_key"]:
        raise ValueError("candidate key material is invalid")


def _validate_observer_requirements(policy: Mapping[str, Any], evidence: Mapping[str, Any]) -> None:
    requirements = policy["observer_requirements"]
    source = evidence["source"]
    counts = evidence["counts"]
    flags = evidence["flags"]
    if flags["evidence_complete"] is not True:
        raise ValueError("observer evidence is incomplete")
    if source["observer_degraded"] is not False:
        raise ValueError("observer evidence is degraded")
    if not source["strace_available"] or not source["strace_log_present"] or not source["strace_parse_success"]:
        raise ValueError("required strace evidence is unavailable, missing, or unparsed")
    if counts["strace_parse_error_count"] or counts["runtime_hook_parse_error_count"]:
        raise ValueError("observer evidence contains parse errors")
    if requirements["runtime_hook_required"] and (
        not source["runtime_hook_available"]
        or not source["runtime_hook_active"]
        or not source["runtime_hook_parse_success"]
    ):
        raise ValueError("required runtime hook evidence is unavailable, inactive, or unparsed")
    if requirements["evidence_required"] and flags["evidence_complete"] is not True:
        raise ValueError("policy requires complete observer evidence")


def validate_sandbox_behavior_policy_binding(
    approval: Mapping[str, Any],
    behavior_policy: Mapping[str, Any],
    normalized_observer_evidence: Mapping[str, Any],
    candidate_key_material: Mapping[str, Any],
    *,
    image_lock_binding_validation_result: Mapping[str, Any] | None = None,
) -> None:
    """Fail closed unless static approval, policy, and evidence bind exactly.

    A validation report alone cannot replace its source artifact because it
    omits command and fingerprint material required for exact comparison.
    """
    inputs = (approval, behavior_policy, normalized_observer_evidence, candidate_key_material)
    if any(_contains_unsafe_value(item) for item in inputs):
        raise ValueError("unsafe value in behavior policy binding input")
    if image_lock_binding_validation_result is not None and _contains_unsafe_value(image_lock_binding_validation_result):
        raise ValueError("unsafe value in image lock binding validation result")
    validate_unknown_repo_command_approval(approval)
    validate_behavior_policy(behavior_policy)
    validate_normalized_observer_evidence(normalized_observer_evidence)
    _validate_optional_image_lock_result(image_lock_binding_validation_result)

    if approval["schema_version"] != COMMAND_APPROVAL_SCHEMA_VERSION or approval["report_kind"] != REPORT_KIND_COMMAND_APPROVAL:
        raise ValueError("approval schema or report kind mismatch")
    if behavior_policy["schema_version"] != BEHAVIOR_POLICY_SCHEMA_VERSION or behavior_policy["report_kind"] != REPORT_KIND_BEHAVIOR_POLICY:
        raise ValueError("behavior policy schema or report kind mismatch")
    if (
        normalized_observer_evidence["schema_version"] != NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION
        or normalized_observer_evidence["report_kind"] != REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE
    ):
        raise ValueError("normalized observer evidence schema or report kind mismatch")

    approval_policy = approval["behavior_policy_binding"]
    if (
        approval_policy["schema_version"] != behavior_policy["schema_version"]
        or approval_policy["report_kind"] != behavior_policy["report_kind"]
        or approval_policy["policy_id"] != behavior_policy["policy_id"]
        or approval_policy["binding_fingerprint"] != behavior_policy_binding_fingerprint(behavior_policy)
    ):
        raise ValueError("approval behavior policy binding mismatch")

    approval_command = approval["command"]
    policy_binding = behavior_policy["binding"]
    evidence_command = normalized_observer_evidence["command"]
    if approval["candidate_key"] != policy_binding["candidate_key"]:
        raise ValueError("approval and behavior policy candidate key mismatch")
    if any(approval_command[field] != policy_binding[field] for field in ("phase", "kind", "cwd", "argv", "env_allowlist", "shell")):
        raise ValueError("approval and behavior policy command binding mismatch")
    if approval_command["network_policy"] != policy_binding["network_policy"]:
        raise ValueError("approval and behavior policy network policy mismatch")
    if _argv_fingerprint(approval_command["argv"]) != evidence_command["argv_fingerprint"]:
        raise ValueError("approval and observer evidence argv fingerprint mismatch")
    if any(approval_command[field] != evidence_command[field] for field in ("phase", "kind", "cwd", "shell", "network_policy")):
        raise ValueError("approval and observer evidence command binding mismatch")
    if approval_command["shell"] is not False or evidence_command["shell"] is not False:
        raise ValueError("shell is not permitted")
    if approval_command["network_policy"] != "none" or evidence_command["network_policy"] != "none":
        raise ValueError("network is not permitted")

    _validate_observer_requirements(behavior_policy, normalized_observer_evidence)
    _validate_candidate_material(candidate_key_material, approval, behavior_policy, normalized_observer_evidence)
    if evaluate_behavior_policy(behavior_policy, normalized_observer_evidence)["verdict"] != "pass":
        raise ValueError("behavior policy verdict is not pass for normalized evidence")


def _invalid_report() -> dict[str, Any]:
    return {
        "schema_version": BEHAVIOR_POLICY_BINDING_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_BEHAVIOR_POLICY_BINDING_VALIDATION,
        "verdict": "block",
        "binding_status": "invalid_or_mismatch",
        "approval_reference": {},
        "behavior_policy_reference": {},
        "observer_evidence_reference": {},
        "checked_fields": [],
        "mismatches": ["static_binding_validation_failed"],
        "blockers": ["invalid_or_mismatched_behavior_policy_binding"],
        "warnings": [],
        "limitations": ["Static binding validation failed closed; no approval was created or used, and no runner, Docker, or observer capture was contacted."],
        "residual_risks": ["unknown_or_unsupported_static_binding_input"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "observer_capture_performed": False,
    }


def validate_sandbox_behavior_policy_binding_report(
    approval: Mapping[str, Any],
    behavior_policy: Mapping[str, Any],
    normalized_observer_evidence: Mapping[str, Any],
    candidate_key_material: Mapping[str, Any],
    *,
    image_lock_binding_validation_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a redacted static-binding report; it never authorizes execution."""
    try:
        validate_sandbox_behavior_policy_binding(
            approval,
            behavior_policy,
            normalized_observer_evidence,
            candidate_key_material,
            image_lock_binding_validation_result=image_lock_binding_validation_result,
        )
    except (KeyError, TypeError, ValueError):
        return _invalid_report()
    return {
        "schema_version": BEHAVIOR_POLICY_BINDING_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_BEHAVIOR_POLICY_BINDING_VALIDATION,
        "verdict": "pass",
        "binding_status": "matched",
        "approval_reference": {"schema_version": approval["schema_version"], "report_kind": approval["report_kind"], "approval_id": approval["approval_id"], "risk_tier": approval["source_risk_tier"]},
        "behavior_policy_reference": {"schema_version": behavior_policy["schema_version"], "report_kind": behavior_policy["report_kind"], "policy_id": behavior_policy["policy_id"]},
        "observer_evidence_reference": {"schema_version": normalized_observer_evidence["schema_version"], "report_kind": normalized_observer_evidence["report_kind"], "evidence_id": normalized_observer_evidence["evidence_id"]},
        "checked_fields": ["approval_artifact", "behavior_policy_binding", "normalized_observer_evidence", "phase_kind_cwd_argv_fingerprint_shell_network", "observer_requirements", "candidate_key_material", "behavior_policy_verdict"],
        "mismatches": [],
        "blockers": [],
        "warnings": ["static_binding_validation_is_not_runner_authorization"],
        "limitations": ["This verifier compares supplied static artifacts only; it does not connect a runner, contact Docker, execute a command, or capture strace or runtime-hook evidence."],
        "residual_risks": ["runner_and_live_execution_gates_remain_unimplemented", "static_binding_match_is_not_execution_authorization"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "observer_capture_performed": False,
    }
