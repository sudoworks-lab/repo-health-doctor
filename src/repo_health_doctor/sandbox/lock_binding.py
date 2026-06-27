"""Static approval, image-lock, and behavior-policy binding verification."""

from __future__ import annotations

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
    validate_behavior_policy,
)
from .image_lock import (
    IMAGE_LOCK_SCHEMA_VERSION,
    REPORT_KIND_IMAGE_LOCK,
    validate_sandbox_image_lock,
)
from .workspace import GENERIC_SECRET_PATTERNS


LOCK_BINDING_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_IMAGE_LOCK_BINDING_VALIDATION = "sandbox_image_lock_binding_validation"

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOME_PATH = re.compile(r"(?:^|[\s\"])/(?:home|Users)/")
_CANDIDATE_MATERIAL_FIELDS = {
    "candidate_key",
    "exact_match_key",
    "repository_identity",
    "commit",
    "source_risk_tier",
    "phase",
    "kind",
    "cwd",
    "argv",
    "env_allowlist",
    "shell",
    "network_policy",
    "image_lock_schema_version",
    "image_lock_report_kind",
    "image_lock_id",
    "registry_digest",
    "expected_image_id",
    "pull_policy",
    "host_home",
    "docker_socket",
    "platform",
    "tool_versions",
    "behavior_policy_schema_version",
    "behavior_policy_report_kind",
    "behavior_policy_id",
    "behavior_policy_binding_fingerprint",
}


def _contains_unsafe_value(value: Any) -> bool:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return any(pattern.search(rendered) for pattern in GENERIC_SECRET_PATTERNS) or bool(_HOME_PATH.search(rendered))


def _exact_mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} schema mismatch or unknown field")
    return value


def _canonical_json(value: Any, label: str) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not JSON-compatible") from exc


def _matching_image(lock: Mapping[str, Any], approval: Mapping[str, Any]) -> Mapping[str, Any]:
    binding = approval["image_lock_binding"]
    expected_digest = binding["registry_digest"]
    expected_image_id = binding["expected_image_id"]
    matches = [
        image
        for image in lock["images"]
        if image["registry_digest"] == expected_digest and image["expected_image_id"] == expected_image_id
    ]
    if len(matches) != 1:
        raise ValueError("image identity binding is missing or ambiguous")
    return matches[0]


def _validate_candidate_material(
    material: Mapping[str, Any],
    approval: Mapping[str, Any],
    image: Mapping[str, Any],
    lock: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    material = _exact_mapping(material, _CANDIDATE_MATERIAL_FIELDS, "candidate key material")
    command = approval["command"]
    repo = approval["repo_scope"]
    image_binding = approval["image_lock_binding"]
    policy_binding = approval["behavior_policy_binding"]
    runtime = lock["required_runtime_flags"]
    expected = {
        "candidate_key": approval["candidate_key"],
        "exact_match_key": approval["exact_match_key"],
        "repository_identity": repo["repository_identity"],
        "commit": repo["commit"],
        "source_risk_tier": approval["source_risk_tier"],
        "phase": command["phase"],
        "kind": command["kind"],
        "cwd": command["cwd"],
        "argv": command["argv"],
        "env_allowlist": command["env_allowlist"],
        "shell": command["shell"],
        "network_policy": command["network_policy"],
        "image_lock_schema_version": lock["schema_version"],
        "image_lock_report_kind": lock["report_kind"],
        "image_lock_id": lock["lock_id"],
        "registry_digest": image["registry_digest"],
        "expected_image_id": image["expected_image_id"],
        "pull_policy": runtime["pull_policy"],
        "host_home": runtime["host_home"],
        "docker_socket": runtime["docker_socket"],
        "platform": image["expected_platform"],
        "tool_versions": image["tool_versions"],
        "behavior_policy_schema_version": policy["schema_version"],
        "behavior_policy_report_kind": policy["report_kind"],
        "behavior_policy_id": policy["policy_id"],
        "behavior_policy_binding_fingerprint": behavior_policy_binding_fingerprint(policy),
    }
    if _canonical_json(material, "candidate key material") != _canonical_json(expected, "expected candidate key material"):
        raise ValueError("candidate key material does not exactly bind supplied inputs")
    if image_binding["schema_version"] != material["image_lock_schema_version"] or image_binding["report_kind"] != material["image_lock_report_kind"] or image_binding["lock_id"] != material["image_lock_id"]:
        raise ValueError("approval image lock material mismatch")
    if policy_binding["schema_version"] != material["behavior_policy_schema_version"] or policy_binding["report_kind"] != material["behavior_policy_report_kind"] or policy_binding["policy_id"] != material["behavior_policy_id"] or policy_binding["binding_fingerprint"] != material["behavior_policy_binding_fingerprint"]:
        raise ValueError("approval behavior policy material mismatch")


def validate_sandbox_image_lock_binding(
    approval: Mapping[str, Any],
    image_lock: Mapping[str, Any],
    behavior_policy: Mapping[str, Any],
    candidate_key_material: Mapping[str, Any],
) -> None:
    """Fail closed unless supplied static artifacts describe one exact command.

    This function deliberately receives in-memory data only.  It does not
    write approvals, contact Docker, access a network, or invoke a runner.
    """
    if any(_contains_unsafe_value(item) for item in (approval, image_lock, behavior_policy, candidate_key_material)):
        raise ValueError("unsafe value in static binding input")
    validate_unknown_repo_command_approval(approval)
    validate_sandbox_image_lock(image_lock)
    validate_behavior_policy(behavior_policy)

    if approval["schema_version"] != COMMAND_APPROVAL_SCHEMA_VERSION or approval["report_kind"] != REPORT_KIND_COMMAND_APPROVAL:
        raise ValueError("approval schema or report kind mismatch")
    if image_lock["schema_version"] != IMAGE_LOCK_SCHEMA_VERSION or image_lock["report_kind"] != REPORT_KIND_IMAGE_LOCK:
        raise ValueError("image lock schema or report kind mismatch")
    if behavior_policy["schema_version"] != BEHAVIOR_POLICY_SCHEMA_VERSION or behavior_policy["report_kind"] != REPORT_KIND_BEHAVIOR_POLICY:
        raise ValueError("behavior policy schema or report kind mismatch")

    image_binding = approval["image_lock_binding"]
    if image_binding["lock_id"] != image_lock["lock_id"]:
        raise ValueError("image lock id mismatch")
    image = _matching_image(image_lock, approval)
    if image_binding["platform"] != image["expected_platform"] or image_binding["tool_versions"] != image["tool_versions"]:
        raise ValueError("image platform or tool version mismatch")
    runtime = image_lock["required_runtime_flags"]
    if runtime != {"pull_policy": "never", "network": "none", "shell": False, "host_home": False, "docker_socket": False}:
        raise ValueError("unsafe runtime expectation")
    if approval["command"]["shell"] is not False or approval["command"]["network_policy"] != "none" or image_binding["pull_policy"] != "never":
        raise ValueError("approval command runtime expectation mismatch")

    if image["distribution"] == "registry_primary":
        if image["registry_digest"] is None or image["expected_image_id"] is not None:
            raise ValueError("registry image is not digest pinned")
    elif image["distribution"] == "local_dev_only":
        if image["local_sanctioned_allowed"] is not True or not _SHA256.fullmatch(str(image["expected_image_id"])) or not image["local_sanctioned_limitations"] or "dev" not in image["purpose"]:
            raise ValueError("local image is not an explicit development-only sanctioned image")
    else:
        raise ValueError("unknown image distribution")

    policy_binding = approval["behavior_policy_binding"]
    if policy_binding["schema_version"] != behavior_policy["schema_version"] or policy_binding["report_kind"] != behavior_policy["report_kind"] or policy_binding["policy_id"] != behavior_policy["policy_id"] or policy_binding["binding_fingerprint"] != behavior_policy_binding_fingerprint(behavior_policy):
        raise ValueError("behavior policy binding mismatch")
    binding = behavior_policy["binding"]
    command = approval["command"]
    repo = approval["repo_scope"]
    if binding["candidate_key"] != approval["candidate_key"] or binding["repo_identity"] != repo["repository_identity"] or binding["commit"] != repo["commit"] or any(binding[field] != command[field] for field in ("phase", "kind", "cwd", "argv", "env_allowlist", "shell")) or binding["network_policy"] != command["network_policy"] or binding["image_policy_schema_version"] != image_lock["schema_version"]:
        raise ValueError("behavior policy command binding mismatch")
    expected_behavior = behavior_policy["expected_behavior"]
    if expected_behavior["network"]["allowed"] is not False:
        raise ValueError("behavior policy permits network")

    _validate_candidate_material(candidate_key_material, approval, image, image_lock, behavior_policy)


def _invalid_report() -> dict[str, Any]:
    return {
        "schema_version": LOCK_BINDING_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_IMAGE_LOCK_BINDING_VALIDATION,
        "verdict": "block",
        "binding_status": "invalid_or_mismatch",
        "approval_reference": {},
        "image_lock_reference": {},
        "behavior_policy_reference": {},
        "checked_fields": [],
        "mismatches": ["static_binding_validation_failed"],
        "blockers": ["invalid_or_mismatched_static_binding"],
        "warnings": [],
        "limitations": ["Static binding validation failed closed; no approval was created or used and no Docker or runner was contacted."],
        "residual_risks": ["unknown_or_unsupported_static_binding_input"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
    }


def validate_sandbox_image_lock_binding_report(
    approval: Mapping[str, Any],
    image_lock: Mapping[str, Any],
    behavior_policy: Mapping[str, Any],
    candidate_key_material: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a redacted static binding report; never authorize execution."""
    try:
        validate_sandbox_image_lock_binding(approval, image_lock, behavior_policy, candidate_key_material)
    except (TypeError, ValueError):
        return _invalid_report()

    image = _matching_image(image_lock, approval)
    local = image["distribution"] == "local_dev_only"
    warnings = ["local_sanctioned_image_dev_only"] if local else []
    limitations = [
        "This static verifier checks supplied approval, lock, policy, and candidate material only; it does not authorize a runner.",
        "Docker was not inspected, pulled, run, or otherwise contacted.",
    ]
    if local:
        limitations.extend(["Local sanctioned images are development-only and are not portable.", *image["local_sanctioned_limitations"]])
    return {
        "schema_version": LOCK_BINDING_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_IMAGE_LOCK_BINDING_VALIDATION,
        "verdict": "warn" if local else "pass",
        "binding_status": "matched_with_local_limitations" if local else "matched",
        "approval_reference": {"schema_version": approval["schema_version"], "report_kind": approval["report_kind"], "risk_tier": approval["source_risk_tier"]},
        "image_lock_reference": {"schema_version": image_lock["schema_version"], "report_kind": image_lock["report_kind"], "lock_id": image_lock["lock_id"], "distribution": image["distribution"], "identity_kind": "registry_digest" if image["registry_digest"] is not None else "local_full_image_id"},
        "behavior_policy_reference": {"schema_version": behavior_policy["schema_version"], "report_kind": behavior_policy["report_kind"], "policy_id": behavior_policy["policy_id"]},
        "checked_fields": ["approval_artifact", "candidate_key_material", "image_lock_identity", "image_platform_and_tool_versions", "required_runtime_flags", "behavior_policy_binding", "default_deny_network"],
        "mismatches": [],
        "blockers": [],
        "warnings": warnings,
        "limitations": limitations,
        "residual_risks": ["static_binding_match_is_not_runner_authorization", "container_runtime_and_observer_gates_remain_unimplemented"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
    }
