from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping

from .profiles import SandboxProfile
from .run_workspace import FINGERPRINT_METHOD, InventoryResult, target_identity


SANDBOX_RUN_APPROVAL_KIND = "repo_health_sandbox_run_approval"
SANDBOX_RUN_APPROVAL_SCHEMA_VERSION = "0.1-draft"
SANDBOX_RUN_ACTION = "sandbox_run"

APPROVAL_TOP_LEVEL_FIELDS = {
    "approval_kind",
    "schema_version",
    "approved",
    "approved_by",
    "approved_at",
    "expires_at",
    "action",
    "target",
    "command",
    "image",
    "sandbox_profile",
    "network",
    "timeout_seconds",
    "resource_limits",
    "root_user_allowed",
    "limitations",
    "residual_risks",
}


@dataclass(frozen=True)
class SandboxRunApprovalValidation:
    approved: bool
    matched: bool
    refusal_reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]


def load_sandbox_run_approval(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("approval_missing") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("approval_invalid_json") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("approval_must_be_object")
    return payload


def validate_sandbox_run_approval(
    approval: Mapping[str, Any],
    *,
    target_path: Path,
    target_inventory: InventoryResult,
    command_argv: list[str],
    image: str,
    profile: SandboxProfile,
    timeout_seconds: int,
    now: datetime | None = None,
) -> SandboxRunApprovalValidation:
    errors: list[str] = []
    warnings: list[str] = []

    if set(approval) != APPROVAL_TOP_LEVEL_FIELDS:
        errors.append("approval_top_level_required_or_unknown_field")
    if approval.get("approval_kind") != SANDBOX_RUN_APPROVAL_KIND:
        errors.append("approval_kind_unsupported")
    if approval.get("schema_version") != SANDBOX_RUN_APPROVAL_SCHEMA_VERSION:
        errors.append("approval_schema_version_unsupported")
    if approval.get("approved") is not True:
        errors.append("approval_missing")
    if approval.get("action") != SANDBOX_RUN_ACTION:
        errors.append("approval_action_not_sandbox_run")

    limitations = tuple(_string_items(approval.get("limitations")))
    residual_risks = tuple(_string_items(approval.get("residual_risks")))
    if not limitations:
        errors.append("approval_limitations_empty")
    if not residual_risks:
        errors.append("approval_residual_risks_empty")

    target = _mapping(approval.get("target"))
    target_identity_value = target_identity(target_path)
    if target.get("identity") != target_identity_value:
        errors.append("target_identity_mismatch")
    if target.get("fingerprint") != target_inventory.fingerprint:
        errors.append("target_fingerprint_mismatch")
    if target.get("fingerprint_method") != FINGERPRINT_METHOD:
        errors.append("target_fingerprint_method_mismatch")

    command = _mapping(approval.get("command"))
    approved_argv = command.get("argv")
    if not isinstance(approved_argv, list) or approved_argv != command_argv or not all(isinstance(item, str) and item for item in approved_argv):
        errors.append("command_argv_mismatch")
    if command.get("shell") is not False:
        errors.append("shell_wrapping_not_allowed")

    image_doc = _mapping(approval.get("image"))
    if image_doc.get("reference") != image:
        errors.append("image_reference_mismatch")
    if image_doc.get("pull_policy") != "never":
        errors.append("image_pull_policy_must_be_never")

    profile_doc = _mapping(approval.get("sandbox_profile"))
    if profile_doc.get("name") != profile.name:
        errors.append("sandbox_profile_mismatch")
    if profile_doc.get("network") != profile.network:
        errors.append("sandbox_profile_network_mismatch")
    if approval.get("network") != profile.network:
        errors.append("network_mismatch")

    approved_timeout = approval.get("timeout_seconds")
    if not isinstance(approved_timeout, int) or approved_timeout <= 0:
        errors.append("timeout_seconds_invalid")
    elif timeout_seconds > approved_timeout:
        errors.append("timeout_exceeds_approval")

    if approval.get("resource_limits") != profile.resource_limits:
        errors.append("resource_limits_mismatch")

    root_user_allowed = approval.get("root_user_allowed")
    if not isinstance(root_user_allowed, bool):
        errors.append("root_user_allowed_must_be_boolean")
    if profile.user in {"0", "0:0", "root"} and root_user_allowed is not True:
        errors.append("root_user_not_approved")

    if not _not_expired(approval.get("expires_at"), now=now):
        errors.append("approval_expired")
    _approved_metadata_valid(approval, errors)

    if image == "latest" or image.endswith(":latest"):
        warnings.append("image_latest_tag_is_not_reproducible")

    matched = not errors
    return SandboxRunApprovalValidation(
        approved=approval.get("approved") is True,
        matched=matched,
        refusal_reasons=tuple(dict.fromkeys(errors)),
        warnings=tuple(dict.fromkeys(warnings)),
        limitations=limitations,
        residual_risks=residual_risks,
    )


def build_demo_sandbox_run_approval(
    *,
    target_path: Path,
    target_inventory: InventoryResult,
    command_argv: list[str],
    image: str,
    profile: SandboxProfile,
    expires_at: str,
) -> dict[str, Any]:
    return {
        "approval_kind": SANDBOX_RUN_APPROVAL_KIND,
        "schema_version": SANDBOX_RUN_APPROVAL_SCHEMA_VERSION,
        "approved": True,
        "approved_by": "demo-reviewer@example.invalid",
        "approved_at": "2026-06-27T00:00:00Z",
        "expires_at": expires_at,
        "action": SANDBOX_RUN_ACTION,
        "target": {
            "identity": target_identity(target_path),
            "fingerprint": target_inventory.fingerprint,
            "fingerprint_method": FINGERPRINT_METHOD,
        },
        "command": {
            "argv": list(command_argv),
            "shell": False,
        },
        "image": {
            "reference": image,
            "pull_policy": "never",
        },
        "sandbox_profile": {
            "name": profile.name,
            "network": profile.network,
        },
        "network": profile.network,
        "timeout_seconds": 30,
        "resource_limits": profile.resource_limits,
        "root_user_allowed": False,
        "limitations": [
            "Approval is scoped to one reviewed sandbox-run command.",
            "A completed sandbox run is not proof that the repository is safe.",
            "Docker isolation has limitations and does not grant unrestricted execution authorization.",
        ],
        "residual_risks": [
            "The container image, Docker daemon, host kernel, and copied repository content remain trust boundaries.",
            "The disposable workspace evidence is bounded and does not prove absence of malicious behavior.",
        ],
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _not_expired(value: Any, *, now: datetime | None = None) -> bool:
    if value is None:
        return True
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    current = datetime.now(timezone.utc) if now is None else now
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed > current


def _approved_metadata_valid(approval: Mapping[str, Any], errors: list[str]) -> None:
    for field in ("approved_by", "approved_at"):
        value = approval.get(field)
        if not isinstance(value, str) or not value:
            errors.append(f"{field}_missing")
    approved_at = approval.get("approved_at")
    if isinstance(approved_at, str) and approved_at:
        try:
            datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
        except ValueError:
            errors.append("approved_at_invalid")
