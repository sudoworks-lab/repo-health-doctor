from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .workspace import GENERIC_SECRET_PATTERNS


IMAGE_LOCK_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_IMAGE_LOCK = "sandbox_image_lock"
REPORT_KIND_IMAGE_LOCK_VALIDATION = "sandbox_image_lock_validation"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9./:_@-]{0,255}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_LOCK_FIELDS = {"schema_version", "report_kind", "lock_id", "images", "version_metadata", "required_runtime_flags", "binding_contract", "residual_risks"}
_IMAGE_FIELDS = {"logical_name", "distribution", "registry_reference", "registry_digest", "expected_image_id", "purpose", "supported_phases", "supported_runtimes", "tool_versions", "expected_platform", "source_build_metadata", "local_sanctioned_allowed", "local_sanctioned_limitations"}
_VERSION_FIELDS = {"created_at", "updated_at", "source"}
_RUNTIME_FIELDS = {"pull_policy", "network", "shell", "host_home", "docker_socket"}
_BINDING_FIELDS = {"approval_draft_report_kind", "behavior_policy_report_kind", "behavior_policy_schema_version", "image_lock_schema_version", "candidate_key_includes"}
_TOOL_FIELDS = {"python", "node", "strace", "pip", "npm", "other"}
_PLATFORM_FIELDS = {"os", "architecture"}
_SOURCE_FIELDS = {"source", "build_reference"}
_PHASES = {"phase2_install_probe", "phase3_runtime_probe"}


def build_registry_image_lock() -> dict[str, Any]:
    """Build a static digest-pinned sample lock; it does not contact a registry."""
    digest = "sha256:" + "a" * 64
    return {
        "schema_version": IMAGE_LOCK_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_IMAGE_LOCK,
        "lock_id": "python312-runtime-v1",
        "images": [
            {
                "logical_name": "python312-runtime",
                "distribution": "registry_primary",
                "registry_reference": f"registry.example.invalid/rhd/python312@{digest}",
                "registry_digest": digest,
                "expected_image_id": None,
                "purpose": "unknown_repo_runtime_observation",
                "supported_phases": ["phase2_install_probe", "phase3_runtime_probe"],
                "supported_runtimes": ["python"],
                "tool_versions": {"python": "3.12.x", "node": "not_included", "strace": "6.x", "pip": "24.x", "npm": "not_included", "other": "none"},
                "expected_platform": {"os": "linux", "architecture": "amd64"},
                "source_build_metadata": {"source": "human_reviewed_registry_setup", "build_reference": "release_v1"},
                "local_sanctioned_allowed": False,
                "local_sanctioned_limitations": [],
            }
        ],
        "version_metadata": {"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "source": "human_reviewed_registry_setup"},
        "required_runtime_flags": {"pull_policy": "never", "network": "none", "shell": False, "host_home": False, "docker_socket": False},
        "binding_contract": {
            "approval_draft_report_kind": "sandbox_approval_draft",
            "behavior_policy_report_kind": "sandbox_command_behavior_policy",
            "behavior_policy_schema_version": "0.1-draft",
            "image_lock_schema_version": IMAGE_LOCK_SCHEMA_VERSION,
            "candidate_key_includes": ["image_lock_schema_version", "image_lock_id", "registry_digest", "expected_image_id", "required_runtime_flags", "behavior_policy_schema_version"],
        },
        "residual_risks": ["digest_pinning_does_not_remove_container_runtime_or_kernel_risk"],
    }


def _exact_mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} schema mismatch or unknown field")
    return value


def _safe_labels(value: Any, label: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value) or not all(isinstance(item, str) and _SAFE_LABEL.fullmatch(item) for item in value):
        raise ValueError(f"{label} is invalid")
    return value


def _validate_image(image: Mapping[str, Any]) -> None:
    _exact_mapping(image, _IMAGE_FIELDS, "image lock image")
    for field in ("logical_name", "purpose"):
        if not isinstance(image.get(field), str) or not _SAFE_LABEL.fullmatch(image[field]):
            raise ValueError(f"image {field} is invalid")
    distribution = image.get("distribution")
    if distribution not in {"registry_primary", "local_dev_only"}:
        raise ValueError("image distribution is invalid")
    _safe_labels(image.get("supported_phases"), "supported_phases")
    if not set(image["supported_phases"]).issubset(_PHASES):
        raise ValueError("image supported phases are invalid")
    _safe_labels(image.get("supported_runtimes"), "supported_runtimes")
    tools = _exact_mapping(image.get("tool_versions"), _TOOL_FIELDS, "image tool_versions")
    if not all(isinstance(value, str) and _SAFE_LABEL.fullmatch(value) for value in tools.values()):
        raise ValueError("image tool version is invalid")
    platform = _exact_mapping(image.get("expected_platform"), _PLATFORM_FIELDS, "image expected_platform")
    if platform.get("os") != "linux" or platform.get("architecture") not in {"amd64", "arm64"}:
        raise ValueError("image platform is invalid")
    source = _exact_mapping(image.get("source_build_metadata"), _SOURCE_FIELDS, "image source_build_metadata")
    if not all(isinstance(value, str) and _SAFE_LABEL.fullmatch(value) for value in source.values()):
        raise ValueError("image source build metadata is invalid")
    reference = image.get("registry_reference")
    digest = image.get("registry_digest")
    expected_id = image.get("expected_image_id")
    local_allowed = image.get("local_sanctioned_allowed")
    limitations = image.get("local_sanctioned_limitations")
    if not isinstance(limitations, list) or not all(isinstance(item, str) and _SAFE_LABEL.fullmatch(item) for item in limitations):
        raise ValueError("image local_sanctioned_limitations is invalid")
    if distribution == "registry_primary":
        if not isinstance(reference, str) or "@sha256:" not in reference or not _SAFE_IMAGE_REFERENCE.fullmatch(reference):
            raise ValueError("registry image reference must be digest pinned")
        ref_digest = "sha256:" + reference.rsplit("@sha256:", 1)[1]
        if not _SHA256.fullmatch(str(digest)) or digest != ref_digest:
            raise ValueError("registry image digest is missing or mismatched")
        if expected_id is not None or local_allowed is not False or limitations:
            raise ValueError("registry image local settings are invalid")
    else:
        if not isinstance(reference, str) or "@" in reference or "/" in reference or not _SAFE_LABEL.fullmatch(reference):
            raise ValueError("local image reference is invalid")
        if digest is not None or local_allowed is not True:
            raise ValueError("local image requires explicit local_sanctioned_allowed")
        if not _SHA256.fullmatch(str(expected_id)):
            raise ValueError("local image requires a full expected image id")
        if not limitations:
            raise ValueError("local image requires portability limitations")


def validate_sandbox_image_lock(lock: Mapping[str, Any]) -> None:
    """Validate a lock document statically; no Docker or network calls occur."""
    rendered = json.dumps(lock, sort_keys=True, ensure_ascii=False)
    if any(pattern.search(rendered) for pattern in GENERIC_SECRET_PATTERNS):
        raise ValueError("image lock contains a secret-like value")
    _exact_mapping(lock, _LOCK_FIELDS, "sandbox image lock")
    if lock.get("schema_version") != IMAGE_LOCK_SCHEMA_VERSION:
        raise ValueError("image lock schema_version is unsupported")
    if lock.get("report_kind") != REPORT_KIND_IMAGE_LOCK:
        raise ValueError("image lock report_kind is unsupported")
    if not isinstance(lock.get("lock_id"), str) or not _SAFE_LABEL.fullmatch(lock["lock_id"]):
        raise ValueError("image lock lock_id is invalid")
    images = lock.get("images")
    if not isinstance(images, list) or not images:
        raise ValueError("image lock images are required")
    for image in images:
        _validate_image(image)
    version = _exact_mapping(lock.get("version_metadata"), _VERSION_FIELDS, "image lock version_metadata")
    if not all(isinstance(version.get(field), str) and _TIMESTAMP.fullmatch(version[field]) for field in ("created_at", "updated_at")):
        raise ValueError("image lock version metadata timestamp is invalid")
    if not isinstance(version.get("source"), str) or not _SAFE_LABEL.fullmatch(version["source"]):
        raise ValueError("image lock version metadata source is invalid")
    flags = _exact_mapping(lock.get("required_runtime_flags"), _RUNTIME_FIELDS, "image lock required_runtime_flags")
    if flags != {"pull_policy": "never", "network": "none", "shell": False, "host_home": False, "docker_socket": False}:
        raise ValueError("image lock runtime flags attempt to relax a denied boundary")
    binding = _exact_mapping(lock.get("binding_contract"), _BINDING_FIELDS, "image lock binding_contract")
    if binding.get("approval_draft_report_kind") != "sandbox_approval_draft" or binding.get("behavior_policy_report_kind") != "sandbox_command_behavior_policy" or binding.get("behavior_policy_schema_version") != "0.1-draft" or binding.get("image_lock_schema_version") != IMAGE_LOCK_SCHEMA_VERSION:
        raise ValueError("image lock binding contract is invalid")
    required_key_fields = {"image_lock_schema_version", "image_lock_id", "registry_digest", "expected_image_id", "required_runtime_flags", "behavior_policy_schema_version"}
    if not isinstance(binding.get("candidate_key_includes"), list) or set(binding["candidate_key_includes"]) != required_key_fields:
        raise ValueError("image lock candidate-key binding is invalid")
    _safe_labels(lock.get("residual_risks"), "image lock residual_risks")


def validate_sandbox_image_lock_report(lock: Mapping[str, Any]) -> dict[str, Any]:
    """Return a redacted static validation report; invalid lock content is never echoed."""
    try:
        validate_sandbox_image_lock(lock)
    except ValueError:
        return {
            "schema_version": IMAGE_LOCK_SCHEMA_VERSION,
            "report_kind": REPORT_KIND_IMAGE_LOCK_VALIDATION,
            "lock_schema_version": "unvalidated",
            "verdict": "block",
            "valid": False,
            "blockers": ["invalid_or_unsupported_image_lock"],
            "warnings": [],
            "image_summary": [],
            "limitations": ["Static image-lock validation failed closed; Docker was not queried."],
            "residual_risks": ["unknown_or_unsupported_lock_input"],
            "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        }
    image_summary = [
        {
            "distribution": image["distribution"],
            "digest_pinned": image["distribution"] == "registry_primary",
            "local_dev_only": image["distribution"] == "local_dev_only",
            "expected_image_id_present": image["expected_image_id"] is not None,
        }
        for image in lock["images"]
    ]
    local_present = any(image["distribution"] == "local_dev_only" for image in lock["images"])
    return {
        "schema_version": IMAGE_LOCK_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_IMAGE_LOCK_VALIDATION,
        "lock_schema_version": lock["schema_version"],
        "verdict": "pass",
        "valid": True,
        "blockers": [],
        "warnings": ["local_dev_only_image_portability_limited"] if local_present else [],
        "image_summary": image_summary,
        "limitations": [
            "This report validates lock structure only; it does not inspect, pull, run, or otherwise query Docker.",
            "An image lock is not an approval file or execution permit.",
        ],
        "residual_risks": list(lock["residual_risks"]),
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }
