"""Static image-attestation validation for future live gates.

This module validates supplied JSON-compatible mappings only. It never
contacts Docker, inspects images, pulls images, runs containers, connects a
runner, or performs live execution.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .image_lock import (
    IMAGE_LOCK_SCHEMA_VERSION,
    REPORT_KIND_IMAGE_LOCK,
    REPORT_KIND_IMAGE_LOCK_VALIDATION,
    validate_sandbox_image_lock,
)
from .workspace import GENERIC_SECRET_PATTERNS


IMAGE_ATTESTATION_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_IMAGE_ATTESTATION = "sandbox_image_attestation"
REPORT_KIND_IMAGE_ATTESTATION_VALIDATION = "sandbox_image_attestation_validation"

_ATTESTATION_FIELDS = {
    "schema_version",
    "report_kind",
    "attestation_id",
    "mode",
    "image",
    "lock_binding",
    "tool_inventory",
    "runtime_flags_attested",
    "operator_attestation",
    "local_sanctioned",
    "limitations",
    "residual_risks",
    "redaction",
}
_IMAGE_FIELDS = {"image_logical_name", "image_reference", "image_reference_kind", "registry_digest", "full_image_id", "platform", "architecture", "os", "variant"}
_LOCK_BINDING_FIELDS = {"image_lock_schema_version", "image_lock_report_kind", "image_lock_id", "expected_registry_digest", "expected_full_image_id", "expected_platform"}
_TOOL_FIELDS = {"python", "node", "pip", "npm", "strace", "other_tools"}
_RUNTIME_FIELDS = {"pull_policy", "network", "shell", "no_host_home", "no_docker_socket", "no_credentials", "read_only_rootfs", "non_root_user", "no_new_privileges"}
_OPERATOR_FIELDS = {"attested_by", "attested_at", "source", "method", "docker_engine_version", "docker_desktop_version", "runc_version", "containerd_version", "notes"}
_LOCAL_FIELDS = {"allowed", "dev_only", "portability_limitation"}
_REDACTION_FIELDS = {"raw_host_path_present", "raw_secret_like_value_present"}
_LOCK_RESULT_FIELDS = {"schema_version", "report_kind", "lock_schema_version", "verdict", "valid", "blockers", "warnings", "image_summary", "limitations", "residual_risks", "redaction"}

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9./:_@-]{0,255}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HOME_PATH = re.compile(r"(?:^|[\s\"'])/(?:home|Users)/")


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


def _safe_label(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _safe_list(value: Any, label: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value) or not all(isinstance(item, str) and _LABEL.fullmatch(item) for item in value):
        raise ValueError(f"{label} is invalid")
    return value


def _validate_lock_validation_result(result: Mapping[str, Any] | None) -> None:
    if result is None:
        return
    report = _exact_mapping(result, _LOCK_RESULT_FIELDS, "image lock validation result")
    if (
        report["schema_version"] != IMAGE_LOCK_SCHEMA_VERSION
        or report["report_kind"] != REPORT_KIND_IMAGE_LOCK_VALIDATION
        or report["lock_schema_version"] != IMAGE_LOCK_SCHEMA_VERSION
        or report["verdict"] != "pass"
        or report["valid"] is not True
    ):
        raise ValueError("image lock validation result is not a static pass")


def _matching_lock_image(image_lock: Mapping[str, Any], attestation: Mapping[str, Any]) -> Mapping[str, Any]:
    binding = attestation["lock_binding"]
    matches = [
        image
        for image in image_lock["images"]
        if image["registry_digest"] == binding["expected_registry_digest"]
        and image["expected_image_id"] == binding["expected_full_image_id"]
        and image["expected_platform"] == binding["expected_platform"]
    ]
    if len(matches) != 1:
        raise ValueError("image lock match is missing or ambiguous")
    return matches[0]


def _validate_runtime_flags(flags: Mapping[str, Any]) -> None:
    if flags != {
        "pull_policy": "never",
        "network": "none",
        "shell": False,
        "no_host_home": True,
        "no_docker_socket": True,
        "no_credentials": True,
        "read_only_rootfs": True,
        "non_root_user": True,
        "no_new_privileges": True,
    }:
        raise ValueError("attested runtime flags are unsafe")


def validate_sandbox_image_attestation(
    attestation: Mapping[str, Any],
    *,
    image_lock: Mapping[str, Any] | None = None,
    image_lock_validation_result: Mapping[str, Any] | None = None,
) -> None:
    """Validate static attestation shape and optional image-lock binding.

    The attestation is supplied evidence only. This function never obtains
    evidence from Docker and never authorizes execution.
    """
    if _contains_unsafe_value(attestation) or (image_lock is not None and _contains_unsafe_value(image_lock)) or (image_lock_validation_result is not None and _contains_unsafe_value(image_lock_validation_result)):
        raise ValueError("image attestation contains a raw host path or secret-like value")
    document = _exact_mapping(attestation, _ATTESTATION_FIELDS, "image attestation")
    if document.get("schema_version") != IMAGE_ATTESTATION_SCHEMA_VERSION:
        raise ValueError("image attestation schema_version is unsupported")
    if document.get("report_kind") != REPORT_KIND_IMAGE_ATTESTATION:
        raise ValueError("image attestation report_kind is unsupported")
    _safe_label(document.get("attestation_id"), "attestation_id")
    if document.get("mode") != "static_attestation_input":
        raise ValueError("image attestation mode is invalid")

    image = _exact_mapping(document.get("image"), _IMAGE_FIELDS, "attested image")
    _safe_label(image.get("image_logical_name"), "image_logical_name")
    if not isinstance(image.get("image_reference"), str) or not _IMAGE_REFERENCE.fullmatch(image["image_reference"]):
        raise ValueError("image_reference is invalid")
    if image.get("image_reference_kind") not in {"registry_digest", "local_image_id"}:
        raise ValueError("image_reference_kind is invalid")
    if image.get("os") != "linux" or image.get("architecture") not in {"amd64", "arm64"}:
        raise ValueError("image platform is invalid")
    if image.get("variant") is not None:
        _safe_label(image.get("variant"), "variant")
    platform = _exact_mapping(image.get("platform"), {"os", "architecture"}, "image platform")
    if platform != {"os": image["os"], "architecture": image["architecture"]}:
        raise ValueError("image platform fields are inconsistent")

    binding = _exact_mapping(document.get("lock_binding"), _LOCK_BINDING_FIELDS, "image lock binding")
    if binding.get("image_lock_schema_version") != IMAGE_LOCK_SCHEMA_VERSION or binding.get("image_lock_report_kind") != REPORT_KIND_IMAGE_LOCK:
        raise ValueError("image lock binding schema or report kind is invalid")
    _safe_label(binding.get("image_lock_id"), "image_lock_id")
    expected_platform = _exact_mapping(binding.get("expected_platform"), {"os", "architecture"}, "expected platform")
    if expected_platform != platform:
        raise ValueError("attested platform does not match expected platform")

    if image["image_reference_kind"] == "registry_digest":
        if not isinstance(image["image_reference"], str) or "@sha256:" not in image["image_reference"]:
            raise ValueError("registry image reference is not digest pinned")
        ref_digest = "sha256:" + image["image_reference"].rsplit("@sha256:", 1)[1]
        if not _SHA256.fullmatch(str(image.get("registry_digest"))) or image["registry_digest"] != ref_digest:
            raise ValueError("registry digest is missing or mismatched")
        if binding["expected_registry_digest"] != image["registry_digest"]:
            raise ValueError("registry digest does not match image lock binding")
        if binding["expected_full_image_id"] is not None and binding["expected_full_image_id"] != image["full_image_id"]:
            raise ValueError("full image ID does not match image lock binding")
    else:
        if image["registry_digest"] is not None or binding["expected_registry_digest"] is not None:
            raise ValueError("local image attestation cannot carry registry digest")
        if not _SHA256.fullmatch(str(image.get("full_image_id"))) or binding["expected_full_image_id"] != image["full_image_id"]:
            raise ValueError("local image attestation requires matching full image ID")

    tools = _exact_mapping(document.get("tool_inventory"), _TOOL_FIELDS, "tool inventory")
    for field in ("python", "node", "pip", "npm", "strace"):
        _safe_label(tools.get(field), field)
    _safe_list(tools.get("other_tools"), "other_tools", nonempty=False)
    flags = _exact_mapping(document.get("runtime_flags_attested"), _RUNTIME_FIELDS, "runtime flags")
    _validate_runtime_flags(flags)

    operator = _exact_mapping(document.get("operator_attestation"), _OPERATOR_FIELDS, "operator attestation")
    for field in ("attested_by", "source", "method", "docker_engine_version", "docker_desktop_version", "runc_version", "containerd_version"):
        _safe_label(operator.get(field), field)
    if not isinstance(operator.get("attested_at"), str) or not _TIMESTAMP.fullmatch(operator["attested_at"]):
        raise ValueError("attested_at timestamp is invalid")
    _safe_list(operator.get("notes"), "operator notes", nonempty=False)

    local = _exact_mapping(document.get("local_sanctioned"), _LOCAL_FIELDS, "local sanctioned")
    if image["image_reference_kind"] == "local_image_id":
        if local.get("allowed") is not True or local.get("dev_only") is not True:
            raise ValueError("local sanctioned image requires allowed and dev_only")
        _safe_list(local.get("portability_limitation"), "local portability limitation")
    else:
        if local != {"allowed": False, "dev_only": False, "portability_limitation": []}:
            raise ValueError("registry attestation cannot carry local sanctioned allowances")

    _safe_list(document.get("limitations"), "limitations")
    _safe_list(document.get("residual_risks"), "residual_risks")
    redaction = _exact_mapping(document.get("redaction"), _REDACTION_FIELDS, "redaction")
    if redaction != {"raw_host_path_present": False, "raw_secret_like_value_present": False}:
        raise ValueError("image attestation redaction is unsafe")

    _validate_lock_validation_result(image_lock_validation_result)
    if image_lock is not None:
        validate_sandbox_image_lock(image_lock)
        if image_lock["schema_version"] != binding["image_lock_schema_version"] or image_lock["report_kind"] != binding["image_lock_report_kind"] or image_lock["lock_id"] != binding["image_lock_id"]:
            raise ValueError("image lock identity mismatch")
        lock_image = _matching_lock_image(image_lock, document)
        if lock_image["logical_name"] != image["image_logical_name"]:
            raise ValueError("image logical name mismatch")
        if lock_image["tool_versions"] != {key: tools[key] for key in ("python", "node", "strace", "pip", "npm")} | {"other": "none" if not tools["other_tools"] else tools["other_tools"][0]}:
            raise ValueError("tool inventory mismatch")
        runtime = image_lock["required_runtime_flags"]
        if runtime != {"pull_policy": flags["pull_policy"], "network": flags["network"], "shell": flags["shell"], "host_home": not flags["no_host_home"], "docker_socket": not flags["no_docker_socket"]}:
            raise ValueError("runtime flag mismatch")
        if lock_image["distribution"] == "local_dev_only" and image["image_reference_kind"] != "local_image_id":
            raise ValueError("local lock image requires local image attestation")
        if lock_image["distribution"] == "registry_primary" and image["image_reference_kind"] != "registry_digest":
            raise ValueError("registry lock image requires digest attestation")


def _invalid_report() -> dict[str, Any]:
    return {
        "schema_version": IMAGE_ATTESTATION_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_IMAGE_ATTESTATION_VALIDATION,
        "attestation_schema_version": "unvalidated",
        "verdict": "block",
        "valid": False,
        "attestation_status": "invalid_or_mismatch",
        "image_reference": {},
        "lock_reference": {},
        "checked_fields": [],
        "blockers": ["invalid_or_mismatched_image_attestation"],
        "warnings": [],
        "limitations": ["Static image attestation validation failed closed; Docker was not inspected, pulled, run, or contacted."],
        "residual_risks": ["unknown_or_unsupported_image_attestation_input"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "docker_inspect_performed": False,
        "docker_pull_performed": False,
        "docker_run_performed": False,
    }


def validate_sandbox_image_attestation_report(
    attestation: Mapping[str, Any],
    *,
    image_lock: Mapping[str, Any] | None = None,
    image_lock_validation_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a redacted static validation report; never contact Docker."""
    try:
        validate_sandbox_image_attestation(
            attestation,
            image_lock=image_lock,
            image_lock_validation_result=image_lock_validation_result,
        )
    except (KeyError, TypeError, ValueError):
        return _invalid_report()
    local = attestation["image"]["image_reference_kind"] == "local_image_id"
    limitations = [
        "This report validates supplied image-attestation shape only; it is not Docker inspect and not runner authorization.",
        "Docker was not inspected, pulled, run, or otherwise contacted.",
        "Image rotation requires approval invalidation and a new reviewed binding.",
    ]
    if local:
        limitations.extend(["Local sanctioned images are development-only and not portable.", *attestation["local_sanctioned"]["portability_limitation"]])
    return {
        "schema_version": IMAGE_ATTESTATION_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_IMAGE_ATTESTATION_VALIDATION,
        "attestation_schema_version": attestation["schema_version"],
        "verdict": "warn" if local else "pass",
        "valid": True,
        "attestation_status": "matched_with_local_limitations" if local else "matched",
        "image_reference": {
            "image_logical_name": attestation["image"]["image_logical_name"],
            "image_reference_kind": attestation["image"]["image_reference_kind"],
            "platform": attestation["image"]["platform"],
        },
        "lock_reference": {
            "schema_version": attestation["lock_binding"]["image_lock_schema_version"],
            "report_kind": attestation["lock_binding"]["image_lock_report_kind"],
            "lock_id": attestation["lock_binding"]["image_lock_id"],
        },
        "checked_fields": ["schema_version", "report_kind", "image_identity", "image_lock_binding", "platform", "tool_inventory", "runtime_flags", "operator_attestation", "local_sanctioned", "redaction"],
        "blockers": [],
        "warnings": ["local_sanctioned_image_dev_only"] if local else [],
        "limitations": limitations,
        "residual_risks": ["static_attestation_is_not_live_image_proof", "future_docker_inspect_gate_required"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "docker_inspect_performed": False,
        "docker_pull_performed": False,
        "docker_run_performed": False,
    }
