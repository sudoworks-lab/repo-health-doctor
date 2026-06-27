"""Non-executing runner preflight skeleton for unknown-repo sandbox gates.

The preflight consumes supplied in-memory mappings only.  It never creates an
approval artifact, connects a runner, contacts Docker or the network, captures
observer data, or executes an unknown-repository command.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .approval_promotion import validate_unknown_repo_command_approval_report
from .behavior_policy import BEHAVIOR_POLICY_SCHEMA_VERSION, REPORT_KIND_BEHAVIOR_POLICY, validate_behavior_policy
from .behavior_policy_binding import validate_sandbox_behavior_policy_binding_report
from .image_lock import validate_sandbox_image_lock_report
from .lock_binding import validate_sandbox_image_lock_binding_report
from .observer_evidence import validate_normalized_observer_evidence_report
from .static_transition import REPORT_KIND_STATIC_TRANSITION_VALIDATION, STATIC_TRANSITION_SCHEMA_VERSION
from .workspace import GENERIC_SECRET_PATTERNS


RUNNER_PREFLIGHT_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_RUNNER_PREFLIGHT = "sandbox_runner_preflight"

_INPUT_FIELDS = {
    "approval",
    "image_lock",
    "behavior_policy",
    "observer_evidence",
    "image_lock_material",
    "behavior_policy_material",
    "static_transition_report",
}
_STATIC_TRANSITION_FIELDS = {
    "schema_version",
    "report_kind",
    "mode",
    "fixture_name",
    "source_risk_tier",
    "transition_status",
    "approved",
    "execution_permitted",
    "runner_connected",
    "docker_contacted",
    "observer_capture_performed",
    "approval_artifact_generated",
    "live_candidate_generated",
    "component_results",
    "blockers",
    "warnings",
    "limitations",
    "residual_risks",
    "redaction_status",
}
_CHECKED_GATES = [
    "approval_validation",
    "image_lock_validation",
    "image_lock_binding_validation",
    "behavior_policy_validation",
    "observer_evidence_validation",
    "behavior_policy_binding_validation",
    "static_transition_validation",
]
_HOME_PATH = re.compile(r"(?:^|[\s\"'])/(?:home|Users)/")


def _contains_unsafe_value(value: Any) -> bool:
    try:
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return True
    return bool(_HOME_PATH.search(rendered)) or any(pattern.search(rendered) for pattern in GENERIC_SECRET_PATTERNS)


def _behavior_policy_validation_report(policy: Mapping[str, Any]) -> dict[str, Any]:
    try:
        validate_behavior_policy(policy)
    except (KeyError, TypeError, ValueError):
        return {
            "schema_version": BEHAVIOR_POLICY_SCHEMA_VERSION,
            "report_kind": "sandbox_behavior_policy_validation",
            "policy_schema_version": "unvalidated",
            "verdict": "block",
            "valid": False,
            "blockers": ["invalid_or_unsupported_behavior_policy"],
            "warnings": [],
            "limitations": ["Static behavior-policy validation failed closed; no runner, Docker, observer, or live command was contacted."],
            "residual_risks": ["unknown_or_unsupported_behavior_policy_input"],
            "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        }
    return {
        "schema_version": BEHAVIOR_POLICY_SCHEMA_VERSION,
        "report_kind": "sandbox_behavior_policy_validation",
        "policy_schema_version": policy["schema_version"],
        "policy_report_kind": REPORT_KIND_BEHAVIOR_POLICY,
        "verdict": "pass",
        "valid": True,
        "blockers": [],
        "warnings": ["static_behavior_policy_validation_is_not_runner_authorization"],
        "limitations": ["This validates supplied behavior-policy shape only; it does not authorize or execute a runner."],
        "residual_risks": ["behavior_policy_binding_and_observer_evidence_remain_required"],
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }


def _validate_static_transition_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, Mapping) or set(report) != _STATIC_TRANSITION_FIELDS:
        raise ValueError("static transition report schema mismatch or unknown field")
    if _contains_unsafe_value(report):
        raise ValueError("static transition report contains unsafe value")
    if (
        report["schema_version"] != STATIC_TRANSITION_SCHEMA_VERSION
        or report["report_kind"] != REPORT_KIND_STATIC_TRANSITION_VALIDATION
        or report["mode"] != "static_transition_test"
        or report["approved"] is not False
        or report["execution_permitted"] is not False
        or report["runner_connected"] is not False
        or report["docker_contacted"] is not False
        or report["observer_capture_performed"] is not False
        or report["approval_artifact_generated"] is not False
    ):
        raise ValueError("static transition report is not an eligible static report")
    status = report["transition_status"]
    if status not in {"pass", "warn", "block"}:
        raise ValueError("static transition status is invalid")
    if not isinstance(report["component_results"], Mapping):
        raise ValueError("static transition component results are invalid")
    for field in ("blockers", "warnings", "limitations", "residual_risks"):
        if not isinstance(report[field], list) or not all(isinstance(item, str) for item in report[field]):
            raise ValueError("static transition list field is invalid")
    if not isinstance(report["redaction_status"], Mapping) or report["redaction_status"].get("raw_host_paths_redacted") is not True or report["redaction_status"].get("secret_like_values_redacted") is not True:
        raise ValueError("static transition redaction status is invalid")
    return {
        "schema_version": STATIC_TRANSITION_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_STATIC_TRANSITION_VALIDATION,
        "verdict": status,
        "valid": status != "block",
        "blockers": ["static_transition_blocked"] if status == "block" else [],
        "warnings": ["static_transition_warn"] if status == "warn" else [],
        "transition_status": status,
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "observer_capture_performed": False,
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }


def _invalid_static_transition_result() -> dict[str, Any]:
    return {
        "schema_version": STATIC_TRANSITION_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_STATIC_TRANSITION_VALIDATION,
        "verdict": "block",
        "valid": False,
        "blockers": ["invalid_or_unsupported_static_transition_report"],
        "warnings": [],
        "transition_status": "block",
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "observer_capture_performed": False,
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }


def _reference_inputs(values: Mapping[str, Any] | None) -> dict[str, Any]:
    if values is None or _contains_unsafe_value(values):
        return {
            "approval_reference": {},
            "image_lock_reference": {},
            "behavior_policy_reference": {},
            "observer_evidence_reference": {},
            "static_transition_reference": {},
        }
    approval = values.get("approval")
    image_lock = values.get("image_lock")
    policy = values.get("behavior_policy")
    evidence = values.get("observer_evidence")
    transition = values.get("static_transition_report")
    return {
        "approval_reference": {
            "schema_version": approval.get("schema_version") if isinstance(approval, Mapping) else "unvalidated",
            "report_kind": approval.get("report_kind") if isinstance(approval, Mapping) else "unvalidated",
            "approval_id": approval.get("approval_id") if isinstance(approval, Mapping) else "unvalidated",
            "risk_tier": approval.get("source_risk_tier") if isinstance(approval, Mapping) else "unvalidated",
        },
        "image_lock_reference": {
            "schema_version": image_lock.get("schema_version") if isinstance(image_lock, Mapping) else "unvalidated",
            "report_kind": image_lock.get("report_kind") if isinstance(image_lock, Mapping) else "unvalidated",
            "lock_id": image_lock.get("lock_id") if isinstance(image_lock, Mapping) else "unvalidated",
        },
        "behavior_policy_reference": {
            "schema_version": policy.get("schema_version") if isinstance(policy, Mapping) else "unvalidated",
            "report_kind": policy.get("report_kind") if isinstance(policy, Mapping) else "unvalidated",
            "policy_id": policy.get("policy_id") if isinstance(policy, Mapping) else "unvalidated",
        },
        "observer_evidence_reference": {
            "schema_version": evidence.get("schema_version") if isinstance(evidence, Mapping) else "unvalidated",
            "report_kind": evidence.get("report_kind") if isinstance(evidence, Mapping) else "unvalidated",
            "evidence_id": evidence.get("evidence_id") if isinstance(evidence, Mapping) else "unvalidated",
        },
        "static_transition_reference": {
            "schema_version": transition.get("schema_version") if isinstance(transition, Mapping) else "unvalidated",
            "report_kind": transition.get("report_kind") if isinstance(transition, Mapping) else "unvalidated",
            "transition_status": transition.get("transition_status") if isinstance(transition, Mapping) else "unvalidated",
            "fixture_name": transition.get("fixture_name") if isinstance(transition, Mapping) else "unvalidated",
        },
    }


def _blocked_component(reason: str) -> dict[str, Any]:
    return {"verdict": "block", "valid": False, "blockers": [reason], "warnings": []}


def _base_report(values: Mapping[str, Any] | None, component_results: Mapping[str, Any], blockers: list[str], warnings: list[str], verdict: str) -> dict[str, Any]:
    return {
        "schema_version": RUNNER_PREFLIGHT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_RUNNER_PREFLIGHT,
        "mode": "non_executing_preflight",
        "verdict": verdict,
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "docker_pull_performed": False,
        "docker_inspect_performed": False,
        "docker_run_performed": False,
        "network_contacted": False,
        "observer_capture_performed": False,
        "phase_live_performed": False,
        "approval_artifact_generated": False,
        "inputs": _reference_inputs(values),
        "component_results": dict(component_results),
        "checked_gates": list(_CHECKED_GATES),
        "blockers": blockers,
        "warnings": warnings,
        "limitations": [
            "Non-executing runner preflight skeleton only; a PASS is not runner authorization.",
            "No Docker daemon, network, observer capture, strace, runtime hook, live phase, or unknown-repo command was contacted or executed.",
            "The report confirms static artifact consistency only and does not prove an unknown repository is safe.",
        ],
        "residual_risks": ["runner_execution_gate_remains_unimplemented", "static_artifacts_can_be_stale_or_incomplete"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }


def run_non_executing_runner_preflight(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Run static preflight gates over supplied mappings; never execute them."""
    if not isinstance(inputs, Mapping) or set(inputs) != _INPUT_FIELDS:
        components = {gate: _blocked_component("missing_or_unknown_preflight_input") for gate in _CHECKED_GATES}
        return _base_report(None, components, ["missing_or_unknown_preflight_input"], [], "block")
    if _contains_unsafe_value(inputs):
        components = {gate: _blocked_component("unsafe_preflight_input") for gate in _CHECKED_GATES}
        return _base_report(inputs, components, ["unsafe_preflight_input"], [], "block")

    approval = inputs["approval"]
    image_lock = inputs["image_lock"]
    behavior_policy = inputs["behavior_policy"]
    observer_evidence = inputs["observer_evidence"]
    image_lock_material = inputs["image_lock_material"]
    behavior_policy_material = inputs["behavior_policy_material"]
    static_transition_report = inputs["static_transition_report"]

    approval_report = validate_unknown_repo_command_approval_report(approval)
    image_lock_report = validate_sandbox_image_lock_report(image_lock)
    image_lock_binding_report = validate_sandbox_image_lock_binding_report(approval, image_lock, behavior_policy, image_lock_material)
    behavior_policy_report = _behavior_policy_validation_report(behavior_policy)
    observer_evidence_report = validate_normalized_observer_evidence_report(observer_evidence)
    behavior_policy_binding_report = validate_sandbox_behavior_policy_binding_report(
        approval,
        behavior_policy,
        observer_evidence,
        behavior_policy_material,
        image_lock_binding_validation_result=image_lock_binding_report,
    )
    try:
        static_transition_validation = _validate_static_transition_report(static_transition_report)
    except (TypeError, ValueError):
        static_transition_validation = _invalid_static_transition_result()

    component_results = {
        "approval_validation": approval_report,
        "image_lock_validation": image_lock_report,
        "image_lock_binding_validation": image_lock_binding_report,
        "behavior_policy_validation": behavior_policy_report,
        "observer_evidence_validation": observer_evidence_report,
        "behavior_policy_binding_validation": behavior_policy_binding_report,
        "static_transition_validation": static_transition_validation,
    }
    blockers = [f"{gate}_blocked" for gate, result in component_results.items() if result.get("verdict") == "block"]
    warnings = [f"{gate}_warn" for gate, result in component_results.items() if result.get("verdict") in {"warn", "needs_review"}]
    verdict = "block" if blockers else "warn" if warnings else "pass"
    return _base_report(inputs, component_results, blockers, warnings, verdict)
