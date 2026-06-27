"""Controlled-fixture-only static transition composition.

This module assembles in-memory test mappings for static validation.  It never
writes an approval artifact, authorizes execution, or connects to a runner,
Docker, strace, or a runtime hook.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .approval_draft import generate_unknown_repo_approval_draft, validate_unknown_repo_approval_draft
from .approval_promotion import validate_unknown_repo_command_approval_report
from .behavior_policy import behavior_policy_binding_fingerprint, build_default_behavior_policy, evaluate_behavior_policy
from .behavior_policy_binding import validate_sandbox_behavior_policy_binding_report
from .dry_run import _clean_controlled_evidence
from .image_lock import build_registry_image_lock, validate_sandbox_image_lock_report
from .lock_binding import validate_sandbox_image_lock_binding_report
from .observer_evidence import validate_normalized_observer_evidence_report
from .unknown_profile import profile_unknown_repo


STATIC_TRANSITION_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_STATIC_TRANSITION_VALIDATION = "sandbox_static_transition_validation"
_CONTROLLED_FIXTURE_PREFIX = "sandbox-unknown-profile-"
_CONTROLLED_STATIC_COMMIT = "c" * 40


def _is_controlled_fixture(root: Path) -> bool:
    return root.parent.name == "fixtures" and root.name.startswith(_CONTROLLED_FIXTURE_PREFIX)


def _argv_fingerprint(argv: list[str]) -> str:
    raw = json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _t3_exception() -> dict[str, Any]:
    return {
        "exception_rationale": "controlled_static_transition_fixture",
        "exception_scope": "single_exact_command",
        "phase1_required": True,
        "phase1_5_required": True,
        "subprocess_allowlist": [],
        "stronger_isolation_required": True,
        "expiry": "2099-01-02T00:00:00Z",
        "reviewers": ["human_reviewer"],
        "network_none_required": True,
        "shell_false_required": True,
        "disallowed_if_direct_url_or_vcs_or_credential_or_obfuscation": True,
    }


def _in_memory_approval(draft: Mapping[str, Any], policy: Mapping[str, Any], lock: Mapping[str, Any], *, t3_exception_present: bool) -> dict[str, Any]:
    candidate = draft["candidate"]
    if not isinstance(candidate, Mapping):
        raise ValueError("controlled draft has no candidate")
    image = lock["images"][0]
    tier = draft["source_risk_tier"]
    return {
        "schema_version": "0.1-draft",
        "report_kind": "sandbox_unknown_repo_command_approval",
        "approval_id": "controlled-static-transition",
        "approved": True,
        "approval_status": "approved_human_reviewed",
        "approval_scope": {"scope": "single_command", "phase": candidate["phase"], "kind": candidate["kind"]},
        "repo_scope": {"repository_identity": draft["repo_scope"]["repository_identity"], "commit": _CONTROLLED_STATIC_COMMIT, "path": "<repo>", "working_tree_status": "clean_verified"},
        "source_approval_draft": {"schema_version": draft["schema_version"], "report_kind": draft["report_kind"], "candidate_key": draft["candidate_key"], "exact_match_key": draft["exact_match_key"]},
        "source_profile_report": {"schema_version": draft["source_profile_report"]["schema_version"], "report_kind": draft["source_profile_report"]["report_kind"], "repository_identity": draft["repo_scope"]["repository_identity"]},
        "source_risk_tier": tier,
        "command": {"phase": candidate["phase"], "kind": candidate["kind"], "cwd": candidate["cwd"], "argv": candidate["argv"], "env_allowlist": candidate["env_allowlist"], "shell": False, "network_policy": "none"},
        "image_lock_binding": {"schema_version": lock["schema_version"], "report_kind": lock["report_kind"], "lock_id": lock["lock_id"], "registry_digest": image["registry_digest"], "expected_image_id": image["expected_image_id"], "platform": image["expected_platform"], "tool_versions": image["tool_versions"], "pull_policy": "never"},
        "behavior_policy_binding": {"schema_version": policy["schema_version"], "report_kind": policy["report_kind"], "policy_id": policy["policy_id"], "binding_fingerprint": behavior_policy_binding_fingerprint(policy)},
        "candidate_key": draft["candidate_key"],
        "exact_match_key": draft["exact_match_key"],
        "lifecycle": {"created_at": "2099-01-01T00:00:00Z", "expires_at": "2099-01-02T00:00:00Z", "created_by": "human_creator", "reviewed_by": "human_reviewer", "reviewed_at": "2099-01-01T00:01:00Z", "review_rationale": "controlled_static_transition_review", "review_evidence_handle": "review-record-001"},
        "human_review_requirements": ["verify_exact_candidate", "verify_image_and_policy_binding"],
        "revocation": {"state": "active", "invalidation_conditions": ["commit_changed", "candidate_changed", "policy_changed", "image_changed"]},
        "t3_exception": _t3_exception() if tier == "T3" and t3_exception_present else None,
        "limitations": ["in_memory_controlled_fixture_only"],
        "residual_risks": ["runner_not_connected"],
    }


def _image_lock_material(approval: Mapping[str, Any], lock: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    command = approval["command"]
    repo = approval["repo_scope"]
    image = lock["images"][0]
    runtime = lock["required_runtime_flags"]
    return {
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


def _behavior_policy_material(approval: Mapping[str, Any], policy: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    command = approval["command"]
    return {
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


def build_controlled_static_transition_inputs(
    repo_path: str | Path,
    *,
    phase: str = "phase2_install_probe",
    kind: str | None = None,
    argv: tuple[str, ...] = ("python", "-m", "build"),
    env_allowlist: tuple[str, ...] = ("PYTHONPATH",),
    t3_exception_present: bool = True,
) -> dict[str, Any]:
    """Build controlled in-memory inputs only; never write an approval file."""
    root = Path(repo_path).resolve()
    if not _is_controlled_fixture(root):
        raise ValueError("static transition helper accepts controlled fixtures only")
    profile = profile_unknown_repo(root)
    tier = profile["risk"]["tier"]
    candidate_kind = kind or ("harmless_static_probe" if tier == "T1" else "install_probe")
    if tier in {"T0", "T4", "T5"}:
        draft = generate_unknown_repo_approval_draft(root, source_profile=profile)
        return {"profile": profile, "draft": draft, "approval": None, "image_lock": None, "behavior_policy": None, "observer_evidence": None, "image_lock_material": None, "behavior_policy_material": None}
    draft = generate_unknown_repo_approval_draft(root, phase=phase, kind=candidate_kind, cwd="/workspace", argv=argv, env_allowlist=env_allowlist, source_profile=profile)
    candidate = draft["candidate"]
    if not isinstance(candidate, Mapping):
        raise ValueError("controlled transition draft did not produce a candidate")
    lock = build_registry_image_lock()
    policy = build_default_behavior_policy(
        candidate_key=draft["candidate_key"],
        repo_identity=draft["repo_scope"]["repository_identity"],
        commit=_CONTROLLED_STATIC_COMMIT,
        phase=candidate["phase"],
        kind=candidate["kind"],
        cwd=candidate["cwd"],
        argv=tuple(candidate["argv"]),
        env_allowlist=tuple(candidate["env_allowlist"]),
        image_policy_schema_version=lock["schema_version"],
    )
    evidence = _clean_controlled_evidence(phase=candidate["phase"], kind=candidate["kind"], argv=tuple(candidate["argv"]))
    approval = _in_memory_approval(draft, policy, lock, t3_exception_present=t3_exception_present)
    return {
        "profile": profile,
        "draft": draft,
        "approval": approval,
        "image_lock": lock,
        "behavior_policy": policy,
        "observer_evidence": evidence,
        "image_lock_material": _image_lock_material(approval, lock, policy),
        "behavior_policy_material": _behavior_policy_material(approval, policy, evidence),
    }


def _component(valid: bool, verdict: str, **details: Any) -> dict[str, Any]:
    return {"valid": valid, "verdict": verdict, **details}


def _blocked_component() -> dict[str, Any]:
    return _component(False, "block", reason="upstream_candidate_or_component_unavailable")


def _unsupported_fixture_report(fixture_name: str) -> dict[str, Any]:
    return {
        "schema_version": STATIC_TRANSITION_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_STATIC_TRANSITION_VALIDATION,
        "mode": "static_transition_test",
        "fixture_name": fixture_name,
        "source_risk_tier": "unavailable",
        "transition_status": "block",
        "approved": False,
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "observer_capture_performed": False,
        "approval_artifact_generated": False,
        "live_candidate_generated": False,
        "component_results": {},
        "blockers": ["controlled_fixture_required"],
        "warnings": [],
        "limitations": ["The helper accepts only repository-controlled fixture directories; no profile or execution action was started."],
        "residual_risks": ["unsupported_transition_input"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }


def run_controlled_static_transition(
    repo_path: str | Path,
    *,
    fixture_name: str | None = None,
    inputs: Mapping[str, Any] | None = None,
    phase: str = "phase2_install_probe",
    kind: str | None = None,
    argv: tuple[str, ...] = ("python", "-m", "build"),
    env_allowlist: tuple[str, ...] = ("PYTHONPATH",),
    t3_exception_present: bool = True,
) -> dict[str, Any]:
    """Validate the controlled static transition without creating an approval.

    ``inputs`` is test injection for deep-copied, in-memory controlled fixture
    mappings.  It is never serialized or treated as runner authorization.
    """
    root = Path(repo_path).resolve()
    name = fixture_name or root.name.removeprefix(_CONTROLLED_FIXTURE_PREFIX)
    if not _is_controlled_fixture(root):
        return _unsupported_fixture_report(name if name else "controlled-fixture-required")
    try:
        values = copy.deepcopy(dict(inputs)) if inputs is not None else build_controlled_static_transition_inputs(root, phase=phase, kind=kind, argv=argv, env_allowlist=env_allowlist, t3_exception_present=t3_exception_present)
        profile, draft = values["profile"], values["draft"]
        validate_unknown_repo_approval_draft(draft)
    except (KeyError, TypeError, ValueError):
        return _unsupported_fixture_report(name)

    tier = profile["risk"]["tier"]
    component_results: dict[str, Any] = {
        "profile": _component(True, "pass", risk_tier=tier, disposition=profile["risk"]["disposition"]),
        "draft": _component(True, "pass" if draft["candidate"] is not None else "needs_review", source_risk_tier=draft["source_risk_tier"], candidate_key_present=draft["candidate_key"] is not None),
    }
    blockers: list[str] = []
    warnings: list[str] = []
    candidate = draft["candidate"]
    if tier in {"T0", "T4", "T5"} or candidate is None:
        skipped = _component(False, "needs_review", reason="candidate_not_available_for_static_transition")
        component_results.update({
            "approval_validation": skipped,
            "image_lock_validation": skipped,
            "image_lock_binding_validation": skipped,
            "observer_evidence_validation": skipped,
            "behavior_policy_binding_validation": skipped,
            "behavior_policy_verdict": skipped,
        })
        if tier in {"T4", "T5"}:
            blockers.append("risk_tier_not_promotable")
            status = "block"
        else:
            warnings.append("candidate_free_static_transition")
            status = "warn"
        return _final_report(name, tier, status, draft, component_results, blockers, warnings)

    approval = values["approval"]
    lock = values["image_lock"]
    policy = values["behavior_policy"]
    evidence = values["observer_evidence"]
    approval_report = validate_unknown_repo_command_approval_report(approval)
    lock_report = validate_sandbox_image_lock_report(lock)
    observer_report = validate_normalized_observer_evidence_report(evidence)
    image_binding_report = validate_sandbox_image_lock_binding_report(approval, lock, policy, values["image_lock_material"])
    behavior_binding_report = validate_sandbox_behavior_policy_binding_report(approval, policy, evidence, values["behavior_policy_material"], image_lock_binding_validation_result=image_binding_report)
    verdict = evaluate_behavior_policy(policy, evidence)
    component_results.update({
        "approval_validation": approval_report,
        "image_lock_validation": lock_report,
        "image_lock_binding_validation": image_binding_report,
        "observer_evidence_validation": observer_report,
        "behavior_policy_binding_validation": behavior_binding_report,
        "behavior_policy_verdict": verdict,
    })
    required = (approval_report, lock_report, image_binding_report, observer_report, behavior_binding_report, verdict)
    if any(item.get("verdict") == "block" for item in required):
        blockers.append("static_transition_component_blocked")
        status = "block"
    elif tier == "T2":
        warnings.append("phase1_and_phase1_5_requirements_remain_unverified")
        status = "warn"
    elif tier == "T3":
        warnings.append("t3_exception_remains_human_review_boundary")
        status = "warn"
    elif profile["risk"]["disposition"] == "needs_review" and "parse_or_ambiguity" in profile["risk"]["reasons"]:
        warnings.append("profile_parse_or_ambiguity_requires_review")
        status = "warn"
    else:
        status = "pass"
    return _final_report(name, tier, status, draft, component_results, blockers, warnings)


def _final_report(
    fixture_name: str,
    tier: str,
    status: str,
    draft: Mapping[str, Any],
    component_results: Mapping[str, Any],
    blockers: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": STATIC_TRANSITION_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_STATIC_TRANSITION_VALIDATION,
        "mode": "static_transition_test",
        "fixture_name": fixture_name,
        "source_risk_tier": tier,
        "transition_status": status,
        "approved": False,
        "execution_permitted": False,
        "runner_connected": False,
        "docker_contacted": False,
        "observer_capture_performed": False,
        "approval_artifact_generated": False,
        "live_candidate_generated": draft["live_candidate_generated"],
        "component_results": dict(component_results),
        "blockers": blockers,
        "warnings": warnings,
        "limitations": [
            "Controlled-fixture static transition test only; no approval artifact file was generated or promoted.",
            "A static PASS means supplied bindings match only; it is not runner authorization or live readiness.",
            "No Docker, runner, observer capture, strace, runtime hook, network, fetch, or live command was started.",
        ],
        "residual_risks": ["runner_preflight_and_live_execution_remain_unimplemented", "in_memory_approved_shape_is_not_an_executable_approval"],
        "redaction_status": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }
