from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .approval_draft import generate_unknown_repo_approval_draft
from .behavior_policy import (
    BEHAVIOR_POLICY_SCHEMA_VERSION,
    build_default_behavior_policy,
    evaluate_behavior_policy,
)
from .image_lock import (
    IMAGE_LOCK_SCHEMA_VERSION,
    build_registry_image_lock,
    validate_sandbox_image_lock_report,
)
from .unknown_profile import profile_unknown_repo


REPORT_KIND_UNKNOWN_REPO_DRY_RUN = "sandbox_unknown_repo_dry_run"
DRY_RUN_SCHEMA_VERSION = "0.1-draft"
_CANDIDATE_KEY_FIELDS = [
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
    "image_policy",
    "behavior_policy_schema_version",
    "behavior_policy_report_kind",
]


def _clean_controlled_evidence(*, phase: str, kind: str, argv: tuple[str, ...]) -> dict[str, Any]:
    argv_fingerprint = "sha256:" + hashlib.sha256(
        json.dumps(list(argv), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "0.1-draft",
        "report_kind": "sandbox_normalized_observer_evidence",
        "evidence_id": "static-controlled-clean-evidence",
        "source": {
            "observer_mode": "strace_runtime_hook", "strace_available": True,
            "strace_log_present": True, "strace_parse_success": True,
            "runtime_hook_available": True, "runtime_hook_active": True,
            "runtime_hook_parse_success": True, "observer_degraded": False,
            "degraded_reasons": [],
        },
        "command": {"phase": phase, "kind": kind, "cwd": "/workspace", "argv_fingerprint": argv_fingerprint, "shell": False, "network_policy": "none"},
        "execution": {"return_code": 0, "timeout": False, "duration_ms": 0, "completed": True},
        "counts": {
            "process_event_count": 1, "unexpected_exec_count": 0,
            "subprocess_event_count": 0, "network_event_count": 0,
            "file_write_event_count": 0, "outside_allowed_write_count": 0,
            "denied_read_count": 0, "docker_socket_access_count": 0,
            "host_home_access_count": 0, "secret_event_count": 0,
            "outside_writable_delete_count": 0, "strace_parse_error_count": 0,
            "runtime_hook_parse_error_count": 0,
        },
        "flags": {"evidence_complete": True, "raw_logs_included": False, "stdout_included": False, "stderr_included": False, "host_paths_redacted": True, "secrets_redacted": True},
        "summaries": {"process_summary": ["clean"], "file_summary": ["clean"], "network_summary": ["none"], "secret_summary": ["none"], "limitations": ["static_synthetic_evidence"], "residual_risks": ["no_live_observation"]},
        "redaction": {"status": "redacted", "raw_host_path_present": False, "raw_secret_like_value_present": False},
    }


def run_unknown_repo_controlled_dry_run(
    repo_path: str | Path,
    *,
    phase: str = "phase2_install_probe",
    kind: str | None = None,
    argv: tuple[str, ...] = ("python", "-m", "build"),
    env_allowlist: tuple[str, ...] = ("PYTHONPATH",),
    image_lock: Mapping[str, Any] | None = None,
    behavior_policy: Mapping[str, Any] | None = None,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run static component composition only; never execute the target repository."""
    profile = profile_unknown_repo(repo_path)
    tier = profile["risk"]["tier"]
    candidate_kind = kind or ("harmless_static_probe" if tier == "T1" else "install_probe")
    if tier == "T0":
        draft = generate_unknown_repo_approval_draft(repo_path, source_profile=profile)
    else:
        draft = generate_unknown_repo_approval_draft(
            repo_path,
            phase=phase,
            kind=candidate_kind,
            cwd="/workspace",
            argv=argv,
            env_allowlist=env_allowlist,
            source_profile=profile,
        )
    lock_report = validate_sandbox_image_lock_report(image_lock or build_registry_image_lock())
    candidate = draft["candidate"]
    policy_report: dict[str, Any]
    if candidate is None:
        policy_report = {
            "valid": False,
            "verdict": "needs_review",
            "reason": "no_live_candidate_for_tier_or_scope",
            "schema_version": BEHAVIOR_POLICY_SCHEMA_VERSION,
        }
    else:
        policy = behavior_policy or build_default_behavior_policy(
            candidate_key=draft["candidate_key"],
            repo_identity=draft["repo_scope"]["repository_identity"],
            commit=draft["repo_scope"]["commit"],
            phase=candidate["phase"],
            kind=candidate["kind"],
            cwd=candidate["cwd"],
            argv=tuple(candidate["argv"]),
            env_allowlist=tuple(candidate["env_allowlist"]),
            image_policy_schema_version=IMAGE_LOCK_SCHEMA_VERSION,
        )
        verdict = evaluate_behavior_policy(
            policy,
            evidence or _clean_controlled_evidence(
                phase=candidate["phase"],
                kind=candidate["kind"],
                argv=tuple(candidate["argv"]),
            ),
        )
        binding_matches = isinstance(policy.get("binding"), Mapping) and all(
            (
                policy["binding"].get("candidate_key") == draft["candidate_key"],
                policy["binding"].get("repo_identity") == draft["repo_scope"]["repository_identity"],
                policy["binding"].get("phase") == candidate["phase"],
                policy["binding"].get("kind") == candidate["kind"],
                policy["binding"].get("cwd") == candidate["cwd"],
                policy["binding"].get("argv") == candidate["argv"],
                policy["binding"].get("env_allowlist") == candidate["env_allowlist"],
                policy["binding"].get("shell") is False,
                policy["binding"].get("network_policy") == "none",
                policy["binding"].get("image_policy_schema_version") == IMAGE_LOCK_SCHEMA_VERSION,
            )
        )
        policy_report = {
            "valid": verdict["policy_version"] != "unvalidated" and binding_matches,
            "verdict": verdict["verdict"] if binding_matches else "block",
            "schema_version": verdict["policy_version"],
            "report_kind": policy.get("report_kind") if isinstance(policy, Mapping) else "invalid",
        }
    component_blocked = lock_report["verdict"] == "block" or policy_report["verdict"] == "block"
    if component_blocked or tier in {"T4", "T5"}:
        overall_status = "block"
    else:
        overall_status = "needs_review"
    binding = {
        "candidate_key_present": draft["candidate_key"] is not None,
        "candidate_key_fields": list(_CANDIDATE_KEY_FIELDS),
        "source_risk_tier": tier,
        "repo_identity_matches_profile": draft["repo_scope"]["repository_identity"] == profile["repo_scope"]["repository_identity"],
        "phase": candidate["phase"] if candidate is not None else None,
        "behavior_policy_schema_version": policy_report["schema_version"],
        "image_lock_schema_version": lock_report["lock_schema_version"],
        "image_lock_contract_valid": lock_report["valid"],
        "image_lock_id_bound_by_contract": "image_lock_id" in (image_lock or build_registry_image_lock())["binding_contract"]["candidate_key_includes"],
        "image_identity_bound_by_contract": {"registry_digest", "expected_image_id"}.issubset((image_lock or build_registry_image_lock())["binding_contract"]["candidate_key_includes"]),
    }
    return {
        "schema_version": DRY_RUN_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_UNKNOWN_REPO_DRY_RUN,
        "mode": "static_controlled_dry_run",
        "overall_status": overall_status,
        "execution": {
            "docker_used": False,
            "image_pull_performed": False,
            "network_allowed": False,
            "shell_allowed": False,
            "phase1_fetch_requested": False,
            "phase2_live_requested": False,
            "phase3_live_requested": False,
        },
        "profile": {"risk_tier": tier, "disposition": profile["risk"]["disposition"]},
        "approval_draft": {
            "status": draft["status"],
            "approved": draft["approved"],
            "execution_permitted": draft["execution_permitted"],
            "live_candidate_generated": draft["live_candidate_generated"],
        },
        "behavior_policy": policy_report,
        "image_lock": {"valid": lock_report["valid"], "verdict": lock_report["verdict"]},
        "binding": binding,
        "limitations": [
            "Static dry-run integration validates contracts only; it is not live readiness.",
            "No repository command, Docker action, network action, fetch, approval promotion, or runtime phase was performed.",
        ],
        "residual_risks": [
            "unknown_repo_live_execution_not_implemented",
            "static_component_composition_is_not_a_safety_guarantee",
        ],
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }
