from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.approval_promotion import validate_unknown_repo_command_approval
from repo_health_doctor.sandbox.behavior_policy import behavior_policy_binding_fingerprint, build_default_behavior_policy
from repo_health_doctor.sandbox.behavior_policy_binding import (
    BEHAVIOR_POLICY_BINDING_SCHEMA_VERSION,
    REPORT_KIND_BEHAVIOR_POLICY_BINDING_VALIDATION,
    validate_sandbox_behavior_policy_binding_report,
)


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-behavior-policy-binding-validation.schema.json"
KEY = "sha256:" + "a" * 64
IDENTITY = "sha256:" + "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
COMMIT = "d" * 40


def _synthetic_host_path(*parts: str) -> str:
    return "".join(parts)


def _policy() -> dict[str, object]:
    return build_default_behavior_policy(
        candidate_key=KEY,
        repo_identity=IDENTITY,
        commit=COMMIT,
        phase="phase2_install_probe",
        kind="install_probe",
        cwd="/workspace",
        argv=("python", "-m", "build"),
        env_allowlist=("PYTHONPATH",),
        image_policy_schema_version="0.1-draft",
    )


def _approval(policy: dict[str, object], *, tier: str = "T1") -> dict[str, object]:
    approval: dict[str, object] = {
        "schema_version": "0.1-draft",
        "report_kind": "sandbox_unknown_repo_command_approval",
        "approval_id": "approval-policy-binding-only",
        "approved": True,
        "approval_status": "approved_human_reviewed",
        "approval_scope": {"scope": "single_command", "phase": "phase2_install_probe", "kind": "install_probe"},
        "repo_scope": {"repository_identity": IDENTITY, "commit": COMMIT, "path": "<repo>", "working_tree_status": "clean_verified"},
        "source_approval_draft": {"schema_version": "0.1-draft", "report_kind": "sandbox_approval_draft", "candidate_key": KEY, "exact_match_key": KEY},
        "source_profile_report": {"schema_version": "0.1-draft", "report_kind": "sandbox_unknown_repo_profile", "repository_identity": IDENTITY},
        "source_risk_tier": tier,
        "command": {"phase": "phase2_install_probe", "kind": "install_probe", "cwd": "/workspace", "argv": ["python", "-m", "build"], "env_allowlist": ["PYTHONPATH"], "shell": False, "network_policy": "none"},
        "image_lock_binding": {"schema_version": "0.1-draft", "report_kind": "sandbox_image_lock", "lock_id": "python312-runtime-v1", "registry_digest": IMAGE_ID, "expected_image_id": None, "platform": {"os": "linux", "architecture": "amd64"}, "tool_versions": {"python": "3.12.x", "strace": "6.x"}, "pull_policy": "never"},
        "behavior_policy_binding": {"schema_version": policy["schema_version"], "report_kind": policy["report_kind"], "policy_id": policy["policy_id"], "binding_fingerprint": behavior_policy_binding_fingerprint(policy)},
        "candidate_key": KEY,
        "exact_match_key": KEY,
        "lifecycle": {"created_at": "2099-01-01T00:00:00Z", "expires_at": "2099-01-02T00:00:00Z", "created_by": "human_creator", "reviewed_by": "human_reviewer", "reviewed_at": "2099-01-01T00:01:00Z", "review_rationale": "reviewed_exact_static_binding", "review_evidence_handle": "review-record-001"},
        "human_review_requirements": ["verify_exact_candidate", "verify_image_and_policy_binding"],
        "revocation": {"state": "active", "invalidation_conditions": ["commit_changed", "candidate_changed", "policy_changed", "image_changed"]},
        "t3_exception": None,
        "limitations": ["static_validator_only"],
        "residual_risks": ["runner_not_connected"],
    }
    if tier == "T3":
        approval["t3_exception"] = {
            "exception_rationale": "bounded_build_backend_review",
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
    return approval


def _evidence() -> dict[str, object]:
    return {
        "schema_version": "0.1-draft",
        "report_kind": "sandbox_normalized_observer_evidence",
        "evidence_id": "clean-binding-evidence",
        "source": {"observer_mode": "strace_runtime_hook", "strace_available": True, "strace_log_present": True, "strace_parse_success": True, "runtime_hook_available": True, "runtime_hook_active": True, "runtime_hook_parse_success": True, "observer_degraded": False, "degraded_reasons": []},
        "command": {"phase": "phase2_install_probe", "kind": "install_probe", "cwd": "/workspace", "argv_fingerprint": "sha256:" + hashlib.sha256(b'["python","-m","build"]').hexdigest(), "shell": False, "network_policy": "none"},
        "execution": {"return_code": 0, "timeout": False, "duration_ms": 1, "completed": True},
        "counts": {"process_event_count": 0, "unexpected_exec_count": 0, "subprocess_event_count": 0, "network_event_count": 0, "file_write_event_count": 0, "outside_allowed_write_count": 0, "denied_read_count": 0, "docker_socket_access_count": 0, "host_home_access_count": 0, "secret_event_count": 0, "outside_writable_delete_count": 0, "strace_parse_error_count": 0, "runtime_hook_parse_error_count": 0},
        "flags": {"evidence_complete": True, "raw_logs_included": False, "stdout_included": False, "stderr_included": False, "host_paths_redacted": True, "secrets_redacted": True},
        "summaries": {"process_summary": ["clean"], "file_summary": ["clean"], "network_summary": ["none"], "secret_summary": ["none"], "limitations": ["static_fixture"], "residual_risks": ["observed_scope_only"]},
        "redaction": {"status": "redacted", "raw_host_path_present": False, "raw_secret_like_value_present": False},
    }


def _material(approval: dict[str, object], policy: dict[str, object], evidence: dict[str, object]) -> dict[str, object]:
    command = approval["command"]  # type: ignore[assignment]
    return {
        "candidate_key": approval["candidate_key"],
        "exact_match_key": approval["exact_match_key"],
        "phase": command["phase"],
        "kind": command["kind"],
        "cwd": command["cwd"],
        "argv_fingerprint": evidence["command"]["argv_fingerprint"],  # type: ignore[index]
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


class BehaviorPolicyBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = _policy()
        self.approval = _approval(self.policy)
        self.evidence = _evidence()
        self.material = _material(self.approval, self.policy, self.evidence)
        validate_unknown_repo_command_approval(self.approval)

    def _report(self, approval: dict[str, object] | None = None, policy: dict[str, object] | None = None, evidence: dict[str, object] | None = None, material: dict[str, object] | None = None) -> dict[str, object]:
        return validate_sandbox_behavior_policy_binding_report(
            approval or self.approval,
            policy or self.policy,
            evidence or self.evidence,
            material or self.material,
        )

    def _blocked(self, mutate: object) -> None:
        approval, policy, evidence, material = (copy.deepcopy(self.approval), copy.deepcopy(self.policy), copy.deepcopy(self.evidence), copy.deepcopy(self.material))
        assert callable(mutate)
        mutate(approval, policy, evidence, material)
        report = self._report(approval, policy, evidence, material)
        self.assertEqual(report["verdict"], "block")
        self.assertEqual(report["binding_status"], "invalid_or_mismatch")
        self.assertFalse(report["execution_permitted"])
        self.assertFalse(report["runner_connected"])
        self.assertFalse(report["docker_contacted"])
        self.assertFalse(report["observer_capture_performed"])

    def test_valid_static_binding_passes_without_runner_docker_or_observer_capture(self) -> None:
        report = self._report()
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["binding_status"], "matched")
        self.assertEqual(report["schema_version"], BEHAVIOR_POLICY_BINDING_SCHEMA_VERSION)
        self.assertEqual(report["report_kind"], REPORT_KIND_BEHAVIOR_POLICY_BINDING_VALIDATION)
        self.assertFalse(report["execution_permitted"])
        self.assertFalse(report["runner_connected"])
        self.assertFalse(report["docker_contacted"])
        self.assertFalse(report["observer_capture_performed"])

    def test_report_schema_is_closed_and_matches_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        report = self._report()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [BEHAVIOR_POLICY_BINDING_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_BEHAVIOR_POLICY_BINDING_VALIDATION])
        for field in schema["required"]:
            self.assertIn(field, report)

    def test_approval_policy_and_candidate_bindings_fail_closed(self) -> None:
        self._blocked(lambda approval, _policy, _evidence, _material: approval["behavior_policy_binding"].update({"policy_id": "behavior-policy:sha256:" + "e" * 64}))
        self._blocked(lambda approval, _policy, _evidence, _material: approval["behavior_policy_binding"].update({"binding_fingerprint": "sha256:" + "e" * 64}))
        self._blocked(lambda _approval, policy, _evidence, _material: policy["binding"].update({"argv": ["python", "-m", "other"]}))
        self._blocked(lambda _approval, _policy, _evidence, material: material.pop("behavior_policy_id"))
        self._blocked(lambda _approval, _policy, _evidence, material: material.pop("evidence_id"))

    def test_command_and_denied_runtime_mismatches_fail_closed(self) -> None:
        for field, value in (("phase", "phase3_runtime_probe"), ("kind", "other_probe"), ("cwd", "/workspace/subdir"), ("argv_fingerprint", "sha256:" + "e" * 64), ("shell", True), ("network_policy", "host")):
            with self.subTest(field=field):
                self._blocked(lambda _approval, _policy, evidence, _material, field=field, value=value: evidence["command"].update({field: value}))

    def test_observer_requirements_and_parse_failures_fail_closed(self) -> None:
        cases = (
            lambda evidence: evidence["source"].update({"strace_available": False}),
            lambda evidence: evidence["source"].update({"strace_log_present": False}),
            lambda evidence: evidence["source"].update({"strace_parse_success": False}),
            lambda evidence: evidence["source"].update({"runtime_hook_active": False}),
            lambda evidence: evidence["flags"].update({"evidence_complete": False}),
            lambda evidence: evidence["source"].update({"observer_degraded": True, "degraded_reasons": ["observer_partial"]}),
            lambda evidence: evidence["counts"].update({"strace_parse_error_count": 1}),
            lambda evidence: evidence["counts"].update({"runtime_hook_parse_error_count": 1}),
        )
        for mutate in cases:
            with self.subTest(mutate=mutate):
                self._blocked(lambda _approval, _policy, evidence, _material, mutate=mutate: mutate(evidence))

    def test_expiry_tiers_and_t3_exception_metadata_fail_closed(self) -> None:
        self._blocked(lambda approval, _policy, _evidence, _material: approval["lifecycle"].update({"expires_at": "2000-01-01T00:00:00Z"}))
        for tier in ("T4", "T5"):
            with self.subTest(tier=tier):
                self._blocked(lambda approval, _policy, _evidence, _material, tier=tier: approval.update({"source_risk_tier": tier}))
        t3 = _approval(self.policy, tier="T3")
        t3["t3_exception"] = None
        self.assertEqual(self._report(t3, self.policy, self.evidence, _material(t3, self.policy, self.evidence))["verdict"], "block")

    def test_unsafe_values_do_not_leak_into_report(self) -> None:
        for raw in (_synthetic_host_path("/ho", "me", "/private/binding"), "sk-" + "binding_0123456789abcdef"):
            with self.subTest(raw=raw):
                evidence = copy.deepcopy(self.evidence)
                evidence["summaries"]["file_summary"] = [raw]
                payload = json.dumps(self._report(self.approval, self.policy, evidence, self.material))
                self.assertNotIn(raw, payload)
                self.assertIn("invalid_or_mismatched_behavior_policy_binding", payload)
