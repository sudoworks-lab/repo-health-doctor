from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.approval_promotion import validate_unknown_repo_command_approval
from repo_health_doctor.sandbox.behavior_policy import behavior_policy_binding_fingerprint, build_default_behavior_policy
from repo_health_doctor.sandbox.image_lock import build_registry_image_lock
from repo_health_doctor.sandbox.lock_binding import (
    LOCK_BINDING_SCHEMA_VERSION,
    REPORT_KIND_IMAGE_LOCK_BINDING_VALIDATION,
    validate_sandbox_image_lock_binding_report,
)


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-image-lock-binding-validation.schema.json"
KEY = "sha256:" + "a" * 64
IDENTITY = "sha256:" + "b" * 64
COMMIT = "d" * 40


def _synthetic_host_path(*parts: str) -> str:
    return "".join(parts)


def _approval(lock: dict[str, object], policy: dict[str, object]) -> dict[str, object]:
    image = lock["images"][0]  # type: ignore[index]
    return {
        "schema_version": "0.1-draft",
        "report_kind": "sandbox_unknown_repo_command_approval",
        "approval_id": "approval-static-binding-only",
        "approved": True,
        "approval_status": "approved_human_reviewed",
        "approval_scope": {"scope": "single_command", "phase": "phase2_install_probe", "kind": "install_probe"},
        "repo_scope": {"repository_identity": IDENTITY, "commit": COMMIT, "path": "<repo>", "working_tree_status": "clean_verified"},
        "source_approval_draft": {"schema_version": "0.1-draft", "report_kind": "sandbox_approval_draft", "candidate_key": KEY, "exact_match_key": KEY},
        "source_profile_report": {"schema_version": "0.1-draft", "report_kind": "sandbox_unknown_repo_profile", "repository_identity": IDENTITY},
        "source_risk_tier": "T1",
        "command": {"phase": "phase2_install_probe", "kind": "install_probe", "cwd": "/workspace", "argv": ["python", "-m", "build"], "env_allowlist": ["PYTHONPATH"], "shell": False, "network_policy": "none"},
        "image_lock_binding": {
            "schema_version": lock["schema_version"],
            "report_kind": lock["report_kind"],
            "lock_id": lock["lock_id"],
            "registry_digest": image["registry_digest"],
            "expected_image_id": image["expected_image_id"],
            "platform": image["expected_platform"],
            "tool_versions": image["tool_versions"],
            "pull_policy": "never",
        },
        "behavior_policy_binding": {
            "schema_version": policy["schema_version"],
            "report_kind": policy["report_kind"],
            "policy_id": policy["policy_id"],
            "binding_fingerprint": behavior_policy_binding_fingerprint(policy),
        },
        "candidate_key": KEY,
        "exact_match_key": KEY,
        "lifecycle": {"created_at": "2099-01-01T00:00:00Z", "expires_at": "2099-01-02T00:00:00Z", "created_by": "human_creator", "reviewed_by": "human_reviewer", "reviewed_at": "2099-01-01T00:01:00Z", "review_rationale": "reviewed_exact_static_binding", "review_evidence_handle": "review-record-001"},
        "human_review_requirements": ["verify_exact_candidate", "verify_image_and_policy_binding"],
        "revocation": {"state": "active", "invalidation_conditions": ["commit_changed", "candidate_changed", "policy_changed", "image_changed"]},
        "t3_exception": None,
        "limitations": ["static_validator_only"],
        "residual_risks": ["runner_not_connected"],
    }


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


def _material(approval: dict[str, object], lock: dict[str, object], policy: dict[str, object]) -> dict[str, object]:
    command = approval["command"]  # type: ignore[assignment]
    repo = approval["repo_scope"]  # type: ignore[assignment]
    image = lock["images"][0]  # type: ignore[index]
    runtime = lock["required_runtime_flags"]  # type: ignore[assignment]
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


class SandboxImageLockBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = build_registry_image_lock()
        self.policy = _policy()
        self.approval = _approval(self.lock, self.policy)
        self.material = _material(self.approval, self.lock, self.policy)
        validate_unknown_repo_command_approval(self.approval)

    def _report(self, approval: dict[str, object] | None = None, lock: dict[str, object] | None = None, policy: dict[str, object] | None = None, material: dict[str, object] | None = None) -> dict[str, object]:
        return validate_sandbox_image_lock_binding_report(
            approval or self.approval,
            lock or self.lock,
            policy or self.policy,
            material or self.material,
        )

    def _blocked(self, mutate: object) -> None:
        approval, lock, policy, material = (copy.deepcopy(self.approval), copy.deepcopy(self.lock), copy.deepcopy(self.policy), copy.deepcopy(self.material))
        assert callable(mutate)
        mutate(approval, lock, policy, material)
        report = self._report(approval, lock, policy, material)
        self.assertEqual(report["verdict"], "block")
        self.assertEqual(report["binding_status"], "invalid_or_mismatch")
        self.assertFalse(report["execution_permitted"])
        self.assertFalse(report["runner_connected"])
        self.assertFalse(report["docker_contacted"])

    def test_valid_static_bindings_pass_without_runner_or_docker(self) -> None:
        report = self._report()
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["binding_status"], "matched")
        self.assertEqual(report["schema_version"], LOCK_BINDING_SCHEMA_VERSION)
        self.assertEqual(report["report_kind"], REPORT_KIND_IMAGE_LOCK_BINDING_VALIDATION)
        self.assertFalse(report["execution_permitted"])
        self.assertFalse(report["runner_connected"])
        self.assertFalse(report["docker_contacted"])

    def test_report_schema_is_closed_and_matches_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        report = self._report()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [LOCK_BINDING_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_IMAGE_LOCK_BINDING_VALIDATION])
        for field in schema["required"]:
            self.assertIn(field, report)

    def test_image_lock_id_and_digest_mismatches_block(self) -> None:
        self._blocked(lambda approval, _lock, _policy, _material: approval["image_lock_binding"].update({"lock_id": "other-lock"}))
        self._blocked(lambda approval, _lock, _policy, _material: approval["image_lock_binding"].update({"registry_digest": "sha256:" + "c" * 64}))

    def test_behavior_policy_version_and_fingerprint_mismatches_block(self) -> None:
        self._blocked(lambda approval, _lock, _policy, _material: approval["behavior_policy_binding"].update({"schema_version": "99.0"}))
        self._blocked(lambda approval, _lock, _policy, _material: approval["behavior_policy_binding"].update({"binding_fingerprint": "sha256:" + "c" * 64}))
        self._blocked(lambda _approval, _lock, policy, _material: policy.update({"policy_id": "behavior-policy:sha256:" + "c" * 64}))

    def test_candidate_material_requires_image_and_behavior_bindings(self) -> None:
        self._blocked(lambda _approval, _lock, _policy, material: material.pop("image_lock_id"))
        self._blocked(lambda _approval, _lock, _policy, material: material.pop("behavior_policy_binding_fingerprint"))

    def test_unsafe_runtime_flags_block(self) -> None:
        for field, value in (("pull_policy", "always"), ("network", "host"), ("shell", True), ("host_home", True), ("docker_socket", True)):
            with self.subTest(field=field):
                self._blocked(lambda _approval, lock, _policy, _material, field=field, value=value: lock["required_runtime_flags"].update({field: value}))

    def test_local_sanctioned_image_warns_and_has_dev_only_limitations(self) -> None:
        lock = copy.deepcopy(self.lock)
        image = lock["images"][0]
        image.update({"distribution": "local_dev_only", "registry_reference": "rhd-python312-strace:local", "registry_digest": None, "expected_image_id": "sha256:" + "c" * 64, "purpose": "controlled_fixture_dev_only", "local_sanctioned_allowed": True, "local_sanctioned_limitations": ["dev_only_not_portable"]})
        approval = _approval(lock, self.policy)
        material = _material(approval, lock, self.policy)
        report = self._report(approval, lock, self.policy, material)
        self.assertEqual(report["verdict"], "warn")
        self.assertIn("local_sanctioned_image_dev_only", report["warnings"])
        self.assertIn("development-only", " ".join(report["limitations"]))
        image["expected_image_id"] = "sha256:short"
        self.assertEqual(self._report(approval, lock, self.policy, material)["verdict"], "block")

    def test_expired_and_unpromotable_tiers_block(self) -> None:
        self._blocked(lambda approval, _lock, _policy, _material: approval["lifecycle"].update({"expires_at": "2000-01-01T00:00:00Z"}))
        for tier in ("T4", "T5"):
            with self.subTest(tier=tier):
                self._blocked(lambda approval, _lock, _policy, _material, tier=tier: approval.update({"source_risk_tier": tier}))

    def test_raw_host_path_or_secret_like_value_does_not_leak(self) -> None:
        for raw in (_synthetic_host_path("/ho", "me", "/private/binding"), "sk-binding_0123456789abcdef"):
            with self.subTest(raw=raw):
                approval = copy.deepcopy(self.approval)
                approval["lifecycle"]["review_rationale"] = raw
                payload = json.dumps(self._report(approval, self.lock, self.policy, self.material))
                self.assertNotIn(raw, payload)
                self.assertIn("invalid_or_mismatched_static_binding", payload)
