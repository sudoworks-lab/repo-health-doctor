from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.approval_promotion import (
    COMMAND_APPROVAL_SCHEMA_VERSION,
    REPORT_KIND_COMMAND_APPROVAL,
    REPORT_KIND_COMMAND_APPROVAL_VALIDATION,
    validate_unknown_repo_command_approval,
    validate_unknown_repo_command_approval_report,
)


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-unknown-repo-command-approval.schema.json"
KEY = "sha256:" + "a" * 64
IDENTITY = "sha256:" + "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
COMMIT = "d" * 40


def valid_artifact(*, tier: str = "T1") -> dict[str, object]:
    artifact: dict[str, object] = {
        "schema_version": "0.1-draft",
        "report_kind": "sandbox_unknown_repo_command_approval",
        "approval_id": "approval-static-validation-only",
        "approved": True,
        "approval_status": "approved_human_reviewed",
        "approval_scope": {"scope": "single_command", "phase": "phase2_install_probe", "kind": "install_probe"},
        "repo_scope": {"repository_identity": IDENTITY, "commit": COMMIT, "path": "<repo>", "working_tree_status": "clean_verified"},
        "source_approval_draft": {"schema_version": "0.1-draft", "report_kind": "sandbox_approval_draft", "candidate_key": KEY, "exact_match_key": KEY},
        "source_profile_report": {"schema_version": "0.1-draft", "report_kind": "sandbox_unknown_repo_profile", "repository_identity": IDENTITY},
        "source_risk_tier": tier,
        "command": {"phase": "phase2_install_probe", "kind": "install_probe", "cwd": "/workspace", "argv": ["python", "-m", "build"], "env_allowlist": ["PYTHONPATH"], "shell": False, "network_policy": "none"},
        "image_lock_binding": {"schema_version": "0.1-draft", "report_kind": "sandbox_image_lock", "lock_id": "python312-runtime-v1", "registry_digest": IMAGE_ID, "expected_image_id": None, "platform": {"os": "linux", "architecture": "amd64"}, "tool_versions": {"python": "3.12.x", "strace": "6.x"}, "pull_policy": "never"},
        "behavior_policy_binding": {"schema_version": "0.1-draft", "report_kind": "sandbox_command_behavior_policy", "policy_id": "behavior-policy:sha256:reviewed", "binding_fingerprint": KEY},
        "candidate_key": KEY,
        "exact_match_key": KEY,
        "lifecycle": {"created_at": "2099-01-01T00:00:00Z", "expires_at": "2099-01-02T00:00:00Z", "created_by": "human_creator", "reviewed_by": "human_reviewer", "reviewed_at": "2099-01-01T00:01:00Z", "review_rationale": "reviewed_exact_static_candidate", "review_evidence_handle": "review-record-001"},
        "human_review_requirements": ["verify_exact_candidate", "verify_image_and_policy_binding"],
        "revocation": {"state": "active", "invalidation_conditions": ["commit_changed", "candidate_changed", "policy_changed", "image_changed"]},
        "t3_exception": None,
        "limitations": ["static_validator_only"],
        "residual_risks": ["runner_not_connected"],
    }
    if tier == "T3":
        artifact["t3_exception"] = {
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
    return artifact


class UnknownRepositoryApprovalPromotionTests(unittest.TestCase):
    def _invalid(self, mutate: object) -> None:
        artifact = copy.deepcopy(valid_artifact())
        assert callable(mutate)
        mutate(artifact)
        report = validate_unknown_repo_command_approval_report(artifact)
        self.assertEqual(report["verdict"], "block")
        self.assertFalse(report["valid"])

    def test_valid_shape_is_read_only_validation_not_authorization(self) -> None:
        artifact = valid_artifact()
        validate_unknown_repo_command_approval(artifact)
        report = validate_unknown_repo_command_approval_report(artifact)
        self.assertEqual(report["verdict"], "pass")
        self.assertTrue(report["valid"])
        self.assertEqual(report["schema_version"], COMMAND_APPROVAL_SCHEMA_VERSION)
        self.assertEqual(report["report_kind"], REPORT_KIND_COMMAND_APPROVAL_VALIDATION)
        self.assertIn("not_runner_authorization", " ".join(report["warnings"]))

    def test_schema_is_closed_and_matches_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [COMMAND_APPROVAL_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_COMMAND_APPROVAL])
        for field in schema["required"]:
            self.assertIn(field, valid_artifact())

    def test_missing_unsupported_or_mismatched_schema_fields_block(self) -> None:
        self._invalid(lambda item: item.pop("schema_version"))
        self._invalid(lambda item: item.update({"schema_version": "99.0"}))
        self._invalid(lambda item: item.update({"report_kind": "wrong_kind"}))
        self._invalid(lambda item: item.pop("approval_scope"))
        self._invalid(lambda item: item.update({"network_exception": True}))

    def test_approved_shell_network_commit_and_dirty_worktree_are_fail_closed(self) -> None:
        self._invalid(lambda item: item.update({"approved": False}))
        self._invalid(lambda item: item["command"].update({"shell": True}))
        self._invalid(lambda item: item["command"].update({"network_policy": "host"}))
        self._invalid(lambda item: item["repo_scope"].update({"commit": "unavailable_static"}))
        self._invalid(lambda item: item["repo_scope"].update({"working_tree_status": "dirty"}))

    def test_candidate_image_policy_reviewer_and_expiry_bindings_block_when_missing_or_invalid(self) -> None:
        self._invalid(lambda item: item.pop("candidate_key"))
        self._invalid(lambda item: item.pop("image_lock_binding"))
        self._invalid(lambda item: item.pop("behavior_policy_binding"))
        self._invalid(lambda item: item["lifecycle"].pop("reviewed_by"))
        self._invalid(lambda item: item["lifecycle"].update({"expires_at": "2000-01-01T00:00:00Z"}))

    def test_t4_t5_rejected_and_t3_exception_is_required_and_closed(self) -> None:
        for tier in ("T4", "T5"):
            artifact = valid_artifact()
            artifact["source_risk_tier"] = tier
            self.assertEqual(validate_unknown_repo_command_approval_report(artifact)["verdict"], "block")
        t3 = valid_artifact(tier="T3")
        self.assertTrue(validate_unknown_repo_command_approval_report(t3)["valid"])
        missing_exception = valid_artifact(tier="T3")
        missing_exception["t3_exception"] = None
        self.assertEqual(validate_unknown_repo_command_approval_report(missing_exception)["verdict"], "block")
        missing_field = valid_artifact(tier="T3")
        missing_field["t3_exception"].pop("reviewers")  # type: ignore[union-attr]
        self.assertEqual(validate_unknown_repo_command_approval_report(missing_field)["verdict"], "block")

    def test_phase_mismatch_and_key_mismatch_block(self) -> None:
        self._invalid(lambda item: item["command"].update({"phase": "phase3_runtime_probe"}))
        self._invalid(lambda item: item["source_approval_draft"].update({"candidate_key": "sha256:" + "e" * 64}))

    def test_redaction_does_not_echo_raw_host_path_or_secret_like_value(self) -> None:
        raw_secret = "sk-" + "approval_0123456789abcdef"
        raw_host_path = "/" + "home/private/approval"
        for raw in (raw_secret, raw_host_path):
            with self.subTest(raw=raw):
                artifact = valid_artifact()
                artifact["lifecycle"]["review_rationale"] = raw
                payload = json.dumps(validate_unknown_repo_command_approval_report(artifact))
                self.assertNotIn(raw, payload)
                self.assertEqual(validate_unknown_repo_command_approval_report(artifact)["verdict"], "block")
