from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.approval_draft import generate_unknown_repo_approval_draft
from repo_health_doctor.sandbox.behavior_policy import build_default_behavior_policy
from repo_health_doctor.sandbox.dry_run import REPORT_KIND_UNKNOWN_REPO_DRY_RUN, run_unknown_repo_controlled_dry_run
from repo_health_doctor.sandbox.image_lock import build_registry_image_lock


FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"


class UnknownRepositoryControlledDryRunTests(unittest.TestCase):
    def _fixture(self, name: str) -> Path:
        return FIXTURES_ROOT / f"sandbox-unknown-profile-{name}"

    def test_static_workflow_covers_t0_to_t5(self) -> None:
        expected = {"t0": "T0", "t1": "T1", "t2": "T2", "t3": "T3", "t4": "T4", "t5": "T5"}
        for fixture, tier in expected.items():
            with self.subTest(fixture=fixture):
                report = run_unknown_repo_controlled_dry_run(self._fixture(fixture))
                self.assertEqual(report["report_kind"], REPORT_KIND_UNKNOWN_REPO_DRY_RUN)
                self.assertEqual(report["mode"], "static_controlled_dry_run")
                self.assertEqual(report["profile"]["risk_tier"], tier)
                self.assertFalse(any(report["execution"].values()))
                self.assertFalse(report["approval_draft"]["approved"])
                self.assertFalse(report["approval_draft"]["execution_permitted"])
                if tier in {"T4", "T5"}:
                    self.assertFalse(report["approval_draft"]["live_candidate_generated"])
                    self.assertEqual(report["overall_status"], "block")

    def test_t1_t2_t3_are_drafts_only_and_t2_t3_keep_review_reasons(self) -> None:
        for fixture in ("t1", "t2", "t3"):
            with self.subTest(fixture=fixture):
                report = run_unknown_repo_controlled_dry_run(self._fixture(fixture))
                self.assertEqual(report["approval_draft"]["status"], "draft_requires_human_review")
                self.assertTrue(report["approval_draft"]["live_candidate_generated"])
                self.assertEqual(report["overall_status"], "needs_review")
                self.assertTrue(report["behavior_policy"]["valid"])
                self.assertEqual(report["behavior_policy"]["verdict"], "pass")

    def test_ambiguous_and_parse_error_remain_needs_review(self) -> None:
        for fixture in ("ambiguous", "parse-error"):
            with self.subTest(fixture=fixture):
                report = run_unknown_repo_controlled_dry_run(self._fixture(fixture))
                self.assertEqual(report["profile"]["risk_tier"], "T3")
                self.assertEqual(report["overall_status"], "needs_review")
                self.assertFalse(report["approval_draft"]["approved"])

    def test_binding_contract_covers_candidate_and_component_versions(self) -> None:
        report = run_unknown_repo_controlled_dry_run(self._fixture("t1"))
        binding = report["binding"]
        self.assertTrue(binding["candidate_key_present"])
        self.assertIn("source_risk_tier", binding["candidate_key_fields"])
        for field in ("phase", "kind", "cwd", "argv", "env_allowlist", "shell", "network_policy", "image_policy", "behavior_policy_schema_version"):
            self.assertIn(field, binding["candidate_key_fields"])
        self.assertTrue(binding["repo_identity_matches_profile"])
        self.assertTrue(binding["image_lock_contract_valid"])
        self.assertTrue(binding["image_lock_id_bound_by_contract"])
        self.assertTrue(binding["image_identity_bound_by_contract"])
        self.assertEqual(binding["behavior_policy_schema_version"], "0.1-draft")
        self.assertEqual(binding["image_lock_schema_version"], "0.1-draft")

    def test_phase_and_argv_changes_create_distinct_draft_candidates(self) -> None:
        root = self._fixture("t1")
        phase2 = generate_unknown_repo_approval_draft(root, phase="phase2_install_probe", kind="harmless_static_probe", cwd="/workspace", argv=("python", "-m", "build"))
        phase3 = generate_unknown_repo_approval_draft(root, phase="phase3_runtime_probe", kind="harmless_static_probe", cwd="/workspace", argv=("python", "-m", "build"))
        argv_changed = generate_unknown_repo_approval_draft(root, phase="phase2_install_probe", kind="harmless_static_probe", cwd="/workspace", argv=("python", "-m", "pytest"))
        self.assertNotEqual(phase2["candidate_key"], phase3["candidate_key"])
        self.assertNotEqual(phase2["candidate_key"], argv_changed["candidate_key"])

    def test_invalid_image_lock_blocks_integration(self) -> None:
        lock = build_registry_image_lock()
        lock["images"][0]["registry_reference"] = "registry.example.invalid/rhd/python312:stable"
        lock["images"][0]["registry_digest"] = None
        report = run_unknown_repo_controlled_dry_run(self._fixture("t1"), image_lock=lock)
        self.assertEqual(report["image_lock"]["verdict"], "block")
        self.assertEqual(report["overall_status"], "block")

    def test_invalid_behavior_policy_or_schema_blocks_integration(self) -> None:
        policy = build_default_behavior_policy()
        policy.pop("schema_version")
        report = run_unknown_repo_controlled_dry_run(self._fixture("t1"), behavior_policy=policy)
        self.assertFalse(report["behavior_policy"]["valid"])
        self.assertEqual(report["behavior_policy"]["verdict"], "block")
        self.assertEqual(report["overall_status"], "block")

    def test_redaction_and_static_execution_contract(self) -> None:
        secret = "sk-" + "dryrun_0123456789abcdef"
        lock = build_registry_image_lock()
        lock["images"][0]["source_build_metadata"]["build_reference"] = secret
        report = run_unknown_repo_controlled_dry_run(self._fixture("t1"), image_lock=lock)
        payload = json.dumps(report)
        self.assertNotIn(secret, payload)
        self.assertTrue(report["redaction"]["raw_host_paths_redacted"])
        self.assertTrue(report["redaction"]["secret_like_values_redacted"])
        self.assertFalse(any(report["execution"].values()))
