from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = ROOT / "docs" / "human-review" / "seccomp-review-packet.json"
MARKDOWN_PATH = ROOT / "docs" / "human-review" / "seccomp-review-packet.md"
BASELINE_PATH = (
    ROOT
    / "src"
    / "repo_health_doctor"
    / "sandbox"
    / "resources"
    / "rhd-moby-default-v1.json"
)
PROVENANCE_PATH = BASELINE_PATH.with_name("rhd-moby-default-v1.provenance.json")

RUNTIME_CASES = {1, 2, 3, 4, 5, 6, 8, 10}
NON_RUNTIME_CASES = {7, 9}


class SeccompReviewPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packet = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
        cls.markdown = MARKDOWN_PATH.read_text(encoding="utf-8")
        cls.baseline_bytes = BASELINE_PATH.read_bytes()
        cls.baseline = json.loads(cls.baseline_bytes)
        cls.provenance = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))

    def test_packet_is_analysis_only_and_pending_human_decision(self) -> None:
        self.assertEqual("0.1-draft", self.packet["schema_version"])
        self.assertEqual("seccomp_human_review", self.packet["packet_kind"])
        self.assertEqual("F028", self.packet["feature_id"])
        self.assertEqual("pending_human_decision", self.packet["review_state"])

        scope = self.packet["review_scope"]
        self.assertEqual("rhd-moby-default-v1", scope["baseline_profile"])
        self.assertEqual("rhd-locked-down-v1", scope["candidate_profile_name"])
        self.assertFalse(scope["candidate_artifact_created"])
        self.assertFalse(scope["candidate_product_connected"])
        self.assertFalse(scope["human_approval_recorded"])
        self.assertEqual("pending", self.packet["human_review"]["decision"])
        self.assertEqual([], self.packet["candidate_runtime_results"])

    def test_baseline_hash_provenance_and_allowlist_shape_match_package_data(self) -> None:
        baseline = self.packet["baseline"]
        actual_hash = hashlib.sha256(self.baseline_bytes).hexdigest()
        allowed_names = [
            name
            for group in self.baseline["syscalls"]
            if group["action"] == "SCMP_ACT_ALLOW"
            for name in group["names"]
        ]

        self.assertEqual(actual_hash, baseline["profile_sha256"])
        self.assertEqual(actual_hash, self.provenance["profile_sha256"])
        self.assertEqual(self.provenance["source"]["version"], baseline["source_version"])
        self.assertEqual(self.provenance["source"]["revision"], baseline["source_revision"])
        self.assertEqual(self.baseline["defaultAction"], baseline["default_action"])
        self.assertEqual(1, baseline["allow_group_count"])
        expected_mqueue = {
            "mq_getsetattr",
            "mq_notify",
            "mq_open",
            "mq_timedreceive",
            "mq_timedreceive_time64",
            "mq_timedsend",
            "mq_timedsend_time64",
            "mq_unlink",
        }
        self.assertEqual(281, baseline["allowlisted_syscall_count"])
        self.assertEqual(281, len(allowed_names))
        self.assertEqual(281, len(set(allowed_names)))
        self.assertEqual(1, allowed_names.count("statx"))
        self.assertEqual(expected_mqueue, {name for name in allowed_names if name.startswith("mq_")})
        self.assertEqual(0, allowed_names.count("mq_send"))
        self.assertEqual(0, baseline["syscall_reductions_from_source"])
        self.assertEqual([], baseline["local_compatibility_additions"])
        normalization = baseline["upstream_contract_normalization"]
        self.assertTrue(normalization["statx_present"])
        self.assertEqual(expected_mqueue, set(normalization["posix_message_queue_syscalls"]))
        self.assertEqual(["mq_send"], normalization["removed_library_interface_names"])
        self.assertEqual("upstream_contract_normalization", normalization["repair_kind"])

    def test_comparison_records_distinct_moby_and_sandbox_purposes(self) -> None:
        comparison = self.packet["comparison"]
        self.assertIn("upstream default", comparison["moby_default"]["role"])
        self.assertIn("281 syscall", comparison["moby_default"]["policy_shape"])
        self.assertIn("network none", comparison["sandbox_use"]["role"])
        self.assertIn("capability drop", comparison["sandbox_use"]["role"])
        self.assertEqual(
            RUNTIME_CASES,
            set(comparison["sandbox_use"]["runtime_regression_cases"]),
        )
        self.assertEqual(
            NON_RUNTIME_CASES,
            set(comparison["sandbox_use"]["non_runtime_cases"]),
        )
        self.assertIn("Human review", comparison["conclusion"])

    def test_each_reduction_candidate_is_small_grounded_and_non_overlapping(self) -> None:
        evidence_ids = {
            item["evidence_id"] for item in self.packet["evidence_sources"]
        }
        allowed_names = {
            name
            for group in self.baseline["syscalls"]
            if group["action"] == "SCMP_ACT_ALLOW"
            for name in group["names"]
        }
        candidates = self.packet["reduction_candidates"]
        self.assertEqual(
            {"SC-001", "SC-002", "SC-003", "SC-004", "SC-005"},
            {candidate["candidate_id"] for candidate in candidates},
        )

        seen_syscalls: set[str] = set()
        for candidate in candidates:
            with self.subTest(candidate=candidate["candidate_id"]):
                syscalls = candidate["syscalls"]
                self.assertGreaterEqual(len(syscalls), 1)
                self.assertLessEqual(len(syscalls), 8)
                self.assertTrue(set(syscalls) <= allowed_names)
                self.assertFalse(set(syscalls) & seen_syscalls)
                seen_syscalls.update(syscalls)
                self.assertGreaterEqual(len(candidate["rationale"]), 40)
                self.assertTrue(candidate["evidence_ids"])
                self.assertTrue(set(candidate["evidence_ids"]) <= evidence_ids)

        sc005 = next(candidate for candidate in candidates if candidate["candidate_id"] == "SC-005")
        self.assertEqual(
            [
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedreceive_time64",
                "mq_timedsend",
                "mq_timedsend_time64",
                "mq_unlink",
            ],
            sc005["syscalls"],
        )
        self.assertIn("mq_sendとmq_receiveはlibrary interface", sc005["rationale"])

    def test_each_candidate_maps_runtime_cases_and_rejection_conditions(self) -> None:
        for candidate in self.packet["reduction_candidates"]:
            with self.subTest(candidate=candidate["candidate_id"]):
                impact = candidate["case_impact"]
                self.assertEqual(
                    RUNTIME_CASES,
                    set(impact["must_remain_green"]),
                )
                self.assertEqual(
                    NON_RUNTIME_CASES,
                    set(impact["not_executed_under_candidate"]),
                )
                self.assertIn("未確認", impact["expected_impact"])
                self.assertGreaterEqual(len(candidate["rejection_conditions"]), 3)
                self.assertTrue(
                    all(condition.strip() for condition in candidate["rejection_conditions"])
                )

    def test_each_candidate_names_all_unconfirmed_runtime_scopes(self) -> None:
        runtime_ids = {
            runtime["runtime_id"] for runtime in self.packet["unconfirmed_runtimes"]
        }
        self.assertEqual(
            {"UR-ROOTFUL", "UR-ROOTLESS", "UR-IMAGE", "UR-ARCH", "UR-OCI"},
            runtime_ids,
        )
        for runtime in self.packet["unconfirmed_runtimes"]:
            self.assertTrue(runtime["scope"])
            self.assertTrue(runtime["reason"])

        for candidate in self.packet["reduction_candidates"]:
            with self.subTest(candidate=candidate["candidate_id"]):
                self.assertEqual(runtime_ids, set(candidate["unconfirmed_runtimes"]))

    def test_residual_risks_and_human_checks_are_explicit(self) -> None:
        risk_ids = {
            risk["risk_id"] for risk in self.packet["residual_risks"]
        }
        self.assertEqual(
            {
                "RR-NO-CANDIDATE-RUNTIME-EVIDENCE",
                "RR-CASE-COVERAGE",
                "RR-PLATFORM-SCOPE",
                "RR-SECCOMP-LIMIT",
                "RR-HUMAN-DECISION",
                "RR-POSIX-MQ-RUNTIME-COVERAGE",
            },
            risk_ids,
        )
        self.assertTrue(
            all(risk["description"].strip() for risk in self.packet["residual_risks"])
        )
        self.assertGreaterEqual(
            len(self.packet["human_review"]["required_checks"]),
            5,
        )
        self.assertIn(
            "製品path接続",
            self.packet["human_review"]["decision_effect"],
        )

    def test_statx_history_and_mqueue_repair_are_bounded_and_pending_reverification(self) -> None:
        repair = self.packet["statx_compatibility_repair"]

        self.assertEqual("2026-07-17 JST", repair["human_measured_at"])
        self.assertEqual("29.5.3", repair["environment"]["docker_engine_version"])
        self.assertEqual("1.3.6", repair["environment"]["runc_version"])
        self.assertEqual("linux/amd64", repair["environment"]["os_architecture"])
        self.assertEqual(
            "python@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9",
            repair["environment"]["image_digest"],
        )
        self.assertEqual(
            "failed_at_container_init",
            repair["pre_repair_baseline"]["package_real_cases_8_and_10"],
        )
        self.assertEqual(["statx"], repair["temporary_profile"]["local_compatibility_additions"])
        self.assertEqual("passed", repair["temporary_profile"]["minimal_run"])
        self.assertEqual("passed", repair["temporary_profile"]["sandbox_boundary_run"])
        self.assertEqual(
            "completed_before_mqueue_contract_normalization",
            repair["repository_repair"]["post_repair_real_docker_state"],
        )
        self.assertTrue(
            any("does not establish compatibility" in item for item in repair["limitations"])
        )
        mqueue_repair = self.packet["posix_message_queue_contract_repair"]
        repository_repair = mqueue_repair["repository_repair"]
        self.assertTrue(mqueue_repair["human_contract_confirmed"])
        self.assertTrue(mqueue_repair["official_baseline_contract"]["statx_present"])
        self.assertEqual(
            {
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedreceive_time64",
                "mq_timedsend",
                "mq_timedsend_time64",
                "mq_unlink",
            },
            set(mqueue_repair["official_baseline_contract"]["posix_message_queue_syscalls"]),
        )
        self.assertEqual("upstream_contract_normalization", repository_repair["repair_kind"])
        self.assertEqual("pending_human_reverification", repository_repair["real_docker_state"])
        self.assertFalse(repository_repair["candidate_bytes_changed"])
        self.assertIn("Human shellでの再検証待ち", self.markdown)

    def test_markdown_corresponds_to_machine_readable_packet(self) -> None:
        self.assertIn(self.packet["baseline"]["profile_sha256"], self.markdown)
        for candidate in self.packet["reduction_candidates"]:
            with self.subTest(candidate=candidate["candidate_id"]):
                self.assertIn(candidate["candidate_id"], self.markdown)
                for syscall in candidate["syscalls"]:
                    self.assertIn(f"`{syscall}`", self.markdown)
                for runtime_id in candidate["unconfirmed_runtimes"]:
                    self.assertIn(runtime_id, self.markdown)
        for risk in self.packet["residual_risks"]:
            self.assertIn(
                risk["description"].split("。", maxsplit=1)[0],
                json.dumps(self.packet, ensure_ascii=False),
            )


if __name__ == "__main__":
    unittest.main()
