from __future__ import annotations

import argparse
import hashlib
from importlib import resources
import json
from pathlib import Path
import unittest

from repo_health_doctor.cli import _parse_seccomp_profile
from repo_health_doctor.sandbox.docker_runner import build_docker_run_argv
from repo_health_doctor.sandbox.profiles import (
    SECCOMP_PROFILE_CHOICES,
    get_sandbox_profile,
    resolve_seccomp_profile,
    resolve_seccomp_selection,
)


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_NAME = "rhd-locked-down-v1"
CANDIDATE_PATH = (
    ROOT / "docs" / "human-review" / "rhd-locked-down-v1.candidate.json"
)
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


class SeccompCandidateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.candidate_bytes = CANDIDATE_PATH.read_bytes()
        cls.candidate = json.loads(cls.candidate_bytes)
        cls.baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        cls.packet = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
        cls.markdown = MARKDOWN_PATH.read_text(encoding="utf-8")

    def test_candidate_hash_and_review_packet_record_match(self) -> None:
        artifact = self.packet["candidate_artifact"]
        actual_hash = hashlib.sha256(self.candidate_bytes).hexdigest()

        self.assertEqual("F029", artifact["created_by_feature_id"])
        self.assertEqual(CANDIDATE_NAME, artifact["profile"])
        self.assertEqual(
            "docs/human-review/rhd-locked-down-v1.candidate.json",
            artifact["path"],
        )
        self.assertEqual(actual_hash, artifact["profile_sha256"])
        self.assertEqual(64, len(actual_hash))
        self.assertIn(actual_hash, self.markdown)

    def test_candidate_is_exact_baseline_subtraction(self) -> None:
        artifact = self.packet["candidate_artifact"]
        packet_candidates = self.packet["reduction_candidates"]
        removed_from_candidates = [
            syscall
            for candidate in packet_candidates
            for syscall in candidate["syscalls"]
        ]
        removed = set(removed_from_candidates)
        expected = json.loads(json.dumps(self.baseline))
        for group in expected["syscalls"]:
            if group["action"] == "SCMP_ACT_ALLOW":
                group["names"] = [name for name in group["names"] if name not in removed]

        allowed_names = [
            name
            for group in self.candidate["syscalls"]
            if group["action"] == "SCMP_ACT_ALLOW"
            for name in group["names"]
        ]
        self.assertEqual(expected, self.candidate)
        self.assertEqual(265, len(allowed_names))
        self.assertEqual(265, len(set(allowed_names)))
        self.assertEqual(artifact["removed_syscalls"], removed_from_candidates)
        self.assertEqual(
            artifact["removed_candidate_ids"],
            [candidate["candidate_id"] for candidate in packet_candidates],
        )
        self.assertEqual(265, artifact["allowlisted_syscall_count"])
        self.assertEqual(1, artifact["allow_group_count"])

    def test_candidate_remains_human_unapproved_and_unrun(self) -> None:
        artifact = self.packet["candidate_artifact"]

        self.assertEqual("human_unapproved", artifact["approval_state"])
        self.assertEqual("not_run", artifact["runtime_regression_state"])
        self.assertEqual("disconnected", artifact["product_connection_state"])
        self.assertEqual("pending_human_decision", self.packet["review_state"])
        self.assertEqual("pending", self.packet["human_review"]["decision"])
        self.assertFalse(self.packet["review_scope"]["human_approval_recorded"])
        self.assertFalse(self.packet["review_scope"]["candidate_product_connected"])
        self.assertEqual([], self.packet["candidate_runtime_results"])
        self.assertIn("Human未承認candidate artifact", self.markdown)

    def test_candidate_materials_do_not_use_verified_or_production_ready_wording(self) -> None:
        candidate_materials = "\n".join(
            (
                self.candidate_bytes.decode("utf-8"),
                json.dumps(self.packet, ensure_ascii=False),
                self.markdown,
            )
        ).lower()

        self.assertNotIn("verified", candidate_materials)
        self.assertNotIn("production-ready", candidate_materials)
        self.assertNotIn("production_ready", candidate_materials)

    def test_candidate_is_unreachable_from_package_schema_and_cli(self) -> None:
        self.assertNotIn(CANDIDATE_NAME, SECCOMP_PROFILE_CHOICES)
        self.assertFalse(
            resources.files("repo_health_doctor.sandbox.resources")
            .joinpath(f"{CANDIDATE_NAME}.json")
            .is_file()
        )
        with self.assertRaises(ValueError):
            resolve_seccomp_profile(CANDIDATE_NAME)
        with self.assertRaises(ValueError):
            resolve_seccomp_selection(CANDIDATE_NAME)
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_seccomp_profile(CANDIDATE_NAME)

        for schema_path in (ROOT / "schemas").glob("*.json"):
            with self.subTest(schema=schema_path.name):
                self.assertNotIn(
                    CANDIDATE_NAME,
                    schema_path.read_text(encoding="utf-8"),
                )

    def test_candidate_is_unreachable_from_docker_argv_builder(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported seccomp profile"):
            build_docker_run_argv(
                image="<image>",
                command_argv=["python3", "-c", "print('candidate contract')"],
                workspace_host_path=Path("<workspace>"),
                out_host_path=Path("<out>"),
                profile=get_sandbox_profile("locked-down"),
                seccomp_profile_name=CANDIDATE_NAME,
                seccomp_profile_path=CANDIDATE_PATH,
            )


if __name__ == "__main__":
    unittest.main()
