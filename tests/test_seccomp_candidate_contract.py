from __future__ import annotations

import hashlib
from importlib import resources
import json
from pathlib import Path
import subprocess
import unittest

from repo_health_doctor.cli import _parse_seccomp_profile
from repo_health_doctor.sandbox.docker_runner import build_docker_run_argv
from repo_health_doctor.sandbox.profiles import (
    PROFILE_LOCKED_DOWN_SECCOMP,
    PROFILE_MOBY_DEFAULT,
    SECCOMP_PROFILE_CHOICES,
    SECCOMP_RUNTIME_DEFAULT,
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
PACKAGE_PATH = BASELINE_PATH.with_name("rhd-locked-down-v1.json")
PROVENANCE_PATH = BASELINE_PATH.with_name("rhd-locked-down-v1.provenance.json")
FINAL_GATES_PATH = ROOT / "docs" / "human-review" / "final-security-gates.json"
SCHEMA_PATH = ROOT / "schemas" / "sandbox-run.schema.json"
EXPECTED_REMOVED_SYSCALLS = [
    "chroot",
    "mknod",
    "mknodat",
    "fanotify_mark",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "mq_getsetattr",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedreceive_time64",
    "mq_timedsend",
    "mq_timedsend_time64",
    "mq_unlink",
]


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
        self.assertEqual(266, len(allowed_names))
        self.assertEqual(266, len(set(allowed_names)))
        self.assertEqual(1, allowed_names.count("statx"))
        self.assertEqual([], [name for name in allowed_names if name.startswith("mq_")])
        self.assertEqual(0, allowed_names.count("mq_send"))
        self.assertEqual(EXPECTED_REMOVED_SYSCALLS, removed_from_candidates)
        self.assertEqual(artifact["removed_syscalls"], removed_from_candidates)
        self.assertEqual(
            artifact["removed_candidate_ids"],
            [candidate["candidate_id"] for candidate in packet_candidates],
        )
        self.assertEqual(266, artifact["allowlisted_syscall_count"])
        self.assertEqual(1, artifact["allow_group_count"])
        baseline_names = {
            name
            for group in self.baseline["syscalls"]
            if group["action"] == "SCMP_ACT_ALLOW"
            for name in group["names"]
        }
        self.assertEqual(set(EXPECTED_REMOVED_SYSCALLS), baseline_names - set(allowed_names))
        self.assertFalse(set(allowed_names) - baseline_names)
        self.assertEqual(
            hashlib.sha256(BASELINE_PATH.read_bytes()).hexdigest(),
            artifact["baseline_profile_sha256"],
        )

    def test_current_approval_and_connection_preserve_historical_regression(self) -> None:
        artifact = self.packet["candidate_artifact"]

        self.assertEqual("human_approved", artifact["approval_state"])
        self.assertEqual("completed", artifact["runtime_regression_state"])
        self.assertEqual("connected", artifact["product_connection_state"])
        self.assertEqual("human_approved_and_product_connected", self.packet["review_state"])
        self.assertEqual("approved", self.packet["human_review"]["decision"])
        self.assertTrue(self.packet["review_scope"]["human_approval_recorded"])
        self.assertTrue(self.packet["review_scope"]["candidate_product_connected"])
        self.assertEqual([], self.packet["candidate_runtime_results"])
        regression = self.packet["candidate_local_regression"]
        self.assertEqual("completed", regression["execution_state"])
        self.assertEqual("human_unapproved", regression["approval_state"])
        self.assertEqual("disconnected", regression["product_connection_state"])
        self.assertEqual(8, regression["attempted_case_count"])
        self.assertEqual(8, regression["passed_case_count"])
        self.assertEqual(0, regression["failed_case_count"])
        self.assertEqual(0, regression["not_run_case_count"])
        self.assertTrue(regression["all_required_cases_recorded"])
        self.assertEqual([], regression["failures"])
        self.assertEqual(8, len(regression["cases"]))
        self.assertEqual({"pass"}, {case["status"] for case in regression["cases"]})
        self.assertTrue(
            all(case["failure_codes"] == [] for case in regression["cases"])
        )
        self.assertIn("human_decision_remains_pending", regression["limitations"])
        self.assertIn(
            "candidate_remains_disconnected_from_product_and_default_paths",
            regression["limitations"],
        )
        previous = self.packet["previous_candidate_local_regression"]
        self.assertEqual("completed", previous["execution_state"])
        self.assertEqual(8, previous["passed_case_count"])
        self.assertEqual("not_reused", previous["current_reuse_state"])
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

    def test_approved_candidate_is_connected_to_package_schema_and_cli(self) -> None:
        self.assertEqual(
            (SECCOMP_RUNTIME_DEFAULT, PROFILE_MOBY_DEFAULT, PROFILE_LOCKED_DOWN_SECCOMP),
            SECCOMP_PROFILE_CHOICES,
        )
        self.assertEqual(SECCOMP_RUNTIME_DEFAULT, resolve_seccomp_selection().profile)
        self.assertEqual(CANDIDATE_NAME, PROFILE_LOCKED_DOWN_SECCOMP)
        self.assertIn(CANDIDATE_NAME, SECCOMP_PROFILE_CHOICES)
        self.assertTrue(
            resources.files("repo_health_doctor.sandbox.resources")
            .joinpath(f"{CANDIDATE_NAME}.json")
            .is_file()
        )
        resolved = resolve_seccomp_profile(CANDIDATE_NAME)
        approval = json.loads(FINAL_GATES_PATH.read_text(encoding="utf-8"))["seccomp_approval"]
        self.assertEqual(self.candidate_bytes, PACKAGE_PATH.read_bytes())
        self.assertEqual(approval["approved_profile_sha256"], resolved.profile_sha256)
        self.assertEqual(resolved.profile_sha256, json.loads(PROVENANCE_PATH.read_text())["profile_sha256"])
        self.assertEqual(CANDIDATE_NAME, resolve_seccomp_selection(CANDIDATE_NAME).profile)
        self.assertEqual(CANDIDATE_NAME, _parse_seccomp_profile(CANDIDATE_NAME))
        self.assertIn(CANDIDATE_NAME, SCHEMA_PATH.read_text(encoding="utf-8"))

        completed = subprocess.run(
            ["python3", "scripts/validate_final_security_gates.py", str(FINAL_GATES_PATH)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["valid"])

    def test_approved_candidate_is_accepted_by_docker_argv_builder(self) -> None:
        argv = build_docker_run_argv(
            image="<image>",
            command_argv=["python3", "-c", "print('candidate contract')"],
            workspace_host_path=Path("<workspace>"),
            out_host_path=Path("<out>"),
            profile=get_sandbox_profile("locked-down"),
            seccomp_profile_name=CANDIDATE_NAME,
            seccomp_profile_path=Path("<sandbox-run-root>/rhd-locked-down-v1.json"),
        )

        self.assertEqual(1, argv.count("seccomp=<sandbox-run-root>/rhd-locked-down-v1.json"))
        self.assertFalse(any("docs/human-review" in token for token in argv))


if __name__ == "__main__":
    unittest.main()
