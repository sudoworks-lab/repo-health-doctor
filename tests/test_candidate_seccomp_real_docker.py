from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from repo_health_doctor.sandbox.profiles import SECCOMP_PROFILE_CHOICES
from scripts.run_candidate_seccomp_review import CASES, _build_docker_argv


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_NAME = "rhd-locked-down-v1"
CANDIDATE_PATH = ROOT / "docs" / "human-review" / "rhd-locked-down-v1.candidate.json"
PACKET_PATH = ROOT / "docs" / "human-review" / "seccomp-review-packet.json"
MARKDOWN_PATH = ROOT / "docs" / "human-review" / "seccomp-review-packet.md"
SCRIPT_PATH = ROOT / "scripts" / "run_candidate_seccomp_review.py"
REAL_DOCKER_ENABLED = os.environ.get("RHD_REAL_DOCKER_TEST") == "1"
EXPECTED_CASE_IDS = {1, 2, 3, 4, 5, 6, 8, 10}


class CandidateSeccompReviewContractTests(unittest.TestCase):
    def _record(self) -> dict[str, object]:
        packet = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
        record = packet["candidate_local_regression"]
        self.assertIsInstance(record, dict)
        return record

    def test_candidate_argv_is_review_only_pull_never_and_network_none(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            out = root / "out"
            workspace.mkdir()
            out.mkdir()
            argv = _build_docker_argv(
                image="<existing-local-image>@sha256:" + ("0" * 64),
                candidate_path=CANDIDATE_PATH,
                workspace=workspace,
                out=out,
                container_name="rhd-candidate-review-contract",
                command=("python3", "-c", "print('contract')"),
            )

        self.assertEqual(1, argv.count("--pull=never"))
        self.assertNotIn("pull", argv)
        network_index = argv.index("--network")
        self.assertEqual("none", argv[network_index + 1])
        self.assertIn(f"seccomp={CANDIDATE_PATH}", argv)
        self.assertNotIn(CANDIDATE_NAME, SECCOMP_PROFILE_CHOICES)

    def test_packet_records_environment_profile_cases_and_every_failure(self) -> None:
        record = self._record()
        candidate_hash = hashlib.sha256(CANDIDATE_PATH.read_bytes()).hexdigest()
        cases = record["cases"]
        failures = record["failures"]

        self.assertEqual("F030", record["recorded_by_feature_id"])
        self.assertEqual(candidate_hash, record["profile_sha256"])
        self.assertEqual("human_unapproved", record["approval_state"])
        self.assertEqual("disconnected", record["product_connection_state"])
        self.assertEqual("never", record["pull_policy"])
        self.assertEqual("none", record["network_mode"])
        self.assertFalse(record["raw_process_output_recorded"])
        self.assertEqual(EXPECTED_CASE_IDS, set(record["required_case_ids"]))
        self.assertEqual(EXPECTED_CASE_IDS, {case["case_id"] for case in cases})
        self.assertTrue(record["all_required_cases_recorded"])
        self.assertEqual(len(CASES), len(cases))
        self.assertEqual(
            len(cases),
            record["passed_case_count"] + record["failed_case_count"] + record["not_run_case_count"],
        )
        environment = record["environment"]
        for field in (
            "docker_server_version",
            "docker_os",
            "docker_architecture",
            "kernel_version",
            "rootless",
            "userns_remap",
            "image_selection_source",
            "image_digest",
            "local_image_id",
        ):
            self.assertIn(field, environment)

        recorded_case_failures = {
            (case["case_id"], code)
            for case in cases
            for code in case["failure_codes"]
        }
        flattened_case_failures = {
            (failure["case_id"], failure["failure_code"])
            for failure in failures
            if failure["scope"] == "case"
        }
        self.assertEqual(recorded_case_failures, flattened_case_failures)
        serialized = json.dumps(record, ensure_ascii=False).lower()
        self.assertNotIn("stdout", serialized)
        self.assertNotIn("stderr", serialized)
        self.assertNotIn(str(ROOT).lower(), serialized)

        markdown = MARKDOWN_PATH.read_text(encoding="utf-8")
        self.assertIn(record["profile_sha256"], markdown)
        for case_id in EXPECTED_CASE_IDS:
            self.assertIn(f"| {case_id} |", markdown)


@unittest.skipUnless(
    REAL_DOCKER_ENABLED,
    "set RHD_REAL_DOCKER_TEST=1 to run the candidate-only real Docker regression",
)
class CandidateSeccompRealDockerTests(unittest.TestCase):
    def test_candidate_regression_attempt_is_fully_recorded(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": "src"},
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertIn(completed.returncode, {0, 1})

        packet = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
        record = packet["candidate_local_regression"]
        self.assertEqual(EXPECTED_CASE_IDS, {case["case_id"] for case in record["cases"]})
        self.assertTrue(record["all_required_cases_recorded"])
        self.assertEqual(
            len(record["cases"]),
            record["passed_case_count"]
            + record["failed_case_count"]
            + record["not_run_case_count"],
        )
        self.assertEqual("disconnected", record["product_connection_state"])
        self.assertNotIn(CANDIDATE_NAME, SECCOMP_PROFILE_CHOICES)


if __name__ == "__main__":
    unittest.main()
