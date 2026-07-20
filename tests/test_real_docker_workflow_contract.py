from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "real-docker-verification.yml"


class RealDockerWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    def _top_level_block(self, key: str) -> str:
        marker = f"{key}:\n"
        start = self.workflow.index(marker)
        following = self.workflow[start + len(marker) :]
        match = re.search(r"(?m)^[A-Za-z][A-Za-z0-9_-]*:\s*$", following)
        end = len(self.workflow) if match is None else start + len(marker) + match.start()
        return self.workflow[start:end]

    def _step_block(self, name: str) -> str:
        marker = f"      - name: {name}\n"
        start = self.workflow.index(marker)
        following = self.workflow[start + len(marker) :]
        match = re.search(r"(?m)^      - name: ", following)
        end = len(self.workflow) if match is None else start + len(marker) + match.start()
        return self.workflow[start:end]

    def test_workflow_has_only_workflow_dispatch_trigger(self) -> None:
        on_block = self._top_level_block("on")
        triggers = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", on_block)

        self.assertEqual(["workflow_dispatch"], triggers)
        self.assertNotRegex(on_block, r"(?m)^  (push|pull_request|schedule):")
        self.assertRegex(on_block, r"(?m)^      image:\s*$")
        self.assertNotIn("inputs.command", self.workflow)

    def test_digest_pin_is_validated_and_acquired_in_an_independent_step(self) -> None:
        acquisition = self._step_block("Acquire digest-pinned test image")
        fixed_tests = self._step_block(
            "Run fixed sandbox --pull=never and real Docker cases 1 to 10"
        )

        self.assertIn(r"@sha256:[0-9a-f]{64}", acquisition)
        self.assertIn('docker pull "$RHD_REAL_DOCKER_IMAGE"', acquisition)
        self.assertIn('docker image inspect "$RHD_REAL_DOCKER_IMAGE"', acquisition)
        self.assertEqual(1, self.workflow.count("docker pull"))
        self.assertNotIn("docker pull", fixed_tests)
        self.assertLess(self.workflow.index(acquisition), self.workflow.index(fixed_tests))

    def test_fixed_tests_cover_sandbox_pull_never_and_real_docker_cases(self) -> None:
        fixed_tests = self._step_block(
            "Run fixed sandbox --pull=never and real Docker cases 1 to 10"
        )

        self.assertIn(
            "tests.test_sandbox_run_docker_command.SandboxRunDockerCommandTests."
            "test_pull_never_and_network_none_are_required_exactly_once",
            fixed_tests,
        )
        self.assertIn(
            "tests.test_real_docker_verification.RealDockerBoundaryCasesOneToSeven",
            fixed_tests,
        )
        self.assertIn(
            "tests.test_real_docker_verification.RealDockerBoundaryCasesEightToTen",
            fixed_tests,
        )
        self.assertIn('RHD_REAL_DOCKER_TEST: "1"', fixed_tests)
        self.assertNotRegex(fixed_tests, r"(?m)^\s+docker (pull|build)\b")

    def test_candidate_gate_is_direct_hash_pinned_and_fail_closed(self) -> None:
        candidate = self._step_block("Run disconnected locked-down candidate regression")
        expected_hash = "92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543"
        required_case_ids = "[1, 2, 3, 4, 5, 6, 8, 10]"

        self.assertIn('PYTHONPATH: src', candidate)
        self.assertIn('RHD_REAL_DOCKER_TEST: "1"', candidate)
        self.assertIn('RHD_REAL_DOCKER_IMAGE: ${{ inputs.image }}', candidate)
        self.assertIn(f'EXPECTED_CANDIDATE_SHA256: "{expected_hash}"', candidate)
        self.assertIn("sha256(candidate_path.read_bytes()).hexdigest()", candidate)
        self.assertIn("python3 scripts/run_candidate_seccomp_review.py", candidate)
        self.assertIn("set -euo pipefail", candidate)
        self.assertIn('packet.get("candidate_local_regression")', candidate)
        self.assertIn('record.get("profile") == candidate_name', candidate)
        self.assertIn('record.get("profile_sha256") == expected_hash', candidate)
        self.assertIn('record.get("execution_state") == "completed"', candidate)
        self.assertIn('record.get("attempted_case_count") == 8', candidate)
        self.assertIn('record.get("passed_case_count") == 8', candidate)
        self.assertIn('record.get("failed_case_count") == 0', candidate)
        self.assertIn('record.get("not_run_case_count") == 0', candidate)
        self.assertIn('record.get("all_required_cases_recorded") is True', candidate)
        self.assertIn(required_case_ids, candidate)
        self.assertIn('case.get("status") == "pass"', candidate)
        self.assertIn('record.get("failures") == []', candidate)
        self.assertIn('record.get("approval_state") == "human_unapproved"', candidate)
        self.assertIn('record.get("product_connection_state") == "disconnected"', candidate)
        self.assertIn('record.get("pull_policy") == "never"', candidate)
        self.assertIn('record.get("network_mode") == "none"', candidate)
        self.assertIn('record.get("raw_process_output_recorded") is False', candidate)
        self.assertIn('value not in {"", "unknown"}', candidate)
        self.assertIn('candidate_name not in SECCOMP_PROFILE_CHOICES', candidate)
        self.assertIn('"RHD_HOSTED_CANDIDATE_EVIDENCE="', candidate)
        self.assertIn('"hosted_candidate_seccomp_regression"', candidate)
        self.assertIn('"github_actions"', candidate)
        self.assertIn('"github_hosted"', candidate)
        self.assertIn('".github/workflows/real-docker-verification.yml"', candidate)
        for field in (
            "GITHUB_EVENT_NAME",
            "GITHUB_RUN_ID",
            "GITHUB_REPOSITORY",
            "GITHUB_SHA",
            "docker_server_version",
            "docker_os",
            "docker_architecture",
            "kernel_version",
            "rootless",
            "userns_remap",
            "image_digest",
            "local_image_id",
            "required_case_ids",
            "attempted_case_count",
            "passed_case_count",
            "failed_case_count",
            "not_run_case_count",
            '"conclusion": "success"',
        ):
            self.assertIn(field, candidate)
        self.assertIn("GITHUB_STEP_SUMMARY", candidate)
        self.assertNotRegex(candidate, r"(?m)^\s+docker (pull|build)\b")

    def test_summary_always_records_docker_version_os_and_architecture(self) -> None:
        summary = self._step_block("Record Docker and runner summary")

        self.assertIn("if: always()", summary)
        self.assertIn("docker version --format", summary)
        self.assertIn("Docker version:", summary)
        self.assertIn("OS:", summary)
        self.assertIn("Architecture:", summary)
        self.assertIn("GITHUB_STEP_SUMMARY", summary)


if __name__ == "__main__":
    unittest.main()
