from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release.yml"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "real-docker-verification.yml"
PRODUCT_TEST_PATH = ROOT / "tests" / "test_candidate_seccomp_real_docker.py"


class RealDockerWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ci_workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.release_workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.product_test = PRODUCT_TEST_PATH.read_text(encoding="utf-8")

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

    def test_checkouts_fetch_full_history_for_final_gate_reachability(self) -> None:
        self.assertRegex(
            self.ci_workflow,
            r"(?m)^      - name: Check out repository\n"
            r"        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            r"        with:\n"
            r"          fetch-depth: 0$",
        )
        self.assertRegex(
            self.workflow,
            r"(?m)^      - name: Check out repository\n"
            r"        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            r"        with:\n"
            r"          fetch-depth: 0$",
        )

    def test_workflow_has_only_workflow_dispatch_trigger(self) -> None:
        on_block = self._top_level_block("on")
        triggers = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", on_block)

        self.assertEqual(["workflow_dispatch"], triggers)
        self.assertNotRegex(on_block, r"(?m)^  (push|pull_request|schedule):")
        self.assertRegex(on_block, r"(?m)^      image:\s*$")
        self.assertNotIn("inputs.command", self.workflow)

    def test_only_approved_digest_acquisition_may_pull_before_binding_checks(self) -> None:
        acquisition = self._step_block("Acquire approved digest-pinned test image")
        fixed_tests = self._step_block(
            "Run fixed sandbox --pull=never and real Docker cases 1 to 10"
        )
        approved_pull = 'docker pull "$RHD_REAL_DOCKER_IMAGE"'
        validation_position = acquisition.index("if re.fullmatch(pattern, image) is None:")
        pull_position = acquisition.index(approved_pull)
        inspect_position = acquisition.index('["docker", "image", "inspect", image]')

        self.assertIn(r"@sha256:[0-9a-f]{64}", acquisition)
        self.assertLess(validation_position, pull_position)
        self.assertLess(pull_position, inspect_position)
        self.assertEqual(1, self.workflow.count(approved_pull))
        self.assertEqual(
            [f"{approved_pull} >/dev/null 2>&1"],
            [line.strip() for line in re.findall(r"(?m)^\s*docker pull[^\n]*$", self.workflow)],
        )
        self.assertIn("RepoDigests", acquisition)
        self.assertIn("image not in repo_digests", acquisition)
        self.assertIn(r'r"sha256:[0-9a-f]{64}"', acquisition)
        self.assertIn("capture_output=True", acquisition)
        self.assertNotIn("GITHUB_OUTPUT", acquisition)
        self.assertNotIn("GITHUB_STEP_SUMMARY", acquisition)
        self.assertNotIn("latest", acquisition)
        self.assertNotIn("docker pull", self.ci_workflow)
        self.assertNotIn("docker pull", self.release_workflow)
        self.assertNotIn("docker pull", fixed_tests)
        self.assertIn("--pull=never", fixed_tests)
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

    def test_approved_product_gate_is_hash_pinned_and_fail_closed(self) -> None:
        product = self._step_block("Run approved locked-down product profile regression")
        expected_hash = "92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543"

        self.assertIn('PYTHONPATH: src', product)
        self.assertIn('RHD_REAL_DOCKER_TEST: "1"', product)
        self.assertIn('RHD_REAL_DOCKER_IMAGE: ${{ inputs.image }}', product)
        self.assertIn(f'EXPECTED_LOCKED_DOWN_SHA256: "{expected_hash}"', product)
        self.assertIn("set -euo pipefail", product)
        self.assertIn("scripts/validate_final_security_gates.py", product)
        self.assertIn(
            "tests.test_candidate_seccomp_real_docker.ApprovedLockedDownProductRealDockerTests",
            product,
        )
        self.assertNotIn("scripts/run_candidate_seccomp_review.py", product)
        self.assertIn("run_sandbox_run(", self.product_test)
        self.assertIn("seccomp_profile_name=PROFILE_LOCKED_DOWN_SECCOMP", self.product_test)
        self.assertIn("self.assertEqual(candidate_bytes, package_bytes)", self.product_test)
        self.assertIn('approval["approved_profile_sha256"]', self.product_test)
        self.assertIn("seccomp=<sandbox-run-root>/rhd-locked-down-v1.json", self.product_test)
        self.assertIn('"RHD_HOSTED_LOCKED_DOWN_PRODUCT_EVIDENCE="', self.product_test)
        self.assertIn('"hosted_locked_down_product_regression"', self.product_test)
        for field in (
            "GITHUB_EVENT_NAME",
            "GITHUB_RUN_ID",
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
            "candidate_docs_path_passed_to_docker",
            "raw_process_output_recorded",
        ):
            self.assertIn(field, self.product_test)
        self.assertIn("self.assertEqual(8, len(cases))", self.product_test)
        self.assertIn("self.assertEqual(8, passed_case_count", self.product_test)
        self.assertIn("self.assertEqual(0, failed_case_count", self.product_test)
        self.assertNotRegex(product, r"(?m)^\s+docker (pull|build)\b")

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
