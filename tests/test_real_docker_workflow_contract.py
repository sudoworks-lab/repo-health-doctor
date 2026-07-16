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
