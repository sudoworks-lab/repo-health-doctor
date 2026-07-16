from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from repo_health_doctor.sandbox.docker_runner import DockerRunner
from repo_health_doctor.sandbox.run import DEFAULT_SANDBOX_IMAGE, run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import CopyBudget, fingerprint_target


ROOT = Path(__file__).resolve().parents[1]
REAL_DOCKER_ENABLED = os.environ.get("RHD_REAL_DOCKER_TEST") == "1"

CASE_1_COMMAND = [
    "python3",
    "-c",
    "from pathlib import Path; Path('/workspace/case-1.txt').write_text('ok\\n', encoding='utf-8')",
]
CASE_2_COMMAND = [
    "python3",
    "-c",
    "import socket; names = {name for _, name in socket.if_nameindex()}; assert names <= {'lo'}, names",
]
CASE_3_COMMAND = [
    "python3",
    "-c",
    (
        "from pathlib import Path; "
        "entries = [line.split() for line in Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines()]; "
        "root = next(parts for parts in entries if parts[4] == '/'); "
        "assert 'ro' in root[5].split(',')"
    ),
]
CASE_4_COMMAND = [
    "python3",
    "-c",
    (
        "from pathlib import Path; "
        "entries = [line.split() for line in Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines()]; "
        "tmp = next(parts for parts in entries if parts[4] == '/tmp'); "
        "assert tmp[tmp.index('-') + 1] == 'tmpfs'; "
        "probe = Path('/tmp/case-4.txt'); probe.write_text('ok\\n', encoding='utf-8'); "
        "assert probe.read_text(encoding='utf-8') == 'ok\\n'"
    ),
]
CASE_5_COMMAND = [
    "python3",
    "-c",
    "import os; assert os.getuid() != 0 and os.getgid() != 0",
]
CASE_6_COMMAND = [
    "python3",
    "-c",
    "import time; time.sleep(2)",
]
CASE_7_COMMAND = [
    "python3",
    "-c",
    "print('copy-budget-command-must-not-start')",
]


@unittest.skipUnless(REAL_DOCKER_ENABLED, "set RHD_REAL_DOCKER_TEST=1 to run real Docker boundary cases")
class RealDockerBoundaryCasesOneToSeven(unittest.TestCase):
    image: str
    runner: DockerRunner

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = os.environ.get("RHD_REAL_DOCKER_IMAGE", "").strip() or DEFAULT_SANDBOX_IMAGE
        cls.runner = DockerRunner()
        if not cls.runner.docker_available():
            raise RuntimeError("RHD_REAL_DOCKER_TEST=1 requires an accessible local Docker daemon")
        if not cls.runner.image_available_locally(cls.image):
            raise RuntimeError(
                "RHD_REAL_DOCKER_TEST=1 requires the selected image to exist locally; the test does not pull images"
            )

    def _repo(self, root: Path, *, readme: str = "synthetic real Docker boundary fixture\n") -> Path:
        repo = root / "repo"
        repo.mkdir()
        (repo / "README.md").write_text(readme, encoding="utf-8")
        return repo

    def _run_case(
        self,
        repo: Path,
        *,
        command: list[str],
        profile: str,
        timeout_seconds: int = 10,
        copy_budget: CopyBudget | None = None,
    ) -> dict[str, object]:
        original_fingerprint = fingerprint_target(repo).fingerprint
        created_run_roots: list[Path] = []
        real_mkdtemp = tempfile.mkdtemp

        def tracked_mkdtemp(*args: object, **kwargs: object) -> str:
            created = Path(real_mkdtemp(*args, **kwargs))
            created_run_roots.append(created)
            return str(created)

        with patch("repo_health_doctor.sandbox.run_workspace.tempfile.mkdtemp", side_effect=tracked_mkdtemp):
            report = run_sandbox_run(
                repo,
                image=self.image,
                profile_name=profile,
                command_argv=command,
                timeout_seconds=timeout_seconds,
                runner=self.runner,
                copy_budget=copy_budget,
            )

        self.assertEqual(original_fingerprint, fingerprint_target(repo).fingerprint)
        self.assertTrue(created_run_roots)
        self.assertTrue(all(not path.exists() for path in created_run_roots))
        self.assertEqual("ok", report["disposable_workspace"]["cleanup"])
        self._assert_schema_valid(report)
        return report

    def _assert_schema_valid(self, report: dict[str, object]) -> None:
        schema = json.loads((ROOT / "schemas" / "sandbox-run.schema.json").read_text(encoding="utf-8"))
        try:
            from jsonschema import Draft202012Validator
        except ModuleNotFoundError:
            self.assertTrue(set(schema["required"]).issubset(report))
            self.assertIn(report["result"]["status"], schema["properties"]["result"]["properties"]["status"]["enum"])
        else:
            Draft202012Validator(schema).validate(report)

    def _assert_completed_execution_contract(self, report: dict[str, object], command: list[str]) -> None:
        self.assertEqual("completed", report["result"]["status"])
        self.assertEqual(0, report["sandbox_exit_code"])
        self.assertTrue(report["command_started"])
        self.assertTrue(report["docker"]["docker_invoked"])
        self.assertEqual("never", report["docker"]["pull_policy"])
        self.assertEqual(1, report["docker"]["argv_redacted"].count("--pull=never"))
        self.assertEqual(1, report["docker"]["argv_redacted"].count("--rm"))
        self.assertEqual(command, report["command"]["argv_redacted"])
        self.assertFalse(report["output_summary"]["raw_stdout_stderr_persisted"])

    def test_case_1_normal_execution_diff_original_repo_unchanged_cleanup_and_schema(self) -> None:
        """case 1: fixed harmless command, --pull=never, diff, original repo unchanged, cleanup, schema-valid evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(Path(tmp))
            report = self._run_case(repo, command=CASE_1_COMMAND, profile="no-network-default")

        self._assert_completed_execution_contract(report, CASE_1_COMMAND)
        self.assertTrue(report["workspace_diff"]["available"])
        self.assertEqual(1, report["workspace_diff"]["created_count"])
        self.assertIn("<workspace>/case-1.txt", report["workspace_diff"]["interesting_paths_redacted"])

    def test_case_2_network_none_without_external_request(self) -> None:
        """case 2: fixed harmless command observes network none without an external request."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(Path(tmp))
            report = self._run_case(repo, command=CASE_2_COMMAND, profile="no-network-default")

        self._assert_completed_execution_contract(report, CASE_2_COMMAND)
        self.assertEqual("none", report["docker"]["network"])
        self.assertEqual("none", report["sandbox_profile"]["network"])
        network_index = report["docker"]["argv_redacted"].index("--network")
        self.assertEqual("none", report["docker"]["argv_redacted"][network_index + 1])

    def test_case_3_read_only_rootfs_mount_is_effective(self) -> None:
        """case 3: fixed harmless command observes a read-only rootfs and schema-valid evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(Path(tmp))
            report = self._run_case(repo, command=CASE_3_COMMAND, profile="no-network-readonly")

        self._assert_completed_execution_contract(report, CASE_3_COMMAND)
        self.assertTrue(report["sandbox_profile"]["filesystem"]["read_only_rootfs"])
        self.assertIn("--read-only", report["docker"]["argv_redacted"])

    def test_case_4_tmpfs_is_mounted_and_writable(self) -> None:
        """case 4: fixed harmless command observes writable /tmp tmpfs and cleanup."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(Path(tmp))
            report = self._run_case(repo, command=CASE_4_COMMAND, profile="no-network-readonly")

        self._assert_completed_execution_contract(report, CASE_4_COMMAND)
        self.assertEqual(["/tmp:rw,nosuid,nodev,size=64m"], report["sandbox_profile"]["filesystem"]["tmpfs"])
        self.assertIn("/tmp:rw,nosuid,nodev,size=64m", report["docker"]["argv_redacted"])

    def test_case_5_container_process_is_non_root(self) -> None:
        """case 5: fixed harmless command observes non-root UID/GID with --pull=never."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(Path(tmp))
            report = self._run_case(repo, command=CASE_5_COMMAND, profile="no-network-readonly")

        self._assert_completed_execution_contract(report, CASE_5_COMMAND)
        self.assertFalse(report["sandbox_profile"]["user"]["root"])
        self.assertFalse(report["docker"]["root_container_user"])

    def test_case_6_timeout_is_bounded_and_workspace_is_cleaned(self) -> None:
        """case 6: fixed harmless command times out and still yields cleanup and schema-valid evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(Path(tmp))
            report = self._run_case(
                repo,
                command=CASE_6_COMMAND,
                profile="no-network-readonly",
                timeout_seconds=1,
            )

        self.assertEqual("timed_out", report["result"]["status"])
        self.assertTrue(report["result"]["timed_out"])
        self.assertTrue(report["command_started"])
        self.assertEqual(1, report["sandbox_exit_code"])
        self.assertEqual("timeout", report["docker"]["failure_class"])
        self.assertEqual("never", report["docker"]["pull_policy"])
        self.assertEqual(1, report["docker"]["argv_redacted"].count("--pull=never"))
        self.assertEqual(CASE_6_COMMAND, report["command"]["argv_redacted"])

    def test_case_7_copy_budget_blocks_before_docker_run(self) -> None:
        """case 7: copy budget blocks the fixed harmless command before Docker and records cleanup/schema evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(Path(tmp), readme="copy budget must block this file\n")
            report = self._run_case(
                repo,
                command=CASE_7_COMMAND,
                profile="no-network-readonly",
                copy_budget=CopyBudget(max_file_bytes=1),
            )

        self.assertTrue(report["policy_blocked"])
        self.assertFalse(report["command_started"])
        self.assertFalse(report["docker"]["docker_invoked"])
        self.assertEqual(2, report["sandbox_exit_code"])
        self.assertEqual("never", report["docker"]["pull_policy"])
        self.assertIn("copy_budget_exceeded", report["approval"]["refusal_reasons"])
        self.assertTrue(report["disposable_workspace"]["copy_budget"]["copy_budget_exceeded"])
        self.assertEqual(CASE_7_COMMAND, report["command"]["argv_redacted"])


if __name__ == "__main__":
    unittest.main()
