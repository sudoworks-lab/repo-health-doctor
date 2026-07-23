from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from repo_health_doctor.gate.authorization import (
    build_execution_authorization_draft,
    validate_execution_authorization,
)
from repo_health_doctor.sandbox.docker_runner import DockerRunner
from repo_health_doctor.sandbox.run import run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import fingerprint_target, inspect_git_worktree


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "python@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9"
REAL_DOCKER_ENABLED = os.environ.get("RHD_REAL_DOCKER_TEST") == "1"


@unittest.skipUnless(REAL_DOCKER_ENABLED, "set RHD_REAL_DOCKER_TEST=1 to run final real Docker probes")
class FinalMajorRealDockerTests(unittest.TestCase):
    runner: DockerRunner
    image_id: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = DockerRunner()
        if not cls.runner.docker_available():
            raise RuntimeError("the local Docker daemon is unavailable")
        if not cls.runner.image_available_locally(IMAGE):
            raise RuntimeError("the selected image is not local; this test never pulls images")
        image_id = cls.runner.image_id(IMAGE)
        if image_id is None:
            raise RuntimeError("the selected local image has no valid immutable image ID")
        cls.image_id = image_id

    def setUp(self) -> None:
        self.containers_before = self._container_ids()
        self.run_roots_before = self._run_root_names()

    def tearDown(self) -> None:
        self.assertEqual(self.containers_before, self._container_ids())
        self.assertEqual(self.run_roots_before, self._run_root_names())

    @staticmethod
    def _container_ids() -> set[str]:
        completed = subprocess.run(
            ["docker", "ps", "-aq"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if completed.returncode != 0:
            raise RuntimeError("docker ps failed")
        return {line.strip() for line in completed.stdout.splitlines() if line.strip()}

    @staticmethod
    def _run_root_names() -> set[str]:
        return {path.name for path in Path("/tmp").glob("rhd-sandbox-run-*")}

    @staticmethod
    def _repo(root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        (repo / "README.md").write_text("synthetic final major fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "synthetic"],
            check=True,
            capture_output=True,
        )
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "synthetic fixture"], check=True, capture_output=True)
        return repo

    def _auth(self, root: Path, repo: Path, command: list[str]) -> tuple[Path, dict[str, object], object]:
        fixture_root = ROOT / "tests" / "fixtures" / "execution-authorization"
        gate = json.loads((fixture_root / "gate-allow-limited.json").read_text(encoding="utf-8"))
        observed = inspect_git_worktree(repo)
        gate["subject"] = {
            "repo": observed["repo_identity"],
            "commit": observed["commit"],
            "tree_hash": observed["tree_hash"],
            "snapshot_id": observed["snapshot_id"],
            "manifest_fingerprint": observed["manifest_fingerprint"],
            "binding_kind": "snapshot_bound",
        }
        authorization = dict(
            build_execution_authorization_draft(
                gate,
                command,
                expires_at="2099-01-01T00:00:00Z",
                approved_image={"requested_reference": IMAGE, "resolved_image_id": self.image_id},
            )
        )
        authorization.update(
            {
                "approved": True,
                "approved_by": "redacted@example.invalid",
                "approved_at": "2026-07-01T00:00:00Z",
            }
        )
        path = root / "authorization.json"
        path.write_text(json.dumps(authorization) + "\n", encoding="utf-8")
        validation = validate_execution_authorization(
            authorization,
            gate,
            command,
            runtime_image_reference=IMAGE,
            runtime_image_id=self.image_id,
            expected_repository_identity=observed["repo_identity"],
            expected_commit=observed["commit"],
            expected_tree=observed["tree_hash"],
            expected_snapshot_id=observed["snapshot_id"],
            expected_manifest_fingerprint=observed["manifest_fingerprint"],
        )
        self.assertTrue(validation.execution_authorized, validation.to_dict())
        return path, gate, validation

    def _run(
        self,
        repo: Path,
        root: Path,
        command: list[str],
        *,
        timeout_seconds: int = 10,
        with_authorization: bool = True,
    ) -> dict[str, object]:
        kwargs: dict[str, object] = {
            "image": IMAGE,
            "profile_name": "locked-down",
            "command_argv": command,
            "timeout_seconds": timeout_seconds,
            "runner": self.runner,
        }
        if with_authorization:
            path, gate, validation = self._auth(root, repo, command)
            kwargs.update(
                {
                    "authorization_path": path,
                    "authorization_validation": validation,
                    "gate_decision": gate,
                    "fail_on_gate": "unknown",
                }
            )
        return run_sandbox_run(repo, **kwargs)  # type: ignore[arg-type]

    def test_missing_authorization_blocks_before_real_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self._repo(root)
            report = self._run(repo, root, ["python3", "-c", "print('blocked')"], with_authorization=False)

        self.assertTrue(report["policy_blocked"])
        self.assertFalse(report["docker"]["docker_invoked"])
        self.assertFalse(report["authorization"]["execution_authorized"])
        self.assertIn("authorization_required", report["approval"]["refusal_reasons"])

    def test_modified_authorization_artifact_blocks_even_with_stale_validation(self) -> None:
        command = ["python3", "-c", "print('modified-authorization')"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self._repo(root)
            authorization_path, gate, validation = self._auth(root, repo, command)
            authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
            authorization["approved"] = False
            authorization["approved_by"] = None
            authorization["approved_at"] = None
            authorization_path.write_text(json.dumps(authorization) + "\n", encoding="utf-8")
            report = run_sandbox_run(
                repo,
                authorization_path=authorization_path,
                authorization_validation=validation,
                gate_decision=gate,
                fail_on_gate="unknown",
                image=IMAGE,
                profile_name="locked-down",
                command_argv=command,
                timeout_seconds=10,
                runner=self.runner,
            )

        self.assertTrue(report["policy_blocked"])
        self.assertFalse(report["docker"]["docker_invoked"])
        self.assertFalse(report["command_started"])
        self.assertIn("approval_missing", report["approval"]["refusal_reasons"])

    def test_valid_authorization_runs_and_cleans_container(self) -> None:
        command = ["python3", "-c", "print('authorized')"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self._run(self._repo(root), root, command)

        self.assertEqual("completed", report["result"]["status"])
        self.assertEqual(0, report["sandbox_exit_code"])
        self.assertTrue(report["command_started"])
        self.assertEqual("confirmed", report["command_start_state"])
        self.assertTrue(report["authorization"]["execution_authorized"])
        self.assertEqual(
            "ok",
            report["docker"]["cleanup_status"],
            {
                "cleanup_attempted": report["docker"]["cleanup_attempted"],
                "cleanup_failure_class": report["docker"]["cleanup_failure_class"],
                "tracking": report["docker"]["container_tracking_enabled"],
                "status": report["result"]["status"],
            },
        )

    def test_timeout_is_unknown_start_state_and_cleans_container(self) -> None:
        command = ["python3", "-c", "import time; time.sleep(30)"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self._run(self._repo(root), root, command, timeout_seconds=1)

        self.assertEqual("timed_out", report["result"]["status"])
        self.assertFalse(report["command_started"])
        self.assertEqual("unknown", report["command_start_state"])
        self.assertEqual("ok", report["docker"]["cleanup_status"])
        self.assertEqual(1, report["sandbox_exit_code"])

    def test_output_budget_stops_32_mib_output_without_raw_persistence(self) -> None:
        command = ["python3", "-c", "import sys; sys.stdout.buffer.write(b'x' * (32 * 1024 * 1024))"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self._run(self._repo(root), root, command)

        output = report["output_summary"]
        self.assertEqual(
            "output_budget_exceeded",
            report["result"]["status"],
            {
                "cleanup_attempted": report["docker"]["cleanup_attempted"],
                "cleanup_failure_class": report["docker"]["cleanup_failure_class"],
                "cleanup_status": report["docker"]["cleanup_status"],
                "tracking": report["docker"]["container_tracking_enabled"],
            },
        )
        self.assertEqual(2, report["sandbox_exit_code"])
        self.assertTrue(output["output_budget_exceeded"])
        self.assertTrue(output["stdout_truncated"])
        self.assertLessEqual(output["stdout_bytes"], output["stdout_byte_budget"] + output["read_chunk_bytes"])
        self.assertLessEqual(len(output["stdout_preview_redacted"]), output["preview_char_budget"] + 64)
        self.assertFalse(output["raw_stdout_stderr_persisted"])
        self.assertEqual(
            "ok",
            report["docker"]["cleanup_status"],
            {
                "cleanup_attempted": report["docker"]["cleanup_attempted"],
                "cleanup_failure_class": report["docker"]["cleanup_failure_class"],
                "tracking": report["docker"]["container_tracking_enabled"],
                "status": report["result"]["status"],
            },
        )

    def test_out_write_is_kernel_bounded_and_original_repo_is_unchanged(self) -> None:
        command = [
            "python3",
            "-c",
            "from pathlib import Path; f=Path('/out/rhd-bounded-disk-probe.bin').open('wb'); [f.write(b'x' * (1024 * 1024)) for _ in range(128)]",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self._repo(root)
            before = fingerprint_target(repo).fingerprint
            report = self._run(repo, root, command)
            after = fingerprint_target(repo).fingerprint

        self.assertEqual(before, after)
        self.assertEqual("failed", report["result"]["status"])
        self.assertTrue(report["command_started"])
        self.assertTrue(report["runtime_write_budget"]["paths"]["out"]["kernel_enforced"])
        self.assertEqual(64 * 1024 * 1024, report["runtime_write_budget"]["paths"]["out"]["max_bytes"])
        self.assertFalse(report["runtime_write_budget"]["paths"]["out"]["host_backed"])
        self.assertEqual("ok", report["docker"]["cleanup_status"])

    def test_option_like_image_is_blocked_without_docker_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self._repo(root)
            report = run_sandbox_run(
                repo,
                image="--label=rhd-benign-option-probe=1",
                profile_name="locked-down",
                command_argv=["python3", "-c", "print('blocked')"],
                runner=self.runner,
                dry_run=True,
            )

        self.assertTrue(report["policy_blocked"])
        self.assertFalse(report["docker"]["docker_invoked"])
        self.assertNotIn("rhd-benign-option-probe", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
