from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from repo_health_doctor.gate.authorization import (
    AUTHORIZATION_RESERVATION_EXISTS_REASON,
    AUTHORIZATION_RESERVATION_WRITE_FAILURE_REASON,
    authorization_reservation_path,
    build_execution_authorization_draft,
    reserve_execution_authorization,
    validate_execution_authorization,
)
from repo_health_doctor.sandbox.docker_runner import FakeDockerRunner
from repo_health_doctor.sandbox.run import run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import (
    DisposableWorkspace,
    create_verified_snapshot,
    inspect_git_worktree,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "execution-authorization"
COMMAND = ["python3", "-m", "pytest", "tests"]


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class CountingFakeDockerRunner(FakeDockerRunner):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.run_calls = 0

    def run(self, argv: list[str], timeout_seconds: int):  # type: ignore[no-untyped-def]
        self.run_calls += 1
        return super().run(argv, timeout_seconds)


class ExecutionAuthorizationSingleUseTests(unittest.TestCase):
    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True, capture_output=True)
        (repo / "README.md").write_text("demo\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True, capture_output=True)
        return repo

    def _authorization(self, root: Path, repo: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
        gate = deepcopy(_fixture("gate-allow-limited.json"))
        observed = inspect_git_worktree(repo)
        subject = {
            "repo": observed["repo_identity"],
            "commit": observed["commit"],
            "tree_hash": observed["tree_hash"],
            "snapshot_id": observed["snapshot_id"],
            "manifest_fingerprint": observed["manifest_fingerprint"],
            "binding_kind": "snapshot_bound",
        }
        gate["subject"] = subject
        authorization = dict(build_execution_authorization_draft(gate, COMMAND, expires_at="2099-01-01T00:00:00Z"))
        authorization["approved"] = True
        authorization["approved_by"] = "redacted@example.invalid"
        authorization["approved_at"] = "2026-07-01T00:00:00Z"
        path = root / "authorization.json"
        path.write_text(json.dumps(authorization) + "\n", encoding="utf-8")
        return path, gate, authorization

    def _validation(
        self,
        gate: dict[str, object],
        authorization: dict[str, object],
    ):
        return validate_execution_authorization(authorization, gate, COMMAND)

    def _run(
        self,
        repo: Path,
        authorization_path: Path,
        validation: object,
        gate: dict[str, object],
        runner: CountingFakeDockerRunner,
        *,
        dry_run: bool = False,
        prepared_workspace: DisposableWorkspace | None = None,
    ) -> dict[str, object]:
        return run_sandbox_run(
            repo,
            authorization_path=authorization_path,
            authorization_validation=validation,
            gate_decision=gate,
            profile_name="locked-down",
            command_argv=COMMAND,
            runner=runner,
            dry_run=dry_run,
            prepared_workspace=prepared_workspace,
        )

    def test_first_reservation_is_atomic_and_reuse_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            authorization_path = Path(tmp) / "authorization.json"
            first = reserve_execution_authorization(authorization_path)
            second = reserve_execution_authorization(authorization_path)

            self.assertTrue(first.reserved)
            self.assertEqual(first.reservation_path, authorization_reservation_path(authorization_path))
            self.assertTrue(first.reservation_path.is_file())
            self.assertEqual(second.refusal_reason, AUTHORIZATION_RESERVATION_EXISTS_REASON)
            self.assertFalse(second.reserved)

            flags = os.O_CREAT | os.O_EXCL
            with patch("repo_health_doctor.gate.authorization.os.open", wraps=os.open) as mocked_open:
                another = reserve_execution_authorization(Path(tmp) / "another.json")
            self.assertTrue(another.reserved)
            used_flags = mocked_open.call_args.args[1]
            self.assertEqual(used_flags & flags, flags)

    def test_write_failure_rejects_before_runner_and_keeps_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            authorization_path, gate, authorization = self._authorization(root, repo)
            validation = self._validation(gate, authorization)
            runner = CountingFakeDockerRunner()
            workspace = create_verified_snapshot(repo)

            with patch(
                "repo_health_doctor.gate.authorization.os.write",
                side_effect=OSError("marker write failed"),
            ):
                report = self._run(
                    repo,
                    authorization_path,
                    validation,
                    gate,
                    runner,
                    prepared_workspace=workspace,
                )

            self.assertTrue(report["policy_blocked"])
            self.assertEqual(runner.run_calls, 0)
            self.assertIn(
                AUTHORIZATION_RESERVATION_WRITE_FAILURE_REASON,
                report["approval"]["refusal_reasons"],  # type: ignore[index]
            )
            self.assertTrue(authorization_reservation_path(authorization_path).exists())

    def test_docker_start_failure_still_consumes_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            authorization_path, gate, authorization = self._authorization(root, repo)
            validation = self._validation(gate, authorization)
            failing_runner = CountingFakeDockerRunner(
                mode="failure",
                exit_code=125,
                docker_invoked=True,
            )

            first = self._run(repo, authorization_path, validation, gate, failing_runner)
            second = self._run(repo, authorization_path, validation, gate, failing_runner)

            self.assertFalse(first["policy_blocked"])
            self.assertEqual(first["result"]["status"], "failed")  # type: ignore[index]
            self.assertEqual(first["authorization"]["single_use_reservation"]["status"], "reserved")  # type: ignore[index]
            self.assertTrue(authorization_reservation_path(authorization_path).exists())
            self.assertTrue(second["policy_blocked"])
            self.assertIn(
                AUTHORIZATION_RESERVATION_EXISTS_REASON,
                second["approval"]["refusal_reasons"],  # type: ignore[index]
            )
            self.assertEqual(failing_runner.run_calls, 1)

    def test_dry_run_and_gate_check_do_not_consume_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            authorization_path, gate, authorization = self._authorization(root, repo)
            validation = self._validation(gate, authorization)
            runner = CountingFakeDockerRunner()

            report = self._run(
                repo,
                authorization_path,
                validation,
                gate,
                runner,
                dry_run=True,
            )

            self.assertEqual(report["result"]["status"], "dry_run")  # type: ignore[index]
            self.assertFalse(report["authorization"]["single_use_reservation"]["consumed"])  # type: ignore[index]
            self.assertFalse(authorization_reservation_path(authorization_path).exists())
            self.assertEqual(runner.run_calls, 0)

            argv_path = root / "argv.json"
            argv_path.write_text(json.dumps(COMMAND) + "\n", encoding="utf-8")
            gate_check = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor",
                    "gate-check",
                    str(repo),
                    "--authorization",
                    str(authorization_path),
                    "--argv-json",
                    str(argv_path),
                    "--no-discover",
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                env={"PYTHONPATH": str(ROOT / "src")},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertIn(gate_check.returncode, {0, 2})
            json.loads(gate_check.stdout)
            self.assertFalse(authorization_reservation_path(authorization_path).exists())


if __name__ == "__main__":
    unittest.main()
