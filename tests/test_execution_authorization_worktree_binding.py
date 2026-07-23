from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from repo_health_doctor.gate.authorization import (
    AUTHORIZATION_SNAPSHOT_BINDING_MISMATCH_REASON,
    AUTHORIZATION_SNAPSHOT_BINDING_UNRESOLVED_REASON,
    AUTHORIZATION_WORKTREE_BINDING_MISMATCH_REASON,
    AUTHORIZATION_WORKTREE_BINDING_UNRESOLVED_REASON,
    AUTHORIZATION_WORKTREE_DIRTY_REASON,
    AUTHORIZATION_WORKTREE_NOT_GIT_REASON,
    build_execution_authorization_draft,
    validate_execution_authorization,
    validate_execution_authorization_worktree_binding,
)
from repo_health_doctor.sandbox.docker_runner import FakeDockerRunner
from repo_health_doctor.sandbox.run import run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import (
    create_verified_snapshot,
    inspect_git_worktree,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "execution-authorization"
COMMAND = ["python3", "-c", "print('worktree binding')"]


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


class ExecutionAuthorizationWorktreeBindingTests(unittest.TestCase):
    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "test@example.invalid")
        _git(repo, "config", "user.name", "test")
        (repo / "README.md").write_text("clean\n", encoding="utf-8")
        _git(repo, "add", "README.md")
        _git(repo, "commit", "-qm", "initial")
        return repo

    def _authorization(self, repo: Path, root: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
        workspace = create_verified_snapshot(repo)
        snapshot = workspace.verified_snapshot
        self.assertIsNotNone(snapshot)
        gate = deepcopy(_fixture("gate-allow-limited.json"))
        gate_subject = {
            "repo": "<repo>",
            "commit": snapshot.source_commit,  # type: ignore[union-attr]
            "tree_hash": snapshot.source_tree,  # type: ignore[union-attr]
            "snapshot_id": snapshot.snapshot_id,  # type: ignore[union-attr]
            "manifest_fingerprint": snapshot.manifest_fingerprint,  # type: ignore[union-attr]
            "binding_kind": "snapshot_bound",
        }
        gate["subject"] = gate_subject
        authorization = dict(
            build_execution_authorization_draft(
                gate,
                COMMAND,
                expires_at="2099-01-01T00:00:00Z",
            )
        )
        authorization["approved"] = True
        authorization["approved_by"] = "redacted@example.invalid"
        authorization["approved_at"] = "2026-07-01T00:00:00Z"
        path = root / "authorization.json"
        path.write_text(json.dumps(authorization) + "\n", encoding="utf-8")
        workspace.cleanup()
        return path, gate, authorization

    def test_direct_git_observation_matches_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            _, _, authorization = self._authorization(repo, root)

            result = validate_execution_authorization_worktree_binding(
                authorization,
                inspect_git_worktree(repo),
            )

            self.assertTrue(result.matched)
            self.assertEqual(result.status, "matched")
            self.assertEqual(result.refusal_reasons, ())

    def test_subject_mismatch_blocks_before_runner_starts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            authorization_path, gate, authorization = self._authorization(repo, root)
            validation = validate_execution_authorization(authorization, gate, COMMAND)
            changed = deepcopy(authorization)
            changed_subject = dict(changed["subject"])  # type: ignore[arg-type]
            changed_subject["commit"] = "f" * 40
            changed["subject"] = changed_subject
            authorization_path.write_text(json.dumps(changed) + "\n", encoding="utf-8")
            runner = FakeDockerRunner()

            report = run_sandbox_run(
                repo,
                authorization_path=authorization_path,
                authorization_validation=validation,
                gate_decision=gate,
                command_argv=COMMAND,
                runner=runner,
            )

            self.assertTrue(report["policy_blocked"])
            self.assertFalse(report["command_started"])
            self.assertEqual(report["authorization"]["snapshot_binding"]["status"], "mismatch")  # type: ignore[index]
            self.assertIn(
                AUTHORIZATION_SNAPSHOT_BINDING_MISMATCH_REASON,
                report["authorization"]["snapshot_binding"]["refusal_reasons"],  # type: ignore[index]
            )
            self.assertNotIn("allow_dirty", json.dumps(report))

    def test_dirty_worktree_blocks_before_workspace_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            authorization_path, gate, authorization = self._authorization(repo, root)
            validation = validate_execution_authorization(authorization, gate, COMMAND)
            (repo / "README.md").write_text("dirty\n", encoding="utf-8")
            runner = FakeDockerRunner()

            report = run_sandbox_run(
                repo,
                authorization_path=authorization_path,
                authorization_validation=validation,
                gate_decision=gate,
                command_argv=COMMAND,
                runner=runner,
            )

            self.assertTrue(report["policy_blocked"])
            self.assertTrue(report["disposable_workspace"]["created"])  # type: ignore[index]
            self.assertFalse(report["disposable_workspace"]["copy_safety_ok"])  # type: ignore[index]
            self.assertEqual(report["authorization"]["snapshot_binding"]["status"], "unresolved")  # type: ignore[index]
            self.assertIn(
                AUTHORIZATION_SNAPSHOT_BINDING_UNRESOLVED_REASON,
                report["authorization"]["snapshot_binding"]["refusal_reasons"],  # type: ignore[index]
            )
            self.assertIn("source_worktree_not_exact_commit", report["approval"]["refusal_reasons"])

    def test_non_git_and_unresolved_worktree_are_not_implicitly_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "not-git"
            repo.mkdir()
            (repo / "README.md").write_text("not git\n", encoding="utf-8")
            authorization_path, gate, authorization = self._authorization(self._repo(root), root)
            validation = validate_execution_authorization(authorization, gate, COMMAND)
            runner = FakeDockerRunner()

            report = run_sandbox_run(
                repo,
                authorization_path=authorization_path,
                authorization_validation=validation,
                gate_decision=gate,
                command_argv=COMMAND,
                runner=runner,
            )

            self.assertTrue(report["policy_blocked"])
            self.assertEqual(report["authorization"]["snapshot_binding"]["status"], "mismatch")  # type: ignore[index]
            reasons = report["authorization"]["snapshot_binding"]["refusal_reasons"]  # type: ignore[index]
            self.assertIn(AUTHORIZATION_SNAPSHOT_BINDING_MISMATCH_REASON, reasons)


if __name__ == "__main__":
    unittest.main()
