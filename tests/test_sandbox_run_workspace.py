from __future__ import annotations

import os
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.docker_runner import FakeDockerRunner
from repo_health_doctor.sandbox.run import run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import (
    CopyBudget,
    create_disposable_workspace,
    snapshot_workspace,
    summarize_workspace_diff,
)


def test_workspace_copy_excludes_git_env_and_caches(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("demo\n", encoding="utf-8")
    (repo / ".env").write_text("TOKEN=not-copied\n", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (repo / "__pycache__").mkdir()
    (repo / "__pycache__" / "x.pyc").write_bytes(b"cached")

    workspace = create_disposable_workspace(repo)
    try:
        assert workspace.copy_safety_ok is True
        assert (workspace.workspace / "README.md").is_file()
        assert not (workspace.workspace / ".env").exists()
        assert not (workspace.workspace / ".git").exists()
        assert not (workspace.workspace / "__pycache__").exists()
        categories = {item["category"] for item in workspace.to_report()["excluded_path_categories"]}
        assert "credential_like" in categories
        assert "vcs_metadata" in categories
        assert "cache" in categories
    finally:
        workspace.cleanup()


def test_workspace_copy_detects_symlink_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (repo / "escape").symlink_to(outside)

    workspace = create_disposable_workspace(repo)
    try:
        assert workspace.copy_safety_ok is False
        assert workspace.unsafe_symlinks == ["escape"]
        assert not (workspace.workspace / "escape").exists()
    finally:
        workspace.cleanup()


def test_workspace_diff_reports_created_modified_deleted_without_raw_contents(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "keep.txt").write_text("before\n", encoding="utf-8")
    (workspace / "delete.txt").write_text("delete\n", encoding="utf-8")
    before = snapshot_workspace(workspace)

    (workspace / "keep.txt").write_text("after\n", encoding="utf-8")
    (workspace / "delete.txt").unlink()
    (workspace / "created.txt").write_text("created\n", encoding="utf-8")
    after = snapshot_workspace(workspace)
    diff = summarize_workspace_diff(before, after)

    assert diff["available"] is True
    assert diff["created_count"] == 1
    assert diff["modified_count"] == 1
    assert diff["deleted_count"] == 1
    assert diff["raw_contents_persisted"] is False
    assert "<workspace>/created.txt" in diff["interesting_paths_redacted"]


class SandboxRunWorkspaceContractTests(unittest.TestCase):
    def test_copy_policy_excludes_secret_cache_history_git_and_special_files(self) -> None:
        with self.subTest("copy exclusions"):
            import tempfile

            with tempfile.TemporaryDirectory() as tmp:
                repo = Path(tmp) / "repo"
                repo.mkdir()
                (repo / "README.md").write_text("demo\n", encoding="utf-8")
                (repo / ".env.local").write_text("TOKEN=not-copied\n", encoding="utf-8")
                (repo / ".bash_history").write_text("secret command\n", encoding="utf-8")
                (repo / ".git").mkdir()
                (repo / ".git" / "config").write_text("[core]\n", encoding="utf-8")
                (repo / ".ssh").mkdir()
                (repo / ".ssh" / "id_rsa").write_text("not-copied\n", encoding="utf-8")
                (repo / "node_modules").mkdir()
                (repo / "node_modules" / "pkg.js").write_text("not-copied\n", encoding="utf-8")
                workspace = create_disposable_workspace(repo)
                try:
                    self.assertTrue(workspace.copy_safety_ok)
                    self.assertIsNotNone(workspace.verified_snapshot)
                    self.assertTrue((workspace.workspace / "README.md").is_file())
                    self.assertFalse((workspace.workspace / ".env.local").exists())
                    self.assertFalse((workspace.workspace / ".bash_history").exists())
                    self.assertFalse((workspace.workspace / ".git").exists())
                    self.assertFalse((workspace.workspace / ".ssh").exists())
                    self.assertFalse((workspace.workspace / "node_modules").exists())
                    categories = {
                        item["category"]
                        for item in workspace.to_report()["excluded_path_categories"]
                    }
                    self.assertIn("credential_like", categories)
                    self.assertIn("history", categories)
                    self.assertIn("vcs_metadata", categories)
                    self.assertIn("dependency_tree", categories)
                finally:
                    workspace.cleanup()

                if hasattr(os, "mkfifo"):
                    os.mkfifo(repo / "pipe")
                    refused = create_disposable_workspace(repo)
                    try:
                        self.assertFalse(refused.copy_safety_ok)
                        self.assertIsNone(refused.verified_snapshot)
                        self.assertEqual(list(refused.workspace.iterdir()), [])
                        self.assertIn(
                            "source_special_file_refused",
                            refused.refusal_reasons,
                        )
                    finally:
                        refused.cleanup()

    def test_copy_budget_exceeded_blocks_before_runner_starts(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "large.txt").write_text("too large\n", encoding="utf-8")

            report = run_sandbox_run(
                repo,
                image="python:3.12-slim",
                profile_name="locked-down",
                command_argv=["python", "-c", "print('should not run')"],
                runner=FakeDockerRunner(),
                copy_budget=CopyBudget(max_file_bytes=1),
            )

        self.assertTrue(report["policy_blocked"])
        self.assertFalse(report["command_started"])
        self.assertEqual(report["sandbox_exit_code"], 2)
        self.assertIn("copy_budget_exceeded", report["approval"]["refusal_reasons"])

    def test_symlink_escape_is_skipped_and_blocks_execution(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            outside = root / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            (repo / "escape").symlink_to(outside)

            workspace = create_disposable_workspace(repo)
            try:
                self.assertFalse(workspace.copy_safety_ok)
                self.assertEqual(workspace.unsafe_symlinks, ["escape"])
                self.assertFalse((workspace.workspace / "escape").exists())
            finally:
                workspace.cleanup()
