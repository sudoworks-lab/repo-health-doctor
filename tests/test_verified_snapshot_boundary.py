from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from repo_health_doctor.gate.authorization import (
    build_execution_authorization_draft,
    validate_execution_authorization,
)
from repo_health_doctor.sandbox.docker_runner import FakeDockerRunner
from repo_health_doctor.sandbox.run import run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import (
    CopyBudget,
    GIT_MINIMUM_VERSION,
    create_verified_snapshot,
    verify_verified_snapshot,
)


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ["python3", "-c", "print('verified snapshot')"]


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _git_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "README.md").write_text("verified snapshot\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(
        repo,
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "user.name=test",
        "commit",
        "-qm",
        "initial",
    )
    return repo


class _CountingRunner(FakeDockerRunner):
    def __init__(self) -> None:
        super().__init__()
        self.run_calls = 0

    def run(self, argv: list[str], timeout_seconds: int):  # type: ignore[no-untyped-def]
        self.run_calls += 1
        return super().run(argv, timeout_seconds)


class VerifiedSnapshotBoundaryTests(unittest.TestCase):
    def test_sparse_huge_file_is_refused_before_full_read_and_partial_tree_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            huge = repo / "huge.bin"
            with huge.open("wb") as handle:
                handle.truncate(1024 * 1024)

            with patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("full-file read is forbidden"),
            ):
                workspace = create_verified_snapshot(
                    repo,
                    copy_budget=CopyBudget(max_file_bytes=1024),
                )
            try:
                self.assertFalse(workspace.copy_safety_ok)
                self.assertIsNone(workspace.verified_snapshot)
                self.assertEqual(
                    workspace.copy_budget_exceeded_reason,
                    "max_file_bytes",
                )
                self.assertEqual(list(workspace.workspace.iterdir()), [])
            finally:
                workspace.cleanup()

    def test_streaming_reads_are_fixed_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "payload.bin").write_bytes(b"x" * (256 * 1024))
            read_sizes: list[int] = []
            real_read = os.read

            def bounded_read(fd: int, size: int) -> bytes:
                read_sizes.append(size)
                return real_read(fd, size)

            with patch(
                "repo_health_doctor.sandbox.run_workspace.os.read",
                side_effect=bounded_read,
            ):
                workspace = create_verified_snapshot(repo)
            try:
                self.assertTrue(workspace.copy_safety_ok)
                self.assertTrue(read_sizes)
                self.assertLessEqual(max(read_sizes), 64 * 1024)
            finally:
                workspace.cleanup()

    def test_file_count_budget_stops_at_first_entry_beyond_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            for index in range(20):
                (repo / f"{index:02d}.txt").write_text("x", encoding="utf-8")

            workspace = create_verified_snapshot(
                repo,
                copy_budget=CopyBudget(max_file_count=2),
            )
            try:
                self.assertFalse(workspace.copy_safety_ok)
                self.assertEqual(
                    workspace.copy_budget_exceeded_reason,
                    "max_file_count",
                )
                self.assertEqual(workspace.entries_examined, 3)
                self.assertEqual(list(workspace.workspace.iterdir()), [])
            finally:
                workspace.cleanup()

    def test_deep_directory_budget_fails_without_python_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            current = repo
            current.mkdir()
            for index in range(12):
                current = current / f"d{index}"
                current.mkdir()
            (current / "payload.txt").write_text("deep", encoding="utf-8")

            workspace = create_verified_snapshot(
                repo,
                copy_budget=CopyBudget(max_depth=4),
            )
            try:
                self.assertFalse(workspace.copy_safety_ok)
                self.assertEqual(
                    workspace.copy_budget_exceeded_reason,
                    "max_depth",
                )
                self.assertNotIn("RecursionError", " ".join(workspace.copy_errors))
            finally:
                workspace.cleanup()

    def test_git_tree_applies_file_directory_and_depth_budgets_before_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _git_repo(Path(tmp))
            deep = repo / "one" / "two" / "three"
            deep.mkdir(parents=True)
            (deep / "payload.txt").write_text("deep", encoding="utf-8")
            for index in range(4):
                (repo / f".env.{index}").write_text("excluded", encoding="utf-8")
            _git(repo, "add", "one/two/three/payload.txt", *[f".env.{index}" for index in range(4)])
            _git(
                repo,
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "user.name=test",
                "commit",
                "-qm",
                "budget fixture",
            )

            depth_refusal = create_verified_snapshot(
                repo,
                copy_budget=CopyBudget(max_depth=2),
            )
            try:
                self.assertFalse(depth_refusal.copy_safety_ok)
                self.assertEqual(
                    depth_refusal.copy_budget_exceeded_reason,
                    "max_depth",
                )
                self.assertEqual(list(depth_refusal.workspace.iterdir()), [])
            finally:
                depth_refusal.cleanup()

            file_refusal = create_verified_snapshot(
                repo,
                copy_budget=CopyBudget(max_file_count=2),
            )
            try:
                self.assertFalse(file_refusal.copy_safety_ok)
                self.assertEqual(
                    file_refusal.copy_budget_exceeded_reason,
                    "max_file_count",
                )
                self.assertEqual(file_refusal.entries_examined, 3)
                self.assertEqual(list(file_refusal.workspace.iterdir()), [])
            finally:
                file_refusal.cleanup()

    def test_symlinks_and_special_files_are_never_followed_or_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.write_text("outside", encoding="utf-8")
            repo = root / "repo"
            repo.mkdir()
            (repo / "outside-link").symlink_to(outside)
            if hasattr(os, "mkfifo"):
                os.mkfifo(repo / "pipe")
            unix_socket = socket.socket(socket.AF_UNIX)
            try:
                unix_socket.bind(str(repo / "socket"))
                workspace = create_verified_snapshot(repo)
                try:
                    self.assertFalse(workspace.copy_safety_ok)
                    self.assertIsNone(workspace.verified_snapshot)
                    self.assertFalse((workspace.workspace / "outside-link").exists())
                    self.assertEqual(list(workspace.workspace.iterdir()), [])
                finally:
                    workspace.cleanup()
            finally:
                unix_socket.close()

    def test_symlink_swap_between_lstat_and_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.write_text("outside", encoding="utf-8")
            repo = root / "repo"
            repo.mkdir()
            victim = repo / "victim"
            victim.write_text("inside", encoding="utf-8")
            swapped = False

            def swap(event: str, relative: str) -> None:
                nonlocal swapped
                if event == "before_open" and relative == "victim" and not swapped:
                    victim.unlink()
                    victim.symlink_to(outside)
                    swapped = True

            workspace = create_verified_snapshot(repo, _event_hook=swap)
            try:
                self.assertTrue(swapped)
                self.assertFalse(workspace.copy_safety_ok)
                self.assertIsNone(workspace.verified_snapshot)
                self.assertEqual(list(workspace.workspace.iterdir()), [])
            finally:
                workspace.cleanup()

    def test_concurrent_mutation_invalidates_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            victim = repo / "victim"
            victim.write_bytes(b"a" * (192 * 1024))
            mutated = False

            def mutate(event: str, relative: str) -> None:
                nonlocal mutated
                if event == "after_chunk" and relative == "victim" and not mutated:
                    with victim.open("r+b") as handle:
                        handle.seek(0)
                        handle.write(b"b" * 4096)
                        handle.flush()
                        os.fsync(handle.fileno())
                    mutated = True

            workspace = create_verified_snapshot(repo, _event_hook=mutate)
            try:
                self.assertTrue(mutated)
                self.assertFalse(workspace.copy_safety_ok)
                self.assertIsNone(workspace.verified_snapshot)
                self.assertEqual(list(workspace.workspace.iterdir()), [])
            finally:
                workspace.cleanup()

    def test_source_root_rename_swap_invalidates_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "payload.txt").write_text("original", encoding="utf-8")
            original = root / "original"
            swapped = False

            def swap(event: str, relative: str) -> None:
                nonlocal swapped
                if event == "before_source_root_recheck" and not swapped:
                    repo.rename(original)
                    repo.mkdir()
                    (repo / "payload.txt").write_text("replacement", encoding="utf-8")
                    swapped = True

            workspace = create_verified_snapshot(repo, _event_hook=swap)
            try:
                self.assertTrue(swapped)
                self.assertFalse(workspace.copy_safety_ok)
                self.assertIn("source_root_swap_detected", workspace.refusal_reasons)
                self.assertEqual(list(workspace.workspace.iterdir()), [])
            finally:
                workspace.cleanup()

    def test_identity_is_canonical_and_changes_for_content_path_or_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            (first / "b.txt").write_text("b", encoding="utf-8")
            (first / "a.txt").write_text("a", encoding="utf-8")
            (second / "a.txt").write_text("a", encoding="utf-8")
            (second / "b.txt").write_text("b", encoding="utf-8")

            first_snapshot = create_verified_snapshot(first)
            second_snapshot = create_verified_snapshot(second)
            try:
                self.assertEqual(
                    first_snapshot.verified_snapshot.snapshot_id,  # type: ignore[union-attr]
                    second_snapshot.verified_snapshot.snapshot_id,  # type: ignore[union-attr]
                )
                baseline = second_snapshot.verified_snapshot.snapshot_id  # type: ignore[union-attr]
            finally:
                first_snapshot.cleanup()
                second_snapshot.cleanup()

            (second / "a.txt").write_text("changed", encoding="utf-8")
            changed_content = create_verified_snapshot(second)
            try:
                self.assertNotEqual(
                    baseline,
                    changed_content.verified_snapshot.snapshot_id,  # type: ignore[union-attr]
                )
            finally:
                changed_content.cleanup()

            (second / "a.txt").write_text("a", encoding="utf-8")
            (second / "b.txt").rename(second / "c.txt")
            changed_path = create_verified_snapshot(second)
            try:
                self.assertNotEqual(
                    baseline,
                    changed_path.verified_snapshot.snapshot_id,  # type: ignore[union-attr]
                )
            finally:
                changed_path.cleanup()

            (second / "c.txt").rename(second / "b.txt")
            (second / "a.txt").chmod(
                (second / "a.txt").stat().st_mode | stat.S_IXUSR
            )
            changed_mode = create_verified_snapshot(second)
            try:
                self.assertNotEqual(
                    baseline,
                    changed_mode.verified_snapshot.snapshot_id,  # type: ignore[union-attr]
                )
            finally:
                changed_mode.cleanup()

    def test_verified_snapshot_report_matches_closed_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "payload.txt").write_text("schema", encoding="utf-8")
            workspace = create_verified_snapshot(repo)
            try:
                snapshot = workspace.verified_snapshot
                self.assertIsNotNone(snapshot)
                schema = json.loads(
                    (ROOT / "schemas" / "verified-snapshot.schema.json").read_text(
                        encoding="utf-8"
                    )
                )
                try:
                    from jsonschema import Draft202012Validator
                except ModuleNotFoundError:
                    self.assertEqual(
                        set(snapshot.to_report()),  # type: ignore[union-attr]
                        set(schema["required"]),
                    )
                else:
                    Draft202012Validator(schema).validate(
                        snapshot.to_report()  # type: ignore[union-attr]
                    )
            finally:
                workspace.cleanup()

    def test_git_snapshot_is_exact_commit_and_dirty_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _git_repo(Path(tmp))
            workspace = create_verified_snapshot(repo)
            try:
                snapshot = workspace.verified_snapshot
                self.assertTrue(workspace.copy_safety_ok)
                self.assertIsNotNone(snapshot)
                self.assertEqual(snapshot.source_kind, "git_commit")  # type: ignore[union-attr]
                self.assertEqual(snapshot.source_commit, _git(repo, "rev-parse", "HEAD"))  # type: ignore[union-attr]
                self.assertEqual(snapshot.source_tree, _git(repo, "rev-parse", "HEAD^{tree}"))  # type: ignore[union-attr]
                self.assertTrue(verify_verified_snapshot(workspace))
            finally:
                workspace.cleanup()

            (repo / "untracked.txt").write_text("dirty", encoding="utf-8")
            dirty = create_verified_snapshot(repo)
            try:
                self.assertFalse(dirty.copy_safety_ok)
                self.assertIsNone(dirty.verified_snapshot)
                self.assertIn("source_worktree_not_exact_commit", dirty.refusal_reasons)
            finally:
                dirty.cleanup()

    def test_unsupported_git_version_fails_closed(self) -> None:
        self.assertGreaterEqual(GIT_MINIMUM_VERSION, (2, 42, 0))
        with tempfile.TemporaryDirectory() as tmp:
            repo = _git_repo(Path(tmp))
            with patch(
                "repo_health_doctor.sandbox.run_workspace._git_version",
                return_value=(2, 41, 0),
            ):
                workspace = create_verified_snapshot(repo)
            try:
                self.assertFalse(workspace.copy_safety_ok)
                self.assertIsNone(workspace.verified_snapshot)
                self.assertIn("unsupported_git_version", workspace.refusal_reasons)
            finally:
                workspace.cleanup()

    def test_subject_consistency_is_end_to_end_and_mismatch_prevents_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _git_repo(root)
            workspace = create_verified_snapshot(repo)
            self.assertIsNotNone(workspace.verified_snapshot)
            snapshot = workspace.verified_snapshot
            gate = json.loads(
                (
                    ROOT
                    / "tests"
                    / "fixtures"
                    / "execution-authorization"
                    / "gate-allow-limited.json"
                ).read_text(encoding="utf-8")
            )
            gate["subject"] = {
                "repo": snapshot.source_identity_redacted,
                "commit": snapshot.source_commit,
                "tree_hash": snapshot.source_tree,
                "snapshot_id": snapshot.snapshot_id,
                "manifest_fingerprint": snapshot.manifest_fingerprint,
                "binding_kind": "snapshot_bound",
            }
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
            validation = validate_execution_authorization(
                authorization,
                gate,
                COMMAND,
            )
            authorization_path = root / "authorization.json"
            authorization_path.write_text(
                json.dumps(authorization) + "\n",
                encoding="utf-8",
            )
            runner = _CountingRunner()

            report = run_sandbox_run(
                repo,
                command_argv=COMMAND,
                runner=runner,
                gate_decision=gate,
                authorization_path=authorization_path,
                authorization_validation=validation,
                prepared_workspace=workspace,
            )

            self.assertEqual(runner.run_calls, 1)
            consistency = report["subject_consistency"]
            self.assertTrue(consistency["consistent"])
            self.assertEqual(
                {
                    consistency["scan_snapshot_id"],
                    consistency["gate_snapshot_id"],
                    consistency["authorization_snapshot_id"],
                    consistency["workspace_snapshot_id"],
                    consistency["evidence_snapshot_id"],
                },
                {snapshot.snapshot_id},
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _git_repo(root)
            workspace = create_verified_snapshot(repo)
            snapshot = workspace.verified_snapshot
            mismatched_gate = deepcopy(gate)
            mismatched_gate["subject"]["snapshot_id"] = "sha256:" + "f" * 64
            runner = _CountingRunner()
            try:
                report = run_sandbox_run(
                    repo,
                    command_argv=COMMAND,
                    runner=runner,
                    gate_decision=mismatched_gate,
                    prepared_workspace=workspace,
                )
            finally:
                if workspace.cleanup_status == "not_started":
                    workspace.cleanup()

            self.assertEqual(runner.run_calls, 0)
            self.assertTrue(report["policy_blocked"])
            self.assertIn(
                "snapshot_subject_mismatch",
                report["approval"]["refusal_reasons"],
            )

    def test_snapshot_mutation_after_planning_blocks_immediately_before_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            payload = repo / "payload.txt"
            payload.write_text("immutable", encoding="utf-8")
            workspace = create_verified_snapshot(repo)
            snapshot_payload = workspace.workspace / "payload.txt"

            class MutatingRuntimeProbe(_CountingRunner):
                def detect_runtime(self) -> dict[str, str]:
                    snapshot_payload.chmod(0o600)
                    snapshot_payload.write_text("mutated", encoding="utf-8")
                    return super().detect_runtime()

            runner = MutatingRuntimeProbe()
            report = run_sandbox_run(
                repo,
                command_argv=COMMAND,
                runner=runner,
                prepared_workspace=workspace,
            )

            self.assertEqual(runner.run_calls, 0)
            self.assertTrue(report["policy_blocked"])
            self.assertIn(
                "snapshot_integrity_verification_failed",
                report["approval"]["refusal_reasons"],
            )


if __name__ == "__main__":
    unittest.main()
