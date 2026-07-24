from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import tracemalloc
import unittest
from unittest import mock

from repo_health_doctor import cli
from repo_health_doctor.external_scanner.adapters import (
    gitleaks_adapter,
    osv_scanner_adapter,
    trivy_adapter,
)
from repo_health_doctor.gate.authorization import (
    build_execution_authorization_draft,
    validate_execution_authorization,
    validate_execution_authorization_snapshot_binding,
)
from repo_health_doctor.gate.v3_evaluator import (
    evaluate_gate_decision_from_scan_envelope,
    evaluate_gate_decision_from_v3_report,
    scan_verified_snapshot,
)
import repo_health_doctor.gate.v3_evaluator as v3_evaluator
from repo_health_doctor.sandbox import run_workspace
from repo_health_doctor.sandbox.docker_runner import DockerRunner, FakeDockerRunner
from repo_health_doctor.sandbox.run import (
    _load_authorization_document,
    run_sandbox_run,
)
from repo_health_doctor.sandbox.run_workspace import (
    CopyBudget,
    SnapshotManifestEntry,
    create_verified_snapshot,
    verify_verified_snapshot,
)


COMMAND = ["python3", "-c", "print('verified snapshot closure')"]
ROOT = Path(__file__).resolve().parents[1]


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _git_repo(root: Path, name: str, *, message: str = "initial") -> Path:
    repo = root / name
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "test")
    (repo / "README.md").write_text("same tree\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", message)
    return repo


class _StartedProcess:
    returncode = None
    stdout = object()
    stderr = object()


class _CountingRunner(FakeDockerRunner):
    def __init__(self) -> None:
        super().__init__()
        self.run_calls = 0

    def run(self, argv: list[str], timeout_seconds: int):  # type: ignore[no-untyped-def]
        self.run_calls += 1
        return super().run(argv, timeout_seconds)


class VerifiedSnapshotClosureRegressionTests(unittest.TestCase):
    def test_vsbr_static_001_real_scanners_do_not_run_adapter_local_git(self) -> None:
        cases = (
            (
                gitleaks_adapter,
                gitleaks_adapter.run_gitleaks_scan,
            ),
            (
                osv_scanner_adapter,
                osv_scanner_adapter.run_osv_scan,
            ),
            (
                trivy_adapter,
                trivy_adapter.run_trivy_scan,
            ),
        )

        def unavailable_runner(argv, timeout_seconds):
            del argv, timeout_seconds
            raise FileNotFoundError("scanner unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("bounded\n", encoding="utf-8")
            for adapter, run_scan in cases:
                with self.subTest(adapter=adapter.__name__):
                    with mock.patch.object(
                        adapter.subprocess,
                        "run",
                        side_effect=AssertionError("adapter-local subprocess.run invoked"),
                    ) as ambient_run:
                        result = run_scan(repo, runner=unavailable_runner)
                    self.assertFalse(result.valid)
                    ambient_run.assert_not_called()

    def test_vsbr_static_002_default_scan_always_prepares_verified_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("bounded\n", encoding="utf-8")
            with mock.patch.object(
                cli,
                "create_static_scan_snapshot",
                wraps=run_workspace.create_static_scan_snapshot,
            ) as create:
                with redirect_stdout(io.StringIO()):
                    exit_code = cli.main([str(repo), "--format", "json"])

        self.assertIn(exit_code, {0, 1})
        create.assert_called_once_with(repo)

    def test_vsbr_static_002_dirty_git_fallback_keeps_bounded_tracked_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _git_repo(Path(tmp), "repo")
            (repo / ".gitignore").write_text("logs/\n", encoding="utf-8")
            (repo / "build").mkdir()
            (repo / "build" / "output.txt").write_text(
                "tracked artifact\n",
                encoding="utf-8",
            )
            _git(repo, "add", ".gitignore", "build/output.txt")
            _git(repo, "commit", "-qm", "tracked scope")
            (repo / "README.md").write_text("dirty\n", encoding="utf-8")
            (repo / "logs").mkdir()
            (repo / "logs" / "ignored.log").write_text(
                "ignored artifact\n",
                encoding="utf-8",
            )

            workspace = run_workspace.create_static_scan_snapshot(repo)
            try:
                snapshot = workspace.verified_snapshot
                self.assertIsNotNone(snapshot)
                self.assertEqual(snapshot.source_kind, "filesystem")  # type: ignore[union-attr]
                self.assertIn("build/output.txt", snapshot.source_tracked_paths)  # type: ignore[union-attr]
                self.assertNotIn("logs/ignored.log", snapshot.source_tracked_paths)  # type: ignore[union-attr]
            finally:
                workspace.cleanup()

    def test_vsbr_static_002_linked_worktree_uses_bounded_git_tree_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = _git_repo(root, "repo")
            (repo / ".gitignore").write_text("logs/\n", encoding="utf-8")
            (repo / "build").mkdir()
            (repo / "build" / "output.txt").write_text(
                "tracked artifact\n",
                encoding="utf-8",
            )
            _git(repo, "add", ".gitignore", "build/output.txt")
            _git(repo, "commit", "-qm", "tracked scope")
            linked = root / "linked"
            linked.mkdir()
            linked_git_dir = repo / ".git" / "worktrees" / "linked"
            linked_git_dir.mkdir(parents=True)
            (linked_git_dir / "HEAD").write_text(
                _git(repo, "rev-parse", "HEAD") + "\n",
                encoding="utf-8",
            )
            (linked_git_dir / "commondir").write_text(
                "../..\n",
                encoding="utf-8",
            )
            (linked_git_dir / "gitdir").write_text(
                str(linked / ".git") + "\n",
                encoding="utf-8",
            )
            (linked / ".git").write_text(
                f"gitdir: {linked_git_dir}\n",
                encoding="utf-8",
            )
            (linked / ".gitignore").write_text("logs/\n", encoding="utf-8")
            (linked / "README.md").write_text("same tree\n", encoding="utf-8")
            (linked / "build").mkdir()
            (linked / "build" / "output.txt").write_text(
                "tracked artifact\n",
                encoding="utf-8",
            )
            (linked / "logs").mkdir()
            (linked / "logs" / "ignored.log").write_text(
                "ignored artifact\n",
                encoding="utf-8",
            )

            workspace = run_workspace.create_static_scan_snapshot(linked)
            try:
                snapshot = workspace.verified_snapshot
                self.assertIsNotNone(snapshot)
                self.assertEqual(snapshot.source_kind, "filesystem")  # type: ignore[union-attr]
                self.assertIn("build/output.txt", snapshot.source_tracked_paths)  # type: ignore[union-attr]
                self.assertNotIn("logs/ignored.log", snapshot.source_tracked_paths)  # type: ignore[union-attr]
                self.assertNotIn(".git", {entry.path for entry in snapshot.manifest})  # type: ignore[union-attr]
                self.assertFalse(  # type: ignore[union-attr]
                    any(entry.path.startswith("logs/") for entry in snapshot.manifest)
                )
            finally:
                workspace.cleanup()

    def test_vsbr_static_003_git_child_installs_os_resource_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _git_repo(Path(tmp), "repo")
            popen_kwargs: list[dict[str, object]] = []

            def refuse_exec(*args, **kwargs):
                del args
                popen_kwargs.append(dict(kwargs))
                raise OSError("synthetic exec refusal")

            with mock.patch.object(run_workspace.subprocess, "Popen", side_effect=refuse_exec):
                workspace = create_verified_snapshot(repo)
            try:
                self.assertFalse(workspace.copy_safety_ok)
            finally:
                workspace.cleanup()

        self.assertTrue(popen_kwargs)
        self.assertTrue(callable(popen_kwargs[0].get("preexec_fn")))
        self.assertIs(popen_kwargs[0].get("start_new_session"), True)
        installed: list[tuple[int, tuple[int, int]]] = []
        with mock.patch.object(
            run_workspace.resource,
            "getrlimit",
            return_value=(
                run_workspace.resource.RLIM_INFINITY,
                run_workspace.resource.RLIM_INFINITY,
            ),
        ), mock.patch.object(
            run_workspace.resource,
            "setrlimit",
            side_effect=lambda kind, value: installed.append((kind, value)),
        ):
            run_workspace._install_git_resource_limits()
        self.assertEqual(
            {kind for kind, _ in installed},
            {
                run_workspace.resource.RLIMIT_AS,
                run_workspace.resource.RLIMIT_DATA,
                run_workspace.resource.RLIMIT_CPU,
                run_workspace.resource.RLIMIT_FSIZE,
                run_workspace.resource.RLIMIT_NOFILE,
                run_workspace.resource.RLIMIT_NPROC,
                run_workspace.resource.RLIMIT_CORE,
            },
        )

    def test_vsbr_static_004_runtime_matches_all_five_snapshot_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_a = _git_repo(root, "repo-a", message="commit-a")
            repo_b = _git_repo(root, "repo-b", message="commit-b")
            workspace_a = create_verified_snapshot(repo_a)
            workspace_b = create_verified_snapshot(repo_b)
            try:
                snapshot_a = workspace_a.verified_snapshot
                snapshot_b = workspace_b.verified_snapshot
                self.assertIsNotNone(snapshot_a)
                self.assertIsNotNone(snapshot_b)
                self.assertEqual(snapshot_a.source_tree, snapshot_b.source_tree)  # type: ignore[union-attr]
                self.assertEqual(snapshot_a.snapshot_id, snapshot_b.snapshot_id)  # type: ignore[union-attr]
                self.assertNotEqual(
                    snapshot_a.source_identity_redacted,  # type: ignore[union-attr]
                    snapshot_b.source_identity_redacted,  # type: ignore[union-attr]
                )
                gate = {
                    "decision_kind": "pre_execution_gate",
                    "schema_version": "0.3-draft",
                    "verdict": "allow_limited",
                    "execution_authorized": False,
                    "subject": {
                        "repo": snapshot_a.source_identity_redacted,  # type: ignore[union-attr]
                        "commit": snapshot_a.source_commit,  # type: ignore[union-attr]
                        "tree_hash": snapshot_a.source_tree,  # type: ignore[union-attr]
                        "snapshot_id": snapshot_a.snapshot_id,  # type: ignore[union-attr]
                        "manifest_fingerprint": snapshot_a.manifest_fingerprint,  # type: ignore[union-attr]
                        "binding_kind": "snapshot_bound",
                    },
                    "policy": {"policy_version": "test-policy"},
                    "limitations": ["limited"],
                    "residual_risks": ["review required"],
                }
                authorization = dict(
                    build_execution_authorization_draft(
                        gate,
                        COMMAND,
                        expires_at="2099-01-01T00:00:00Z",
                    )
                )
                binding = validate_execution_authorization_snapshot_binding(
                    authorization,
                    gate,
                    repository_identity=snapshot_b.source_identity_redacted,  # type: ignore[union-attr]
                    commit=snapshot_b.source_commit,  # type: ignore[union-attr]
                    tree=snapshot_b.source_tree,  # type: ignore[union-attr]
                    snapshot_id=snapshot_b.snapshot_id,  # type: ignore[union-attr]
                    manifest_fingerprint=snapshot_b.manifest_fingerprint,  # type: ignore[union-attr]
                )
            finally:
                workspace_a.cleanup()
                workspace_b.cleanup()

        self.assertFalse(binding.matched)
        self.assertFalse(binding.repo_matches)

    def test_vsbr_static_004_runtime_blocks_foreign_same_manifest_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_a = _git_repo(root, "repo-a", message="commit-a")
            repo_b = _git_repo(root, "repo-b", message="commit-b")
            workspace_a = create_verified_snapshot(repo_a)
            workspace_b = create_verified_snapshot(repo_b)
            snapshot_a = workspace_a.verified_snapshot
            snapshot_b = workspace_b.verified_snapshot
            self.assertIsNotNone(snapshot_a)
            self.assertIsNotNone(snapshot_b)
            self.assertEqual(snapshot_a.snapshot_id, snapshot_b.snapshot_id)  # type: ignore[union-attr]
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
                "repo": snapshot_a.source_identity_redacted,  # type: ignore[union-attr]
                "commit": snapshot_a.source_commit,  # type: ignore[union-attr]
                "tree_hash": snapshot_a.source_tree,  # type: ignore[union-attr]
                "snapshot_id": snapshot_a.snapshot_id,  # type: ignore[union-attr]
                "manifest_fingerprint": snapshot_a.manifest_fingerprint,  # type: ignore[union-attr]
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
            authorization["approved_by"] = "reviewer@example.invalid"
            authorization["approved_at"] = "2026-07-01T00:00:00Z"
            authorization_path = root / "authorization.json"
            authorization_path.write_text(
                json.dumps(authorization),
                encoding="utf-8",
            )
            validation = validate_execution_authorization(
                authorization,
                gate,
                COMMAND,
            )
            runner = _CountingRunner()
            workspace_a.cleanup()

            report = run_sandbox_run(
                repo_b,
                command_argv=COMMAND,
                runner=runner,
                gate_decision=gate,
                authorization_path=authorization_path,
                authorization_validation=validation,
                prepared_workspace=workspace_b,
            )

        self.assertEqual(runner.run_calls, 0)
        self.assertTrue(report["policy_blocked"])
        self.assertFalse(
            report["subject_consistency"]["gate_field_matches"][
                "repository_identity"
            ]
        )

    def test_vsbr_static_005_base_exception_still_cleans_started_container(self) -> None:
        runner = DockerRunner()
        cleanup = (True, "ok", None)
        argv = [
            "docker",
            "run",
            "--label",
            "repo-health-doctor.run=synthetic",
            "--cidfile",
            "/tmp/rhd-synthetic.cid",
            "example.invalid/image",
        ]
        with mock.patch(
            "repo_health_doctor.sandbox.docker_runner.subprocess.Popen",
            return_value=_StartedProcess(),
        ), mock.patch(
            "repo_health_doctor.sandbox.docker_runner._stream_process_output",
            side_effect=KeyboardInterrupt(),
        ), mock.patch.object(
            runner,
            "_cleanup_tracked_container",
            return_value=cleanup,
        ) as cleanup_container:
            with self.assertRaises(KeyboardInterrupt):
                runner.run(argv, 1)

        cleanup_container.assert_called_once()

    def test_vsbr_static_006_explicit_control_files_are_no_follow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = root / "authorization.actual.json"
            actual.write_text(json.dumps({"approved": False}), encoding="utf-8")
            link = root / "authorization.json"
            link.symlink_to(actual.name)

            with self.assertRaises(ValueError):
                cli._load_json_object(link, "authorization")
            self.assertIsNone(_load_authorization_document(link))
            argv_actual = root / "argv.actual.json"
            argv_actual.write_text(json.dumps(COMMAND), encoding="utf-8")
            argv_link = root / "argv.json"
            argv_link.symlink_to(argv_actual.name)
            with self.assertRaises(ValueError):
                cli._load_argv_json(argv_link)

    def test_vsbr_static_006_prepared_workspace_is_cleaned_on_cli_parse_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("bounded\n", encoding="utf-8")
            authorization = root / "authorization.json"
            authorization.write_text("{", encoding="utf-8")
            prepared = create_verified_snapshot(repo)
            with mock.patch.object(cli, "create_verified_snapshot", return_value=prepared):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    cli.main(
                        [
                            "sandbox-run",
                            str(repo),
                            "--runner",
                            "fake",
                            "--authorization",
                            str(authorization),
                            "--",
                            *COMMAND,
                        ]
                    )

            self.assertEqual(prepared.cleanup_status, "ok")

    def test_vsbr_static_007_raw_report_and_subject_cannot_construct_gate(self) -> None:
        report = {
            "tool": "repo-health-doctor",
            "version": "0.1.0",
            "schema_version": "1.1",
            "repo_path": "<repo>",
            "overall_status": "warn",
            "summary": {"pass": 1, "warn": 0, "block": 0},
            "checks": [],
        }

        with self.assertRaises(TypeError):
            evaluate_gate_decision_from_v3_report(
                report,
                subject={
                    "repo": "sha256:" + "a" * 64,
                    "commit": "a" * 40,
                    "tree_hash": "b" * 40,
                    "snapshot_id": "sha256:" + "c" * 64,
                    "manifest_fingerprint": "sha256:" + "d" * 64,
                },
            )

    def test_vsbr_static_007_foreign_and_stale_scan_envelopes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_a = _git_repo(root, "repo-a", message="scan-a")
            repo_b = _git_repo(root, "repo-b", message="scan-b")
            workspace_a = create_verified_snapshot(repo_a)
            workspace_b = create_verified_snapshot(repo_b)
            try:
                snapshot_a = workspace_a.verified_snapshot
                snapshot_b = workspace_b.verified_snapshot
                self.assertIsNotNone(snapshot_a)
                self.assertIsNotNone(snapshot_b)
                envelope = scan_verified_snapshot(workspace_a, public_safety=True)

                self.assertFalse(
                    hasattr(v3_evaluator, "build_verified_snapshot_scan_envelope")
                )
                self.assertFalse(hasattr(cli, "_bind_gate_decision_subject"))

                with self.assertRaises(TypeError):
                    evaluate_gate_decision_from_scan_envelope(envelope, snapshot_b)

                foreign_report = deepcopy(envelope.report)
                foreign_report["overall_status"] = "block"
                with self.assertRaises(TypeError):
                    evaluate_gate_decision_from_v3_report(
                        foreign_report,
                        subject={
                            "repo": snapshot_b.source_identity_redacted,
                            "commit": snapshot_b.source_commit,
                            "tree_hash": snapshot_b.source_tree,
                            "snapshot_id": snapshot_b.snapshot_id,
                            "manifest_fingerprint": snapshot_b.manifest_fingerprint,
                        },
                    )

                envelope.report["overall_status"] = "block"  # type: ignore[index]
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    evaluate_gate_decision_from_scan_envelope(envelope)
            finally:
                workspace_a.cleanup()
                workspace_b.cleanup()

    def test_vsbr_static_008_manifest_path_budget_is_independent_and_streaming(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "payload.txt").write_text("bounded\n", encoding="utf-8")
            refused = create_verified_snapshot(
                repo,
                copy_budget=CopyBudget(max_manifest_path_bytes=1),
            )
            try:
                self.assertFalse(refused.copy_safety_ok)
                self.assertEqual(
                    refused.copy_budget_exceeded_reason,
                    "max_manifest_path_bytes",
                )
            finally:
                refused.cleanup()

        entries = tuple(
            SnapshotManifestEntry(
                path=f"{index:04d}/" + ("x" * 1024),
                entry_type="file",
                mode="100644",
                size=0,
                sha256="0" * 64,
            )
            for index in range(256)
        )
        tracemalloc.start()
        try:
            with mock.patch.object(
                run_workspace.json,
                "dumps",
                side_effect=AssertionError("canonical manifest must stream"),
            ):
                _, snapshot_id, manifest_fingerprint = run_workspace._manifest_identity(
                    entries,
                    max_manifest_path_bytes=2 * 1024 * 1024,
                )
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertRegex(snapshot_id, r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(manifest_fingerprint, r"^sha256:[0-9a-f]{64}$")
        self.assertLess(peak, 2 * 1024 * 1024)

        _, list_snapshot_id, list_manifest_fingerprint = run_workspace._manifest_identity(
            list(entries),
            max_manifest_path_bytes=2 * 1024 * 1024,
        )
        consumed = 0

        def generator_bomb():
            nonlocal consumed
            for index in range(10_000):
                consumed += 1
                yield SnapshotManifestEntry(
                    path=f"p{index}",
                    entry_type="file",
                    mode="100644",
                    size=0,
                    sha256="0" * 64,
                )

        with self.assertRaisesRegex(
            run_workspace._SnapshotRefusal,
            "max_manifest_path_bytes",
        ):
            run_workspace._manifest_identity(
                generator_bomb(),
                max_manifest_path_bytes=1,
            )
        self.assertEqual(consumed, 1)

        count_consumed = 0

        def entry_count_bomb():
            nonlocal count_consumed
            for index in range(10_000):
                count_consumed += 1
                yield SnapshotManifestEntry(
                    path=f"entry-{index}",
                    entry_type="file",
                    mode="100644",
                    size=0,
                    sha256="0" * 64,
                )

        with self.assertRaisesRegex(
            run_workspace._SnapshotRefusal,
            "max_manifest_entry_count",
        ):
            run_workspace._manifest_identity(
                entry_count_bomb(),
                max_manifest_path_bytes=2 * 1024 * 1024,
                max_manifest_entry_count=2,
            )
        self.assertEqual(count_consumed, 3)

        _, generator_snapshot_id, generator_manifest_fingerprint = (
            run_workspace._manifest_identity(
                (entry for entry in entries),
                max_manifest_path_bytes=2 * 1024 * 1024,
            )
        )
        self.assertEqual(list_snapshot_id, generator_snapshot_id)
        self.assertEqual(list_manifest_fingerprint, generator_manifest_fingerprint)

    def test_vsbr_static_009_snapshot_schema_rejects_missing_null_malformed_and_extra(self) -> None:
        from jsonschema import Draft202012Validator

        gate = deepcopy(
            json.loads(
                (
                    ROOT
                    / "tests"
                    / "fixtures"
                    / "execution-authorization"
                    / "gate-allow-limited.json"
                ).read_text(encoding="utf-8")
            )
        )
        gate["subject"] = {
            "repo": "sha256:" + "a" * 64,
            "commit": "b" * 40,
            "tree_hash": "c" * 40,
            "snapshot_id": "sha256:" + "d" * 64,
            "manifest_fingerprint": "sha256:" + "e" * 64,
            "binding_kind": "snapshot_bound",
        }
        authorization = dict(
            build_execution_authorization_draft(
                gate,
                COMMAND,
                expires_at="2099-01-01T00:00:00Z",
            )
        )
        schema = json.loads(
            (ROOT / "schemas" / "execution-authorization.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        cases = {
            "missing": lambda item: item["approved_scope"].pop("snapshot_id"),
            "null": lambda item: item["subject"].update({"snapshot_id": None}),
            "malformed": lambda item: item["approved_scope"].update(
                {"manifest_fingerprint": "sha256:NOT-A-FINGERPRINT"}
            ),
            "extra": lambda item: item["subject"].update({"unexpected": "field"}),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                candidate = deepcopy(authorization)
                mutate(candidate)
                self.assertTrue(list(validator.iter_errors(candidate)))

    def test_vsbr_static_010_duplicate_paths_and_type_collisions_fail_in_both_paths(self) -> None:
        duplicate = SnapshotManifestEntry(
            path="same.txt",
            entry_type="file",
            mode="100644",
            size=0,
            sha256="0" * 64,
        )
        directory = SnapshotManifestEntry(
            path="same.txt",
            entry_type="directory",
            mode="040755",
            size=0,
            sha256=None,
        )
        with self.assertRaisesRegex(RuntimeError, "manifest_duplicate_path"):
            run_workspace._manifest_identity([duplicate, duplicate])
        with self.assertRaisesRegex(RuntimeError, "manifest_path_type_collision"):
            run_workspace._manifest_identity([duplicate, directory])

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "payload.txt").write_text("verified\n", encoding="utf-8")
            workspace = create_verified_snapshot(repo)
            try:
                self.assertIsNotNone(workspace.verified_snapshot)
                with mock.patch.object(
                    run_workspace,
                    "_inventory_existing_tree",
                    return_value=(
                        [duplicate, duplicate],
                        {},
                        [],
                        [],
                    ),
                ):
                    self.assertFalse(verify_verified_snapshot(workspace))
            finally:
                workspace.cleanup()


if __name__ == "__main__":
    unittest.main()
