from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from textwrap import dedent
import unittest
from unittest.mock import patch

from repo_health_doctor.gate.authorization import (
    build_execution_authorization_draft,
    validate_execution_authorization,
)
from repo_health_doctor.sandbox.docker_runner import DockerRunner
from repo_health_doctor.sandbox.image_binding import (
    is_digest_pinned_authorization_reference,
    is_full_local_image_id,
)
from repo_health_doctor.sandbox.profiles import PROFILE_MOBY_DEFAULT, resolve_seccomp_profile
from repo_health_doctor.sandbox.run import DEFAULT_SANDBOX_IMAGE, run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import CopyBudget, fingerprint_target, inspect_git_worktree


ROOT = Path(__file__).resolve().parents[1]
REAL_DOCKER_ENABLED = os.environ.get("RHD_REAL_DOCKER_TEST") == "1"

CASE_1_COMMAND = [
    "python3",
    "-c",
    "from pathlib import Path; Path('/out/case-1.txt').write_text('ok\\n', encoding='utf-8')",
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
CASE_8_COMMAND = [
    "python3",
    "-c",
    "print('packaged-seccomp-profile-active')",
]
CASE_10_COMMAND = [
    "python3",
    "-c",
    "print('installed-package-seccomp-profile-active')",
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
        cls.image_id = cls.runner.image_id(cls.image)
        if cls.image_id is None:
            raise RuntimeError("RHD_REAL_DOCKER_TEST=1 requires a resolvable local image ID")

    def _repo(self, root: Path, *, readme: str = "synthetic real Docker boundary fixture\n") -> Path:
        repo = root / "repo"
        repo.mkdir()
        (repo / "README.md").write_text(readme, encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "synthetic"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "synthetic fixture"], check=True, capture_output=True)
        return repo

    def _authorization(self, root: Path, repo: Path, command: list[str]) -> tuple[Path, dict[str, object], object]:
        fixture_root = ROOT / "tests" / "fixtures" / "execution-authorization"
        gate = json.loads((fixture_root / "gate-allow-limited.json").read_text(encoding="utf-8"))
        observed = inspect_git_worktree(repo)
        gate["subject"] = {
            **gate["subject"],
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
                approved_image={
                    "requested_reference": self.image,
                    "resolved_image_id": self.image_id,
                },
            )
        )
        authorization.update(
            {
                "approved": True,
                "approved_by": "redacted@example.invalid",
                "approved_at": "2026-07-01T00:00:00Z",
            }
        )
        authorization_path = root / "authorization.json"
        authorization_path.write_text(json.dumps(authorization) + "\n", encoding="utf-8")
        validation = validate_execution_authorization(
            authorization,
            gate,
            command,
            runtime_image_reference=self.image,
            runtime_image_id=self.image_id,
        )
        self.assertTrue(validation.execution_authorized, validation.to_dict())
        return authorization_path, gate, validation

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
            authorization_path, gate, validation = self._authorization(repo.parent, repo, command)
            report = run_sandbox_run(
                repo,
                authorization_path=authorization_path,
                authorization_validation=validation,
                gate_decision=gate,
                fail_on_gate="unknown",
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
        self.assertEqual("confirmed", report["command_start_state"])
        self.assertTrue(report["docker"]["docker_invoked"])
        self.assertEqual("ok", report["docker"]["cleanup_status"])
        self.assertTrue(report["docker"]["container_tracking_enabled"])
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
        self.assertEqual(0, report["workspace_diff"]["created_count"])
        self.assertEqual(0, report["runtime_write_budget"]["paths"]["workspace"]["observed_bytes"])

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
        self.assertFalse(report["command_started"])
        self.assertEqual("unknown", report["command_start_state"])
        self.assertEqual(1, report["sandbox_exit_code"])
        self.assertEqual("timeout", report["docker"]["failure_class"])
        self.assertEqual("ok", report["docker"]["cleanup_status"])
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


@unittest.skipUnless(REAL_DOCKER_ENABLED, "set RHD_REAL_DOCKER_TEST=1 to run real Docker boundary cases")
class RealDockerBoundaryCasesEightToTen(unittest.TestCase):
    image: str
    image_id: str
    runner: DockerRunner

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = os.environ.get("RHD_REAL_DOCKER_IMAGE", "").strip()
        if not cls.image:
            raise RuntimeError(
                "cases 8-10 require RHD_REAL_DOCKER_IMAGE to name an existing local digest-pinned image"
            )
        if not is_digest_pinned_authorization_reference(cls.image):
            raise RuntimeError("cases 8-10 require a digest-pinned RHD_REAL_DOCKER_IMAGE")
        cls.runner = DockerRunner()
        if not cls.runner.docker_available():
            raise RuntimeError("RHD_REAL_DOCKER_TEST=1 requires an accessible local Docker daemon")
        if not cls.runner.image_available_locally(cls.image):
            raise RuntimeError(
                "RHD_REAL_DOCKER_IMAGE must already exist locally; cases 8-10 do not pull images"
            )
        completed = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", cls.image],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        cls.image_id = completed.stdout.strip()
        if completed.returncode != 0 or not is_full_local_image_id(cls.image_id):
            raise RuntimeError("the selected local image must resolve to one full sha256 image ID")

    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        (repo / "README.md").write_text("synthetic real Docker cases 8-10 fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "synthetic"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "synthetic fixture"], check=True, capture_output=True)
        return repo

    def _authorization(self, root: Path, repo: Path, command: list[str]) -> tuple[Path, dict[str, object], object]:
        fixture_root = ROOT / "tests" / "fixtures" / "execution-authorization"
        gate = json.loads((fixture_root / "gate-allow-limited.json").read_text(encoding="utf-8"))
        observed = inspect_git_worktree(repo)
        gate["subject"] = {
            **gate["subject"],
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
                approved_image={
                    "requested_reference": self.image,
                    "resolved_image_id": self.image_id,
                },
            )
        )
        authorization.update(
            {
                "approved": True,
                "approved_by": "redacted@example.invalid",
                "approved_at": "2026-07-01T00:00:00Z",
            }
        )
        authorization_path = root / "authorization.json"
        authorization_path.write_text(json.dumps(authorization) + "\n", encoding="utf-8")
        validation = validate_execution_authorization(
            authorization,
            gate,
            command,
            runtime_image_reference=self.image,
            runtime_image_id=self.image_id,
        )
        self.assertTrue(validation.execution_authorized, validation.to_dict())
        return authorization_path, gate, validation

    def _run_case(self, repo: Path, *, command: list[str]) -> dict[str, object]:
        original_fingerprint = fingerprint_target(repo).fingerprint
        created_run_roots: list[Path] = []
        real_mkdtemp = tempfile.mkdtemp

        def tracked_mkdtemp(*args: object, **kwargs: object) -> str:
            created = Path(real_mkdtemp(*args, **kwargs))
            created_run_roots.append(created)
            return str(created)

        with patch("repo_health_doctor.sandbox.run_workspace.tempfile.mkdtemp", side_effect=tracked_mkdtemp):
            authorization_path, gate, validation = self._authorization(repo.parent, repo, command)
            report = run_sandbox_run(
                repo,
                authorization_path=authorization_path,
                authorization_validation=validation,
                gate_decision=gate,
                fail_on_gate="unknown",
                image=self.image,
                profile_name="no-network-readonly",
                seccomp_profile_name=PROFILE_MOBY_DEFAULT,
                command_argv=command,
                timeout_seconds=10,
                runner=self.runner,
            )

        self.assertEqual(original_fingerprint, fingerprint_target(repo).fingerprint)
        self.assertTrue(created_run_roots)
        self.assertTrue(all(not path.exists() for path in created_run_roots))
        self._assert_completed_execution_contract(report, command)
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
        self._assert_schema_valid(report)
        self.assertEqual("completed", report["result"]["status"])
        self.assertEqual(0, report["sandbox_exit_code"])
        self.assertTrue(report["command_started"])
        self.assertEqual("confirmed", report["command_start_state"])
        self.assertTrue(report["docker"]["docker_invoked"])
        self.assertEqual("ok", report["docker"]["cleanup_status"])
        self.assertEqual("never", report["docker"]["pull_policy"])
        self.assertEqual(1, report["docker"]["argv_redacted"].count("--pull=never"))
        self.assertEqual(1, report["docker"]["argv_redacted"].count("--rm"))
        self.assertEqual(command, report["command"]["argv_redacted"])
        self.assertEqual("ok", report["disposable_workspace"]["cleanup"])
        self.assertFalse(report["output_summary"]["raw_stdout_stderr_persisted"])

    def _assert_packaged_seccomp_evidence(self, report: dict[str, object]) -> None:
        resolved = resolve_seccomp_profile()
        self.assertEqual(PROFILE_MOBY_DEFAULT, report["seccomp"]["profile"])
        self.assertEqual(resolved.profile_sha256, report["seccomp"]["profile_sha256"])
        self.assertEqual("package_data", report["seccomp"]["source"])
        argv = report["docker"]["argv_redacted"]
        self.assertIn("--security-opt", argv)
        self.assertIn("seccomp=<sandbox-run-root>/rhd-moby-default-v1.json", argv)

    def test_case_8_packaged_moby_default_seccomp_runs_with_local_image(self) -> None:
        """case 8: rhd-moby-default-v1 executes under Docker without pulling the selected local image."""
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run_case(self._repo(Path(tmp)), command=CASE_8_COMMAND)

        self._assert_packaged_seccomp_evidence(report)
        self.assertTrue(report["docker"]["image_digest_pinned"])

    def test_case_9_real_local_image_identity_matches_and_mismatch_fails_closed(self) -> None:
        """case 9: a real local image ID binds separately from its digest-pinned requested reference."""
        fixture_root = ROOT / "tests" / "fixtures" / "execution-authorization"
        authorization = json.loads((fixture_root / "approved-exact-0.2.json").read_text(encoding="utf-8"))
        gate = json.loads((fixture_root / "gate-allow-limited.json").read_text(encoding="utf-8"))
        argv = json.loads((fixture_root / "argv.json").read_text(encoding="utf-8"))
        authorization["approved_image"] = {
            "requested_reference": self.image,
            "resolved_image_id": self.image_id,
        }

        matched = validate_execution_authorization(
            authorization,
            gate,
            argv,
            now=datetime(2026, 6, 26, tzinfo=timezone.utc),
            runtime_image_reference=self.image,
            runtime_image_id=self.image_id,
        )
        self.assertTrue(matched.execution_authorized, matched.to_dict())
        self.assertTrue(matched.image_reference_matches)
        self.assertTrue(matched.image_id_matches)

        mismatched_id = "sha256:" + ("0" if self.image_id[7] != "0" else "1") + self.image_id[8:]
        mismatched = validate_execution_authorization(
            deepcopy(authorization),
            gate,
            argv,
            now=datetime(2026, 6, 26, tzinfo=timezone.utc),
            runtime_image_reference=self.image,
            runtime_image_id=mismatched_id,
        )
        self.assertFalse(mismatched.execution_authorized)
        self.assertIn("approved_image_id_mismatch", mismatched.blocking_errors)
        self.assertNotIn("approved_image_reference_mismatch", mismatched.blocking_errors)

    def test_case_10_installed_package_resource_runs_the_seccomp_profile(self) -> None:
        """case 10: an offline-installed wheel resolves package seccomp data for a real Docker run."""
        original_fingerprint: str
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self._repo(root)
            original_fingerprint = fingerprint_target(repo).fingerprint
            authorization_path, gate, _ = self._authorization(root, repo, CASE_10_COMMAND)
            gate_path = root / "gate.json"
            gate_path.write_text(json.dumps(gate) + "\n", encoding="utf-8")
            wheel_dir = root / "wheel"
            install_dir = root / "install"
            wheel_dir.mkdir()
            install_dir.mkdir()

            built = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    str(ROOT),
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(wheel_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": "", "PIP_NO_INDEX": "1"},
            )
            self.assertEqual(0, built.returncode, built.stderr)
            wheels = sorted(wheel_dir.glob("repo_health_doctor-*.whl"))
            self.assertEqual(1, len(wheels), built.stdout)

            installed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--no-deps",
                    "--no-index",
                    "--target",
                    str(install_dir),
                    str(wheels[0]),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": ""},
            )
            self.assertEqual(0, installed.returncode, installed.stderr)

            probe_code = dedent(
                """
                import json
                from pathlib import Path
                import sys
                import tempfile
                from unittest.mock import patch

                from repo_health_doctor.gate.authorization import validate_execution_authorization
                from repo_health_doctor.sandbox.docker_runner import DockerRunner
                from repo_health_doctor.sandbox.profiles import PROFILE_MOBY_DEFAULT
                from repo_health_doctor.sandbox.run import run_sandbox_run

                created = []
                real_mkdtemp = tempfile.mkdtemp

                def tracked_mkdtemp(*args, **kwargs):
                    path = Path(real_mkdtemp(*args, **kwargs))
                    created.append(path)
                    return str(path)

                with patch(
                    "repo_health_doctor.sandbox.run_workspace.tempfile.mkdtemp",
                    side_effect=tracked_mkdtemp,
                ):
                    image = sys.argv[3]
                    authorization_path = Path(sys.argv[2])
                    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
                    gate = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
                    command = [
                        "python3",
                        "-c",
                        "print('installed-package-seccomp-profile-active')",
                    ]
                    runner = DockerRunner()
                    validation = validate_execution_authorization(
                        authorization,
                        gate,
                        command,
                        runtime_image_reference=image,
                        runtime_image_id=runner.image_id(image),
                    )
                    report = run_sandbox_run(
                        Path(sys.argv[1]),
                        authorization_path=authorization_path,
                        authorization_validation=validation,
                        gate_decision=gate,
                        fail_on_gate="unknown",
                        image=image,
                        profile_name="no-network-readonly",
                        seccomp_profile_name=PROFILE_MOBY_DEFAULT,
                        command_argv=command,
                        timeout_seconds=10,
                        runner=runner,
                    )

                print(
                    json.dumps(
                        {
                            "report": report,
                            "run_roots_removed": bool(created)
                            and all(not path.exists() for path in created),
                        }
                    )
                )
                """
            )
            probed = subprocess.run(
                [sys.executable, "-c", probe_code, str(repo), str(authorization_path), self.image, str(gate_path)],
                check=False,
                capture_output=True,
                text=True,
                cwd=root,
                env={**os.environ, "PYTHONPATH": str(install_dir)},
            )
            self.assertEqual(0, probed.returncode, probed.stderr)
            envelope = json.loads(probed.stdout)
            report = envelope["report"]

            self.assertTrue(envelope["run_roots_removed"])
            self.assertEqual(original_fingerprint, fingerprint_target(repo).fingerprint)

        self._assert_completed_execution_contract(report, CASE_10_COMMAND)
        self._assert_packaged_seccomp_evidence(report)


if __name__ == "__main__":
    unittest.main()
