from __future__ import annotations

from dataclasses import fields
import inspect
import re
from pathlib import Path
import subprocess
import unittest

from repo_health_doctor.sandbox.docker_runner import (
    RunnerResult,
    build_docker_run_argv,
)
from repo_health_doctor.sandbox.profiles import get_sandbox_profile
from repo_health_doctor.sandbox.run import run_sandbox_run


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "python@sha256:" + ("a" * 64)


class _RealRunnerProbe:
    runner_name = "docker"
    docker_invoked = True

    def __init__(self) -> None:
        self.run_calls = 0

    def docker_available(self) -> bool:
        return True

    def image_available_locally(self, image: str) -> bool:
        return True

    def detect_runtime(self) -> dict[str, str]:
        return {
            "rootless_docker_detected": "unknown",
            "userns_remap_detected": "unknown",
        }

    def run(self, argv: list[str], timeout_seconds: int) -> RunnerResult:
        self.run_calls += 1
        return RunnerResult(
            status="completed",
            exit_code=0,
            stdout="probe\n",
            stderr="",
            timed_out=False,
            duration_ms=1,
        )


class AdversarialMajorRegressionTests(unittest.TestCase):
    def test_f01_real_runner_without_authorization_never_starts(self) -> None:
        runner = _RealRunnerProbe()
        with self.subTest("synthetic target"):
            import tempfile

            with tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary)
                (target / "README.md").write_text("synthetic\n", encoding="utf-8")
                report = run_sandbox_run(
                    target,
                    image=IMAGE,
                    command_argv=["python3", "-c", "print('probe')"],
                    runner=runner,  # type: ignore[arg-type]
                )

        self.assertTrue(report["policy_blocked"])
        self.assertEqual(0, runner.run_calls)
        self.assertIn("authorization_required", report["approval"]["refusal_reasons"])

    def test_f02_option_like_image_is_rejected_at_argv_boundary(self) -> None:
        with self.assertRaises(ValueError):
            build_docker_run_argv(
                image="--label=rhd-benign-option-probe=1",
                command_argv=["python3", "-c", "print('probe')"],
                workspace_host_path=Path("/tmp/rhd-workspace"),
                out_host_path=Path("/tmp/rhd-out"),
                profile=get_sandbox_profile("locked-down"),
            )

    def test_f02_explicit_mutable_image_is_rejected_for_real_runner(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            (target / "README.md").write_text("synthetic\n", encoding="utf-8")
            runner = _RealRunnerProbe()
            report = run_sandbox_run(
                target,
                image="python:3.12-slim",
                command_argv=["python3", "-c", "print('probe')"],
                runner=runner,  # type: ignore[arg-type]
            )

        self.assertTrue(report["policy_blocked"])
        self.assertIn("image_digest_pinned_required", report["approval"]["refusal_reasons"])

    def test_f03_runner_uses_streaming_process_and_cleanup_evidence(self) -> None:
        from repo_health_doctor.sandbox import docker_runner

        source = inspect.getsource(docker_runner.DockerRunner.run)
        self.assertIn("Popen", source)
        self.assertNotIn("capture_output=True", source)
        names = {field.name for field in fields(RunnerResult)}
        self.assertIn("container_cleanup_status", names)
        self.assertIn("command_start_state", names)

    def test_f04_runner_result_has_bounded_output_evidence(self) -> None:
        names = {field.name for field in fields(RunnerResult)}
        for name in (
            "stdout_bytes",
            "stderr_bytes",
            "total_output_bytes",
            "stdout_truncated",
            "stderr_truncated",
            "output_budget_exceeded",
        ):
            self.assertIn(name, names)

    def test_f05_host_backed_workspace_is_read_only_and_out_is_bounded(self) -> None:
        argv = build_docker_run_argv(
            image=IMAGE,
            command_argv=["python3", "-c", "print('probe')"],
            workspace_host_path=Path("/tmp/rhd-workspace"),
            out_host_path=Path("/tmp/rhd-out"),
            profile=get_sandbox_profile("locked-down"),
        )
        mount_specs = [argv[index + 1] for index, token in enumerate(argv[:-1]) if token == "--mount"]
        self.assertTrue(any(spec.endswith("dst=/workspace,readonly") for spec in mount_specs))
        self.assertTrue(any(token.startswith("/out:") and "size=64m" in token for token in argv))
        self.assertFalse(any(spec.endswith("dst=/out") for spec in mount_specs))

    def test_f06_actions_and_dependency_install_are_immutable(self) -> None:
        uses_pattern = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
        workflows: dict[str, str] = {}
        for workflow_name in ("ci.yml", "release.yml", "real-docker-verification.yml"):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            workflows[workflow_name] = workflow
            for value in uses_pattern.findall(workflow):
                with self.subTest(workflow=workflow_name, value=value):
                    self.assertTrue(value.startswith("./") or re.fullmatch(r"[^/@\s]+/[^/@\s]+@[0-9a-f]{40}", value))

        self.assertNotIn("docker pull", workflows["ci.yml"])
        self.assertNotIn("docker pull", workflows["release.yml"])
        real_docker_workflow = workflows["real-docker-verification.yml"]
        approved_pull = 'docker pull "$RHD_REAL_DOCKER_IMAGE"'
        self.assertEqual(1, real_docker_workflow.count(approved_pull))
        self.assertEqual(
            [f"{approved_pull} >/dev/null 2>&1"],
            [
                line.strip()
                for line in re.findall(r"(?m)^\s*docker pull[^\n]*$", real_docker_workflow)
            ],
        )
        self.assertLess(
            real_docker_workflow.index("if re.fullmatch(pattern, image) is None:"),
            real_docker_workflow.index(approved_pull),
        )
        self.assertLess(
            real_docker_workflow.index(approved_pull),
            real_docker_workflow.index('["docker", "image", "inspect", image]'),
        )
        self.assertIn("RepoDigests", real_docker_workflow)
        self.assertIn(r'r"sha256:[0-9a-f]{64}"', real_docker_workflow)
        self.assertIn("Run fixed sandbox --pull=never", real_docker_workflow)

        lock = ROOT / "requirements-ci.lock"
        self.assertTrue(lock.is_file())
        lock_text = lock.read_text(encoding="utf-8")
        self.assertIn("--require-hashes", lock_text)
        self.assertIn("pip==", lock_text)
        self.assertIn("build==", lock_text)
        self.assertIn("jsonschema==", lock_text)

    def test_f06_ci_project_install_preserves_exact_self_scan_target(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        requirements_install = (
            "python3 -m pip install --require-hashes -r requirements-ci.lock"
        )
        install_source = (
            'INSTALL_SOURCE="$RUNNER_TEMP/repo-health-doctor-install-source"'
        )
        archive_install = 'git archive HEAD | tar -x -C "$INSTALL_SOURCE"'
        change_to_install_source = 'cd "$INSTALL_SOURCE"'
        editable_install = (
            'python3 -m pip install --no-deps -e "$INSTALL_SOURCE"'
        )
        temporary_working_directory = (
            "working-directory: "
            "${{ runner.temp }}/repo-health-doctor-install-source"
        )
        self_scan = "- name: Run self-scan gate"

        self.assertNotIn("python3 -m pip install --no-deps -e .", workflow)
        self.assertIn(requirements_install, workflow)
        self.assertIn(install_source, workflow)
        self.assertIn(archive_install, workflow)
        self.assertIn(change_to_install_source, workflow)
        self.assertIn(editable_install, workflow)
        self.assertIn(temporary_working_directory, workflow)
        self.assertIn(self_scan, workflow)
        self.assertLess(
            workflow.index(requirements_install),
            workflow.index(archive_install),
        )
        self.assertLess(
            workflow.index(archive_install),
            workflow.index(change_to_install_source),
        )
        self.assertLess(
            workflow.index(change_to_install_source),
            workflow.index(editable_install),
        )
        self.assertLess(
            workflow.index(editable_install),
            workflow.index(temporary_working_directory),
        )
        self.assertLess(workflow.index(editable_install), workflow.index(self_scan))


if __name__ == "__main__":
    unittest.main()
