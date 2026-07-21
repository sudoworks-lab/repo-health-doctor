from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from repo_health_doctor.sandbox.docker_runner import (
    DockerRunner,
    _assert_no_prohibited_docker_options,
    build_docker_run_argv,
)
from repo_health_doctor.sandbox.profiles import (
    PROFILE_LOCKED_DOWN_SECCOMP,
    PROFILE_MOBY_DEFAULT,
    SECCOMP_PROFILE_CHOICES,
    get_sandbox_profile,
    recognized_profiles,
)


ROOT = Path(__file__).resolve().parents[1]
DOCKER_ARGV_GOLDEN = (
    ROOT / "tests" / "fixtures" / "golden" / "sandbox-run-docker-argv.json"
)


def _docker_argv_with(*option_tokens: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        *option_tokens,
        "--mount",
        "type=bind,src=/tmp/rhd-workspace,dst=/workspace",
        "python:3.12-slim",
        "python3",
        "-c",
        "print('hello')",
    ]


class SandboxRunDockerCommandTests(unittest.TestCase):
    def _workspace_path(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name) / "workspace"

    def test_all_implemented_profile_seccomp_argv_match_golden(self) -> None:
        golden = json.loads(DOCKER_ARGV_GOLDEN.read_text(encoding="utf-8"))
        implemented_profiles = tuple(
            name for name in recognized_profiles() if get_sandbox_profile(name).implemented
        )
        expected_cases = {
            f"{profile_name}:{seccomp_name}"
            for profile_name in implemented_profiles
            for seccomp_name in SECCOMP_PROFILE_CHOICES
        }

        self.assertEqual(expected_cases, set(golden))
        for case_name in sorted(expected_cases):
            profile_name, seccomp_name = case_name.split(":", maxsplit=1)
            profile = get_sandbox_profile(profile_name)
            seccomp_path = (
                Path("<seccomp-profile>")
                if seccomp_name in {PROFILE_MOBY_DEFAULT, PROFILE_LOCKED_DOWN_SECCOMP}
                else None
            )
            argv = build_docker_run_argv(
                image="<image>",
                command_argv=["python3", "-c", "print('hello')"],
                workspace_host_path=Path("<workspace>"),
                out_host_path=Path("<out>"),
                profile=profile,
                seccomp_profile_name=seccomp_name,
                seccomp_profile_path=seccomp_path,
            )
            argv[argv.index("--user") + 1] = "<container-user>"

            with self.subTest(case=case_name):
                self.assertEqual(golden[case_name], argv)
                _assert_no_prohibited_docker_options(argv)

    def test_rootless_detection_uses_docker_security_options(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='["name=seccomp,profile=builtin", "name=rootless", "name=userns"]',
            stderr="",
        )
        with patch(
            "repo_health_doctor.sandbox.docker_runner.subprocess.run",
            return_value=completed,
        ) as run:
            detected = DockerRunner().detect_runtime()

        self.assertEqual(
            {
                "rootless_docker_detected": "true",
                "userns_remap_detected": "true",
            },
            detected,
        )
        run.assert_called_once_with(
            ["docker", "info", "--format", "{{json .SecurityOptions}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_rootless_detection_is_false_only_for_valid_marker_absence(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='["name=seccomp,profile=builtin", "name=cgroupns"]',
            stderr="",
        )
        with patch(
            "repo_health_doctor.sandbox.docker_runner.subprocess.run",
            return_value=completed,
        ):
            detected = DockerRunner().detect_runtime()

        self.assertEqual(
            {
                "rootless_docker_detected": "false",
                "userns_remap_detected": "false",
            },
            detected,
        )

    def test_rootless_detection_failures_remain_unknown(self) -> None:
        unknown = {
            "rootless_docker_detected": "unknown",
            "userns_remap_detected": "unknown",
        }
        invalid_results = (
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="not-json", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout='{"name": "rootless"}', stderr=""
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout='["name=rootless", 1]', stderr=""
            ),
        )
        for completed in invalid_results:
            with self.subTest(returncode=completed.returncode, stdout=completed.stdout):
                with patch(
                    "repo_health_doctor.sandbox.docker_runner.subprocess.run",
                    return_value=completed,
                ):
                    self.assertEqual(unknown, DockerRunner().detect_runtime())

        with patch(
            "repo_health_doctor.sandbox.docker_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker info", timeout=10),
        ):
            self.assertEqual(unknown, DockerRunner().detect_runtime())

    def test_no_network_default_docker_argv_includes_required_constraints(self) -> None:
        workspace_path = self._workspace_path()
        profile = get_sandbox_profile("no-network-default")
        argv = build_docker_run_argv(
            image="python:3.12-slim",
            command_argv=["python3", "-c", "print('hello')"],
            workspace_host_path=workspace_path,
            profile=profile,
        )

        self.assertEqual(["docker", "run"], argv[:2])
        self.assertIn("--rm", argv)
        self.assertIn("--pull=never", argv)
        self.assertEqual(["--network", "none"], argv[argv.index("--network") : argv.index("--network") + 2])
        self.assertEqual(["--workdir", "/workspace"], argv[argv.index("--workdir") : argv.index("--workdir") + 2])
        self.assertEqual(["--cap-drop", "ALL"], argv[argv.index("--cap-drop") : argv.index("--cap-drop") + 2])
        self.assertEqual(
            ["--security-opt", "no-new-privileges"],
            argv[argv.index("--security-opt") : argv.index("--security-opt") + 2],
        )
        self.assertIn("--memory", argv)
        self.assertIn("--cpus", argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--mount", argv)
        mount_spec = argv[argv.index("--mount") + 1]
        self.assertEqual(f"type=bind,src={workspace_path},dst=/workspace,readonly", mount_spec)
        self.assertTrue(any(item.startswith("/out:") and "size=64m" in item and "nr_inodes=4096" in item for item in argv))
        self.assertIn("python:3.12-slim", argv)
        self.assertEqual(["python3", "-c", "print('hello')"], argv[-3:])

    def test_docker_argv_excludes_prohibited_options_and_shell_wrapping(self) -> None:
        profile = get_sandbox_profile("no-network-default")
        argv = build_docker_run_argv(
            image="python:3.12-slim",
            command_argv=["python3", "-c", "print('hello')"],
            workspace_host_path=self._workspace_path(),
            profile=profile,
        )
        rendered = " ".join(argv)

        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--network host", rendered)
        self.assertNotIn("--pid host", rendered)
        self.assertNotIn("--ipc host", rendered)
        self.assertNotIn("--uts host", rendered)
        self.assertNotIn("--cap-add", argv)
        self.assertNotIn("/var/run/docker.sock", rendered)
        self.assertNotIn("dst=/", rendered.replace("dst=/workspace", "").replace("dst=/out", ""))
        command_pairs = [argv[index : index + 2] for index in range(len(argv) - 1)]
        self.assertNotIn(["sh", "-c"], command_pairs)
        self.assertNotIn(["bash", "-c"], command_pairs)

    def test_no_network_default_generated_argv_passes_prohibited_option_guard(self) -> None:
        profile = get_sandbox_profile("no-network-default")
        argv = build_docker_run_argv(
            image="python:3.12-slim",
            command_argv=["python3", "-c", "print('hello')"],
            workspace_host_path=self._workspace_path(),
            profile=profile,
        )

        _assert_no_prohibited_docker_options(argv)

    def test_prohibited_docker_options_are_rejected(self) -> None:
        prohibited_cases = [
            ("--network", "host"),
            ("--network=host",),
            ("--network", "bridge"),
            ("--network=bridge",),
            ("--net", "host"),
            ("--net=host",),
            ("--pid", "host"),
            ("--pid=host",),
            ("--ipc", "host"),
            ("--ipc=host",),
            ("--uts", "host"),
            ("--uts=host",),
            ("--cgroupns", "host"),
            ("--cgroupns=host",),
            ("--userns", "host"),
            ("--userns=host",),
            ("--cap-add", "NET_ADMIN"),
            ("--cap-add=NET_ADMIN",),
            ("--privileged",),
            ("--privileged=true",),
            ("--pull", "always"),
            ("--pull=always",),
            ("--pull", "missing"),
            ("--pull=missing",),
            ("--security-opt", "seccomp=unconfined"),
            ("--security-opt=seccomp=unconfined",),
            ("--security-opt", "apparmor=unconfined"),
            ("--security-opt=apparmor=unconfined",),
        ]

        for option_tokens in prohibited_cases:
            with self.subTest(option_tokens=option_tokens):
                with self.assertRaisesRegex(ValueError, "prohibited docker option generated"):
                    _assert_no_prohibited_docker_options(_docker_argv_with(*option_tokens))

    def test_pull_never_and_network_none_are_required_exactly_once(self) -> None:
        valid = _docker_argv_with()

        with self.assertRaisesRegex(ValueError, "exactly one --pull=never"):
            _assert_no_prohibited_docker_options([token for token in valid if token != "--pull=never"])
        with self.assertRaisesRegex(ValueError, "exactly one --pull=never"):
            _assert_no_prohibited_docker_options(["--pull=never", *valid])
        network_index = valid.index("--network")
        without_network = valid[:network_index] + valid[network_index + 2 :]
        with self.assertRaisesRegex(ValueError, "exactly one --network none"):
            _assert_no_prohibited_docker_options(without_network)
        with self.assertRaises(ValueError):
            _assert_no_prohibited_docker_options(["--network=none", *valid])

    def test_docker_socket_mount_is_rejected(self) -> None:
        argv = _docker_argv_with("--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock")

        with self.assertRaisesRegex(ValueError, "docker socket mount generated"):
            _assert_no_prohibited_docker_options(argv)

    def test_no_network_readonly_adds_read_only_rootfs_and_tmpfs(self) -> None:
        profile = get_sandbox_profile("no-network-readonly")
        argv = build_docker_run_argv(
            image="python:3.12-slim",
            command_argv=["python3", "-c", "print('hello')"],
            workspace_host_path=self._workspace_path(),
            profile=profile,
        )

        self.assertIn("--read-only", argv)
        self.assertIn("--tmpfs", argv)
        self.assertTrue(any(item.startswith("/tmp:rw") for item in argv))

    def test_locked_down_profile_adds_v1_env_out_mount_and_read_only_rootfs(self) -> None:
        profile = get_sandbox_profile("locked-down")
        argv = build_docker_run_argv(
            image="python:3.12-slim",
            command_argv=["python3", "-c", "print('hello')"],
            workspace_host_path=self._workspace_path(),
            profile=profile,
        )

        self.assertIn("--read-only", argv)
        self.assertIn("--tmpfs", argv)
        self.assertIn("--env", argv)
        self.assertIn("HOME=/tmp/home", argv)
        self.assertIn("TMPDIR=/tmp", argv)
        self.assertTrue(any(item.startswith("/out:") and "size=64m" in item for item in argv))
        self.assertEqual(profile.network, "none")
        self.assertFalse(profile.user in {"0", "0:0", "root"})


if __name__ == "__main__":
    unittest.main()
