from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_health_doctor.sandbox.docker_runner import _assert_no_prohibited_docker_options, build_docker_run_argv
from repo_health_doctor.sandbox.profiles import get_sandbox_profile


def _docker_argv_with(*option_tokens: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
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
        self.assertEqual(f"type=bind,src={workspace_path},dst=/workspace", mount_spec)
        self.assertTrue(any(item.endswith("dst=/out") for item in argv))
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
            ("--cap-add", "NET_ADMIN"),
            ("--cap-add=NET_ADMIN",),
            ("--privileged",),
            ("--privileged=true",),
        ]

        for option_tokens in prohibited_cases:
            with self.subTest(option_tokens=option_tokens):
                with self.assertRaisesRegex(ValueError, "prohibited docker option generated"):
                    _assert_no_prohibited_docker_options(_docker_argv_with(*option_tokens))

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
        self.assertTrue(any(item.endswith("dst=/out") for item in argv))
        self.assertEqual(profile.network, "none")
        self.assertFalse(profile.user in {"0", "0:0", "root"})


if __name__ == "__main__":
    unittest.main()
