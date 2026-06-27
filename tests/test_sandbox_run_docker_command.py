from __future__ import annotations

from pathlib import Path

from repo_health_doctor.sandbox.docker_runner import build_docker_run_argv
from repo_health_doctor.sandbox.profiles import get_sandbox_profile


def test_no_network_default_docker_argv_includes_required_constraints(tmp_path: Path) -> None:
    profile = get_sandbox_profile("no-network-default")
    argv = build_docker_run_argv(
        image="python:3.12-slim",
        command_argv=["python3", "-c", "print('hello')"],
        workspace_host_path=tmp_path / "workspace",
        profile=profile,
    )

    assert argv[:2] == ["docker", "run"]
    assert "--rm" in argv
    assert "--pull=never" in argv
    assert ["--network", "none"] == argv[argv.index("--network") : argv.index("--network") + 2]
    assert ["--workdir", "/workspace"] == argv[argv.index("--workdir") : argv.index("--workdir") + 2]
    assert ["--cap-drop", "ALL"] == argv[argv.index("--cap-drop") : argv.index("--cap-drop") + 2]
    assert ["--security-opt", "no-new-privileges"] == argv[argv.index("--security-opt") : argv.index("--security-opt") + 2]
    assert "--memory" in argv
    assert "--cpus" in argv
    assert "--pids-limit" in argv
    assert "--mount" in argv
    mount_spec = argv[argv.index("--mount") + 1]
    assert mount_spec == f"type=bind,src={tmp_path / 'workspace'},dst=/workspace"
    assert ",rw" not in mount_spec
    assert "python:3.12-slim" in argv
    assert argv[-3:] == ["python3", "-c", "print('hello')"]


def test_docker_argv_excludes_prohibited_options_and_shell_wrapping(tmp_path: Path) -> None:
    profile = get_sandbox_profile("no-network-default")
    argv = build_docker_run_argv(
        image="python:3.12-slim",
        command_argv=["python3", "-c", "print('hello')"],
        workspace_host_path=tmp_path / "workspace",
        profile=profile,
    )
    rendered = " ".join(argv)

    assert "--privileged" not in argv
    assert "--network host" not in rendered
    assert "--pid host" not in rendered
    assert "--ipc host" not in rendered
    assert "--uts host" not in rendered
    assert "--cap-add" not in argv
    assert "/var/run/docker.sock" not in rendered
    assert "dst=/" not in rendered.replace("dst=/workspace", "")
    assert ["sh", "-c"] not in [argv[index : index + 2] for index in range(len(argv) - 1)]
    assert ["bash", "-c"] not in [argv[index : index + 2] for index in range(len(argv) - 1)]


def test_no_network_readonly_adds_read_only_rootfs_and_tmpfs(tmp_path: Path) -> None:
    profile = get_sandbox_profile("no-network-readonly")
    argv = build_docker_run_argv(
        image="python:3.12-slim",
        command_argv=["python3", "-c", "print('hello')"],
        workspace_host_path=tmp_path / "workspace",
        profile=profile,
    )

    assert "--read-only" in argv
    assert "--tmpfs" in argv
    assert any(item.startswith("/tmp:rw") for item in argv)
