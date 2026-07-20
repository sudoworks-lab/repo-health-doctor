from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import time
from typing import Any, Protocol

from .docker import is_digest_pinned
from .profiles import (
    OUTDIR,
    PROFILE_LOCKED_DOWN_SECCOMP,
    PROFILE_MOBY_DEFAULT,
    SECCOMP_RUNTIME_DEFAULT,
    SandboxProfile,
    WORKDIR,
)


PULL_POLICY = "never"
_ALLOWED_NETWORK_MODES = {"none"}
_NETWORK_OPTIONS = ("--network", "--net")
_NAMESPACE_OPTIONS = ("--pid", "--ipc", "--uts", "--cgroupns", "--userns")
_NAMESPACE_OPTION_PREFIXES = tuple(f"{option}=" for option in _NAMESPACE_OPTIONS)
_PROHIBITED_SECURITY_OPTIONS = ("seccomp=unconfined", "apparmor=unconfined")


@dataclass(frozen=True)
class RunnerResult:
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


class SandboxDockerRunner(Protocol):
    runner_name: str
    docker_invoked: bool

    def docker_available(self) -> bool:
        ...

    def image_available_locally(self, image: str) -> bool:
        ...

    def detect_runtime(self) -> dict[str, str]:
        ...

    def run(self, argv: list[str], timeout_seconds: int) -> RunnerResult:
        ...


def build_docker_run_argv(
    *,
    image: str,
    command_argv: list[str],
    workspace_host_path: Path,
    profile: SandboxProfile,
    out_host_path: Path | None = None,
    seccomp_profile_name: str = SECCOMP_RUNTIME_DEFAULT,
    seccomp_profile_path: Path | None = None,
) -> list[str]:
    if not command_argv:
        raise ValueError("command argv must not be empty")
    if seccomp_profile_name == SECCOMP_RUNTIME_DEFAULT:
        if seccomp_profile_path is not None:
            raise ValueError("runtime-default must not use a seccomp profile path")
    elif seccomp_profile_name in {PROFILE_MOBY_DEFAULT, PROFILE_LOCKED_DOWN_SECCOMP}:
        if seccomp_profile_path is None:
            raise ValueError("packaged seccomp profile path is required")
    else:
        raise ValueError("unsupported seccomp profile")
    out_host_path = workspace_host_path.parent / "out" if out_host_path is None else out_host_path
    argv = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--workdir",
        WORKDIR,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
    ]
    if seccomp_profile_path is not None:
        argv.extend(["--security-opt", f"seccomp={seccomp_profile_path}"])
    argv.extend(
        [
            "--memory",
            profile.memory,
            "--cpus",
            profile.cpus,
            "--pids-limit",
            str(profile.pids_limit),
            "--user",
            profile.user,
        ]
    )
    for key, value in profile.env.items():
        argv.extend(["--env", f"{key}={value}"])
    if profile.read_only_rootfs:
        argv.append("--read-only")
        for tmpfs in profile.tmpfs:
            argv.extend(["--tmpfs", tmpfs])
    argv.extend(
        [
            "--mount",
            f"type=bind,src={workspace_host_path},dst={WORKDIR}",
            "--mount",
            f"type=bind,src={out_host_path},dst={OUTDIR}",
            image,
            *command_argv,
        ]
    )
    _assert_no_prohibited_docker_options(argv)
    return argv


def docker_report_fields(
    *,
    image: str,
    profile: SandboxProfile,
    argv_redacted: list[str] | None = None,
    runtime: dict[str, str] | None = None,
    runner_name: str = "docker",
    docker_invoked: bool = False,
) -> dict[str, Any]:
    runtime = runtime or {
        "rootless_docker_detected": "unknown",
        "userns_remap_detected": "unknown",
    }
    return {
        "image": image,
        "image_digest_pinned": is_digest_pinned(image),
        "latest_tag": image == "latest" or image.endswith(":latest"),
        "pull_policy": PULL_POLICY,
        "network": profile.network,
        "workdir": WORKDIR,
        "mounts_summary": {
            "workspace": {
                "source": "<disposable-workspace>",
                "target": WORKDIR,
                "read_only": False,
            },
            "out": {
                "source": "<sandbox-out>",
                "target": OUTDIR,
                "read_only": False,
            },
            "docker_socket": "not_mounted",
            "host_home": "not_mounted",
            "credentials": "not_mounted",
            "ssh_agent": "not_mounted",
        },
        "resource_limits": profile.resource_limits,
        "security_options": profile.security_options,
        "env": {
            "keys": sorted(profile.env),
            "values_recorded": False,
            "host_environment_inherited": False,
        },
        "user": profile.user,
        "root_container_user": profile.user in {"0", "0:0", "root"},
        "rootless_docker_detected": runtime["rootless_docker_detected"],
        "userns_remap_detected": runtime["userns_remap_detected"],
        "argv_redacted": argv_redacted or [],
        "runner": runner_name,
        "invoked": docker_invoked,
        "docker_invoked": docker_invoked,
        "exit_code": None,
        "failure_class": None,
        "diagnostic_redacted": None,
        "stdout_preview_redacted": "",
        "stderr_preview_redacted": "",
    }


class DockerRunner:
    runner_name = "docker"
    docker_invoked = True

    def docker_available(self) -> bool:
        try:
            completed = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def image_available_locally(self, image: str) -> bool:
        try:
            completed = subprocess.run(
                ["docker", "image", "inspect", image],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def detect_runtime(self) -> dict[str, str]:
        result = {
            "rootless_docker_detected": "unknown",
            "userns_remap_detected": "unknown",
        }
        try:
            completed = subprocess.run(
                ["docker", "info", "--format", "{{json .SecurityOptions}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return result
        if completed.returncode != 0:
            return result
        try:
            options = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return result
        if not isinstance(options, list) or any(not isinstance(item, str) for item in options):
            return result
        normalized_options = tuple(item.strip().lower() for item in options)
        result["rootless_docker_detected"] = (
            "true" if _security_option_detected(normalized_options, "rootless") else "false"
        )
        result["userns_remap_detected"] = (
            "true" if _security_option_detected(normalized_options, "userns") else "false"
        )
        return result

    def run(self, argv: list[str], timeout_seconds: int) -> RunnerResult:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout_seconds,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            return RunnerResult(
                status="timed_out",
                exit_code=None,
                stdout=_decode_timeout_stream(exc.stdout),
                stderr=_decode_timeout_stream(exc.stderr),
                timed_out=True,
                duration_ms=duration_ms,
            )
        except (FileNotFoundError, OSError) as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            return RunnerResult(
                status="failed",
                exit_code=None,
                stdout="",
                stderr=str(exc),
                timed_out=False,
                duration_ms=duration_ms,
            )
        duration_ms = int((time.monotonic() - started) * 1000)
        return RunnerResult(
            status="completed" if completed.returncode == 0 else "failed",
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            duration_ms=duration_ms,
        )


class FakeDockerRunner:
    docker_invoked = False

    def __init__(
        self,
        *,
        mode: str = "success",
        stdout: str = "fake sandbox-run output\n",
        stderr: str = "",
        exit_code: int = 0,
        docker_invoked: bool = False,
    ) -> None:
        self.mode = mode
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.docker_invoked = docker_invoked
        self.runner_name = f"fake-{mode}"

    def docker_available(self) -> bool:
        return self.mode != "docker-unavailable"

    def image_available_locally(self, image: str) -> bool:
        return self.mode != "image-unavailable"

    def detect_runtime(self) -> dict[str, str]:
        return {
            "rootless_docker_detected": "unknown",
            "userns_remap_detected": "unknown",
        }

    def run(self, argv: list[str], timeout_seconds: int) -> RunnerResult:
        if self.mode == "timeout":
            return RunnerResult(
                status="timed_out",
                exit_code=None,
                stdout=self.stdout,
                stderr=self.stderr,
                timed_out=True,
                duration_ms=timeout_seconds * 1000,
            )
        if self.mode == "failure":
            return RunnerResult(
                status="failed",
                exit_code=self.exit_code if self.exit_code != 0 else 1,
                stdout=self.stdout,
                stderr=self.stderr or "fake runner failure\n",
                timed_out=False,
                duration_ms=1,
            )
        return RunnerResult(
            status="completed",
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            timed_out=False,
            duration_ms=1,
        )


def _decode_timeout_stream(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _assert_no_prohibited_docker_options(argv: list[str]) -> None:
    pull_never_count = 0
    network_none_count = 0
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--pull":
            value = argv[index + 1] if index + 1 < len(argv) else None
            if value != PULL_POLICY:
                rendered = f"{token} {value}" if value is not None else token
                raise ValueError(f"prohibited docker option generated: {rendered}")
            pull_never_count += 1
            index += 2
            continue
        if token.startswith("--pull="):
            if token != f"--pull={PULL_POLICY}":
                raise ValueError(f"prohibited docker option generated: {token}")
            pull_never_count += 1
        if token in _NETWORK_OPTIONS:
            value = argv[index + 1] if index + 1 < len(argv) else None
            if value not in _ALLOWED_NETWORK_MODES:
                rendered = f"{token} {value}" if value is not None else token
                raise ValueError(f"prohibited docker option generated: {rendered}")
            network_none_count += 1
            index += 2
            continue
        network_prefix = _network_option_prefix(token)
        if network_prefix is not None:
            value = token[len(network_prefix) :]
            if value not in _ALLOWED_NETWORK_MODES:
                raise ValueError(f"prohibited docker option generated: {token}")
            network_none_count += 1
        if token in _NAMESPACE_OPTIONS or token.startswith(_NAMESPACE_OPTION_PREFIXES):
            raise ValueError(f"prohibited docker option generated: {token}")
        if token == "--cap-add" or token.startswith("--cap-add="):
            raise ValueError(f"prohibited docker option generated: {token}")
        if token == "--privileged" or token.startswith("--privileged="):
            raise ValueError(f"prohibited docker option generated: {token}")
        if any(option in token.lower() for option in _PROHIBITED_SECURITY_OPTIONS):
            raise ValueError(f"prohibited docker option generated: {token}")
        if token in {"/var/run/docker.sock", "/", "/etc"}:
            raise ValueError(f"prohibited mount target generated: {token}")
        if "docker.sock" in token:
            raise ValueError("docker socket mount generated")
        if "dst=/" in token and "dst=/workspace" not in token and "dst=/out" not in token:
            raise ValueError("prohibited root-like mount generated")
        index += 1
    if pull_never_count != 1:
        raise ValueError("docker argv must contain exactly one --pull=never")
    if network_none_count != 1:
        raise ValueError("docker argv must contain exactly one --network none")


def _network_option_prefix(token: str) -> str | None:
    for option in _NETWORK_OPTIONS:
        prefix = f"{option}="
        if token.startswith(prefix):
            return prefix
    return None


def _security_option_detected(options: tuple[str, ...], name: str) -> bool:
    return any(
        option in {name, f"name={name}"} or option.startswith(f"name={name},")
        for option in options
    )
