from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
from typing import Any, Protocol

from .docker import is_digest_pinned
from .image_binding import is_full_local_image_id, is_safe_docker_image_token
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
_ALLOWED_RUN_FLAGS = frozenset({"--rm", "--read-only"})
_ALLOWED_RUN_PAIRS = frozenset(
    {
        "--network",
        "--workdir",
        "--cap-drop",
        "--security-opt",
        "--memory",
        "--cpus",
        "--pids-limit",
        "--user",
        "--env",
        "--tmpfs",
        "--mount",
        "--label",
        "--cidfile",
    }
)
_RUN_LABEL_PREFIX = "com.repo-health-doctor.run-id="
_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
STREAM_READ_CHUNK_BYTES = 8192
STDOUT_BYTE_BUDGET = 64 * 1024
STDERR_BYTE_BUDGET = 64 * 1024
TOTAL_OUTPUT_BYTE_BUDGET = 128 * 1024
STREAM_PREVIEW_BYTE_BUDGET = 16 * 1024
OUT_TMPFS_SPEC = "/out:rw,nosuid,nodev,size=64m,nr_inodes=4096"
CLEANUP_RETRY_DELAYS_SECONDS = (0.05, 0.1, 0.25, 0.5, 1.0)


@dataclass(frozen=True)
class RunnerResult:
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    total_output_bytes: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    output_budget_exceeded: bool = False
    container_tracking_enabled: bool = False
    cleanup_attempted: bool = False
    container_cleanup_status: str = "not_attempted"
    cleanup_failure_class: str | None = None
    command_start_state: str = "unknown"


class SandboxDockerRunner(Protocol):
    runner_name: str
    docker_invoked: bool

    def docker_available(self) -> bool:
        ...

    def image_available_locally(self, image: str) -> bool:
        ...

    def image_id(self, image: str) -> str | None:
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
    container_tracking_label: str | None = None,
    cidfile_path: Path | None = None,
) -> list[str]:
    if not command_argv:
        raise ValueError("command argv must not be empty")
    if not is_safe_docker_image_token(image):
        raise ValueError("image reference is not a safe Docker image token")
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
    if container_tracking_label is not None:
        if not _RUN_ID.fullmatch(container_tracking_label):
            raise ValueError("container tracking label is invalid")
        argv.extend(["--label", f"{_RUN_LABEL_PREFIX}{container_tracking_label}"])
    if cidfile_path is not None:
        argv.extend(["--cidfile", str(cidfile_path)])
    argv.extend(
        [
            "--mount",
            f"type=bind,src={workspace_host_path},dst={WORKDIR},readonly",
            "--tmpfs",
            OUT_TMPFS_SPEC,
            image,
            *command_argv,
        ]
    )
    _assert_no_prohibited_docker_options(argv, image=image)
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
        "image": image if is_safe_docker_image_token(image) else "<invalid-image>",
        "image_digest_pinned": is_digest_pinned(image),
        "latest_tag": image == "latest" or image.endswith(":latest"),
        "pull_policy": PULL_POLICY,
        "network": profile.network,
        "workdir": WORKDIR,
        "mounts_summary": {
            "workspace": {
                "source": "<disposable-workspace>",
                "target": WORKDIR,
                "read_only": True,
            },
            "out": {
                "source": "<bounded-tmpfs>",
                "target": OUTDIR,
                "read_only": False,
                "size": "64m",
                "max_files": 4096,
                "host_backed": False,
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
        "container_tracking_enabled": False,
        "cleanup_attempted": False,
        "cleanup_status": "not_attempted",
        "cleanup_failure_class": None,
        "command_start_state": "not_started",
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "total_output_bytes": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "output_budget_exceeded": False,
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

    def image_id(self, image: str) -> str | None:
        try:
            completed = subprocess.run(
                ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None
        value = completed.stdout.strip()
        return value if completed.returncode == 0 and is_full_local_image_id(value) else None

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
        tracking = _tracking_from_argv(argv)
        command_start_state = "unknown"
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                bufsize=0,
            )
        except (FileNotFoundError, OSError) as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            cleanup = self._cleanup_tracked_container(tracking)
            return RunnerResult(
                status="failed",
                exit_code=None,
                stdout="",
                stderr=exc.__class__.__name__,
                timed_out=False,
                duration_ms=duration_ms,
                container_tracking_enabled=tracking.enabled,
                cleanup_attempted=cleanup[0],
                container_cleanup_status=cleanup[1],
                cleanup_failure_class=cleanup[2],
                command_start_state="not_started",
            )
        stdout, stderr, counts, timed_out, output_budget_exceeded = _stream_process_output(
            process,
            timeout_seconds=timeout_seconds,
        )
        if timed_out:
            command_start_state = "unknown"
        elif output_budget_exceeded:
            command_start_state = "confirmed"
        elif process.returncode == 125:
            command_start_state = "not_started"
        else:
            command_start_state = "confirmed"
        cleanup = self._cleanup_tracked_container(tracking)
        duration_ms = int((time.monotonic() - started) * 1000)
        if timed_out:
            status = "timed_out"
        elif output_budget_exceeded:
            status = "output_budget_exceeded"
        else:
            status = "completed" if process.returncode == 0 else "failed"
        return RunnerResult(
            status=status,
            exit_code=None if timed_out or output_budget_exceeded else process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            duration_ms=duration_ms,
            stdout_bytes=counts["stdout_bytes"],
            stderr_bytes=counts["stderr_bytes"],
            total_output_bytes=counts["total_output_bytes"],
            stdout_truncated=counts["stdout_truncated"],
            stderr_truncated=counts["stderr_truncated"],
            output_budget_exceeded=output_budget_exceeded,
            container_tracking_enabled=tracking.enabled,
            cleanup_attempted=cleanup[0],
            container_cleanup_status=cleanup[1],
            cleanup_failure_class=cleanup[2],
            command_start_state=command_start_state,
        )

    def _cleanup_tracked_container(
        self,
        tracking: "_ContainerTracking",
    ) -> tuple[bool, str, str | None]:
        if not tracking.enabled or tracking.label is None:
            return False, "not_attempted", None
        try:
            ids = _matching_container_ids(tracking.label)
        except _ContainerTrackingError as exc:
            return True, "failed", exc.failure_class
        cid = _read_cidfile(tracking.cidfile)
        if cid is not None and cid not in ids:
            try:
                label = _inspect_container_label(cid)
            except _ContainerTrackingError as exc:
                return True, "failed", exc.failure_class
            if label == tracking.label:
                ids.add(cid)
            elif label is not None:
                return True, "failed", "tracking_label_mismatch"
        remaining = set(ids)
        for delay in (0.0, *CLEANUP_RETRY_DELAYS_SECONDS):
            if delay:
                time.sleep(delay)
            for container_id in sorted(remaining):
                try:
                    subprocess.run(
                        ["docker", "container", "rm", "--force", container_id],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                    )
                except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                    return True, "failed", "container_remove_failed"
            try:
                remaining = _matching_container_ids(tracking.label)
            except _ContainerTrackingError as exc:
                return True, "failed", exc.failure_class
            if not remaining:
                break
        if remaining:
            return True, "failed", "container_remove_failed"
        if tracking.cidfile is not None:
            try:
                tracking.cidfile.unlink(missing_ok=True)
            except OSError:
                return True, "failed", "cidfile_cleanup_failed"
        return True, "ok", None


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
                command_start_state="unknown",
            )
        if self.mode == "failure":
            return RunnerResult(
                status="failed",
                exit_code=self.exit_code if self.exit_code != 0 else 1,
                stdout=self.stdout,
                stderr=self.stderr or "fake runner failure\n",
                timed_out=False,
                duration_ms=1,
                command_start_state="confirmed",
            )
        return RunnerResult(
            status="completed",
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            timed_out=False,
            duration_ms=1,
            command_start_state="confirmed",
        )


@dataclass(frozen=True)
class _ContainerTracking:
    label: str | None
    cidfile: Path | None

    @property
    def enabled(self) -> bool:
        return self.label is not None


class _ContainerTrackingError(RuntimeError):
    def __init__(self, failure_class: str) -> None:
        super().__init__(failure_class)
        self.failure_class = failure_class


def _tracking_from_argv(argv: list[str]) -> _ContainerTracking:
    label: str | None = None
    cidfile: Path | None = None
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--label" and index + 1 < len(argv):
            value = argv[index + 1]
            if value.startswith(_RUN_LABEL_PREFIX):
                label = value[len(_RUN_LABEL_PREFIX) :]
            index += 2
            continue
        if token == "--cidfile" and index + 1 < len(argv):
            cidfile = Path(argv[index + 1])
            index += 2
            continue
        index += 1
    return _ContainerTracking(label=label, cidfile=cidfile)


def _stream_process_output(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: int,
) -> tuple[str, str, dict[str, int | bool], bool, bool]:
    selector = selectors.DefaultSelector()
    previews: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    counts: dict[str, int | bool] = {
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "total_output_bytes": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }
    streams = (("stdout", process.stdout), ("stderr", process.stderr))
    for name, stream in streams:
        if stream is not None:
            selector.register(stream, selectors.EVENT_READ, name)
    started = time.monotonic()
    timed_out = False
    output_budget_exceeded = False
    try:
        while selector.get_map():
            remaining = timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                _stop_process(process)
                break
            events = selector.select(min(0.1, remaining))
            if not events and process.poll() is not None:
                continue
            for key, _ in events:
                stream_name = str(key.data)
                try:
                    chunk = os.read(key.fileobj.fileno(), STREAM_READ_CHUNK_BYTES)
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream_bytes_key = f"{stream_name}_bytes"
                counts[stream_bytes_key] = int(counts[stream_bytes_key]) + len(chunk)
                counts["total_output_bytes"] = int(counts["total_output_bytes"]) + len(chunk)
                preview = previews[stream_name]
                if len(preview) < STREAM_PREVIEW_BYTE_BUDGET:
                    preview.extend(chunk[: STREAM_PREVIEW_BYTE_BUDGET - len(preview)])
                if int(counts[stream_bytes_key]) > (
                    STDOUT_BYTE_BUDGET if stream_name == "stdout" else STDERR_BYTE_BUDGET
                ) or int(counts["total_output_bytes"]) > TOTAL_OUTPUT_BYTE_BUDGET:
                    counts[f"{stream_name}_truncated"] = True
                    output_budget_exceeded = True
                    _stop_process(process)
                    break
            if timed_out or output_budget_exceeded:
                break
    finally:
        selector.close()
        if process.poll() is None:
            _stop_process(process)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            process.wait(timeout=2)
        for _, stream in streams:
            if stream is not None:
                stream.close()
    if output_budget_exceeded:
        counts["stdout_truncated"] = True if int(counts["stdout_bytes"]) > STDOUT_BYTE_BUDGET else counts["stdout_truncated"]
        counts["stderr_truncated"] = True if int(counts["stderr_bytes"]) > STDERR_BYTE_BUDGET else counts["stderr_truncated"]
    stdout = bytes(previews["stdout"]).decode("utf-8", errors="replace")
    stderr = bytes(previews["stderr"]).decode("utf-8", errors="replace")
    return stdout, stderr, counts, timed_out, output_budget_exceeded


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.terminate()
    except OSError:
        return
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass


def _read_cidfile(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        with path.open("rb") as stream:
            value = stream.read(256).decode("ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return value if _CONTAINER_ID.fullmatch(value) else None


def _matching_container_ids(label: str) -> set[str]:
    if not _RUN_ID.fullmatch(label):
        raise _ContainerTrackingError("tracking_label_invalid")
    try:
        completed = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label={_RUN_LABEL_PREFIX}{label}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        raise _ContainerTrackingError("tracking_query_failed") from None
    if completed.returncode != 0:
        raise _ContainerTrackingError("tracking_query_failed")
    values = {line.strip() for line in completed.stdout.splitlines() if line.strip()}
    if len(values) > 32 or any(not _CONTAINER_ID.fullmatch(value) for value in values):
        raise _ContainerTrackingError("tracking_query_invalid")
    return values


def _inspect_container_label(container_id: str) -> str | None:
    if not _CONTAINER_ID.fullmatch(container_id):
        raise _ContainerTrackingError("container_id_invalid")
    try:
        completed = subprocess.run(
            [
                "docker",
                "container",
                "inspect",
                "--format",
                "{{index .Config.Labels \"com.repo-health-doctor.run-id\"}}",
                container_id,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        raise _ContainerTrackingError("tracking_inspect_failed") from None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value if _RUN_ID.fullmatch(value) else None


def _assert_no_prohibited_docker_options(argv: list[str], *, image: str | None = None) -> None:
    image_index = _find_image_index(argv, image=image)
    if image_index < 0 or image_index >= len(argv):
        raise ValueError("docker argv image boundary is missing")
    image_token = argv[image_index]
    if not is_safe_docker_image_token(image_token):
        if image is not None:
            raise ValueError("image reference is not a safe Docker image token")
        raise ValueError(f"prohibited docker option generated: {image_token}")
    pull_never_count = 0
    network_none_count = 0
    index = 2
    while index < image_index:
        token = argv[index]
        if token in _ALLOWED_RUN_FLAGS:
            index += 1
            continue
        if token.startswith("--pull="):
            if token != f"--pull={PULL_POLICY}":
                raise ValueError(f"prohibited docker option generated: {token}")
            pull_never_count += 1
            index += 1
            continue
        if token in _ALLOWED_RUN_PAIRS:
            value = argv[index + 1] if index + 1 < image_index else None
            if value is None:
                raise ValueError(f"prohibited docker option generated: {token}")
            if token == "--network" and value not in _ALLOWED_NETWORK_MODES:
                raise ValueError(f"prohibited docker option generated: {token} {value}")
            if token == "--label" and not value.startswith(_RUN_LABEL_PREFIX):
                raise ValueError(f"prohibited docker option generated: {token}")
            if token == "--mount" and _mount_is_prohibited(value):
                raise ValueError("prohibited mount generated")
            if token == "--security-opt" and any(option in value.lower() for option in _PROHIBITED_SECURITY_OPTIONS):
                raise ValueError(f"prohibited docker option generated: {token} {value}")
            if token == "--pull" and value != PULL_POLICY:
                raise ValueError(f"prohibited docker option generated: {token} {value}")
            if token == "--network":
                network_none_count += 1
            index += 2
            continue
        if token.startswith("--network="):
            if token != "--network=none":
                raise ValueError(f"prohibited docker option generated: {token}")
            network_none_count += 1
            index += 1
            continue
        if token.startswith("--security-opt="):
            value = token.split("=", 1)[1]
            if any(option in value.lower() for option in _PROHIBITED_SECURITY_OPTIONS):
                raise ValueError(f"prohibited docker option generated: {token}")
            raise ValueError(f"prohibited docker option generated: {token}")
        if token.startswith("-"):
            raise ValueError(f"prohibited docker option generated: {token}")
        raise ValueError("docker argv option boundary is ambiguous")
    if image_index + 1 >= len(argv):
        raise ValueError("docker argv command is missing")
    for token in argv[image_index + 1 :]:
        if not isinstance(token, str) or any(ord(character) < 0x20 or ord(character) == 0x7F for character in token):
            raise ValueError("command contains a control character")
    if pull_never_count != 1:
        raise ValueError("docker argv must contain exactly one --pull=never")
    if network_none_count != 1:
        raise ValueError("docker argv must contain exactly one --network none")


def _find_image_index(argv: list[str], *, image: str | None) -> int:
    if image is not None:
        try:
            return argv.index(image, 2)
        except ValueError:
            return -1
    index = 2
    while index < len(argv):
        token = argv[index]
        if token in _ALLOWED_RUN_FLAGS or token.startswith("--pull=") or token.startswith("--network="):
            index += 1
            continue
        if token in _ALLOWED_RUN_PAIRS:
            index += 2
            continue
        if token.startswith("-"):
            return index
        return index
    return -1


def _mount_is_prohibited(value: str) -> bool:
    lowered = value.lower()
    if "docker.sock" in lowered:
        raise ValueError("docker socket mount generated")
    if any(fragment in lowered for fragment in ("dst=/", "dst=/etc", "dst=/mnt", "dst=/root")):
        if "dst=/workspace" not in lowered and "dst=/out" not in lowered:
            return True
    return False


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
