from __future__ import annotations

from dataclasses import dataclass
import glob
import json
from pathlib import Path
import subprocess
from typing import Any

from .docker import build_container_command_argv
from .observer import (
    ALLOWED_WRITE_ROOTS_ENV,
    NODE_HOOK_LOGICAL_PATH,
    OBSERVER_EVENT_FILE,
    OBSERVER_STRACE_PREFIX,
    PYTHON_HOOK_LOGICAL_DIR,
    SECRET_ENV_NAMES_ENV,
)
from .workspace import (
    HONEYPOT_FILE_SPECS,
    HOME_PATH,
    MaterializedWorkspace,
    NPM_CACHE_PATH,
    PIP_CACHE_PATH,
    TMP_PATH,
    WORKSPACE_PATH,
    XDG_CACHE_PATH,
)


DEFAULT_DYNAMIC_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class DynamicCommandResult:
    kind: str
    argv: tuple[str, ...]
    return_code: int | None
    status: str
    timed_out: bool
    stdout_summary: str
    stderr_summary: str
    observer_summary: dict[str, Any]
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "argv": list(self.argv),
            "return_code": self.return_code,
            "status": self.status,
            "timed_out": self.timed_out,
            "stdout_summary": self.stdout_summary,
            "stderr_summary": self.stderr_summary,
            "observer_summary": self.observer_summary,
        }
        if self.error is not None:
            payload["error"] = self.error
        return payload


def _summarize_output(output: str, materialized: MaterializedWorkspace) -> str:
    sanitized = materialized.redact_text(output.strip())
    if not sanitized:
        return ""
    lines = sanitized.splitlines()[:3]
    clipped = " | ".join(lines)
    if len(clipped) > 200:
        return clipped[:197] + "..."
    return clipped


def _observer_event_host_path(materialized: MaterializedWorkspace) -> Path:
    return materialized.host_paths["tmp"] / Path(OBSERVER_EVENT_FILE).name


def _strace_output_prefix_host_path(materialized: MaterializedWorkspace) -> Path:
    return materialized.host_paths["tmp"] / Path(OBSERVER_STRACE_PREFIX).name


def _clear_strace_outputs(materialized: MaterializedWorkspace) -> bool:
    cleared = True
    prefix = str(_strace_output_prefix_host_path(materialized))
    for candidate in glob.glob(prefix + "*"):
        try:
            Path(candidate).unlink()
        except OSError:
            cleared = False
    return cleared


def _build_syscall_observer_prefix(observer: dict[str, Any]) -> list[str]:
    syscall_observer = observer.get("syscall_observer", {})
    if not isinstance(syscall_observer, dict) or not syscall_observer.get("active"):
        return []
    trace_expression = (
        "execve,execveat,open,openat,write,writev,exit_group,"
        "connect,sendto,sendmsg,clone,clone3,fork,vfork,unlink,unlinkat,rmdir"
    )
    return [
        "strace",
        "-ff",
        "-qq",
        "-s",
        "256",
        "-o",
        OBSERVER_STRACE_PREFIX,
        "-e",
        f"trace={trace_expression}",
    ]


def _build_observer_docker_args(
    observer: dict[str, Any],
    detected_languages: list[str],
    materialized: MaterializedWorkspace,
) -> list[str]:
    args = ["--env", f"RHD_OBSERVER_EVENT_FILE={observer['event_sink']}"]
    args.extend(
        [
            "--env",
            f"{SECRET_ENV_NAMES_ENV}={','.join(sorted(materialized.observer_environment()))}",
            "--env",
            (
                f"{ALLOWED_WRITE_ROOTS_ENV}="
                f"{','.join([WORKSPACE_PATH, HOME_PATH, NPM_CACHE_PATH, PIP_CACHE_PATH, XDG_CACHE_PATH, TMP_PATH])}"
            ),
        ]
    )
    for name, value in sorted(materialized.observer_environment().items()):
        args.extend(["--env", f"{name}={value}"])
    languages = set(detected_languages)
    hook_map = {item["language"]: item for item in observer["runtime_hooks"]}
    python_hook = hook_map.get("python")
    if "python" in languages and python_hook and python_hook.get("implemented"):
        args.extend(["--env", f"PYTHONPATH={PYTHON_HOOK_LOGICAL_DIR}"])
        args.extend(["--env", "PIP_DISABLE_PIP_VERSION_CHECK=1"])
        args.extend(["--env", "PIP_NO_INDEX=1"])
    node_hook = hook_map.get("node")
    if "node" in languages and node_hook and node_hook.get("implemented"):
        args.extend(["--env", f"NODE_OPTIONS=--require={NODE_HOOK_LOGICAL_PATH}"])
    return args


def _parse_strace_events(materialized: MaterializedWorkspace) -> dict[str, int]:
    prefix = str(_strace_output_prefix_host_path(materialized))
    counts: dict[str, Any] = {
        "network_event_count": 0,
        "secret_file_open_count": 0,
        "process_event_count": 0,
        "delete_inside_writable_count": 0,
        "delete_outside_writable_count": 0,
        "syscall_log_file_count": 0,
        "read_error_count": 0,
        "syscall_event_type_counts": {
            "execve": 0,
            "openat": 0,
            "write": 0,
            "exit_group": 0,
        },
        "syscall_log_handles": [],
    }
    honeypot_paths = {
        f"{HOME_PATH}/{relative_path}" if base_key == "home" else f"{WORKSPACE_PATH}/{relative_path}"
        for base_key, relative_path, _content in HONEYPOT_FILE_SPECS
    }
    writable_roots = (WORKSPACE_PATH, HOME_PATH, NPM_CACHE_PATH, PIP_CACHE_PATH, XDG_CACHE_PATH, TMP_PATH)
    for candidate in glob.glob(prefix + "*"):
        counts["syscall_log_file_count"] += 1
        counts["syscall_log_handles"].append(f"{TMP_PATH}/{Path(candidate).name}")
        try:
            lines = Path(candidate).read_text(encoding="utf-8").splitlines()
        except OSError:
            counts["read_error_count"] += 1
            continue
        for line in lines:
            if "execve(" in line:
                counts["syscall_event_type_counts"]["execve"] += 1
            if "openat(" in line or "open(" in line:
                counts["syscall_event_type_counts"]["openat"] += 1
            if "write(" in line or "writev(" in line:
                counts["syscall_event_type_counts"]["write"] += 1
            if "exit_group(" in line:
                counts["syscall_event_type_counts"]["exit_group"] += 1
            if "connect(" in line or "sendto(" in line or "sendmsg(" in line:
                counts["network_event_count"] += 1
            if "clone(" in line or "clone3(" in line or "fork(" in line or "vfork(" in line:
                counts["process_event_count"] += 1
            if ("open(" in line or "openat(" in line) and any(path in line for path in honeypot_paths):
                counts["secret_file_open_count"] += 1
            if "unlink(" in line or "unlinkat(" in line or "rmdir(" in line:
                if any(root in line for root in writable_roots):
                    counts["delete_inside_writable_count"] += 1
                elif '"/' in line:
                    counts["delete_outside_writable_count"] += 1
    return counts


def _parse_observer_events(materialized: MaterializedWorkspace) -> dict[str, Any]:
    event_path = _observer_event_host_path(materialized)
    if not event_path.exists():
        return {
            "event_count": 0,
            "event_type_counts": {},
            "network_event_count": 0,
            "secret_event_count": 0,
            "process_event_count": 0,
            "env_sweep_count": 0,
            "delete_inside_writable_count": 0,
            "delete_outside_writable_count": 0,
            "observer_mode": "unknown",
            "pass_possible": False,
            "read_error": False,
        }
    try:
        lines = event_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {
            "event_count": 0,
            "event_type_counts": {},
            "network_event_count": 0,
            "secret_event_count": 0,
            "process_event_count": 0,
            "env_sweep_count": 0,
            "delete_inside_writable_count": 0,
            "delete_outside_writable_count": 0,
            "observer_mode": "unknown",
            "pass_possible": False,
            "read_error": True,
        }
    event_type_counts: dict[str, int] = {}
    delete_inside_writable_count = 0
    delete_outside_writable_count = 0
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        event_type = payload.get("event_type")
        if isinstance(event_type, str):
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
            if event_type == "file_delete_attempt":
                detail = payload.get("detail", {})
                zone = detail.get("zone") if isinstance(detail, dict) else None
                if zone == "outside_sandbox_writable":
                    delete_outside_writable_count += 1
                else:
                    delete_inside_writable_count += 1
    return {
        "event_count": sum(event_type_counts.values()),
        "event_type_counts": event_type_counts,
        "network_event_count": event_type_counts.get("dns_lookup", 0) + event_type_counts.get("socket_connect", 0),
        "secret_event_count": event_type_counts.get("secret_file_open", 0) + event_type_counts.get("secret_env_access", 0),
        "process_event_count": event_type_counts.get("subprocess_spawn", 0) + event_type_counts.get("child_process_spawn", 0),
        "env_sweep_count": event_type_counts.get("env_sweep", 0),
        "delete_inside_writable_count": delete_inside_writable_count,
        "delete_outside_writable_count": delete_outside_writable_count,
        "observer_mode": "unknown",
        "pass_possible": False,
        "read_error": False,
    }


def _combined_observer_summary(materialized: MaterializedWorkspace) -> dict[str, Any]:
    runtime_hook_summary = _parse_observer_events(materialized)
    strace_summary = _parse_strace_events(materialized)
    runtime_hook_summary["network_event_count"] += strace_summary["network_event_count"]
    runtime_hook_summary["secret_event_count"] += strace_summary["secret_file_open_count"]
    runtime_hook_summary["process_event_count"] += strace_summary["process_event_count"]
    runtime_hook_summary["delete_inside_writable_count"] += strace_summary["delete_inside_writable_count"]
    runtime_hook_summary["delete_outside_writable_count"] += strace_summary["delete_outside_writable_count"]
    runtime_hook_summary["syscall_log_file_count"] = strace_summary["syscall_log_file_count"]
    runtime_hook_summary["syscall_read_error_count"] = strace_summary["read_error_count"]
    runtime_hook_summary["syscall_secret_file_open_count"] = strace_summary["secret_file_open_count"]
    runtime_hook_summary["syscall_event_type_counts"] = strace_summary["syscall_event_type_counts"]
    runtime_hook_summary["syscall_log_handles"] = strace_summary["syscall_log_handles"]
    return runtime_hook_summary


def run_dynamic_phase(
    *,
    resolved_base_argv: list[str],
    commands: list[dict[str, Any]],
    materialized: MaterializedWorkspace,
    observer: dict[str, Any],
    detected_languages: list[str],
    timeout_seconds: int = DEFAULT_DYNAMIC_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    results: list[DynamicCommandResult] = []
    limitations: list[str] = list(observer.get("limitations", ()))
    approved_command_count = len(commands)
    pass_possible = bool(observer.get("pass_possible"))
    observation_mode = str(observer.get("mode", "unknown"))
    syscall_active = bool(observer.get("syscall_observer", {}).get("active"))
    for command in commands:
        argv = command.get("argv")
        kind = command.get("kind", "dynamic_probe")
        if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
            results.append(
                DynamicCommandResult(
                    kind=str(kind),
                    argv=(),
                    return_code=None,
                    status="invalid_command",
                    timed_out=False,
                    stdout_summary="",
                    stderr_summary="",
                    observer_summary={},
                    error="dynamic command must use normalized argv form",
                )
            )
            return {
                "requested": True,
                "performed": False,
                "status": "failed",
                "network_mode": "none",
                "timeout_seconds": timeout_seconds,
                "approved_command_count": approved_command_count,
                "results": [item.as_dict() for item in results],
                "limitations": ["Dynamic probe plan contained an invalid command payload."],
            }
        event_path = _observer_event_host_path(materialized)
        try:
            if event_path.exists():
                event_path.unlink()
        except OSError:
            limitations.append("Observer event file could not be cleared before executing a dynamic probe.")
        if not _clear_strace_outputs(materialized):
            limitations.append("Syscall observer output files could not be cleared before executing a dynamic probe.")
        container_argv = [*_build_syscall_observer_prefix(observer), *argv]
        full_argv = build_container_command_argv(
            resolved_base_argv,
            container_argv=tuple(container_argv),
            network_mode="none",
            extra_docker_args=_build_observer_docker_args(observer, detected_languages, materialized),
        )
        try:
            completed = subprocess.run(
                full_argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                shell=False,
            )
        except FileNotFoundError as exc:
            results.append(
                DynamicCommandResult(
                    kind=str(kind),
                    argv=tuple(materialized.redact_text(token) for token in full_argv),
                    return_code=None,
                    status="docker_binary_missing",
                    timed_out=False,
                    stdout_summary="",
                    stderr_summary="",
                    observer_summary={},
                    error=materialized.redact_text(str(exc)),
                )
            )
            return {
                "requested": True,
                "performed": False,
                "status": "failed",
                "network_mode": "none",
                "timeout_seconds": timeout_seconds,
                "approved_command_count": approved_command_count,
                "results": [item.as_dict() for item in results],
                "limitations": ["Dynamic probe execution failed because the Docker binary is unavailable."],
            }
        except subprocess.TimeoutExpired as exc:
            results.append(
                DynamicCommandResult(
                    kind=str(kind),
                    argv=tuple(materialized.redact_text(token) for token in full_argv),
                    return_code=None,
                    status="timeout",
                    timed_out=True,
                    stdout_summary=_summarize_output(exc.stdout or "", materialized),
                    stderr_summary=_summarize_output(exc.stderr or "", materialized),
                    observer_summary=_combined_observer_summary(materialized),
                    error="dynamic_probe_timeout",
                )
            )
            return {
                "requested": True,
                "performed": True,
                "status": "failed",
                "network_mode": "none",
                "timeout_seconds": timeout_seconds,
                "approved_command_count": approved_command_count,
                "results": [item.as_dict() for item in results],
                "limitations": ["Dynamic probe timed out before the command completed."],
            }
        except OSError as exc:
            results.append(
                DynamicCommandResult(
                    kind=str(kind),
                    argv=tuple(materialized.redact_text(token) for token in full_argv),
                    return_code=None,
                    status="host_error",
                    timed_out=False,
                    stdout_summary="",
                    stderr_summary="",
                    observer_summary={},
                    error=materialized.redact_text(str(exc)),
                )
            )
            return {
                "requested": True,
                "performed": False,
                "status": "failed",
                "network_mode": "none",
                "timeout_seconds": timeout_seconds,
                "approved_command_count": approved_command_count,
                "results": [item.as_dict() for item in results],
                "limitations": ["Dynamic probe failed on the host before the sandbox command completed."],
            }
        observer_summary = _combined_observer_summary(materialized)
        observer_summary["observer_mode"] = observation_mode
        observer_summary["pass_possible"] = pass_possible
        result_status = "passed"
        if (
            observer_summary["network_event_count"]
            or observer_summary["secret_event_count"]
            or observer_summary["delete_outside_writable_count"]
        ):
            result_status = "observer_blocked"
        elif (
            observer_summary["process_event_count"]
            or observer_summary["env_sweep_count"]
            or observer_summary["delete_inside_writable_count"]
        ):
            result_status = "observer_warn"
        elif syscall_active and (
            observer_summary.get("syscall_read_error_count", 0)
            or not observer_summary.get("syscall_log_file_count", 0)
        ):
            result_status = "observer_degraded"
        elif completed.returncode != 0:
            result_status = "non_zero_exit"
        elif not pass_possible:
            result_status = "observer_degraded"
        results.append(
            DynamicCommandResult(
                kind=str(kind),
                argv=tuple(materialized.redact_text(token) for token in full_argv),
                return_code=completed.returncode,
                status=result_status,
                timed_out=False,
                stdout_summary=_summarize_output(completed.stdout, materialized),
                stderr_summary=_summarize_output(completed.stderr, materialized),
                observer_summary=observer_summary,
            )
        )
    if any(item.status == "observer_blocked" for item in results):
        overall_status = "blocked"
        limitations.append(
            "Observer recorded network, secret-access, or non-disposable destructive events during a dynamic probe."
        )
    elif any(item.status in {"invalid_command", "docker_binary_missing", "timeout", "host_error", "non_zero_exit"} for item in results):
        overall_status = "failed"
    elif any(item.status == "observer_warn" for item in results):
        overall_status = "findings"
        limitations.append("Observer recorded env sweep, nested process creation, or in-sandbox destructive activity.")
    elif any(item.status == "observer_degraded" for item in results):
        overall_status = "degraded"
        limitations.append("Dynamic probes completed under runtime-hook-only observation and cannot PASS.")
    else:
        overall_status = "passed"
    return {
        "requested": True,
        "performed": True,
        "status": overall_status,
        "network_mode": "none",
        "timeout_seconds": timeout_seconds,
        "approved_command_count": approved_command_count,
        "results": [item.as_dict() for item in results],
        "limitations": limitations,
    }
