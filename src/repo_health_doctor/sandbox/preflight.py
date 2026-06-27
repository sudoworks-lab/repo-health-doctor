from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Any

from .docker import build_container_command_argv
from .workspace import MaterializedWorkspace


DEFAULT_PREFLIGHT_TIMEOUT_SECONDS = 10
PREFLIGHT_COMMANDS: tuple[dict[str, Any], ...] = (
    {
        "kind": "docker_preflight",
        "argv": ("true",),
        "required": True,
    },
    {
        "kind": "docker_preflight",
        "argv": ("id",),
        "required": True,
    },
    {
        "kind": "syscall_observer_preflight",
        "argv": ("strace", "-V"),
        "required": False,
    },
)


@dataclass(frozen=True)
class PreflightCommandResult:
    command_kind: str
    argv: tuple[str, ...]
    return_code: int | None
    status: str
    timed_out: bool
    stdout_summary: str
    stderr_summary: str
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "command_kind": self.command_kind,
            "argv": list(self.argv),
            "return_code": self.return_code,
            "status": self.status,
            "timed_out": self.timed_out,
            "stdout_summary": self.stdout_summary,
            "stderr_summary": self.stderr_summary,
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


def build_preflight_commands() -> list[dict[str, Any]]:
    return [
        {
            "kind": str(command["kind"]),
            "argv": list(command["argv"]),
            "shell": False,
        }
        for command in PREFLIGHT_COMMANDS
    ]


def run_docker_preflight(
    *,
    resolved_base_argv: list[str],
    materialized: MaterializedWorkspace,
    timeout_seconds: int = DEFAULT_PREFLIGHT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    results: list[PreflightCommandResult] = []
    limitations: list[str] = []
    for command in PREFLIGHT_COMMANDS:
        command_kind = str(command["kind"])
        command_argv = tuple(command["argv"])
        required = bool(command["required"])
        full_argv = build_container_command_argv(
            resolved_base_argv,
            container_argv=command_argv,
            network_mode="none",
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
                PreflightCommandResult(
                    command_kind=command_kind,
                    argv=tuple(materialized.redact_text(token) for token in full_argv),
                    return_code=None,
                    status="docker_binary_missing",
                    timed_out=False,
                    stdout_summary="",
                    stderr_summary="",
                    error=materialized.redact_text(str(exc)),
                )
            )
            return {
                "requested": True,
                "performed": False,
                "status": "failed",
                "timeout_seconds": timeout_seconds,
                "commands": build_preflight_commands(),
                "results": [result.as_dict() for result in results],
                "limitations": [
                    "Docker binary is unavailable on the host."
                    if required
                    else "Docker invocation failed while probing syscall observer availability."
                ],
            }
        except subprocess.TimeoutExpired as exc:
            results.append(
                PreflightCommandResult(
                    command_kind=command_kind,
                    argv=tuple(materialized.redact_text(token) for token in full_argv),
                    return_code=None,
                    status="timeout",
                    timed_out=True,
                    stdout_summary=_summarize_output(exc.stdout or "", materialized),
                    stderr_summary=_summarize_output(exc.stderr or "", materialized),
                    error="docker_preflight_timeout",
                )
            )
            if required:
                return {
                    "requested": True,
                    "performed": True,
                    "status": "failed",
                    "timeout_seconds": timeout_seconds,
                    "commands": build_preflight_commands(),
                    "results": [result.as_dict() for result in results],
                    "limitations": ["Docker preflight timed out before harmless command execution completed."],
                }
            limitations.append("Syscall observer probe timed out; observer remains degraded.")
            continue
        except OSError as exc:
            results.append(
                PreflightCommandResult(
                    command_kind=command_kind,
                    argv=tuple(materialized.redact_text(token) for token in full_argv),
                    return_code=None,
                    status="host_error",
                    timed_out=False,
                    stdout_summary="",
                    stderr_summary="",
                    error=materialized.redact_text(str(exc)),
                )
            )
            return {
                "requested": True,
                "performed": False,
                "status": "failed",
                "timeout_seconds": timeout_seconds,
                "commands": build_preflight_commands(),
                "results": [result.as_dict() for result in results],
                "limitations": [
                    "Docker preflight failed before the harmless probe command could finish."
                    if required
                    else "Docker invocation failed while probing syscall observer readiness."
                ],
            }

        result = PreflightCommandResult(
            command_kind=command_kind,
            argv=tuple(materialized.redact_text(token) for token in full_argv),
            return_code=completed.returncode,
            status=(
                "passed"
                if completed.returncode == 0
                else "non_zero_exit"
                if required
                else "probe_unavailable"
            ),
            timed_out=False,
            stdout_summary=_summarize_output(completed.stdout, materialized),
            stderr_summary=_summarize_output(completed.stderr, materialized),
        )
        results.append(result)
        if completed.returncode != 0:
            if required:
                return {
                    "requested": True,
                    "performed": True,
                    "status": "failed",
                    "timeout_seconds": timeout_seconds,
                    "commands": build_preflight_commands(),
                    "results": [item.as_dict() for item in results],
                    "limitations": ["Docker preflight returned a non-zero exit code under --pull=never constraints."],
                }
            limitations.append("Selected image did not provide strace for syscall/process observation; observer remains degraded.")

    return {
        "requested": True,
        "performed": True,
        "status": "passed",
        "timeout_seconds": timeout_seconds,
        "commands": build_preflight_commands(),
        "results": [result.as_dict() for result in results],
        "limitations": limitations,
    }
