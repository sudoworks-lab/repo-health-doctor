from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from ..doctor import REPORT_SCHEMA_VERSION, TOOL_VERSION
from ..doctor import STATUS_BLOCK, STATUS_PASS, STATUS_WARN
from ..doctor import _safe_repo_path  # type: ignore[attr-defined]
from .detect import detect_execution_plan
from .docker import build_docker_spec, evaluate_image_policy, resolve_docker_argv
from .dynamic import DEFAULT_DYNAMIC_TIMEOUT_SECONDS, run_dynamic_phase
from .fetch_plan import DEFAULT_PHASE1_TIMEOUT_SECONDS, build_fetch_plan, run_phase1_fetch
from .models import (
    ExecutionCommand,
    PHASE_0_STATIC,
    PHASE_1B_STRACE_SMOKE,
    PHASE_1_5_RESCAN,
    PHASE_1_FETCH,
    PHASE_2_INSTALL_PROBE,
    PHASE_3_RUNTIME_PROBE,
    SEVERITY_DETAIL_BLOCK,
    SEVERITY_DETAIL_PASS,
    SEVERITY_DETAIL_WARN_MED,
    SEVERITY_DETAIL_WARN_HIGH,
    SEVERITY_DETAIL_WARN_LOW,
    SandboxCheck,
    SkippedCommand,
)
from .observer import build_observer_plan
from .preflight import DEFAULT_PREFLIGHT_TIMEOUT_SECONDS, build_preflight_commands, run_docker_preflight
from .rescan import run_phase1_rescan
from .workspace import build_disposable_workspace_plan, materialize_disposable_workspace


REPORT_KIND_SANDBOX = "sandbox"


def _default_dynamic_phase_result(
    *,
    requested: bool,
    timeout_seconds: int,
    limitations: list[str],
) -> dict[str, Any]:
    return {
        "requested": requested,
        "performed": False,
        "status": "not_requested" if not requested else "skipped",
        "network_mode": "none",
        "timeout_seconds": timeout_seconds,
        "approved_command_count": 0,
        "results": [],
        "limitations": limitations,
    }


def _default_strace_smoke_result(
    *,
    requested: bool,
    timeout_seconds: int,
    limitations: list[str],
) -> dict[str, Any]:
    return {
        "requested": requested,
        "performed": False,
        "status": "not_requested" if not requested else "skipped",
        "network_mode": "none",
        "timeout_seconds": timeout_seconds,
        "approved_command_count": 0,
        "results": [],
        "target_argv": [],
        "wrapper_argv": [],
        "limitations": limitations,
    }


def _phase1_satisfies_dynamic_gate(phase1: dict[str, Any]) -> bool:
    return phase1.get("status") in {"passed", "not_required"}


def _phase1_5_satisfies_dynamic_gate(phase1_5: dict[str, Any]) -> bool:
    return phase1_5.get("status") in {"passed", "warn", "not_required"}


def _phase2_dependency_gate_limitation(phase1: dict[str, Any], phase1_5: dict[str, Any]) -> str | None:
    if phase1.get("status") != "not_required" and phase1_5.get("status") != "not_required":
        return None
    if not _phase1_satisfies_dynamic_gate(phase1) or not _phase1_5_satisfies_dynamic_gate(phase1_5):
        return None
    return (
        "Phase 2 prior-phase dependency gate is cleared: Phase 1 is not_required "
        "(no_external_fetch_required) and Phase 1.5 is not_required (no_artifacts_to_rescan)."
    )


def _build_strace_smoke_command() -> dict[str, Any]:
    return {
        "phase": PHASE_1B_STRACE_SMOKE,
        "kind": "strace_target_wrap_smoke",
        "cwd": ".",
        "argv": [
            "python",
            "-c",
            (
                "import os, pathlib; "
                "pathlib.Path('/tmp/tmp/rhd-strace-smoke.txt').write_text('ok', encoding='utf-8'); "
                "print(os.getpid())"
            ),
        ],
        "env_allowlist": [],
        "shell": False,
        "approved": True,
        "evidence": {
            "purpose": "tool_generated_harmless_strace_target_wrap_smoke",
            "writes_only_to": "/tmp/tmp/rhd-strace-smoke.txt",
        },
    }


def _approved_commands_for_phase(execution_plan: dict[str, Any], phase: str) -> list[dict[str, Any]]:
    return [
        command
        for command in execution_plan["commands"]
        if command.get("phase") == phase and bool(command.get("approved"))
    ]


def _summarize_dynamic_observation(*phases: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "performed": False,
        "result_count": 0,
        "network_event_count": 0,
        "secret_event_count": 0,
        "env_sweep_count": 0,
        "process_event_count": 0,
        "delete_inside_writable_count": 0,
        "delete_outside_writable_count": 0,
        "syscall_log_file_count": 0,
        "syscall_read_error_count": 0,
        "syscall_secret_file_open_count": 0,
        "observer_modes": [],
        "pass_possible": False,
    }
    observer_modes: set[str] = set()
    for phase in phases:
        if not phase.get("performed"):
            continue
        summary["performed"] = True
        for result in phase.get("results", []):
            if not isinstance(result, dict):
                continue
            summary["result_count"] += 1
            observer_summary = result.get("observer_summary", {})
            if not isinstance(observer_summary, dict):
                continue
            for key in (
                "network_event_count",
                "secret_event_count",
                "env_sweep_count",
                "process_event_count",
                "delete_inside_writable_count",
                "delete_outside_writable_count",
                "syscall_log_file_count",
                "syscall_read_error_count",
                "syscall_secret_file_open_count",
            ):
                value = observer_summary.get(key, 0)
                if isinstance(value, int):
                    summary[key] += value
            if observer_summary.get("pass_possible"):
                summary["pass_possible"] = True
            observer_mode = observer_summary.get("observer_mode")
            if isinstance(observer_mode, str) and observer_mode:
                observer_modes.add(observer_mode)
    summary["observer_modes"] = sorted(observer_modes)
    return summary


def _has_successful_observed_dynamic_result(*phases: dict[str, Any]) -> bool:
    """Require a successful, parseable syscall trace before claiming activation."""
    for phase in phases:
        if not phase.get("performed"):
            continue
        for result in phase.get("results", []):
            if not isinstance(result, dict) or result.get("status") != "passed":
                continue
            observer_summary = result.get("observer_summary")
            if not isinstance(observer_summary, dict) or not observer_summary.get("pass_possible"):
                continue
            if (
                isinstance(observer_summary.get("syscall_log_file_count"), int)
                and observer_summary["syscall_log_file_count"] > 0
                and observer_summary.get("syscall_read_error_count") == 0
            ):
                return True
    return False


def _dynamic_phase_statuses(*phases: dict[str, Any]) -> dict[str, dict[str, Any]]:
    statuses: dict[str, dict[str, Any]] = {}
    for index, phase in enumerate(phases, start=2):
        phase_label = f"phase{index}"
        if index == 2:
            phase_label = "phase2"
        elif index == 3:
            phase_label = "phase3"
        statuses[phase_label] = {
            "requested": bool(phase.get("requested")),
            "performed": bool(phase.get("performed")),
            "status": str(phase.get("status", "unknown")),
            "approved_command_count": int(phase.get("approved_command_count", 0) or 0),
            "result_count": len(phase.get("results", [])) if isinstance(phase.get("results", []), list) else 0,
        }
    return statuses


def _dynamic_result_status_counts(*phases: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for phase in phases:
        for result in phase.get("results", []):
            if not isinstance(result, dict):
                continue
            status = result.get("status")
            if not isinstance(status, str) or not status:
                continue
            counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _dynamic_evidence_limitations(
    *,
    observer: dict[str, Any],
    phase2: dict[str, Any],
    phase3: dict[str, Any],
) -> list[str]:
    limitations: list[str] = []
    for source in (observer, phase2, phase3):
        for limitation in source.get("limitations", []):
            if isinstance(limitation, str) and limitation not in limitations:
                limitations.append(limitation)
    return limitations


def _dynamic_degraded_reasons(
    *,
    dynamic_observation: dict[str, Any],
    observer: dict[str, Any],
    phase2: dict[str, Any],
    phase3: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if not dynamic_observation["performed"]:
        reasons.append("No dynamic probe result was collected in this report.")
    if not dynamic_observation["pass_possible"]:
        reasons.append("The active observer configuration cannot establish a dynamic PASS result.")
    for phase in (phase2, phase3):
        if phase.get("status") in {"degraded", "failed", "skipped", "not_requested"}:
            for limitation in phase.get("limitations", []):
                if isinstance(limitation, str) and limitation not in reasons:
                    reasons.append(limitation)
    if not observer.get("pass_possible"):
        for limitation in observer.get("limitations", []):
            if isinstance(limitation, str) and limitation not in reasons:
                reasons.append(limitation)
    return reasons


def _build_dynamic_check_evidence(
    *,
    dynamic_observation: dict[str, Any],
    observer: dict[str, Any],
    phase2: dict[str, Any],
    phase3: dict[str, Any],
) -> dict[str, Any]:
    confidence = "high" if dynamic_observation["performed"] and dynamic_observation["pass_possible"] else "medium" if dynamic_observation["performed"] else "low"
    return {
        "performed": dynamic_observation["performed"],
        "result_count": dynamic_observation["result_count"],
        "observer_mode": observer["mode"],
        "observer_modes": dynamic_observation["observer_modes"],
        "confidence": confidence,
        "limitations": _dynamic_evidence_limitations(
            observer=observer,
            phase2=phase2,
            phase3=phase3,
        ),
        "degraded_reasons": _dynamic_degraded_reasons(
            dynamic_observation=dynamic_observation,
            observer=observer,
            phase2=phase2,
            phase3=phase3,
        ),
        "observation": {
            "performed": dynamic_observation["performed"],
            "result_count": dynamic_observation["result_count"],
            "pass_possible": dynamic_observation["pass_possible"],
            "observer_modes": dynamic_observation["observer_modes"],
        },
        "phase_statuses": _dynamic_phase_statuses(phase2, phase3),
        "result_status_counts": _dynamic_result_status_counts(phase2, phase3),
        "event_counts": {
            "network_event_count": dynamic_observation["network_event_count"],
            "secret_event_count": dynamic_observation["secret_event_count"],
            "env_sweep_count": dynamic_observation["env_sweep_count"],
            "process_event_count": dynamic_observation["process_event_count"],
            "delete_inside_writable_count": dynamic_observation["delete_inside_writable_count"],
            "delete_outside_writable_count": dynamic_observation["delete_outside_writable_count"],
        },
        "syscall_trace": {
            "log_file_count": dynamic_observation["syscall_log_file_count"],
            "read_error_count": dynamic_observation["syscall_read_error_count"],
            "secret_file_open_count": dynamic_observation["syscall_secret_file_open_count"],
        },
    }


def _activate_observer_from_preflight(observer: dict[str, Any], preflight: dict[str, Any]) -> dict[str, Any]:
    activated = json.loads(json.dumps(observer))
    syscall_observer = activated.get("syscall_observer", {})
    runtime_ready = bool(activated.get("runtime_hook_active_languages"))
    if not isinstance(syscall_observer, dict):
        return activated
    results = preflight.get("results", [])
    if not isinstance(results, list):
        return activated
    probe_result = next(
        (
            item
            for item in results
            if isinstance(item, dict) and item.get("command_kind") == "syscall_observer_preflight"
        ),
        None,
    )
    if probe_result is None:
        return activated

    status = probe_result.get("status")
    if status == "passed":
        syscall_observer["available"] = True
        syscall_observer["active"] = True
        syscall_observer["limitations"] = [
            "Docker preflight confirmed strace binary availability inside the selected image, but full syscall tracing is only exercised when a later dynamic probe wraps a target process."
        ]
        activated["mode"] = "strace+runtime_hook" if runtime_ready else "strace"
        activated["status"] = "ready"
        activated["pass_possible"] = runtime_ready
        limitations = [
            limitation
            for limitation in activated.get("limitations", [])
            if "runtime-hook-only observation remains degraded" not in limitation
            and "not trusted until Docker preflight confirms availability inside the selected image" not in limitation
        ]
        if runtime_ready:
            limitations.append(
                "strace-backed syscall/process observation and runtime hooks are both active for this invocation."
            )
        limitations.append(
            "Docker preflight confirmed strace binary availability inside the selected image, but full syscall tracing is only exercised when a later dynamic probe wraps a target process."
        )
        activated["limitations"] = limitations
        return activated

    syscall_observer["available"] = False
    syscall_observer["active"] = False
    syscall_observer["limitations"] = [
        "Selected image did not provide strace for syscall/process observation, so runtime-hook-only coverage remains degraded."
    ]
    limitations = list(activated.get("limitations", []))
    if not any("Selected image did not provide strace" in item for item in limitations):
        limitations.append(
            "Selected image did not provide strace for syscall/process observation, so runtime-hook-only coverage remains degraded."
        )
    activated["limitations"] = limitations
    activated["pass_possible"] = False
    return activated


def _approval_path_handle(path: Path, repo_root: Path) -> str:
    resolved = path.resolve()
    for base in (repo_root.resolve(), Path.cwd().resolve()):
        try:
            return resolved.relative_to(base).as_posix()
        except ValueError:
            continue
    return "<approval-file>"


def _load_approval_payload(path: Path) -> tuple[list[dict[str, Any]], list[SkippedCommand], dict[str, Any]]:
    try:
        raw_payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"approval file not found: {path}")
    except OSError as exc:
        raise ValueError(f"could not read approval file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid approval JSON: {path}") from exc

    commands_payload: Any
    if isinstance(raw_payload, dict) and isinstance(raw_payload.get("commands"), list):
        commands_payload = raw_payload["commands"]
    elif (
        isinstance(raw_payload, dict)
        and isinstance(raw_payload.get("execution_plan"), dict)
        and isinstance(raw_payload["execution_plan"].get("commands"), list)
    ):
        commands_payload = raw_payload["execution_plan"]["commands"]
    else:
        raise ValueError("approval file must contain a commands array")

    approval_contract: dict[str, Any] = {}
    if isinstance(raw_payload, dict):
        raw_contract = raw_payload.get("approval_contract")
        if isinstance(raw_contract, dict):
            approval_contract = raw_contract

    approvals: list[dict[str, Any]] = []
    skipped: list[SkippedCommand] = []
    for item in commands_payload:
        if not isinstance(item, dict):
            skipped.append(SkippedCommand(reason="invalid_approval_entry"))
            continue
        if "command" in item:
            skipped.append(
                SkippedCommand(
                    reason="legacy_command_string_not_supported",
                    detail="approval entries must use argv form",
                )
            )
            continue
        approvals.append(item)
    return approvals, skipped, approval_contract


def _validate_approval_contract(
    approval_contract: dict[str, Any],
    *,
    approval_path: Path,
    repo_root: Path,
    selected_image_reference: str,
    expected_image_id: str | None,
    local_sanctioned: bool,
) -> list[str]:
    mismatches: list[str] = []
    docker_image = approval_contract.get("docker_image")
    if docker_image is not None:
        if not isinstance(docker_image, str) or docker_image != selected_image_reference:
            mismatches.append("approval_docker_image_mismatch")

    contract_expected_image_id = approval_contract.get("expected_image_id")
    if contract_expected_image_id is not None:
        if not isinstance(contract_expected_image_id, str) or contract_expected_image_id != expected_image_id:
            mismatches.append("approval_expected_image_id_mismatch")

    contract_local_sanctioned = approval_contract.get("local_sanctioned_image")
    if contract_local_sanctioned is not None:
        if not isinstance(contract_local_sanctioned, bool) or contract_local_sanctioned != local_sanctioned:
            mismatches.append("approval_local_image_policy_mismatch")

    network_policy = approval_contract.get("network_policy")
    if network_policy is not None:
        if not isinstance(network_policy, str) or network_policy != "none":
            mismatches.append("approval_network_policy_mismatch")

    approval_scope = approval_contract.get("approval_scope")
    if approval_scope is not None:
        if not isinstance(approval_scope, dict):
            mismatches.append("approval_scope_invalid")
        else:
            scope_kind = approval_scope.get("kind")
            scope_repo_path = approval_scope.get("repo_path")
            if scope_kind != "controlled_fixture_only":
                mismatches.append("approval_scope_invalid")
            elif not isinstance(scope_repo_path, str) or not scope_repo_path.strip():
                mismatches.append("approval_scope_invalid")
            else:
                scoped_root = (approval_path.parent / scope_repo_path).resolve()
                if scoped_root != repo_root.resolve():
                    mismatches.append("approval_scope_mismatch")

    human_review_required = approval_contract.get("human_review_required")
    if human_review_required is not None and not isinstance(human_review_required, bool):
        mismatches.append("approval_human_review_invalid")

    for field_name in ("created_at", "expires_at"):
        field_value = approval_contract.get(field_name)
        if field_value is not None and not isinstance(field_value, str):
            mismatches.append(f"approval_{field_name}_invalid")

    return sorted(dict.fromkeys(mismatches))


def _apply_approvals(
    execution_plan: dict[str, Any],
    *,
    approval_file: str | Path | None = None,
    repo_root: Path,
    selected_image_reference: str,
    expected_image_id: str | None,
    local_sanctioned: bool,
) -> tuple[dict[str, Any], list[str], str]:
    commands = [
        ExecutionCommand.from_mapping(item, approved=False)
        for item in execution_plan["commands"]
        if isinstance(item, dict)
    ]
    skipped_commands = [
        SkippedCommand(
            reason=item["reason"],
            phase=item.get("phase"),
            kind=item.get("kind"),
            cwd=item.get("cwd"),
            argv=tuple(item.get("argv", [])),
            shell=bool(item.get("shell", False)),
            detail=item.get("detail"),
        )
        for item in execution_plan["skipped_commands"]
    ]

    approval_limitations: list[str] = []
    approval_status = STATUS_WARN
    matched_keys: set[tuple[str, str, str, tuple[str, ...], tuple[str, ...], bool]] = set()
    approval_contract: dict[str, Any] = {}
    approval_path_handle: str | None = None
    approval_mismatch_reasons: list[str] = []

    if approval_file is None:
        for command in commands:
            skipped_commands.append(
                SkippedCommand(
                    phase=command.phase,
                    kind=command.kind,
                    cwd=command.cwd,
                    argv=command.argv,
                    shell=command.shell,
                    reason="not_explicitly_approved",
                )
            )
        approval_limitations.append("No approval file was provided; sandbox remains approval-gated.")
    else:
        approval_path = Path(approval_file)
        approval_path_handle = _approval_path_handle(approval_path, repo_root)
        try:
            approval_entries, invalid_entries, approval_contract = _load_approval_payload(approval_path)
        except ValueError as exc:
            approval_limitations.append(str(exc))
            approval_status = STATUS_BLOCK
            approval_entries = []
            invalid_entries = []
            approval_contract = {}
        skipped_commands.extend(invalid_entries)
        contract_mismatches = _validate_approval_contract(
            approval_contract,
            approval_path=approval_path,
            repo_root=repo_root,
            selected_image_reference=selected_image_reference,
            expected_image_id=expected_image_id,
            local_sanctioned=local_sanctioned,
        )
        if contract_mismatches:
            approval_mismatch_reasons.extend(contract_mismatches)
            approval_limitations.append("Approval file constraints did not match the current sandbox execution context.")
            approval_status = STATUS_BLOCK
        approvals: list[ExecutionCommand] = []
        if approval_status != STATUS_BLOCK:
            for entry in approval_entries:
                try:
                    approvals.append(ExecutionCommand.from_mapping(entry, approved=True))
                except ValueError as exc:
                    skipped_commands.append(
                        SkippedCommand(
                            reason="unsafe_or_ambiguous",
                            phase=entry.get("phase") if isinstance(entry.get("phase"), str) else None,
                            kind=entry.get("kind") if isinstance(entry.get("kind"), str) else None,
                            cwd=entry.get("cwd") if isinstance(entry.get("cwd"), str) else None,
                            argv=tuple(entry.get("argv", [])) if isinstance(entry.get("argv"), list) else (),
                            shell=bool(entry.get("shell", False)),
                            detail=str(exc),
                        )
                    )
            command_map = {command.approval_key(): command for command in commands}
            approved_commands: list[ExecutionCommand] = []
            for approval in approvals:
                key = approval.approval_key()
                if key not in command_map:
                    approval_mismatch_reasons.append("approval_mismatch")
                    skipped_commands.append(
                        SkippedCommand(
                            phase=approval.phase,
                            kind=approval.kind,
                            cwd=approval.cwd,
                            argv=approval.argv,
                            shell=approval.shell,
                            reason="approval_mismatch",
                        )
                    )
                    continue
                matched_keys.add(key)
            for command in commands:
                if command.approval_key() in matched_keys:
                    approved_commands.append(
                        ExecutionCommand(
                            phase=command.phase,
                            kind=command.kind,
                            cwd=command.cwd,
                            argv=command.argv,
                            env_allowlist=command.env_allowlist,
                            shell=command.shell,
                            evidence=command.evidence,
                            approved=True,
                        )
                    )
                else:
                    approved_commands.append(command)
                    skipped_commands.append(
                        SkippedCommand(
                            phase=command.phase,
                            kind=command.kind,
                            cwd=command.cwd,
                            argv=command.argv,
                            shell=command.shell,
                            reason="not_explicitly_approved",
                        )
                    )
            commands = approved_commands
            approval_status = STATUS_PASS if len(matched_keys) == len(commands) and not invalid_entries else STATUS_WARN
            if approval_status == STATUS_WARN:
                approval_limitations.append("Some commands were not approved exactly as detected.")

    execution_plan["commands"] = [command.as_dict() for command in sorted(commands, key=lambda item: item.approval_key())]
    execution_plan["skipped_commands"] = [
        item.as_dict()
        for item in sorted(
            skipped_commands,
            key=lambda item: (
                item.phase or "",
                item.kind or "",
                item.cwd or "",
                item.argv,
                item.reason,
            ),
        )
    ]
    execution_plan["approval"] = {
        "provided": approval_file is not None,
        "matched_command_count": sum(1 for command in commands if command.approved),
        "total_command_count": len(commands),
        "path_handle": approval_path_handle,
        "approval_scope": approval_contract.get("approval_scope"),
        "docker_image": approval_contract.get("docker_image"),
        "expected_image_id": approval_contract.get("expected_image_id"),
        "local_sanctioned_image": approval_contract.get("local_sanctioned_image"),
        "network_policy": approval_contract.get("network_policy"),
        "human_review_required": approval_contract.get("human_review_required"),
        "created_at": approval_contract.get("created_at"),
        "expires_at": approval_contract.get("expires_at"),
        "mismatch_reasons": sorted(dict.fromkeys(approval_mismatch_reasons)),
    }
    if approval_file is None:
        execution_plan["approval"]["status"] = "not_provided"
    elif approval_status == STATUS_BLOCK:
        execution_plan["approval"]["status"] = "invalid"
    elif execution_plan["approval"]["matched_command_count"] == len(commands):
        execution_plan["approval"]["status"] = "matched"
    else:
        execution_plan["approval"]["status"] = "partial"

    return execution_plan, approval_limitations, approval_status


def _build_phase_plan(
    execution_plan: dict[str, Any],
    *,
    detection_limitations: list[str],
    fetch_plan: dict[str, Any],
    preflight: dict[str, Any],
    strace_smoke: dict[str, Any],
    phase1: dict[str, Any],
    phase1_5: dict[str, Any],
    observer: dict[str, Any],
    phase2: dict[str, Any],
    phase3: dict[str, Any],
) -> list[dict[str, Any]]:
    install_probe_commands = [
        command for command in execution_plan["commands"] if command.get("phase") == PHASE_2_INSTALL_PROBE
    ]
    runtime_probe_commands = [
        command for command in execution_plan["commands"] if command.get("phase") == PHASE_3_RUNTIME_PROBE
    ]
    return [
        {
            "phase": PHASE_0_STATIC,
            "status": "completed",
            "summary": "Read-only manifest and script discovery completed.",
            "commands": [],
            "skipped_commands": [],
            "limitations": detection_limitations,
            "execution_enabled": False,
            "approval_required": False,
        },
        {
            "phase": PHASE_1_FETCH,
            "status": (
                phase1["status"]
                if phase1["status"] == "not_required"
                else
                "executed"
                if phase1["status"] == "passed" and phase1["performed"]
                else phase1["status"]
                if phase1["requested"] and phase1["status"] not in {"not_requested", "passed"}
                else "ready"
                if preflight["status"] == "passed"
                else "planned"
            ),
            "summary": (
                "No external dependency fetch was required for the detected manifest shape."
                if phase1["status"] == "not_required"
                else
                "Dependency fetch commands were executed under explicit Phase 1 gating."
                if phase1["status"] == "passed" and phase1["performed"]
                else "Dependency fetch commands remain planned or gated in dry-run form."
            ),
            "commands": fetch_plan["commands"],
            "skipped_commands": fetch_plan["skipped_commands"],
            "limitations": (
                list(fetch_plan["limitations"])
                if phase1["status"] == "not_required"
                else list(fetch_plan["limitations"])
                + list(preflight["phase_gate_limitations"])
                + list(phase1["phase_gate_limitations"])
            ),
            "execution_enabled": phase1["status"] == "passed" and phase1["performed"],
            "approval_required": False,
        },
        {
            "phase": PHASE_1B_STRACE_SMOKE,
            "status": (
                "executed"
                if strace_smoke["status"] == "passed" and strace_smoke["performed"]
                else strace_smoke["status"]
                if strace_smoke["requested"]
                else "planned"
            ),
            "summary": (
                "A fixed harmless target process was wrapped with strace and its syscall logs were collected."
                if strace_smoke["performed"]
                else "strace target-wrap smoke remains unrequested or gated."
            ),
            "commands": [_build_strace_smoke_command()] if strace_smoke["requested"] else [],
            "skipped_commands": [],
            "limitations": list(strace_smoke["limitations"]),
            "execution_enabled": strace_smoke["status"] == "passed" and strace_smoke["performed"],
            "approval_required": False,
        },
        {
            "phase": PHASE_1_5_RESCAN,
            "status": (
                "completed"
                if phase1_5["status"] == "passed"
                else phase1_5["status"]
            ),
            "summary": (
                "Fetched dependency artifacts were statically rescanned before any later dynamic phase."
                if phase1_5["performed"]
                else "No fetched dependency artifacts required static rescanning after the safe Phase 1 bypass."
                if phase1_5["status"] == "not_required"
                else "No fetched dependency artifacts were available for static rescanning."
            ),
            "commands": [],
            "skipped_commands": [],
            "limitations": list(phase1_5["limitations"]),
            "execution_enabled": False,
            "approval_required": False,
        },
        {
            "phase": PHASE_2_INSTALL_PROBE,
            "status": (
                "executed"
                if phase2["status"] == "passed" and phase2["performed"]
                else phase2["status"]
                if phase2["requested"]
                else "planned"
            ),
            "summary": (
                "Approved install-script probes executed under sandbox gates."
                if phase2["performed"]
                else "Install script probes remain approval-gated and unexecuted."
            ),
            "commands": install_probe_commands,
            "skipped_commands": [
                item for item in execution_plan["skipped_commands"] if item.get("phase") == PHASE_2_INSTALL_PROBE
            ],
            "limitations": list(phase2["limitations"]),
            "execution_enabled": phase2["status"] == "passed" and phase2["performed"],
            "approval_required": True,
        },
        {
            "phase": PHASE_3_RUNTIME_PROBE,
            "status": (
                "executed"
                if phase3["status"] == "passed" and phase3["performed"]
                else phase3["status"]
                if phase3["requested"]
                else "planned"
            ),
            "summary": (
                "Approved runtime probes executed under sandbox gates."
                if phase3["performed"]
                else "Runtime probes remain approval-gated and unexecuted."
            ),
            "commands": runtime_probe_commands,
            "skipped_commands": [
                item for item in execution_plan["skipped_commands"] if item.get("phase") == PHASE_3_RUNTIME_PROBE
            ],
            "limitations": list(phase3["limitations"]),
            "execution_enabled": phase3["status"] == "passed" and phase3["performed"],
            "approval_required": True,
        },
    ]


def _build_report(
    root: Path,
    checks: list[SandboxCheck],
    execution_plan: dict[str, Any],
    *,
    phase_plan: list[dict[str, Any]],
    docker_spec: dict[str, Any],
    workspace_plan: dict[str, Any],
    preflight: dict[str, Any],
    strace_smoke: dict[str, Any],
    phase1: dict[str, Any],
    phase1_5: dict[str, Any],
    observer: dict[str, Any],
    phase2: dict[str, Any],
    phase3: dict[str, Any],
) -> dict[str, Any]:
    summary = {
        STATUS_PASS: sum(1 for check in checks if check.status == STATUS_PASS),
        STATUS_WARN: sum(1 for check in checks if check.status == STATUS_WARN),
        STATUS_BLOCK: sum(1 for check in checks if check.status == STATUS_BLOCK),
    }
    overall_status = (
        STATUS_BLOCK
        if summary[STATUS_BLOCK]
        else STATUS_WARN
        if summary[STATUS_WARN]
        else STATUS_PASS
    )
    dynamic_evidence = _build_dynamic_check_evidence(
        dynamic_observation=_summarize_dynamic_observation(phase2, phase3),
        observer=observer,
        phase2=phase2,
        phase3=phase3,
    )
    return {
        "tool": "repo-health-doctor",
        "version": TOOL_VERSION,
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_SANDBOX,
        "repo_path": _safe_repo_path(root),
        "overall_status": overall_status,
        "summary": summary,
        "checks": [check.as_dict() for check in checks],
        "execution_plan": execution_plan,
        "phase_plan": phase_plan,
        "sandbox": {
            "mode": "plan_only",
            "network": docker_spec["network"],
            "rootfs": docker_spec["rootfs"],
            "user": docker_spec["user"],
            "capabilities": "cap_drop_all_planned",
            "docker_socket_mounted": False,
            "observation_mode": observer["mode"],
            "docker_spec": docker_spec,
            "disposable_workspace": workspace_plan,
            "preflight": preflight,
            "strace_target_wrap_smoke": strace_smoke,
            "phase1_fetch": phase1,
            "phase1_5_rescan": phase1_5,
            "observer": observer,
            "dynamic_evidence": dynamic_evidence,
            "phase2_install_probes": phase2,
            "phase3_runtime_probes": phase3,
        },
        "residual_risks": [
            "docker_daemon_attack_surface",
            "host_mount_breakout",
            "kernel_exploit",
            (
                "pinned_execution_image_selected"
                if docker_spec["selected_image_digest_pinned"]
                else "local_sanctioned_image_not_portable"
                if docker_spec.get("local_sanctioned")
                else "unpinned_base_image_selection"
            ),
            (
                "phase1_fetch_not_required_for_selected_manifest_shape"
                if phase1["status"] == "not_required"
                else "phase1_fetch_not_executed_in_report"
                if not (phase1["status"] == "passed" and phase1["performed"])
                else "phase1_fetch_limited_to_tool_generated_commands"
            ),
            (
                "dynamic_observation_degraded"
                if not observer.get("pass_possible")
                else "dynamic_observation_not_yet_activated"
                if not _has_successful_observed_dynamic_result(phase2, phase3)
                else "dynamic_observation_evidence_limited"
            ),
            "dynamic_checks_not_fully_implemented",
        ],
    }


def run_sandbox(
    repo_path: str | Path,
    *,
    approval_file: str | Path | None = None,
    docker_image: str | None = None,
    allow_local_image: bool = False,
    expected_image_id: str | None = None,
    run_preflight: bool = False,
    run_strace_smoke: bool = False,
    preflight_timeout_seconds: int = DEFAULT_PREFLIGHT_TIMEOUT_SECONDS,
    run_phase1: bool = False,
    phase1_timeout_seconds: int = DEFAULT_PHASE1_TIMEOUT_SECONDS,
    run_phase2: bool = False,
    run_phase3: bool = False,
    dynamic_timeout_seconds: int = DEFAULT_DYNAMIC_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    root = Path(repo_path).resolve()
    execution_plan, detection_limitations = detect_execution_plan(root)
    fetch_plan = build_fetch_plan(root)
    workspace_plan = build_disposable_workspace_plan()
    docker_spec = build_docker_spec(
        detected_languages=execution_plan["detected_languages"],
        workspace_plan=workspace_plan,
        image_reference=docker_image,
    )
    image_policy = evaluate_image_policy(
        docker_spec["selected_image_reference"],
        explicitly_selected=docker_image is not None,
        allow_local_image=allow_local_image,
        expected_image_id=expected_image_id,
    )
    docker_spec["selected_image_execution_allowed"] = image_policy["execution_allowed"]
    docker_spec["image_reference_kind"] = image_policy["image_reference_kind"]
    docker_spec["expected_image_id"] = image_policy["expected_image_id"]
    docker_spec["actual_image_id"] = image_policy["actual_image_id"]
    docker_spec["image_id_match"] = image_policy["image_id_match"]
    docker_spec["local_sanctioned"] = image_policy["local_sanctioned"]
    docker_spec["local_sanctioned_limitations"] = image_policy["local_sanctioned_limitations"]
    docker_spec["decision"] = image_policy["decision"]
    execution_plan, approval_limitations, approval_status = _apply_approvals(
        execution_plan,
        approval_file=approval_file,
        repo_root=root,
        selected_image_reference=docker_spec["selected_image_reference"],
        expected_image_id=docker_spec["expected_image_id"],
        local_sanctioned=docker_spec["local_sanctioned"],
    )
    materialized_workspace = materialize_disposable_workspace(root, workspace_plan)
    observer = build_observer_plan(execution_plan["detected_languages"])
    docker_resolution_limitations: list[str] = []
    preflight = {
        "requested": run_preflight,
        "performed": False,
        "status": "not_requested",
        "timeout_seconds": preflight_timeout_seconds,
        "commands": build_preflight_commands(),
        "results": [],
        "limitations": ["Docker preflight was not requested; dynamic execution remains gated."],
        "phase_gate_limitations": [
            "Phase 1 execution remains disabled until Docker preflight is explicitly requested and passes.",
        ],
    }
    strace_smoke = _default_strace_smoke_result(
        requested=run_strace_smoke,
        timeout_seconds=dynamic_timeout_seconds,
        limitations=[
            "strace target-wrap smoke was not requested; harmless target-process tracing remains unverified."
            if not run_strace_smoke
            else "strace target-wrap smoke is gated until image policy, Docker preflight, and observer readiness are satisfied."
        ],
    )
    phase1 = {
        "requested": run_phase1,
        "performed": False,
        "status": "not_required" if fetch_plan.get("not_required_status") == "not_required" else "not_requested",
        "network_mode": "bridge",
        "timeout_seconds": phase1_timeout_seconds,
        "results": [],
        "limitations": (
            list(fetch_plan["limitations"])
            if fetch_plan.get("not_required_status") == "not_required"
            else ["Phase 1 fetch was not requested; dependency retrieval remains gated."]
        ),
        "phase_gate_limitations": (
            []
            if fetch_plan.get("not_required_status") == "not_required"
            else ["Phase 1 execution requires explicit --run-phase1 and a successful Docker preflight."]
        ),
    }
    phase1_5 = {
        "requested": True,
        "performed": False,
        "status": "skipped",
        "artifact_summary": {
            "scanned_file_count": 0,
            "artifact_candidate_count": 0,
            "read_error_count": 0,
            "artifact_kind_counts": {
                "node_package_manifest": 0,
                "node_package_archive": 0,
                "python_archive": 0,
                "plain_text_artifact": 0,
            },
        },
        "finding_summary": {
            "blocked_count": 0,
            "warn_count": 0,
            "info_count": 0,
            "unknown_count": 0,
        },
        "findings": [],
        "blocked_findings": [],
        "warn_findings": [],
        "info_findings": [],
        "unknown_findings": [],
        "ordinary_library_capabilities": [],
        "install_time_risks": [],
        "dependency_source_risks": [],
        "limitations": [
            "No fetched dependency artifacts were available for Phase 1.5 static rescan.",
        ],
        "residual_risks": [],
    }
    phase2 = _default_dynamic_phase_result(
        requested=run_phase2,
        timeout_seconds=dynamic_timeout_seconds,
        limitations=[
            "Phase 2 install-script probes were not requested; explicit opt-in is required."
            if not run_phase2
            else "Phase 2 install-script probes are gated until preflight, Phase 1, Phase 1.5, observer readiness, and approval conditions are satisfied."
        ],
    )
    phase3 = _default_dynamic_phase_result(
        requested=run_phase3,
        timeout_seconds=dynamic_timeout_seconds,
        limitations=[
            "Phase 3 runtime probes were not requested; explicit opt-in is required."
            if not run_phase3
            else "Phase 3 runtime probes are gated until preflight, Phase 1, Phase 1.5, observer readiness, and approval conditions are satisfied."
        ],
    )
    try:
        if materialized_workspace.materialization_status == "failed":
            docker_resolution = {
                "path_resolution_status": "failed",
                "raw_argv": [],
                "resolved_argv_redacted": [],
                "mount_source_handles": [],
                "selected_image_reference": docker_spec["selected_image_reference"],
            }
            docker_resolution_limitations.append(
                "Docker argv path resolution did not complete because disposable workspace materialization failed."
            )
        else:
            docker_resolution = resolve_docker_argv(docker_spec, materialized_workspace)
        docker_spec["path_resolution_status"] = docker_resolution["path_resolution_status"]
        docker_spec["resolved_argv_redacted"] = docker_resolution["resolved_argv_redacted"]
        docker_spec["mount_source_handles"] = docker_resolution["mount_source_handles"]
        docker_spec["selected_image_reference"] = docker_resolution["selected_image_reference"]

        if run_preflight:
            if not docker_spec["selected_image_execution_allowed"]:
                preflight["status"] = "skipped"
                preflight["limitations"] = list(image_policy["limitations"]) or [
                    "Docker preflight requires a digest-pinned image reference or a sanctioned local image with a matching full image ID.",
                ]
                preflight["phase_gate_limitations"] = [
                    "Phase 1 execution remains disabled because Docker preflight was skipped.",
                ]
            elif docker_spec["path_resolution_status"] != "completed":
                preflight["status"] = "skipped"
                preflight["limitations"] = [
                    "Docker preflight requires completed Docker argv path resolution.",
                ]
                preflight["phase_gate_limitations"] = [
                    "Phase 1 execution remains disabled because Docker preflight prerequisites were not met.",
                ]
            elif materialized_workspace.materialization_status not in {"completed", "partial"}:
                preflight["status"] = "skipped"
                preflight["limitations"] = [
                    "Docker preflight requires a disposable workspace that was materialized successfully.",
                ]
                preflight["phase_gate_limitations"] = [
                    "Phase 1 execution remains disabled because workspace materialization failed.",
                ]
            else:
                preflight = run_docker_preflight(
                    resolved_base_argv=docker_resolution["raw_argv"],
                    materialized=materialized_workspace,
                    timeout_seconds=preflight_timeout_seconds,
                )
                preflight["phase_gate_limitations"] = (
                    []
                    if preflight["status"] == "passed"
                    else ["Phase 1 execution remains disabled because Docker preflight did not pass."]
                )
                observer = _activate_observer_from_preflight(observer, preflight)

        if run_strace_smoke:
            if not docker_spec["selected_image_execution_allowed"]:
                strace_smoke["limitations"] = list(image_policy["limitations"]) or [
                    "strace target-wrap smoke requires a digest-pinned image reference or a sanctioned local image with a matching full image ID.",
                ]
            elif preflight["status"] != "passed":
                strace_smoke["limitations"] = [
                    "strace target-wrap smoke requires a successful Docker preflight result in the same invocation.",
                ]
            elif docker_spec["path_resolution_status"] != "completed":
                strace_smoke["limitations"] = [
                    "strace target-wrap smoke requires completed Docker argv path resolution.",
                ]
            elif materialized_workspace.materialization_status not in {"completed", "partial"}:
                strace_smoke["limitations"] = [
                    "strace target-wrap smoke requires a disposable workspace that was materialized successfully.",
                ]
            elif not observer.get("syscall_observer", {}).get("active"):
                strace_smoke["limitations"] = list(observer["limitations"]) + [
                    "strace target-wrap smoke requires an active syscall observer after Docker preflight.",
                ]
            else:
                smoke_command = _build_strace_smoke_command()
                strace_smoke = run_dynamic_phase(
                    resolved_base_argv=docker_resolution["raw_argv"],
                    commands=[smoke_command],
                    materialized=materialized_workspace,
                    observer=observer,
                    detected_languages=["python"],
                    timeout_seconds=dynamic_timeout_seconds,
                )
                strace_smoke["target_argv"] = list(smoke_command["argv"])
                strace_smoke["wrapper_argv"] = (
                    list(strace_smoke["results"][0]["argv"])
                    if strace_smoke.get("results")
                    else []
                )
                strace_smoke["limitations"] = list(strace_smoke["limitations"]) + [
                    "Successful strace target-wrap smoke proves tracing for this fixed harmless target only and does not establish safety for unknown repository commands."
                ]

        if run_phase1:
            if phase1["status"] == "not_required":
                phase1["phase_gate_limitations"] = []
            elif not docker_spec["selected_image_execution_allowed"]:
                phase1["status"] = "skipped"
                phase1["limitations"] = list(image_policy["limitations"]) or [
                    "Phase 1 fetch requires a digest-pinned image reference or a sanctioned local image with a matching full image ID.",
                ]
                phase1["phase_gate_limitations"] = [
                    "Phase 1 execution was skipped because the selected image did not satisfy sandbox image policy.",
                ]
            elif preflight["status"] != "passed":
                phase1["status"] = "skipped"
                phase1["limitations"] = [
                    "Phase 1 fetch requires a successful Docker preflight result in the same invocation.",
                ]
                phase1["phase_gate_limitations"] = [
                    "Phase 1 execution was skipped because Docker preflight did not pass.",
                ]
            elif docker_spec["path_resolution_status"] != "completed":
                phase1["status"] = "skipped"
                phase1["limitations"] = [
                    "Phase 1 fetch requires completed Docker argv path resolution.",
                ]
                phase1["phase_gate_limitations"] = [
                    "Phase 1 execution was skipped because Docker argv resolution did not complete.",
                ]
            elif not fetch_plan["commands"]:
                phase1["status"] = "skipped"
                phase1["limitations"] = [
                    "Phase 1 fetch had no runnable tool-generated commands after planning.",
                ]
                phase1["phase_gate_limitations"] = []
            else:
                phase1 = run_phase1_fetch(
                    resolved_base_argv=docker_resolution["raw_argv"],
                    fetch_commands=fetch_plan["commands"],
                    materialized=materialized_workspace,
                    timeout_seconds=phase1_timeout_seconds,
                )
                phase1["phase_gate_limitations"] = (
                    []
                    if phase1["status"] == "passed"
                    else ["Phase 1 execution did not complete successfully and remains fail-closed."]
                )
        phase1_5 = run_phase1_rescan(materialized_workspace)
        if (
            phase1["status"] == "not_required"
            and not phase1_5["performed"]
            and phase1_5["artifact_summary"]["artifact_candidate_count"] == 0
            and phase1_5["artifact_summary"]["read_error_count"] == 0
            and not phase1_5["blocked_findings"]
            and not phase1_5["warn_findings"]
            and not phase1_5["unknown_findings"]
            and not phase1_5["dependency_source_risks"]
        ):
            phase1_5["status"] = "not_required"
            phase1_5["limitations"] = [
                "skipped-safe: Phase 1.5 static rescan is not_required because Phase 1 was no_external_fetch_required and no fetched artifacts were available to rescan."
            ]

        approved_phase2_commands = _approved_commands_for_phase(execution_plan, PHASE_2_INSTALL_PROBE)
        approved_phase3_commands = _approved_commands_for_phase(execution_plan, PHASE_3_RUNTIME_PROBE)

        if run_phase2:
            phase2["approved_command_count"] = len(approved_phase2_commands)
            if not docker_spec["selected_image_execution_allowed"]:
                phase2["limitations"] = list(image_policy["limitations"]) or [
                    "Phase 2 install probes require a digest-pinned image reference or a sanctioned local image with a matching full image ID.",
                ]
            elif preflight["status"] != "passed":
                phase2["limitations"] = [
                    "Phase 2 install probes require a successful Docker preflight result in the same invocation.",
                ]
            elif not _phase1_satisfies_dynamic_gate(phase1):
                phase2["limitations"] = [
                    "Phase 2 install probes require a successful Phase 1 dependency fetch or a not_required no_external_fetch_required decision in the same invocation.",
                ]
            elif not _phase1_5_satisfies_dynamic_gate(phase1_5):
                phase2["limitations"] = [
                    "Phase 2 install probes require a completed Phase 1.5 static rescan without blocked findings or a not_required no_artifacts_to_rescan decision.",
                ]
            elif docker_spec["path_resolution_status"] != "completed":
                phase2["limitations"] = [
                    "Phase 2 install probes require completed Docker argv path resolution.",
                ]
            elif materialized_workspace.materialization_status not in {"completed", "partial"}:
                phase2["limitations"] = [
                    "Phase 2 install probes require a disposable workspace that was materialized successfully.",
                ]
            elif not observer["phase2_ready"]:
                phase2["limitations"] = list(observer["limitations"]) + [
                    "Phase 2 install probes remain disabled until the observer stack is fully ready.",
                ]
            elif not approved_phase2_commands:
                phase2["limitations"] = [
                    "Phase 2 install probes require at least one explicitly approved install-script command.",
                ]
            else:
                phase2 = run_dynamic_phase(
                    resolved_base_argv=docker_resolution["raw_argv"],
                    commands=approved_phase2_commands,
                    materialized=materialized_workspace,
                    observer=observer,
                    detected_languages=execution_plan["detected_languages"],
                    timeout_seconds=dynamic_timeout_seconds,
                )
        phase2_dependency_gate_limitation = _phase2_dependency_gate_limitation(phase1, phase1_5)
        if phase2_dependency_gate_limitation is not None and phase2_dependency_gate_limitation not in phase2["limitations"]:
            phase2["limitations"] = [phase2_dependency_gate_limitation, *phase2["limitations"]]

        if run_phase3:
            phase3["approved_command_count"] = len(approved_phase3_commands)
            if not docker_spec["selected_image_execution_allowed"]:
                phase3["limitations"] = list(image_policy["limitations"]) or [
                    "Phase 3 runtime probes require a digest-pinned image reference or a sanctioned local image with a matching full image ID.",
                ]
            elif preflight["status"] != "passed":
                phase3["limitations"] = [
                    "Phase 3 runtime probes require a successful Docker preflight result in the same invocation.",
                ]
            elif not _phase1_satisfies_dynamic_gate(phase1):
                phase3["limitations"] = [
                    "Phase 3 runtime probes require a successful Phase 1 dependency fetch or a not_required no_external_fetch_required decision in the same invocation.",
                ]
            elif not _phase1_5_satisfies_dynamic_gate(phase1_5):
                phase3["limitations"] = [
                    "Phase 3 runtime probes require a completed Phase 1.5 static rescan without blocked findings or a not_required no_artifacts_to_rescan decision.",
                ]
            elif docker_spec["path_resolution_status"] != "completed":
                phase3["limitations"] = [
                    "Phase 3 runtime probes require completed Docker argv path resolution.",
                ]
            elif materialized_workspace.materialization_status not in {"completed", "partial"}:
                phase3["limitations"] = [
                    "Phase 3 runtime probes require a disposable workspace that was materialized successfully.",
                ]
            elif not observer["phase3_ready"]:
                phase3["limitations"] = list(observer["limitations"]) + [
                    "Phase 3 runtime probes remain disabled until the observer stack is fully ready.",
                ]
            elif not approved_phase3_commands:
                phase3["limitations"] = [
                    "Phase 3 runtime probes require at least one explicitly approved runtime command.",
                ]
            else:
                phase3 = run_dynamic_phase(
                    resolved_base_argv=docker_resolution["raw_argv"],
                    commands=approved_phase3_commands,
                    materialized=materialized_workspace,
                    observer=observer,
                    detected_languages=execution_plan["detected_languages"],
                    timeout_seconds=dynamic_timeout_seconds,
                )
    finally:
        materialized_workspace.cleanup()
    workspace_report = materialized_workspace.as_report_dict()
    phase_plan = _build_phase_plan(
        execution_plan,
        detection_limitations=detection_limitations,
        fetch_plan=fetch_plan,
        preflight=preflight,
        strace_smoke=strace_smoke,
        phase1=phase1,
        phase1_5=phase1_5,
        observer=observer,
        phase2=phase2,
        phase3=phase3,
    )
    image_variants = docker_spec["image_variants"]
    docker_image_pinned = docker_spec["selected_image_digest_pinned"]
    docker_image_allowed = docker_spec["selected_image_execution_allowed"]
    fetch_skipped_count = len(fetch_plan["skipped_commands"])
    fetch_command_count = len(fetch_plan["commands"])
    dynamic_observation = _summarize_dynamic_observation(phase2, phase3)

    checks = [
        SandboxCheck(
            id="sandbox.discovery",
            status=STATUS_PASS,
            severity_detail=SEVERITY_DETAIL_PASS,
            confidence="high",
            phase=PHASE_0_STATIC,
            summary="Read-only sandbox planning inputs were collected.",
            evidence={
                "detected_languages": execution_plan["detected_languages"],
                "manifest_paths": execution_plan["manifest_paths"],
                "candidate_command_count": len(execution_plan["commands"]),
                "skipped_command_count": len(execution_plan["skipped_commands"]),
            },
            limitations=tuple(detection_limitations),
        ),
        SandboxCheck(
            id="sandbox.image_policy",
            status=STATUS_PASS if docker_image_allowed else STATUS_WARN,
            severity_detail=SEVERITY_DETAIL_PASS if docker_image_allowed else SEVERITY_DETAIL_WARN_HIGH,
            confidence="high",
            phase=f"{PHASE_1_FETCH}/{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Selected Docker image is digest-pinned for future gated execution."
                if docker_image_pinned
                else "Selected Docker image is sanctioned through a matching local image ID for future gated execution."
                if docker_spec["local_sanctioned"]
                else "Selected Docker image is not digest-pinned or sanctioned; execution remains blocked."
            ),
            evidence={
                "image_reference": docker_spec["selected_image_reference"],
                "image_reference_kind": docker_spec["image_reference_kind"],
                "selected_image_reference": docker_spec["selected_image_reference"],
                "selected_image_digest_pinned": docker_spec["selected_image_digest_pinned"],
                "selected_image_execution_allowed": docker_spec["selected_image_execution_allowed"],
                "expected_image_id": docker_spec["expected_image_id"],
                "actual_image_id": docker_spec["actual_image_id"],
                "image_id_match": docker_spec["image_id_match"],
                "pull_policy": docker_spec["pull_policy"],
                "local_sanctioned": docker_spec["local_sanctioned"],
                "local_sanctioned_limitations": docker_spec["local_sanctioned_limitations"],
                "decision": docker_spec["decision"],
            },
            limitations=(
                tuple(image_policy["limitations"])
                if image_policy["limitations"]
                else ()
            ),
        ),
        SandboxCheck(
            id="sandbox.phase1_fetch_plan",
            status=STATUS_PASS if phase1["status"] == "not_required" else STATUS_WARN,
            severity_detail=(
                SEVERITY_DETAIL_PASS
                if phase1["status"] == "not_required"
                else SEVERITY_DETAIL_WARN_HIGH
                if fetch_skipped_count
                else SEVERITY_DETAIL_WARN_MED
            ),
            confidence="high",
            phase=PHASE_1_FETCH,
            summary=(
                "Phase 1 dependency fetch was not required because build-system.requires was empty and no external dependency source risk was detected."
                if phase1["status"] == "not_required"
                else
                "Phase 1 dependency fetch candidates were generated and executed in normalized argv form."
                if phase1["status"] == "passed" and phase1["performed"]
                else "Phase 1 dependency fetch candidates were generated in normalized argv form only."
            ),
            evidence={
                "fetch_command_count": fetch_command_count,
                "fetch_skipped_count": fetch_skipped_count,
                "execution_enabled": phase1["status"] == "passed" and phase1["performed"],
            },
            limitations=tuple(
                list(fetch_plan["limitations"])
                + [
                    (
                        "Phase 1 dependency fetch commands were executed under gated Docker preflight."
                        if phase1["status"] == "passed" and phase1["performed"]
                        else "Phase 1 dependency fetch was not required in this report."
                        if phase1["status"] == "not_required"
                        else "Phase 1 dependency fetch commands are not executed in this report."
                    ),
                ]
            ),
        ),
        SandboxCheck(
            id="sandbox.docker_preflight",
            status=(
                STATUS_PASS
                if preflight["status"] == "passed"
                else STATUS_BLOCK
                if run_preflight and preflight["status"] == "failed"
                else STATUS_WARN
            ),
            severity_detail=(
                SEVERITY_DETAIL_PASS
                if preflight["status"] == "passed"
                else SEVERITY_DETAIL_BLOCK
                if run_preflight and preflight["status"] == "failed"
                else SEVERITY_DETAIL_WARN_HIGH
            ),
            confidence="high",
            phase=PHASE_1_FETCH,
            summary=(
                "Docker preflight ran only harmless tool-generated commands successfully."
                if preflight["status"] == "passed"
                else "Docker preflight remains gated, skipped, or failed; sandbox execution is not trusted."
            ),
            evidence={
                "requested": preflight["requested"],
                "performed": preflight["performed"],
                "status": preflight["status"],
                "command_count": len(preflight["commands"]),
                "result_count": len(preflight["results"]),
            },
            limitations=tuple(preflight["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.phase1_execution",
            status=(
                STATUS_PASS
                if phase1["status"] in {"passed", "not_required"}
                else STATUS_BLOCK
                if run_phase1 and phase1["status"] == "failed"
                else STATUS_WARN
            ),
            severity_detail=(
                SEVERITY_DETAIL_PASS
                if phase1["status"] in {"passed", "not_required"}
                else SEVERITY_DETAIL_BLOCK
                if run_phase1 and phase1["status"] == "failed"
                else SEVERITY_DETAIL_WARN_HIGH
            ),
            confidence="high",
            phase=PHASE_1_FETCH,
            summary=(
                "Phase 1 fetch was not required because no external dependency retrieval was needed."
                if phase1["status"] == "not_required"
                else
                "Phase 1 fetch executed only tool-generated dependency commands."
                if phase1["status"] == "passed"
                else "Phase 1 fetch remains gated, skipped, or failed; dependency retrieval is not trusted."
            ),
            evidence={
                "requested": phase1["requested"],
                "performed": phase1["performed"],
                "status": phase1["status"],
                "result_count": len(phase1["results"]),
                "network_mode": phase1["network_mode"],
            },
            limitations=tuple(phase1["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.strace_target_wrap_smoke",
            status=(
                STATUS_PASS
                if strace_smoke["status"] == "passed"
                else STATUS_BLOCK
                if strace_smoke["status"] in {"blocked", "failed"}
                else STATUS_WARN
            ),
            severity_detail=(
                SEVERITY_DETAIL_PASS
                if strace_smoke["status"] == "passed"
                else SEVERITY_DETAIL_BLOCK
                if strace_smoke["status"] in {"blocked", "failed"}
                else SEVERITY_DETAIL_WARN_HIGH
            ),
            confidence="high" if strace_smoke["performed"] else "medium",
            phase=PHASE_1B_STRACE_SMOKE,
            summary=(
                "A fixed harmless target process was wrapped with strace and its syscall log was collected."
                if strace_smoke["status"] == "passed"
                else "strace target-wrap smoke remains gated, skipped, or reported observer findings."
            ),
            evidence={
                "requested": strace_smoke["requested"],
                "performed": strace_smoke["performed"],
                "status": strace_smoke["status"],
                "target_argv": strace_smoke.get("target_argv", []),
                "wrapper_argv": strace_smoke.get("wrapper_argv", []),
                "result_count": len(strace_smoke["results"]),
                "observer_summary": (
                    strace_smoke["results"][0]["observer_summary"]
                    if strace_smoke.get("results")
                    else {}
                ),
            },
            limitations=tuple(strace_smoke["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.phase1_5_rescan",
            status=(
                STATUS_BLOCK
                if phase1_5["status"] == "blocked"
                else STATUS_PASS
                if phase1_5["status"] in {"passed", "not_required"}
                else STATUS_WARN
            ),
            severity_detail=(
                SEVERITY_DETAIL_BLOCK
                if phase1_5["status"] == "blocked"
                else SEVERITY_DETAIL_PASS
                if phase1_5["status"] in {"passed", "not_required"}
                else SEVERITY_DETAIL_WARN_HIGH
            ),
            confidence="medium" if phase1_5["performed"] else "low",
            phase=PHASE_1_5_RESCAN,
            summary=(
                "Phase 1.5 static rescan found high-risk fetched artifacts before later execution phases."
                if phase1_5["status"] == "blocked"
                else "Phase 1.5 static rescan completed without suspicious fetched artifact findings."
                if phase1_5["status"] == "passed"
                else "Phase 1.5 static rescan was not required because there were no fetched artifacts to rescan."
                if phase1_5["status"] == "not_required"
                else "Phase 1.5 static rescan found suspicious artifacts or could not complete with confidence."
            ),
            evidence={
                "performed": phase1_5["performed"],
                "status": phase1_5["status"],
                "artifact_summary": phase1_5["artifact_summary"],
                "finding_summary": phase1_5.get(
                    "finding_summary",
                    {
                        "blocked_count": len(
                            [item for item in phase1_5.get("findings", []) if item.get("severity") == "block"]
                        ),
                        "warn_count": len(
                            [
                                item
                                for item in phase1_5.get("findings", [])
                                if item.get("severity") == "warn"
                                and item.get("classification") != "unknown_requires_review"
                            ]
                        ),
                        "info_count": len(
                            [item for item in phase1_5.get("findings", []) if item.get("severity") == "info"]
                        ),
                        "unknown_count": len(
                            [
                                item
                                for item in phase1_5.get("findings", [])
                                if item.get("classification") == "unknown_requires_review"
                            ]
                        ),
                    },
                ),
                "finding_count": len(phase1_5["findings"]),
            },
            limitations=tuple(phase1_5["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.observer_availability",
            status=STATUS_WARN,
            severity_detail=SEVERITY_DETAIL_WARN_HIGH if not observer.get("pass_possible") else SEVERITY_DETAIL_WARN_MED,
            confidence="high",
            phase=f"{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Dynamic probes can use syscall/process tracing together with runtime hooks, but residual blind spots remain."
                if observer.get("pass_possible")
                else "Dynamic probes can use runtime hooks, but syscall/process tracing is unavailable so results remain degraded."
                if observer.get("phase2_ready") or observer.get("phase3_ready")
                else "Observer planning is present, but no supported runtime-hook coverage is ready for dynamic phases."
            ),
            evidence={
                "mode": observer["mode"],
                "status": observer["status"],
                "languages": observer["languages"],
                "syscall_observer_available": observer["syscall_observer"]["available"],
                "runtime_hook_count": len(observer["runtime_hooks"]),
                "runtime_hook_active_languages": observer.get("runtime_hook_active_languages", []),
                "pass_possible": observer.get("pass_possible", False),
                "phase2_ready": observer["phase2_ready"],
                "phase3_ready": observer["phase3_ready"],
            },
            limitations=tuple(observer["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.phase2_execution",
            status=(
                STATUS_BLOCK
                if phase2["status"] in {"failed", "blocked"}
                else STATUS_PASS
                if phase2["status"] == "passed"
                else STATUS_WARN
            ),
            severity_detail=(
                SEVERITY_DETAIL_BLOCK
                if phase2["status"] in {"failed", "blocked"}
                else SEVERITY_DETAIL_PASS
                if phase2["status"] == "passed"
                else SEVERITY_DETAIL_WARN_HIGH
            ),
            confidence="medium" if phase2["performed"] else "high",
            phase=PHASE_2_INSTALL_PROBE,
            summary=(
                "Approved install-script probes executed under sandbox gates."
                if phase2["status"] == "passed"
                else "Phase 2 install-script probes remain gated, skipped, or reported observer findings."
            ),
            evidence={
                "requested": phase2["requested"],
                "performed": phase2["performed"],
                "status": phase2["status"],
                "approved_command_count": phase2["approved_command_count"],
                "result_count": len(phase2["results"]),
                "network_mode": phase2["network_mode"],
            },
            limitations=tuple(phase2["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.phase3_execution",
            status=(
                STATUS_BLOCK
                if phase3["status"] in {"failed", "blocked"}
                else STATUS_PASS
                if phase3["status"] == "passed"
                else STATUS_WARN
            ),
            severity_detail=(
                SEVERITY_DETAIL_BLOCK
                if phase3["status"] in {"failed", "blocked"}
                else SEVERITY_DETAIL_PASS
                if phase3["status"] == "passed"
                else SEVERITY_DETAIL_WARN_HIGH
            ),
            confidence="medium" if phase3["performed"] else "high",
            phase=PHASE_3_RUNTIME_PROBE,
            summary=(
                "Approved runtime probes executed under sandbox gates."
                if phase3["status"] == "passed"
                else "Phase 3 runtime probes remain gated, skipped, or reported observer findings."
            ),
            evidence={
                "requested": phase3["requested"],
                "performed": phase3["performed"],
                "status": phase3["status"],
                "approved_command_count": phase3["approved_command_count"],
                "result_count": len(phase3["results"]),
                "network_mode": phase3["network_mode"],
            },
            limitations=tuple(phase3["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.dynamic_external_communication",
            status=(
                STATUS_BLOCK
                if dynamic_observation["network_event_count"]
                else STATUS_PASS
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else STATUS_WARN
            ),
            severity_detail=(
                SEVERITY_DETAIL_BLOCK
                if dynamic_observation["network_event_count"]
                else SEVERITY_DETAIL_PASS
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else SEVERITY_DETAIL_WARN_HIGH
            ),
            confidence="medium" if dynamic_observation["performed"] else "low",
            phase=f"{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Observer recorded network activity during a dynamic probe."
                if dynamic_observation["network_event_count"]
                else "No network activity was observed during executed dynamic probes."
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else "Dynamic network observation is incomplete, skipped, or degraded and cannot prove PASS."
            ),
            evidence={
                **_build_dynamic_check_evidence(
                    dynamic_observation=dynamic_observation,
                    observer=observer,
                    phase2=phase2,
                    phase3=phase3,
                ),
                "network_event_count": dynamic_observation["network_event_count"],
            },
            limitations=tuple(observer["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.dynamic_secret_access",
            status=(
                STATUS_BLOCK
                if dynamic_observation["secret_event_count"]
                else STATUS_PASS
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else STATUS_WARN
            ),
            severity_detail=(
                SEVERITY_DETAIL_BLOCK
                if dynamic_observation["secret_event_count"]
                else SEVERITY_DETAIL_PASS
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else SEVERITY_DETAIL_WARN_HIGH
            ),
            confidence="medium" if dynamic_observation["performed"] else "low",
            phase=f"{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Observer recorded honeypot file or secret-like environment access during a dynamic probe."
                if dynamic_observation["secret_event_count"]
                else "No honeypot file or secret-like environment access was observed during executed dynamic probes."
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else "Dynamic secret-access observation is incomplete, skipped, or degraded and cannot prove PASS."
            ),
            evidence={
                **_build_dynamic_check_evidence(
                    dynamic_observation=dynamic_observation,
                    observer=observer,
                    phase2=phase2,
                    phase3=phase3,
                ),
                "secret_event_count": dynamic_observation["secret_event_count"],
            },
            limitations=tuple(observer["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.dynamic_env_sweep",
            status=(
                STATUS_WARN
                if dynamic_observation["env_sweep_count"] or not (dynamic_observation["performed"] and dynamic_observation["pass_possible"])
                else STATUS_PASS
            ),
            severity_detail=(
                SEVERITY_DETAIL_WARN_HIGH
                if dynamic_observation["env_sweep_count"] or not (dynamic_observation["performed"] and dynamic_observation["pass_possible"])
                else SEVERITY_DETAIL_PASS
            ),
            confidence="medium" if dynamic_observation["performed"] else "low",
            phase=f"{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Observer recorded environment enumeration during a dynamic probe."
                if dynamic_observation["env_sweep_count"]
                else "No environment enumeration was observed during executed dynamic probes."
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else "Dynamic environment-sweep observation is incomplete, skipped, or degraded and cannot prove PASS."
            ),
            evidence={
                **_build_dynamic_check_evidence(
                    dynamic_observation=dynamic_observation,
                    observer=observer,
                    phase2=phase2,
                    phase3=phase3,
                ),
                "env_sweep_count": dynamic_observation["env_sweep_count"],
            },
            limitations=tuple(observer["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.dynamic_process_spawn",
            status=(
                STATUS_WARN
                if dynamic_observation["process_event_count"] or not (dynamic_observation["performed"] and dynamic_observation["pass_possible"])
                else STATUS_PASS
            ),
            severity_detail=(
                SEVERITY_DETAIL_WARN_HIGH
                if dynamic_observation["process_event_count"]
                else SEVERITY_DETAIL_WARN_MED
                if not (dynamic_observation["performed"] and dynamic_observation["pass_possible"])
                else SEVERITY_DETAIL_PASS
            ),
            confidence="medium" if dynamic_observation["performed"] else "low",
            phase=f"{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Observer recorded nested or unexpected process creation during a dynamic probe."
                if dynamic_observation["process_event_count"]
                else "No nested process creation was observed during executed dynamic probes."
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else "Dynamic process-spawn observation is incomplete, skipped, or degraded and cannot prove PASS."
            ),
            evidence={
                **_build_dynamic_check_evidence(
                    dynamic_observation=dynamic_observation,
                    observer=observer,
                    phase2=phase2,
                    phase3=phase3,
                ),
                "process_event_count": dynamic_observation["process_event_count"],
            },
            limitations=tuple(observer["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.dynamic_filesystem_delete",
            status=(
                STATUS_BLOCK
                if dynamic_observation["delete_outside_writable_count"]
                else STATUS_WARN
                if dynamic_observation["delete_inside_writable_count"] or not (dynamic_observation["performed"] and dynamic_observation["pass_possible"])
                else STATUS_PASS
            ),
            severity_detail=(
                SEVERITY_DETAIL_BLOCK
                if dynamic_observation["delete_outside_writable_count"]
                else SEVERITY_DETAIL_WARN_HIGH
                if dynamic_observation["delete_inside_writable_count"] or not (dynamic_observation["performed"] and dynamic_observation["pass_possible"])
                else SEVERITY_DETAIL_PASS
            ),
            confidence="medium" if dynamic_observation["performed"] else "low",
            phase=f"{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Observer recorded destructive filesystem access outside sandbox writable paths."
                if dynamic_observation["delete_outside_writable_count"]
                else "Observer recorded destructive filesystem access inside sandbox writable paths."
                if dynamic_observation["delete_inside_writable_count"]
                else "No destructive filesystem activity was observed during executed dynamic probes."
                if dynamic_observation["performed"] and dynamic_observation["pass_possible"]
                else "Dynamic filesystem observation is incomplete, skipped, or degraded and cannot prove PASS."
            ),
            evidence={
                **_build_dynamic_check_evidence(
                    dynamic_observation=dynamic_observation,
                    observer=observer,
                    phase2=phase2,
                    phase3=phase3,
                ),
                "delete_inside_writable_count": dynamic_observation["delete_inside_writable_count"],
                "delete_outside_writable_count": dynamic_observation["delete_outside_writable_count"],
            },
            limitations=tuple(observer["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.disposable_workspace",
            status=(
                STATUS_BLOCK
                if workspace_report["cleanup_status"] == "failed" or workspace_report["materialization_status"] == "failed"
                else STATUS_WARN
                if workspace_report["copy_summary"]["unsafe_symlink_count"] or workspace_report["copy_summary"]["copy_error_count"]
                else STATUS_PASS
            ),
            severity_detail=(
                SEVERITY_DETAIL_BLOCK
                if workspace_report["cleanup_status"] == "failed" or workspace_report["materialization_status"] == "failed"
                else SEVERITY_DETAIL_WARN_HIGH
                if workspace_report["copy_summary"]["unsafe_symlink_count"] or workspace_report["copy_summary"]["copy_error_count"]
                else SEVERITY_DETAIL_PASS
            ),
            confidence="high",
            phase=f"{PHASE_1_FETCH}/{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Disposable workspace materialization and cleanup completed without copy errors."
                if workspace_report["cleanup_status"] == "completed"
                and workspace_report["materialization_status"] == "completed"
                and not workspace_report["copy_summary"]["unsafe_symlink_count"]
                and not workspace_report["copy_summary"]["copy_error_count"]
                else "Disposable workspace materialization completed with safety limitations or cleanup failures."
            ),
            evidence={
                "path_handles": workspace_report["path_handles"],
                "materialization_status": workspace_report["materialization_status"],
                "cleanup_status": workspace_report["cleanup_status"],
                "copy_summary": workspace_report["copy_summary"],
                "execution_enabled": workspace_report["execution_enabled"],
            },
            limitations=tuple(workspace_report["limitations"]),
        ),
        SandboxCheck(
            id="sandbox.docker_spec",
            status=STATUS_WARN,
            severity_detail=SEVERITY_DETAIL_WARN_HIGH if not docker_image_allowed else SEVERITY_DETAIL_WARN_LOW,
            confidence="high",
            phase=f"{PHASE_1_FETCH}/{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary="Docker isolation argv/spec was generated in dry-run form only.",
            evidence={
                "argv_count": len(docker_spec["argv"]),
                "resolved_argv_count": len(docker_spec["resolved_argv_redacted"]),
                "pull_policy": docker_spec["pull_policy"],
                "path_resolution_status": docker_spec["path_resolution_status"],
                "docker_socket_mounted": docker_spec["docker_socket_mounted"],
                "image_variants": image_variants,
            },
            limitations=tuple(
                [
                    "Repo-derived dynamic Docker execution remains gated and is disabled by default.",
                    "Docker argv generation remains dry-run unless explicitly gated.",
                ]
                + docker_resolution_limitations
                + (
                    list(image_policy["limitations"])
                    if image_policy["limitations"]
                    else []
                )
            ),
        ),
        SandboxCheck(
            id="sandbox.approval_gate",
            status=approval_status,
            severity_detail=SEVERITY_DETAIL_BLOCK if approval_status == STATUS_BLOCK else SEVERITY_DETAIL_WARN_LOW if approval_status == STATUS_WARN else SEVERITY_DETAIL_PASS,
            confidence="high",
            phase=f"{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary=(
                "Approval data is valid for the currently detected command candidates."
                if approval_status == STATUS_PASS
                else "Approval coverage is incomplete or invalid; commands will not execute."
            ),
            evidence={
                "approval_provided": execution_plan["approval"]["provided"],
                "approval_status": execution_plan["approval"]["status"],
                "approval_path_handle": execution_plan["approval"]["path_handle"],
                "approval_scope": execution_plan["approval"]["approval_scope"],
                "matched_command_count": execution_plan["approval"]["matched_command_count"],
                "total_command_count": execution_plan["approval"]["total_command_count"],
                "docker_image": execution_plan["approval"]["docker_image"],
                "expected_image_id": execution_plan["approval"]["expected_image_id"],
                "local_sanctioned_image": execution_plan["approval"]["local_sanctioned_image"],
                "network_policy": execution_plan["approval"]["network_policy"],
                "mismatch_reasons": execution_plan["approval"]["mismatch_reasons"],
            },
            limitations=tuple(approval_limitations),
        ),
        SandboxCheck(
            id="sandbox.dynamic_execution",
            status=STATUS_WARN,
            severity_detail=SEVERITY_DETAIL_WARN_HIGH,
            confidence="low",
            phase=f"{PHASE_2_INSTALL_PROBE}/{PHASE_3_RUNTIME_PROBE}",
            summary="Sandbox remains approval-gated; only explicitly gated probes may run when all prerequisites are satisfied.",
            evidence={
                "mode": "plan_only",
                "observation_mode": observer["mode"],
                "dynamic_execution_performed": phase2["performed"] or phase3["performed"],
                "docker_preflight_status": preflight["status"],
                "phase1_status": phase1["status"],
                "phase1_5_status": phase1_5["status"],
                "phase2_status": phase2["status"],
                "phase3_status": phase3["status"],
                "observer_status": observer["status"],
                "dynamic_observation_summary": dynamic_observation,
                "dynamic_observation": _build_dynamic_check_evidence(
                    dynamic_observation=dynamic_observation,
                    observer=observer,
                    phase2=phase2,
                    phase3=phase3,
                ),
            },
            limitations=(
                "Repo-derived Docker execution remains gated by approval, observer readiness, and prior phase checks.",
                *observer["limitations"],
                *(() if phase2["requested"] else ("Install script execution was not requested in this report.",)),
                *(() if phase3["requested"] else ("Runtime smoke execution was not requested in this report.",)),
            ),
        ),
    ]
    report = _build_report(
        root,
        checks,
        execution_plan,
        phase_plan=phase_plan,
        docker_spec=docker_spec,
        workspace_plan=workspace_report,
        preflight=preflight,
        strace_smoke=strace_smoke,
        phase1=phase1,
        phase1_5=phase1_5,
        observer=observer,
        phase2=phase2,
        phase3=phase3,
    )
    return materialized_workspace.redact_report_value(report)
