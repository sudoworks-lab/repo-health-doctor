"""Closed, redacted observer-evidence contract for future sandbox runners.

This module only validates supplied JSON-compatible mappings.  It never
starts an observer, parses raw logs, accesses Docker, or executes a command.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .workspace import GENERIC_SECRET_PATTERNS


NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE = "sandbox_normalized_observer_evidence"
REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE_VALIDATION = "sandbox_normalized_observer_evidence_validation"

_EVIDENCE_FIELDS = {"schema_version", "report_kind", "evidence_id", "source", "command", "execution", "counts", "flags", "summaries", "redaction"}
_SOURCE_FIELDS = {"observer_mode", "strace_available", "strace_log_present", "strace_parse_success", "runtime_hook_available", "runtime_hook_active", "runtime_hook_parse_success", "observer_degraded", "degraded_reasons"}
_COMMAND_FIELDS = {"phase", "kind", "cwd", "argv_fingerprint", "shell", "network_policy"}
_EXECUTION_FIELDS = {"return_code", "timeout", "duration_ms", "completed"}
_COUNT_FIELDS = {"process_event_count", "unexpected_exec_count", "subprocess_event_count", "network_event_count", "file_write_event_count", "outside_allowed_write_count", "denied_read_count", "docker_socket_access_count", "host_home_access_count", "secret_event_count", "outside_writable_delete_count", "strace_parse_error_count", "runtime_hook_parse_error_count"}
_FLAG_FIELDS = {"evidence_complete", "raw_logs_included", "stdout_included", "stderr_included", "host_paths_redacted", "secrets_redacted"}
_SUMMARY_FIELDS = {"process_summary", "file_summary", "network_summary", "secret_summary", "limitations", "residual_risks"}
_REDACTION_FIELDS = {"status", "raw_host_path_present", "raw_secret_like_value_present"}
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOME_PATH = re.compile(r"(?:^|[\s\"'])/(?:home|Users)/")


def _exact_mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} schema mismatch or unknown field")
    return value


def _safe_labels(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value) or not all(isinstance(item, str) and _LABEL.fullmatch(item) for item in value):
        raise ValueError(f"{label} is invalid")
    return value


def _contains_unsafe_value(value: Any) -> bool:
    try:
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return True
    return bool(_HOME_PATH.search(rendered)) or any(pattern.search(rendered) for pattern in GENERIC_SECRET_PATTERNS)


def validate_normalized_observer_evidence(evidence: Mapping[str, Any]) -> None:
    """Validate a redacted normalized observation without deriving a verdict."""
    if _contains_unsafe_value(evidence):
        raise ValueError("observer evidence contains a raw host path or secret-like value")
    document = _exact_mapping(evidence, _EVIDENCE_FIELDS, "normalized observer evidence")
    if document.get("schema_version") != NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION:
        raise ValueError("normalized observer evidence schema_version is unsupported")
    if document.get("report_kind") != REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE:
        raise ValueError("normalized observer evidence report_kind is unsupported")
    if not isinstance(document.get("evidence_id"), str) or not _LABEL.fullmatch(document["evidence_id"]):
        raise ValueError("evidence_id is invalid")

    source = _exact_mapping(document.get("source"), _SOURCE_FIELDS, "observer source")
    if source.get("observer_mode") not in {"strace_runtime_hook", "strace_only", "runtime_hook_only", "none"}:
        raise ValueError("observer_mode is invalid")
    for field in _SOURCE_FIELDS - {"observer_mode", "degraded_reasons"}:
        if not isinstance(source.get(field), bool):
            raise ValueError(f"observer source {field} is invalid")
    reasons = _safe_labels(source.get("degraded_reasons"), "degraded_reasons")
    if source["observer_degraded"] != bool(reasons):
        raise ValueError("observer_degraded and degraded_reasons are inconsistent")

    command = _exact_mapping(document.get("command"), _COMMAND_FIELDS, "observer command")
    if command.get("phase") not in {"phase2_install_probe", "phase3_runtime_probe"}:
        raise ValueError("observer command phase is invalid")
    if not isinstance(command.get("kind"), str) or not _LABEL.fullmatch(command["kind"]):
        raise ValueError("observer command kind is invalid")
    if not isinstance(command.get("cwd"), str) or not (command["cwd"] == "/workspace" or command["cwd"].startswith("/workspace/")):
        raise ValueError("observer command cwd is invalid")
    if not isinstance(command.get("argv_fingerprint"), str) or not _SHA256.fullmatch(command["argv_fingerprint"]):
        raise ValueError("observer command argv_fingerprint is invalid")
    if command.get("shell") is not False or command.get("network_policy") != "none":
        raise ValueError("observer command attempts to relax shell or network boundary")

    execution = _exact_mapping(document.get("execution"), _EXECUTION_FIELDS, "observer execution")
    if execution.get("return_code") is not None and not isinstance(execution.get("return_code"), int):
        raise ValueError("observer execution return_code is invalid")
    if not isinstance(execution.get("timeout"), bool) or not isinstance(execution.get("completed"), bool) or not isinstance(execution.get("duration_ms"), int) or execution["duration_ms"] < 0:
        raise ValueError("observer execution fields are invalid")

    counts = _exact_mapping(document.get("counts"), _COUNT_FIELDS, "observer counts")
    if any(not isinstance(counts.get(field), int) or counts[field] < 0 for field in _COUNT_FIELDS):
        raise ValueError("observer event count is invalid")

    flags = _exact_mapping(document.get("flags"), _FLAG_FIELDS, "observer flags")
    if not isinstance(flags.get("evidence_complete"), bool) or flags.get("raw_logs_included") is not False or flags.get("stdout_included") is not False or flags.get("stderr_included") is not False or flags.get("host_paths_redacted") is not True or flags.get("secrets_redacted") is not True:
        raise ValueError("observer flags are invalid or unsafe")

    summaries = _exact_mapping(document.get("summaries"), _SUMMARY_FIELDS, "observer summaries")
    for field in _SUMMARY_FIELDS:
        _safe_labels(summaries.get(field), f"observer summary {field}")

    redaction = _exact_mapping(document.get("redaction"), _REDACTION_FIELDS, "observer redaction")
    if redaction.get("status") != "redacted" or redaction.get("raw_host_path_present") is not False or redaction.get("raw_secret_like_value_present") is not False:
        raise ValueError("observer redaction is invalid or unsafe")


def normalized_observer_evidence_pass_blockers(evidence: Mapping[str, Any], *, runtime_hook_required: bool = True) -> list[str]:
    """Return policy-use blockers after shape validation, without evaluating policy."""
    validate_normalized_observer_evidence(evidence)
    source = evidence["source"]
    counts = evidence["counts"]
    flags = evidence["flags"]
    execution = evidence["execution"]
    blockers: list[str] = []
    if not source["strace_available"]:
        blockers.append("strace_unavailable")
    if not source["strace_log_present"]:
        blockers.append("strace_log_missing")
    if not source["strace_parse_success"]:
        blockers.append("strace_parse_failure")
    if runtime_hook_required and not source["runtime_hook_available"]:
        blockers.append("runtime_hook_unavailable")
    if runtime_hook_required and not source["runtime_hook_active"]:
        blockers.append("runtime_hook_inactive")
    if runtime_hook_required and not source["runtime_hook_parse_success"]:
        blockers.append("runtime_hook_parse_failure")
    if source["observer_degraded"]:
        blockers.append("observer_degraded")
    if not flags["evidence_complete"]:
        blockers.append("evidence_incomplete")
    if counts["strace_parse_error_count"]:
        blockers.append("strace_parse_errors")
    if counts["runtime_hook_parse_error_count"]:
        blockers.append("runtime_hook_parse_errors")
    if execution["timeout"]:
        blockers.append("execution_timeout")
    return blockers


def normalized_observer_evidence_to_behavior_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Map closed normalized evidence into the evaluator's compatibility shape.

    The normalized document remains canonical.  This map is deliberately lossy:
    raw observer data and binary/path values cannot enter policy evaluation.
    """
    validate_normalized_observer_evidence(evidence)
    source = evidence["source"]
    counts = evidence["counts"]
    execution = evidence["execution"]
    return {
        "observer_available": source["strace_available"],
        "runtime_hook_available": source["runtime_hook_available"],
        "runtime_hook_active": source["runtime_hook_active"],
        "runtime_hook_parse_succeeded": source["runtime_hook_parse_success"],
        "observer_degraded": source["observer_degraded"],
        "strace_log_present": source["strace_log_present"],
        "strace_parse_succeeded": source["strace_parse_success"],
        "evidence_complete": evidence["flags"]["evidence_complete"],
        "network_event_count": counts["network_event_count"],
        "write_outside_allowed_prefix_count": counts["outside_allowed_write_count"],
        "docker_socket_access_count": counts["docker_socket_access_count"],
        "host_home_access_count": counts["host_home_access_count"],
        "denied_read_access_count": counts["denied_read_count"],
        "secret_event_count": counts["secret_event_count"],
        # Canonical evidence deliberately carries counts, not executable names.
        # Stable synthetic labels preserve the evaluator's conservative
        # default-deny behavior without leaking a raw command or path.
        "execve_binaries": ["observer-unexpected-exec"] * counts["unexpected_exec_count"],
        "subprocess_binaries": ["observer-subprocess"] * counts["subprocess_event_count"],
        "outside_writable_delete_count": counts["outside_writable_delete_count"],
        "strace_parse_error_count": counts["strace_parse_error_count"],
        "runtime_hook_parse_error_count": counts["runtime_hook_parse_error_count"],
        "timed_out": execution["timeout"],
        "return_code": execution["return_code"],
    }


def validate_normalized_observer_evidence_report(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Return a redacted validation report; never capture or execute anything."""
    try:
        validate_normalized_observer_evidence(evidence)
    except (TypeError, ValueError):
        return {
            "schema_version": NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION,
            "report_kind": REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE_VALIDATION,
            "evidence_schema_version": "unvalidated",
            "verdict": "block",
            "valid": False,
            "pass_eligible": False,
            "pass_blockers": ["invalid_or_unsupported_normalized_observer_evidence"],
            "blockers": ["invalid_or_unsupported_normalized_observer_evidence"],
            "warnings": [],
            "limitations": ["Static validation failed closed; no observer, Docker, runner, or live command was started."],
            "residual_risks": ["unknown_or_unsupported_observer_evidence_input"],
            "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
            "runner_connected": False,
            "observer_capture_started": False,
        }
    blockers = normalized_observer_evidence_pass_blockers(evidence)
    return {
        "schema_version": NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE_VALIDATION,
        "evidence_schema_version": evidence["schema_version"],
        "verdict": "pass",
        "valid": True,
        "pass_eligible": not blockers,
        "pass_blockers": blockers,
        "blockers": [],
        "warnings": ["schema_validation_is_not_command_safety_verdict"],
        "limitations": ["This validates a supplied normalized report shape only; it does not execute a runner, Docker, strace, runtime hook, or live command."],
        "residual_risks": ["behavior_policy_verdict_remains_required", "normalized_evidence_is_not_a_safety_guarantee"],
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        "runner_connected": False,
        "observer_capture_started": False,
    }
