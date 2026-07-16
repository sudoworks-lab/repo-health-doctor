"""Normalize sandbox-run reports into bounded decision evidence.

The normalizer reads a completed sandbox-run report only.  It keeps stable
identifiers and bounded status summaries, never copies command output or host
paths, and does not evaluate or authorize a gate decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


SANDBOX_RUN_EVIDENCE_SCHEMA_VERSION = "0.1-draft"
SANDBOX_RUN_EVIDENCE_REPORT_KIND = "sandbox_normalized_evidence"
NORMALIZED_SANDBOX_RUN_SCHEMA_VERSION = SANDBOX_RUN_EVIDENCE_SCHEMA_VERSION
REPORT_KIND_NORMALIZED_SANDBOX_RUN_EVIDENCE = SANDBOX_RUN_EVIDENCE_REPORT_KIND

INFORMATIONAL_SUCCESS_NOTE = "successful_execution_is_not_safety"
DECISION_POLICY_BLOCKED = "execution_policy_blocked"
DECISION_BINDING_MISMATCH = "subject_binding_mismatch"
DECISION_TIMEOUT = "execution_timeout"
DECISION_CLEANUP_FAILED = "workspace_cleanup_failed"
DECISION_OBSERVER_DEGRADED = "observer_degraded"
DECISION_NOT_REAL = "not_real_execution_evidence"
DECISION_INVALID = "sandbox_evidence_invalid"
DECISION_STALE = "sandbox_evidence_stale"
DECISION_TRUNCATED = "sandbox_evidence_truncated"
DECISION_OVER_BUDGET = "sandbox_evidence_over_budget"

_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UNSAFE_PATH = re.compile(r"(?:^|[\\/])(?:home|Users)(?:[\\/])|^[A-Za-z]:[\\]")
_SAFE_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")


def sandbox_run_report_fingerprint(report: Mapping[str, Any]) -> str:
    """Return a deterministic fingerprint for the supplied source report."""

    payload = dict(report)
    payload.pop("report_fingerprint", None)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def normalize_sandbox_run_evidence(report: object) -> dict[str, Any]:
    """Normalize one sandbox-run report without retaining untrusted content.

    The returned mapping is suitable for later gate integration.  A malformed
    source report is represented as bounded invalid evidence instead of being
    silently treated as a successful run.
    """

    source = report if isinstance(report, Mapping) else {}
    invalid = not isinstance(report, Mapping)
    if source.get("schema_version") != SANDBOX_RUN_EVIDENCE_SCHEMA_VERSION:
        invalid = True
    if source.get("report_kind") not in {"sandbox_run", "sandbox_run_report"}:
        invalid = True

    fingerprint = _source_fingerprint(source)
    if source.get("report_fingerprint") is not None:
        claimed = source.get("report_fingerprint")
        if not isinstance(claimed, str) or not _FINGERPRINT.fullmatch(claimed) or claimed != fingerprint:
            invalid = True

    run = _mapping(source.get("run"))
    target = _mapping(source.get("target"))
    gate = _mapping(source.get("gate"))
    authorization = _mapping(source.get("authorization"))
    docker = _mapping(source.get("docker"))
    result = _mapping(source.get("result"))
    workspace = _mapping(source.get("disposable_workspace"))
    diff = _mapping(source.get("workspace_diff"))

    run_id = _safe_label(run.get("run_id"))
    generated_at = _safe_timestamp(run.get("ended_at")) or _safe_timestamp(run.get("started_at"))
    if run_id is None or generated_at is None:
        invalid = True

    policy_blocked = _is_true(source.get("policy_blocked")) or _is_true(gate.get("policy_blocked"))
    timed_out = _is_true(result.get("timed_out")) or result.get("status") == "timed_out"
    cleanup_status = _status(workspace.get("cleanup"), default="not_recorded")
    cleanup_failed = cleanup_status == "failed" or result.get("status") == "cleanup_uncertain"
    observer_status, observer_degraded = _observer_status(source)
    binding_status, binding_mismatch = _binding_status(authorization, source)
    runner_kind = _runner_kind(run, docker)
    dry_run = _is_true(run.get("dry_run")) or result.get("status") == "dry_run"
    fake_runner = runner_kind == "fake"
    command_started = _is_true(source.get("command_started"))
    exit_code = result.get("exit_code")
    if not isinstance(exit_code, int) and isinstance(source.get("command_exit_code"), int):
        exit_code = source.get("command_exit_code")
    execution_category = _execution_category(
        result_status=result.get("status"),
        policy_blocked=policy_blocked,
        timed_out=timed_out,
        cleanup_failed=cleanup_failed,
        observer_degraded=observer_degraded,
        dry_run=dry_run,
        command_started=command_started,
        exit_code=exit_code,
    )

    decision_signals: list[str] = []
    if policy_blocked:
        decision_signals.append(DECISION_POLICY_BLOCKED)
    if binding_mismatch:
        decision_signals.append(DECISION_BINDING_MISMATCH)
    if timed_out:
        decision_signals.append(DECISION_TIMEOUT)
    if cleanup_failed:
        decision_signals.append(DECISION_CLEANUP_FAILED)
    if observer_degraded:
        decision_signals.append(DECISION_OBSERVER_DEGRADED)
    if fake_runner or dry_run:
        decision_signals.append(DECISION_NOT_REAL)
    if invalid:
        decision_signals.append(DECISION_INVALID)
    if _is_true(source.get("stale")):
        decision_signals.append(DECISION_STALE)
    if _is_true(source.get("truncated")) or _is_true(diff.get("truncated")):
        decision_signals.append(DECISION_TRUNCATED)

    subject = _subject(source, target, gate)
    policy_version = _policy_version(source, gate)
    gate_fingerprint = _first_fingerprint(
        gate.get("decision_fingerprint"),
        gate.get("fingerprint"),
        source.get("gate_decision_fingerprint"),
    )
    normalized = {
        "schema_version": SANDBOX_RUN_EVIDENCE_SCHEMA_VERSION,
        "report_kind": SANDBOX_RUN_EVIDENCE_REPORT_KIND,
        "run_id": run_id,
        "report_fingerprint": fingerprint,
        "subject": subject,
        "policy": {
            "version": policy_version,
            "blocked": policy_blocked,
        },
        "gate": {
            "decision_fingerprint": gate_fingerprint,
        },
        "generated_at": generated_at,
        "runner": {
            "kind": runner_kind,
            "real_execution": runner_kind == "docker" and not dry_run and bool(docker.get("docker_invoked")),
        },
        "execution": {
            "command_started": command_started,
            "exit_category": execution_category,
            "exit_code": exit_code if isinstance(exit_code, int) else None,
            "timed_out": timed_out,
        },
        "cleanup": {
            "status": cleanup_status,
        },
        "observer": {
            "status": observer_status,
        },
        "binding": {
            "status": binding_status,
            "mismatch": binding_mismatch,
        },
        "sandbox": {
            "seccomp_profile": _safe_label(_mapping(source.get("seccomp")).get("profile")),
            "image": _safe_image(docker.get("image")),
        },
        "workspace_diff": {
            "created_count": _non_negative_int(diff.get("created_count")),
            "modified_count": _non_negative_int(diff.get("modified_count")),
            "deleted_count": _non_negative_int(diff.get("deleted_count")),
        },
        "informational_notes": [INFORMATIONAL_SUCCESS_NOTE],
        "decision_signals": decision_signals,
        "limitations": [
            "sandbox_run_report_is_bounded_evidence",
            "execution_result_is_not_safety_proof",
        ],
    }
    return normalized


def _source_fingerprint(source: Mapping[str, Any]) -> str | None:
    try:
        return sandbox_run_report_fingerprint(source)
    except (TypeError, ValueError):
        return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _is_true(value: Any) -> bool:
    return value is True


def _safe_label(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 128 or _UNSAFE_PATH.search(value):
        return None
    if value.startswith("<") and value.endswith(">"):
        return value
    return value if _SAFE_LABEL.fullmatch(value) else None


def _safe_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    return value if re.fullmatch(r"[0-9T:+.Z-]+", value) else None


def _safe_image(value: Any) -> str | None:
    if not isinstance(value, str) or _UNSAFE_PATH.search(value) or not _SAFE_IMAGE.fullmatch(value):
        return None
    return value


def _first_fingerprint(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and _FINGERPRINT.fullmatch(value):
            return value
    return None


def _object_id(value: Any) -> str | None:
    return value if isinstance(value, str) and _OBJECT_ID.fullmatch(value) else None


def _subject(source: Mapping[str, Any], target: Mapping[str, Any], gate: Mapping[str, Any]) -> dict[str, Any]:
    candidates = (
        _mapping(source.get("subject")),
        _mapping(gate.get("subject")),
        target,
    )
    candidate = next((item for item in candidates if item), {})
    repo = _safe_label(candidate.get("repo")) or _safe_label(candidate.get("repo_identity"))
    if repo is None:
        repo = _safe_label(target.get("identity")) or "<repo>"
    return {
        "repo": repo,
        "commit": _object_id(candidate.get("commit")),
        "tree_hash": _object_id(candidate.get("tree_hash")) or _object_id(candidate.get("tree")),
        "binding_kind": _safe_label(candidate.get("binding_kind")) or "unbound",
    }


def _policy_version(source: Mapping[str, Any], gate: Mapping[str, Any]) -> str | None:
    policy = _mapping(source.get("policy"))
    for value in (policy.get("version"), policy.get("policy_version"), gate.get("policy_version")):
        if isinstance(value, str) and _SAFE_LABEL.fullmatch(value):
            return value
    return None


def _runner_kind(run: Mapping[str, Any], docker: Mapping[str, Any]) -> str:
    if _is_true(run.get("dry_run")):
        return "dry_run"
    runner = docker.get("runner")
    if isinstance(runner, str) and runner.startswith("fake"):
        return "fake"
    if isinstance(runner, str) and _SAFE_LABEL.fullmatch(runner):
        return runner
    return "unknown"


def _status(value: Any, *, default: str) -> str:
    if isinstance(value, str) and _SAFE_LABEL.fullmatch(value):
        return value
    return default


def _observer_status(source: Mapping[str, Any]) -> tuple[str, bool]:
    candidates = (
        _mapping(source.get("observer")),
        _mapping(source.get("observer_evidence")),
        _mapping(_mapping(source.get("sandbox")).get("observer")),
    )
    observer = next((item for item in candidates if item), {})
    degraded = observer.get("status") == "degraded" or _is_true(observer.get("observer_degraded"))
    degraded = degraded or _is_true(source.get("observer_degraded"))
    if degraded:
        return "degraded", True
    if not observer:
        return "not_recorded", False
    status = _status(observer.get("status"), default="recorded")
    return status, False


def _binding_status(authorization: Mapping[str, Any], source: Mapping[str, Any]) -> tuple[str, bool]:
    binding = _mapping(authorization.get("worktree_binding"))
    if not binding:
        binding = _mapping(source.get("binding"))
    if not binding:
        return "not_checked", False
    checked = _is_true(binding.get("checked"))
    matched = binding.get("matched") is True
    status = str(binding.get("status", ""))
    refusal_reasons = binding.get("refusal_reasons")
    mismatch = checked and (matched is False or status in {"mismatch", "unresolved", "dirty"})
    if mismatch:
        return "mismatch", True
    if checked and matched:
        return "matched", False
    if status in {"mismatch", "unresolved", "dirty"}:
        return "mismatch", True
    if isinstance(refusal_reasons, list) and any("mismatch" in str(item) for item in refusal_reasons):
        return "mismatch", True
    return "not_checked", False


def _execution_category(
    *,
    result_status: Any,
    policy_blocked: bool,
    timed_out: bool,
    cleanup_failed: bool,
    observer_degraded: bool,
    dry_run: bool,
    command_started: bool,
    exit_code: Any,
) -> str:
    if policy_blocked:
        return "policy_blocked"
    if timed_out:
        return "timeout"
    if cleanup_failed:
        return "cleanup"
    if observer_degraded or result_status == "observer_degraded":
        return "observer"
    if dry_run:
        return "dry_run"
    if result_status == "completed" and command_started and exit_code == 0:
        return "success"
    if not command_started:
        return "not_started"
    return "failure"


def _non_negative_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0
