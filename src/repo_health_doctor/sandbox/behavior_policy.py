from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from .observer_evidence import (
    REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE,
    normalized_observer_evidence_to_behavior_evidence,
    validate_normalized_observer_evidence,
)

BEHAVIOR_POLICY_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_BEHAVIOR_POLICY = "sandbox_command_behavior_policy"
REPORT_KIND_BEHAVIOR_VERDICT = "sandbox_behavior_verdict"
_SAFE_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_LOGICAL_WRITE_PREFIXES = {"/workspace", "/tmp/home", "/tmp/npm-cache", "/tmp/pip-cache", "/tmp/xdg-cache", "/tmp/tmp"}
_POLICY_FIELDS = {"schema_version", "report_kind", "policy_id", "binding", "expected_behavior", "severity_rules", "observer_requirements", "redaction"}
_BINDING_FIELDS = {"candidate_key", "repo_identity", "commit", "phase", "kind", "cwd", "argv", "env_allowlist", "shell", "network_policy", "image_policy_schema_version"}
_EXPECTED_FIELDS = {"network", "allowed_write_prefixes", "denied_read_prefixes", "denied_socket_paths", "max_process_events", "allowed_exec_binaries", "allow_subprocess", "limited_subprocess_binaries", "max_secret_events", "max_outside_writable_delete", "allowed_env_keys", "timeout_seconds", "expected_return_codes"}
_SEVERITY_FIELDS = {"network_event", "write_outside_allowed_prefix", "docker_socket_access", "host_home_access", "denied_read_access", "secret_event", "unexpected_execve", "subprocess_spawn", "observer_unavailable", "strace_log_missing", "strace_parse_failure", "evidence_missing", "timeout", "return_code_mismatch", "outside_writable_delete"}
_OBSERVER_FIELDS = {"strace_required", "runtime_hook_required", "evidence_required", "default_verdict_on_missing_evidence"}
_REDACTION_FIELDS = {"raw_host_paths_redacted", "secret_like_values_redacted"}
_LEGACY_EVIDENCE_FIELDS = {"observer_available", "runtime_hook_available", "strace_log_present", "strace_parse_succeeded", "evidence_complete", "network_event_count", "write_outside_allowed_prefix_count", "docker_socket_access_count", "host_home_access_count", "denied_read_access_count", "secret_event_count", "execve_binaries", "subprocess_binaries", "outside_writable_delete_count", "timed_out", "return_code"}
_EVIDENCE_FIELDS = _LEGACY_EVIDENCE_FIELDS | {"runtime_hook_active", "runtime_hook_parse_succeeded", "observer_degraded", "strace_parse_error_count", "runtime_hook_parse_error_count"}


def _policy_id(policy_without_id: Mapping[str, Any]) -> str:
    raw = json.dumps(policy_without_id, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "behavior-policy:sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def behavior_policy_binding_fingerprint(policy: Mapping[str, Any]) -> str:
    """Return a stable fingerprint for a validated policy binding only.

    This is static metadata for approval/image binding checks.  It neither
    evaluates evidence nor authorizes a runner.
    """
    binding = policy.get("binding")
    if not isinstance(binding, Mapping):
        raise ValueError("behavior policy binding is missing")
    raw = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_default_behavior_policy(
    *,
    candidate_key: str = "sha256:" + "0" * 64,
    repo_identity: str = "sha256:" + "1" * 64,
    commit: str = "unavailable_static",
    phase: str = "phase2_install_probe",
    kind: str = "install_probe",
    cwd: str = "/workspace",
    argv: Sequence[str] = ("python", "-m", "build"),
    env_allowlist: Sequence[str] = ("PYTHONPATH",),
    allow_subprocess: bool | str = False,
    limited_subprocess_binaries: Sequence[str] = (),
    image_policy_schema_version: str = "unconfigured",
) -> dict[str, Any]:
    """Build a static default-deny policy; it does not authorize a runner."""
    policy: dict[str, Any] = {
        "schema_version": BEHAVIOR_POLICY_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_BEHAVIOR_POLICY,
        "binding": {
            "candidate_key": candidate_key,
            "repo_identity": repo_identity,
            "commit": commit,
            "phase": phase,
            "kind": kind,
            "cwd": cwd,
            "argv": list(argv),
            "env_allowlist": sorted(dict.fromkeys(env_allowlist)),
            "shell": False,
            "network_policy": "none",
            "image_policy_schema_version": image_policy_schema_version,
        },
        "expected_behavior": {
            "network": {"allowed": False},
            "allowed_write_prefixes": ["/workspace", "/tmp/tmp"],
            "denied_read_prefixes": ["<host-home>", "<credential-paths>"],
            "denied_socket_paths": ["/var/run/docker.sock"],
            "max_process_events": 1 if allow_subprocess == "limited" else 0,
            "allowed_exec_binaries": ["python"],
            "allow_subprocess": allow_subprocess,
            "limited_subprocess_binaries": sorted(dict.fromkeys(limited_subprocess_binaries)),
            "max_secret_events": 0,
            "max_outside_writable_delete": 0,
            "allowed_env_keys": sorted(dict.fromkeys(("HOME", "PYTHONPATH", "TMPDIR"))),
            "timeout_seconds": 60,
            "expected_return_codes": [0],
        },
        "severity_rules": {field: "block" for field in sorted(_SEVERITY_FIELDS)},
        "observer_requirements": {
            "strace_required": True,
            "runtime_hook_required": True,
            "evidence_required": True,
            "default_verdict_on_missing_evidence": "block",
        },
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }
    policy["policy_id"] = _policy_id(policy)
    validate_behavior_policy(policy)
    return policy


def _validate_exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{label} schema mismatch or unknown field")
    return value


def _validate_safe_labels(values: Any, label: str, pattern: re.Pattern[str] = _SAFE_LABEL) -> list[str]:
    if not isinstance(values, list) or not values or not all(isinstance(item, str) and pattern.fullmatch(item) for item in values):
        raise ValueError(f"{label} is invalid")
    return values


def validate_behavior_policy(policy: Mapping[str, Any]) -> None:
    """Validate the closed behavior-policy contract without executing anything."""
    _validate_exact_keys(policy, _POLICY_FIELDS, "behavior policy")
    if policy.get("schema_version") != BEHAVIOR_POLICY_SCHEMA_VERSION:
        raise ValueError("behavior policy schema_version is unsupported")
    if policy.get("report_kind") != REPORT_KIND_BEHAVIOR_POLICY:
        raise ValueError("behavior policy report_kind is unsupported")
    if not isinstance(policy.get("policy_id"), str) or not re.fullmatch(r"behavior-policy:sha256:[0-9a-f]{64}", policy["policy_id"]):
        raise ValueError("behavior policy policy_id is invalid")
    expected_policy_id = _policy_id({key: value for key, value in policy.items() if key != "policy_id"})
    if policy["policy_id"] != expected_policy_id:
        raise ValueError("behavior policy policy_id does not match policy content")
    binding = _validate_exact_keys(policy.get("binding"), _BINDING_FIELDS, "behavior policy binding")
    if not _SAFE_SHA256.fullmatch(str(binding.get("candidate_key"))) or not _SAFE_SHA256.fullmatch(str(binding.get("repo_identity"))):
        raise ValueError("behavior policy binding fingerprint is invalid")
    if binding.get("phase") not in {"phase2_install_probe", "phase3_runtime_probe"} or not isinstance(binding.get("commit"), str):
        raise ValueError("behavior policy binding phase or commit is invalid")
    if not isinstance(binding.get("kind"), str) or not _SAFE_LABEL.fullmatch(binding["kind"]):
        raise ValueError("behavior policy binding kind is invalid")
    if not isinstance(binding.get("cwd"), str) or not (binding["cwd"] == "/workspace" or binding["cwd"].startswith("/workspace/")):
        raise ValueError("behavior policy binding cwd is invalid")
    if not isinstance(binding.get("argv"), list) or not binding["argv"] or not all(isinstance(item, str) and item and not item.startswith("/") for item in binding["argv"]):
        raise ValueError("behavior policy binding argv is invalid")
    if not isinstance(binding.get("env_allowlist"), list) or not all(isinstance(item, str) and _SAFE_ENV.fullmatch(item) for item in binding["env_allowlist"]):
        raise ValueError("behavior policy binding env_allowlist is invalid")
    if binding.get("shell") is not False or binding.get("network_policy") != "none" or binding.get("image_policy_schema_version") not in {"unconfigured", "0.1-draft"}:
        raise ValueError("behavior policy binding attempts to relax a denied boundary")
    expected = _validate_exact_keys(policy.get("expected_behavior"), _EXPECTED_FIELDS, "expected behavior")
    network = expected.get("network")
    if not isinstance(network, Mapping) or set(network) != {"allowed"} or network.get("allowed") is not False:
        raise ValueError("behavior policy network must remain denied")
    prefixes = _validate_safe_labels(expected.get("allowed_write_prefixes"), "allowed_write_prefixes", re.compile(r"^/(?:workspace|tmp/(?:home|npm-cache|pip-cache|xdg-cache|tmp))(?:/[^.][^/]*)*$"))
    if not set(prefixes).issubset(_LOGICAL_WRITE_PREFIXES):
        raise ValueError("allowed_write_prefixes contains an unsupported prefix")
    if expected.get("denied_read_prefixes") != ["<host-home>", "<credential-paths>"] or expected.get("denied_socket_paths") != ["/var/run/docker.sock"]:
        raise ValueError("behavior policy denied boundary is invalid")
    if not isinstance(expected.get("max_process_events"), int) or expected["max_process_events"] < 0:
        raise ValueError("behavior policy max_process_events is invalid")
    _validate_safe_labels(expected.get("allowed_exec_binaries"), "allowed_exec_binaries")
    mode = expected.get("allow_subprocess")
    limited = expected.get("limited_subprocess_binaries")
    if mode not in {False, "limited"} or not isinstance(limited, list) or not all(isinstance(item, str) and _SAFE_LABEL.fullmatch(item) for item in limited):
        raise ValueError("behavior policy subprocess mode is invalid")
    if (mode is False and (limited or expected["max_process_events"] != 0)) or (mode == "limited" and (not limited or expected["max_process_events"] <= 0)):
        raise ValueError("behavior policy subprocess limits are invalid")
    for field in ("max_secret_events", "max_outside_writable_delete", "timeout_seconds"):
        if not isinstance(expected.get(field), int) or expected[field] < 0 or (field == "timeout_seconds" and expected[field] == 0):
            raise ValueError(f"behavior policy {field} is invalid")
    if expected["max_secret_events"] != 0 or expected["max_outside_writable_delete"] != 0:
        raise ValueError("behavior policy cannot relax secret or delete limits")
    if not isinstance(expected.get("allowed_env_keys"), list) or not all(isinstance(item, str) and _SAFE_ENV.fullmatch(item) for item in expected["allowed_env_keys"]):
        raise ValueError("behavior policy allowed_env_keys is invalid")
    if not isinstance(expected.get("expected_return_codes"), list) or not expected["expected_return_codes"] or not all(isinstance(item, int) for item in expected["expected_return_codes"]):
        raise ValueError("behavior policy expected_return_codes is invalid")
    severity = _validate_exact_keys(policy.get("severity_rules"), _SEVERITY_FIELDS, "behavior policy severity_rules")
    if any(value not in {"block", "warn", "needs_review"} for value in severity.values()):
        raise ValueError("behavior policy severity rule is invalid")
    for denied_rule in ("network_event", "write_outside_allowed_prefix", "docker_socket_access", "host_home_access", "denied_read_access", "observer_unavailable", "strace_log_missing", "strace_parse_failure", "evidence_missing", "outside_writable_delete"):
        if severity[denied_rule] != "block":
            raise ValueError("behavior policy attempts to relax a mandatory blocker")
    observers = _validate_exact_keys(policy.get("observer_requirements"), _OBSERVER_FIELDS, "observer requirements")
    if observers.get("strace_required") is not True or observers.get("evidence_required") is not True or observers.get("default_verdict_on_missing_evidence") != "block" or not isinstance(observers.get("runtime_hook_required"), bool):
        raise ValueError("behavior policy observer requirements are invalid")
    redaction = _validate_exact_keys(policy.get("redaction"), _REDACTION_FIELDS, "behavior policy redaction")
    if redaction.get("raw_host_paths_redacted") is not True or redaction.get("secret_like_values_redacted") is not True:
        raise ValueError("behavior policy redaction is invalid")


def _validate_behavior_evidence_shape(evidence: Mapping[str, Any]) -> None:
    _validate_exact_keys(evidence, _EVIDENCE_FIELDS, "behavior evidence")
    for field in ("observer_available", "runtime_hook_available", "runtime_hook_active", "runtime_hook_parse_succeeded", "observer_degraded", "strace_log_present", "strace_parse_succeeded", "evidence_complete", "timed_out"):
        if not isinstance(evidence.get(field), bool):
            raise ValueError("behavior evidence boolean field is invalid")
    for field in ("network_event_count", "write_outside_allowed_prefix_count", "docker_socket_access_count", "host_home_access_count", "denied_read_access_count", "secret_event_count", "outside_writable_delete_count", "strace_parse_error_count", "runtime_hook_parse_error_count"):
        if not isinstance(evidence.get(field), int) or evidence[field] < 0:
            raise ValueError("behavior evidence count is invalid")
    for field in ("execve_binaries", "subprocess_binaries"):
        value = evidence.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) and _SAFE_LABEL.fullmatch(item) for item in value):
            raise ValueError("behavior evidence binary list is invalid")
    if evidence.get("return_code") is not None and not isinstance(evidence.get("return_code"), int):
        raise ValueError("behavior evidence return_code is invalid")


def _coerce_behavior_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Accept canonical observer evidence plus the prior static-only shim.

    New callers must provide ``sandbox_normalized_observer_evidence``.  The
    legacy shape is retained only so existing static dry-run and policy users
    remain compatible until their fixtures are migrated.
    """
    if evidence.get("report_kind") == REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE:
        return normalized_observer_evidence_to_behavior_evidence(evidence)
    if not isinstance(evidence, Mapping) or set(evidence) != _LEGACY_EVIDENCE_FIELDS:
        raise ValueError("behavior evidence schema mismatch or unknown field")
    legacy = dict(evidence)
    legacy.update(
        {
            "runtime_hook_active": legacy["runtime_hook_available"],
            "runtime_hook_parse_succeeded": legacy["runtime_hook_available"],
            "observer_degraded": False,
            "strace_parse_error_count": 0,
            "runtime_hook_parse_error_count": 0,
        }
    )
    return legacy


def validate_behavior_evidence(evidence: Mapping[str, Any]) -> None:
    """Validate canonical normalized evidence or the deprecated static shim."""
    _validate_behavior_evidence_shape(_coerce_behavior_evidence(evidence))


def _invalid_verdict(reason: str) -> dict[str, Any]:
    return {
        "schema_version": BEHAVIOR_POLICY_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_BEHAVIOR_VERDICT,
        "policy_version": "unvalidated",
        "verdict": "block",
        "reasons": [reason],
        "blockers": [reason],
        "warnings": [],
        "evidence_summary": {"validation": "failed"},
        "limitations": ["Policy or evidence validation failed closed; no execution decision is produced."],
        "residual_risks": ["unknown_or_unsupported_input"],
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }


def _normalized_evidence_matches_policy(policy: Mapping[str, Any], evidence: Mapping[str, Any]) -> bool:
    """Bind canonical observer evidence to the exact reviewed command safely."""
    command = evidence["command"]
    binding = policy["binding"]
    argv = json.dumps(binding["argv"], ensure_ascii=False, separators=(",", ":"))
    argv_fingerprint = "sha256:" + hashlib.sha256(argv.encode("utf-8")).hexdigest()
    return (
        command["phase"] == binding["phase"]
        and command["kind"] == binding["kind"]
        and command["cwd"] == binding["cwd"]
        and command["argv_fingerprint"] == argv_fingerprint
        and command["shell"] == binding["shell"]
        and command["network_policy"] == binding["network_policy"]
    )


def evaluate_behavior_policy(policy: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate supplied evidence only; this function never starts a process or Docker."""
    try:
        validate_behavior_policy(policy)
    except ValueError:
        return _invalid_verdict("invalid_or_unsupported_behavior_policy")
    try:
        if evidence.get("report_kind") == REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE:
            validate_normalized_observer_evidence(evidence)
            if not _normalized_evidence_matches_policy(policy, evidence):
                return _invalid_verdict("normalized_evidence_command_binding_mismatch")
        evidence = _coerce_behavior_evidence(evidence)
        _validate_behavior_evidence_shape(evidence)
    except (KeyError, TypeError, ValueError):
        return _invalid_verdict("invalid_or_unsupported_behavior_evidence")

    expected = policy["expected_behavior"]
    severity = policy["severity_rules"]
    observers = policy["observer_requirements"]
    blockers: list[str] = []
    warnings: list[str] = []
    needs_review: list[str] = []

    def record(rule: str) -> None:
        level = severity[rule]
        if level == "block":
            blockers.append(rule)
        elif level == "warn":
            warnings.append(rule)
        else:
            needs_review.append(rule)

    if not evidence["observer_available"]:
        record("observer_unavailable")
    if observers["runtime_hook_required"] and not evidence["runtime_hook_available"]:
        record("observer_unavailable")
    if observers["runtime_hook_required"] and not evidence["runtime_hook_active"]:
        record("observer_unavailable")
    if observers["runtime_hook_required"] and not evidence["runtime_hook_parse_succeeded"]:
        record("observer_unavailable")
    if evidence["observer_degraded"]:
        record("observer_unavailable")
    if observers["strace_required"] and not evidence["strace_log_present"]:
        record("strace_log_missing")
    if observers["strace_required"] and not evidence["strace_parse_succeeded"]:
        record("strace_parse_failure")
    if evidence["strace_parse_error_count"]:
        record("strace_parse_failure")
    if evidence["runtime_hook_parse_error_count"]:
        record("observer_unavailable")
    if observers["evidence_required"] and not evidence["evidence_complete"]:
        record("evidence_missing")
    if evidence["network_event_count"]:
        record("network_event")
    if evidence["write_outside_allowed_prefix_count"]:
        record("write_outside_allowed_prefix")
    if evidence["docker_socket_access_count"]:
        record("docker_socket_access")
    if evidence["host_home_access_count"]:
        record("host_home_access")
    if evidence["denied_read_access_count"]:
        record("denied_read_access")
    if evidence["secret_event_count"] > expected["max_secret_events"]:
        record("secret_event")
    if evidence["outside_writable_delete_count"] > expected["max_outside_writable_delete"]:
        record("outside_writable_delete")
    unexpected_exec = [item for item in evidence["execve_binaries"] if item not in expected["allowed_exec_binaries"]]
    if unexpected_exec:
        record("unexpected_execve")
    subprocesses = evidence["subprocess_binaries"]
    if expected["allow_subprocess"] is False and subprocesses:
        record("subprocess_spawn")
    elif expected["allow_subprocess"] == "limited" and (
        len(subprocesses) > expected["max_process_events"] or any(item not in expected["limited_subprocess_binaries"] for item in subprocesses)
    ):
        record("subprocess_spawn")
    if evidence["timed_out"]:
        record("timeout")
    if evidence["return_code"] not in expected["expected_return_codes"]:
        record("return_code_mismatch")

    if blockers:
        verdict = "block"
    elif needs_review:
        verdict = "needs_review"
    elif warnings:
        verdict = "warn"
    else:
        verdict = "pass"
    summary = {
        "observer_available": evidence["observer_available"],
        "runtime_hook_available": evidence["runtime_hook_available"],
        "runtime_hook_active": evidence["runtime_hook_active"],
        "runtime_hook_parse_succeeded": evidence["runtime_hook_parse_succeeded"],
        "observer_degraded": evidence["observer_degraded"],
        "strace_log_present": evidence["strace_log_present"],
        "strace_parse_succeeded": evidence["strace_parse_succeeded"],
        "evidence_complete": evidence["evidence_complete"],
        "network_event_count": evidence["network_event_count"],
        "write_outside_allowed_prefix_count": evidence["write_outside_allowed_prefix_count"],
        "docker_socket_access_count": evidence["docker_socket_access_count"],
        "host_home_access_count": evidence["host_home_access_count"],
        "denied_read_access_count": evidence["denied_read_access_count"],
        "secret_event_count": evidence["secret_event_count"],
        "execve_count": len(evidence["execve_binaries"]),
        "subprocess_count": len(subprocesses),
        "outside_writable_delete_count": evidence["outside_writable_delete_count"],
        "strace_parse_error_count": evidence["strace_parse_error_count"],
        "runtime_hook_parse_error_count": evidence["runtime_hook_parse_error_count"],
        "timed_out": evidence["timed_out"],
        "return_code": evidence["return_code"],
    }
    return {
        "schema_version": BEHAVIOR_POLICY_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_BEHAVIOR_VERDICT,
        "policy_version": policy["schema_version"],
        "verdict": verdict,
        "reasons": sorted(dict.fromkeys([*blockers, *warnings, *needs_review])),
        "blockers": sorted(dict.fromkeys(blockers)),
        "warnings": sorted(dict.fromkeys(warnings)),
        "evidence_summary": summary,
        "limitations": [
            "PASS means observed evidence was within this policy's monitored scope; it is not an unknown-repository safety guarantee.",
            "This static evaluator does not execute a candidate, Docker, or a live sandbox phase.",
        ],
        "residual_risks": [
            "observed_evidence_is_not_a_safety_guarantee",
            "unobserved_behavior_remains_outside_this_verdict",
        ],
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }
