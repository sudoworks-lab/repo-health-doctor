#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = ROOT / "docs" / "human-review" / "rhd-locked-down-v1.candidate.json"
SCHEMA_PATH = ROOT / "docs" / "human-review" / "final-security-gates.schema.json"
MAX_EVIDENCE_BYTES = 64 * 1024

COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
PROFILE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_METADATA = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+()/@:-]{0,127}\Z")
RUN_URL = re.compile(
    r"https://github\.com/[^/\s]+/[^/\s]+/actions/runs/[0-9]+"
    r"(?:/attempts/[0-9]+)?\Z"
)

ROOT_FIELDS = {
    "schema_version",
    "evidence_kind",
    "hosted_workflow",
    "seccomp_approval",
}
HOSTED_WORKFLOW_FIELDS = {
    "provider",
    "runner_environment",
    "workflow_path",
    "event",
    "conclusion",
    "run_id",
    "run_url",
    "head_sha",
    "docker_server_version",
    "runner_os",
    "runner_architecture",
}
SECCOMP_APPROVAL_FIELDS = {
    "approval_kind",
    "decision",
    "syscall_reduction_approved",
    "profile_name",
    "approved_profile_sha256",
    "approved_by",
    "approved_at",
}


def _closed_object(
    value: Any,
    *,
    required: set[str],
    allowed: set[str],
    reason_prefix: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(value, dict):
        return None, [f"{reason_prefix}_not_object"]

    reasons: list[str] = []
    if set(value) - allowed:
        reasons.append(f"{reason_prefix}_unexpected_fields")
    if required - set(value):
        reasons.append(f"{reason_prefix}_required_fields_missing")
    return value, reasons


def _is_safe_metadata(value: Any) -> bool:
    return isinstance(value, str) and SAFE_METADATA.fullmatch(value) is not None


def _is_rfc3339(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _target_commit_is_reachable(commit_sha: str) -> bool:
    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", commit_sha, "HEAD"],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _candidate_sha256() -> str | None:
    try:
        return hashlib.sha256(CANDIDATE_PATH.read_bytes()).hexdigest()
    except OSError:
        return None


def _load_evidence(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        if path.is_symlink():
            return None, ["evidence_symlink_refused"]
        size = path.stat().st_size
    except FileNotFoundError:
        return None, ["evidence_missing"]
    except OSError:
        return None, ["evidence_unreadable"]

    if size > MAX_EVIDENCE_BYTES:
        return None, ["evidence_over_budget"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, ["evidence_invalid_json"]
    if not isinstance(payload, dict):
        return None, ["evidence_not_object"]
    return payload, []


def validate_final_security_gates(path: Path) -> tuple[bool, list[str]]:
    reasons: list[str] = []

    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, ["schema_contract_unavailable"]
    if not isinstance(schema, dict):
        return False, ["schema_contract_unavailable"]

    payload, load_reasons = _load_evidence(path)
    reasons.extend(load_reasons)
    if payload is None:
        return False, sorted(set(reasons))

    root, root_reasons = _closed_object(
        payload,
        required=ROOT_FIELDS,
        allowed=ROOT_FIELDS,
        reason_prefix="evidence",
    )
    reasons.extend(root_reasons)
    if root is None:
        return False, sorted(set(reasons))
    if root.get("schema_version") != "0.1-draft":
        reasons.append("schema_version_invalid")
    if root.get("evidence_kind") != "final_security_gates":
        reasons.append("evidence_kind_invalid")

    hosted, hosted_reasons = _closed_object(
        root.get("hosted_workflow"),
        required=HOSTED_WORKFLOW_FIELDS - {"run_id", "run_url"},
        allowed=HOSTED_WORKFLOW_FIELDS,
        reason_prefix="hosted_workflow",
    )
    reasons.extend(hosted_reasons)
    if hosted is not None:
        expected_values = {
            "provider": "github_actions",
            "runner_environment": "github_hosted",
            "workflow_path": ".github/workflows/real-docker-verification.yml",
            "event": "workflow_dispatch",
            "conclusion": "success",
        }
        for field, expected in expected_values.items():
            if hosted.get(field) != expected:
                reasons.append(f"hosted_{field}_invalid")

        run_id = hosted.get("run_id")
        run_url = hosted.get("run_url")
        valid_run_id = isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0
        valid_run_url = isinstance(run_url, str) and RUN_URL.fullmatch(run_url) is not None
        if run_id is not None and not valid_run_id:
            reasons.append("hosted_run_id_invalid")
        if run_url is not None and not valid_run_url:
            reasons.append("hosted_run_url_invalid")
        if not valid_run_id and not valid_run_url:
            reasons.append("hosted_run_reference_missing")

        head_sha = hosted.get("head_sha")
        if not isinstance(head_sha, str) or COMMIT_SHA.fullmatch(head_sha) is None:
            reasons.append("hosted_target_commit_invalid")
        elif not _target_commit_is_reachable(head_sha):
            reasons.append("hosted_target_commit_unreachable")

        metadata_fields = {
            "docker_server_version": "hosted_docker_version_invalid",
            "runner_os": "hosted_os_invalid",
            "runner_architecture": "hosted_architecture_invalid",
        }
        for field, reason in metadata_fields.items():
            if not _is_safe_metadata(hosted.get(field)):
                reasons.append(reason)

    approval, approval_reasons = _closed_object(
        root.get("seccomp_approval"),
        required=SECCOMP_APPROVAL_FIELDS,
        allowed=SECCOMP_APPROVAL_FIELDS,
        reason_prefix="seccomp_approval",
    )
    reasons.extend(approval_reasons)
    if approval is not None:
        if approval.get("approval_kind") != "human":
            reasons.append("seccomp_human_approval_invalid")
        if approval.get("decision") != "approved":
            reasons.append("seccomp_decision_invalid")
        if approval.get("syscall_reduction_approved") is not True:
            reasons.append("seccomp_reduction_approval_invalid")
        if approval.get("profile_name") != "rhd-locked-down-v1":
            reasons.append("seccomp_profile_name_invalid")
        if not _is_safe_metadata(approval.get("approved_by")):
            reasons.append("seccomp_approver_invalid")
        if not _is_rfc3339(approval.get("approved_at")):
            reasons.append("seccomp_approval_time_invalid")

        approved_hash = approval.get("approved_profile_sha256")
        candidate_hash = _candidate_sha256()
        if candidate_hash is None:
            reasons.append("candidate_profile_unavailable")
        elif not isinstance(approved_hash, str) or PROFILE_SHA256.fullmatch(approved_hash) is None:
            reasons.append("approved_profile_hash_invalid")
        elif approved_hash != candidate_hash:
            reasons.append("approved_profile_hash_mismatch")

    unique_reasons = sorted(set(reasons))
    return not unique_reasons, unique_reasons


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate bounded Human evidence for the final security gates."
    )
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()

    valid, reason_codes = validate_final_security_gates(args.evidence)
    print(
        json.dumps(
            {
                "schema_version": "0.1-draft",
                "report_kind": "final_security_gates_validation",
                "valid": valid,
                "reason_codes": reason_codes,
            },
            sort_keys=True,
        )
    )
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
