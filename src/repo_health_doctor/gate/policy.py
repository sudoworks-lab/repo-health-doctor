"""Pre-execution gate policy loading.

The policy is local data only. Loading it does not contact a network, execute
scanners, or authorize execution.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


GATE_POLICY_SCHEMA_VERSION = "0.1-draft"
GATE_POLICY_KIND = "pre_execution_gate_policy"
GATE_POLICY_VERSION = "0.1"


def default_gate_policy_path() -> Path:
    return Path(__file__).resolve().parents[3] / "policies" / "pre-execution-gate-policy.v0.1.json"


def default_gate_policy() -> Mapping[str, Any]:
    return {
        "schema_version": GATE_POLICY_SCHEMA_VERSION,
        "policy_kind": GATE_POLICY_KIND,
        "policy_version": GATE_POLICY_VERSION,
        "fail_closed": True,
        "mandatory_evidence": [],
        "accepted_missing_evidence": [],
        "missing_evidence": [],
        "requested_dynamic_judgment": False,
        "limitation_severity": {
            "low": [
                "external scanner output format unverified",
                "Docker integration test not run",
            ],
            "medium": [
                "scanner unavailable",
                "scanner output parse failed",
                "commit binding missing",
                "dirty workspace binding",
                "content digest binding without commit",
            ],
            "high": [
                "runtime observer degraded",
                "runtime observer unavailable",
                "observer missing for requested dynamic judgment",
            ],
            "critical": [
                "expected commit mismatch",
                "approval mismatch",
                "raw output redaction incomplete",
                "raw output retained unknown",
                "policy violation that attempted execution without approval",
                "network allowed during target scan",
                "Docker socket mount",
                "host HOME mount",
                "credential mount",
            ],
        },
    }


def load_pre_execution_gate_policy(path: str | Path | None = None) -> Mapping[str, Any]:
    policy_path = Path(path) if path is not None else default_gate_policy_path()
    try:
        with policy_path.open(encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default_gate_policy()
    if not isinstance(loaded, Mapping):
        return default_gate_policy()
    return loaded
