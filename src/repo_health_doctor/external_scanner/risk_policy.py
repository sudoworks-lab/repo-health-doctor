"""Load the external scanner risk policy draft.

The policy is local, static JSON. Loading it does not execute scanners, contact
the network, invoke Docker, call remote APIs, or inspect target code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


EXTERNAL_SCANNER_RISK_POLICY_SCHEMA_VERSION = "0.1-draft"
EXTERNAL_SCANNER_RISK_POLICY_VERSION = "0.1"
EXTERNAL_SCANNER_RISK_POLICY_KIND = "external_scanner_risk_policy"

RISK_RULE_IDS = tuple(f"RISK{index:03d}" for index in range(1, 21))


def external_scanner_risk_policy_path() -> Path:
    return Path(__file__).resolve().parents[3] / "policies" / "external-scanner-risk-policy.v0.1.json"


def load_external_scanner_risk_policy() -> Mapping[str, Any]:
    with external_scanner_risk_policy_path().open(encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, Mapping):
        raise ValueError("external scanner risk policy is not an object")
    return policy


def risk_rules_by_id(policy: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rules = policy.get("risk_rules")
    if not isinstance(rules, list):
        return {}
    indexed: dict[str, Mapping[str, Any]] = {}
    for item in rules:
        if isinstance(item, Mapping) and isinstance(item.get("rule_id"), str):
            indexed[item["rule_id"]] = item
    return indexed
