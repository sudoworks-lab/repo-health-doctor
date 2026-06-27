"""Limitation severity helpers for gate evaluation."""

from __future__ import annotations

from typing import Any, Mapping


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def limitation_severity(limitation: str, policy: Mapping[str, Any]) -> str:
    text = limitation.lower()
    severity_map = policy.get("limitation_severity")
    if isinstance(severity_map, Mapping):
        for severity in ("critical", "high", "medium", "low"):
            patterns = severity_map.get(severity)
            if isinstance(patterns, list) and any(str(pattern).lower() in text for pattern in patterns):
                return severity
    if "critical" in text or "mismatch" in text or "raw output retained" in text:
        return "critical"
    if "runtime observer" in text or "degraded" in text or "unavailable" in text:
        return "high"
    if "missing" in text or "unverified" in text or "parse failed" in text:
        return "medium"
    return "low"


def highest_limitation_severity(limitations: list[str], policy: Mapping[str, Any]) -> str:
    highest = "low"
    for limitation in limitations:
        severity = limitation_severity(limitation, policy)
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
            highest = severity
    return highest
