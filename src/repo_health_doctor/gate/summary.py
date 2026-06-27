"""Human-readable gate summary formatting.

The formatter is opt-in CLI presentation only. It does not expose raw evidence,
change v3 JSON output, write sidecars, run scanners, or authorize execution.
"""

from __future__ import annotations

from typing import Any, Mapping


def format_gate_summary(report: Mapping[str, Any], gate_decision: Mapping[str, Any]) -> str:
    """Render a compact terminal summary for demo and review workflows."""
    static_health = str(report.get("overall_status", "unknown")).upper()
    verdict = str(gate_decision.get("verdict", "unknown")).upper()
    execution_authorized = "true" if gate_decision.get("execution_authorized") is True else "false"
    explanation = gate_decision.get("explanation") if isinstance(gate_decision.get("explanation"), Mapping) else {}
    key_reasons = _string_items(explanation.get("key_reasons"))
    next_actions = _string_items(explanation.get("next_actions"))

    if not key_reasons:
        key_reasons = [
            "No scanner finding is not proof of safety.",
            "Evidence is missing, degraded, or not strongly bound enough to authorize execution.",
            "Gate decisions and execution authorization are intentionally separate.",
        ]
    if not next_actions:
        next_actions = [
            "Do not run install scripts locally based only on scanner silence.",
            "Review the gate decision sidecar and limitations.",
            "Use a stronger isolated environment if execution is necessary.",
        ]

    lines = [
        "Repo Health Doctor",
        "",
        f"Static health: {static_health}",
        f"Gate decision: {verdict}",
        f"Execution authorized: {execution_authorized}",
        "",
        "Why this is not an execution green light:",
    ]
    lines.extend(f"- {item}" for item in key_reasons)
    lines.extend(["", "Suggested next steps:"])
    lines.extend(f"- {item}" for item in next_actions)
    return "\n".join(lines) + "\n\n"


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []
