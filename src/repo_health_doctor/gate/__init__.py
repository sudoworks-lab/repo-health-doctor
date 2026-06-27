"""Gate decision model helpers for repo-health-doctor."""

from .authorization import (
    AUTHORIZATION_SCHEMA_VERSION,
    ExecutionAuthorizationValidationResult,
    build_execution_authorization_draft,
    gate_decision_fingerprint,
    validate_execution_authorization,
)
from .decision import GateDecisionValidationResult
from .evaluator import GateEvaluationResult, evaluate_gate_decision
from .summary import format_gate_summary
from .validation import GATE_DECISION_SCHEMA_VERSION, validate_gate_decision


def evaluate_gate_decision_from_v3_report(*args, **kwargs):
    """Evaluate a gate decision from a v3 report without eager imports."""
    from .v3_evaluator import evaluate_gate_decision_from_v3_report as _evaluate

    return _evaluate(*args, **kwargs)

__all__ = [
    "AUTHORIZATION_SCHEMA_VERSION",
    "ExecutionAuthorizationValidationResult",
    "GATE_DECISION_SCHEMA_VERSION",
    "GateEvaluationResult",
    "GateDecisionValidationResult",
    "build_execution_authorization_draft",
    "evaluate_gate_decision",
    "evaluate_gate_decision_from_v3_report",
    "format_gate_summary",
    "gate_decision_fingerprint",
    "validate_execution_authorization",
    "validate_gate_decision",
]
