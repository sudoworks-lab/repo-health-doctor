"""Evidence model helpers for repo-health-doctor.

These helpers formalize future evidence records without changing the current
v3 JSON scan report or authorizing execution.
"""

from .models import EvidenceValidationResult
from .adapters import normalize_gitleaks_report_to_evidence, normalize_osv_report_to_evidence
from .sandbox_run import normalize_sandbox_run_evidence
from .validation import EVIDENCE_SCHEMA_VERSION, validate_evidence
from .v3_adapter import (
    build_gate_decision_candidate_from_v3_report,
    extract_evidence_candidates_from_v3_report,
)

__all__ = [
    "EVIDENCE_SCHEMA_VERSION",
    "EvidenceValidationResult",
    "build_gate_decision_candidate_from_v3_report",
    "extract_evidence_candidates_from_v3_report",
    "normalize_gitleaks_report_to_evidence",
    "normalize_osv_report_to_evidence",
    "normalize_sandbox_run_evidence",
    "validate_evidence",
]
