"""Evidence adapters for caller-supplied imported reports.

Adapters in this package normalize already-supplied scanner-compatible reports
into the repo-health-doctor evidence model. They do not install or run scanners,
contact networks, execute target code, persist raw scanner output, or authorize
execution.
"""

from .gitleaks import normalize_gitleaks_report_to_evidence
from .osv_scanner import normalize_osv_report_to_evidence

__all__ = [
    "normalize_gitleaks_report_to_evidence",
    "normalize_osv_report_to_evidence",
]
