"""Compatibility adapter from current v3 JSON reports to future candidates.

The adapter derives evidence and gate decision candidates from the existing
`schema_version: 1.1` report shape. It does not mutate the v3 report, change CLI
defaults, evaluate policy decisions, or authorize execution.
"""

from __future__ import annotations

from typing import Any, Mapping

from .validation import EVIDENCE_KIND, EVIDENCE_SCHEMA_VERSION
from repo_health_doctor.gate.validation import DECISION_KIND, GATE_DECISION_SCHEMA_VERSION


ADAPTER_NAME = "v3_report_compatibility_adapter"
ADAPTER_VERSION = "0.1-draft"
MISSING_EVIDENCE = (
    "v3_report_lacks_commit_binding",
    "v3_report_lacks_tree_hash",
    "v3_report_lacks_formal_confidence_model",
    "v3_report_lacks_structured_raw_handling",
    "v3_report_is_check_oriented_not_gate_evaluator",
)
BASE_LIMITATIONS = (
    "v3_report_candidate_only",
    "not_execution_authorization",
    "no_finding_is_not_safety_proof",
    "missing_evidence_must_not_become_confidence",
)
BASE_RESIDUAL_RISKS = (
    "v3_report_does_not_prove_safety",
    "commit_and_tree_binding_missing",
)


def extract_evidence_candidates_from_v3_report(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Build future evidence candidates from a current v3 report.

    Missing v3 fields are represented as limitations rather than treated as
    safe evidence. All generated candidates have `can_authorize_execution=false`
    and `can_lower_risk=false`.
    """
    checks = report.get("checks")
    if not isinstance(checks, list):
        return []

    candidates: list[Mapping[str, Any]] = []
    for check_index, check in enumerate(checks):
        if not isinstance(check, Mapping):
            continue
        details = check.get("details") if isinstance(check.get("details"), Mapping) else {}
        findings = details.get("findings") if isinstance(details, Mapping) else None
        if isinstance(findings, list) and findings:
            for finding_index, finding in enumerate(findings):
                if isinstance(finding, Mapping):
                    candidates.append(_candidate_for_finding(report, check, finding, check_index, finding_index))
        else:
            candidates.append(_candidate_for_check(report, check, check_index))
    return candidates


def build_gate_decision_candidate_from_v3_report(report: Mapping[str, Any]) -> Mapping[str, Any]:
    """Build a future gate decision candidate from a current v3 report.

    This is a compatibility candidate, not a gate evaluator. It keeps
    `execution_authorized=false` and records v3 gaps as missing evidence.
    """
    checks = [check for check in report.get("checks", []) if isinstance(check, Mapping)]
    blocking = [str(check.get("name")) for check in checks if check.get("status") == "block"]
    warning = [str(check.get("name")) for check in checks if check.get("status") == "warn"]
    finding_count = _finding_count(checks)
    overall = report.get("overall_status")
    verdict = "block" if overall == "block" else "warn"
    required_actions = ["review blocking evidence before execution"] if verdict == "block" else ["review limitations before execution"]

    return {
        "decision_kind": DECISION_KIND,
        "schema_version": GATE_DECISION_SCHEMA_VERSION,
        "subject": {
            "repo": _repo(report),
            "commit": None,
            "tree_hash": None,
            "binding_kind": "path_bound",
        },
        "verdict": verdict,
        "execution_authorized": False,
        "confidence": "low",
        "confidence_reason": "current v3 report lacks formal evidence binding, trust, and gate evaluator semantics",
        "explanation": _candidate_explanation(verdict),
        "evidence_summary": {
            "findings_count": finding_count,
            "blocking_evidence": blocking,
            "warning_evidence": warning,
            "missing_evidence": list(MISSING_EVIDENCE),
            "degraded_observers": [],
        },
        "required_actions": required_actions,
        "limitations": list(BASE_LIMITATIONS),
        "policy": {
            "policy_version": f"v3-report:{report.get('schema_version', 'unknown')}",
            "fail_closed": True,
        },
        "residual_risks": list(BASE_RESIDUAL_RISKS),
    }


def _candidate_for_check(report: Mapping[str, Any], check: Mapping[str, Any], check_index: int) -> Mapping[str, Any]:
    status = str(check.get("status", "warn"))
    finding_present = False
    severity = _severity(status)
    return _base_candidate(
        report=report,
        check=check,
        evidence_id=f"v3-check-{check_index}-{_safe_token(check.get('name'))}",
        category=_category_for_check(str(check.get("name", "unknown"))),
        subcategory=f"check_{_safe_token(check.get('name'))}",
        severity=severity,
        finding_present=finding_present,
        finding_count=0,
        locations=[],
        redacted_summary=str(check.get("summary", "")),
        redaction_status="not_applicable",
    )


def _candidate_for_finding(
    report: Mapping[str, Any],
    check: Mapping[str, Any],
    finding: Mapping[str, Any],
    check_index: int,
    finding_index: int,
) -> Mapping[str, Any]:
    path = finding.get("file")
    line = finding.get("line")
    location = {"path": str(path) if isinstance(path, str) else "<repo>", "line": line if isinstance(line, int) else None}
    redacted = finding.get("redacted") is True
    redaction_status = "redacted" if redacted else "unknown"
    severity = "warn" if finding.get("allowed") is True else _severity(str(finding.get("severity", check.get("status", "warn"))))
    return _base_candidate(
        report=report,
        check=check,
        evidence_id=f"v3-finding-{check_index}-{finding_index}-{_safe_token(finding.get('rule_id'))}",
        category=_category_for_rule_or_check(str(finding.get("rule_id", "")), str(check.get("name", "unknown"))),
        subcategory=str(finding.get("pattern") or finding.get("rule_id") or "unknown"),
        severity=severity,
        finding_present=True,
        finding_count=1,
        locations=[location],
        redacted_summary=str(check.get("summary", "")),
        redaction_status=redaction_status,
    )


def _base_candidate(
    *,
    report: Mapping[str, Any],
    check: Mapping[str, Any],
    evidence_id: str,
    category: str,
    subcategory: str,
    severity: str,
    finding_present: bool,
    finding_count: int,
    locations: list[Mapping[str, Any]],
    redacted_summary: str,
    redaction_status: str,
) -> Mapping[str, Any]:
    limitations = list(BASE_LIMITATIONS)
    limitations.append(f"v3_check:{_safe_token(check.get('name'))}")
    if not finding_present:
        limitations.append("no_finding_scoped_to_current_check_only")
    details = check.get("details") if isinstance(check.get("details"), Mapping) else {}
    path_scope = _path_scope(details, locations)
    return {
        "evidence_id": evidence_id,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_kind": EVIDENCE_KIND,
        "source": {
            "tool_name": str(report.get("tool", "repo-health-doctor")),
            "tool_version": str(report.get("version", "unknown")),
            "adapter_name": ADAPTER_NAME,
            "adapter_version": ADAPTER_VERSION,
            "execution_mode": "native_static",
        },
        "subject": {
            "repo_identity": _repo(report),
            "commit": None,
            "tree_hash": None,
            "path_scope": path_scope,
            "binding_kind": "path_bound",
        },
        "classification": {
            "category": category,
            "subcategory": subcategory,
            "severity": severity,
            "confidence": "low",
            "confidence_reason": "derived from v3 check report; commit binding, tree hash, and formal trust are unavailable",
        },
        "finding": {
            "present": finding_present,
            "count": finding_count,
            "locations": locations,
            "redacted_summary": redacted_summary,
        },
        "raw_handling": {
            "raw_output_retained": False,
            "raw_stdout_retained": False,
            "raw_stderr_retained": False,
            "redaction_status": redaction_status,
            "redaction_failures": [],
        },
        "trust": {
            "level": "schema_validated",
            "commit_bound": False,
            "signature_verified": False,
            "binary_attested": False,
            "limitations": limitations,
        },
        "effects": {
            "can_lower_risk": False,
            "can_authorize_execution": False,
            "recommended_gate_effect": "block" if severity == "block" else "requires_human_review",
        },
        "residual_risks": list(BASE_RESIDUAL_RISKS),
    }


def _candidate_explanation(verdict: str) -> Mapping[str, Any]:
    summary = (
        "Gate evidence blocks execution review; this is not execution authorization."
        if verdict == "block"
        else "Static checks did not find blocking issues, but this is not enough to authorize execution."
    )
    return {
        "summary": summary,
        "key_reasons": [
            "No scanner finding is not proof of safety.",
            "Evidence is missing, degraded, or not strongly bound enough to authorize execution.",
            "Gate decisions and execution authorization are intentionally separate.",
        ],
        "next_actions": [
            "Do not run install scripts locally based only on scanner silence.",
            "Review limitations and evidence gaps.",
            "Use a stronger isolated environment if execution is necessary.",
        ],
    }


def _finding_count(checks: list[Mapping[str, Any]]) -> int:
    total = 0
    for check in checks:
        details = check.get("details")
        if isinstance(details, Mapping) and isinstance(details.get("findings"), list):
            total += len(details["findings"])
    return total


def _category_for_rule_or_check(rule_id: str, check_name: str) -> str:
    if ".secret." in rule_id:
        return "secret"
    if ".public_text." in rule_id or ".tracked_artifact." in rule_id:
        return "repo_posture"
    if ".policy." in rule_id:
        return "approval"
    return _category_for_check(check_name)


def _category_for_check(check_name: str) -> str:
    if check_name == "ci":
        return "ci_cd"
    if check_name == "secrets_scan":
        return "secret"
    if check_name == "policy":
        return "approval"
    return "repo_posture"


def _severity(status: str) -> str:
    if status == "block":
        return "block"
    if status == "warn":
        return "warn"
    if status == "pass":
        return "info"
    return "unknown"


def _path_scope(details: Any, locations: list[Mapping[str, Any]]) -> list[str]:
    if locations:
        return [str(location.get("path", "<repo>")) for location in locations]
    if isinstance(details, Mapping) and isinstance(details.get("scan_scope"), str):
        return [details["scan_scope"]]
    if isinstance(details, Mapping) and isinstance(details.get("found"), list) and details["found"]:
        return [str(item) for item in details["found"] if isinstance(item, str)]
    return ["<repo>"]


def _repo(report: Mapping[str, Any]) -> str:
    return "<repo>"


def _safe_token(value: Any) -> str:
    raw = str(value or "unknown")
    cleaned = "".join(character if character.isalnum() else "_" for character in raw.lower())
    return cleaned.strip("_") or "unknown"
