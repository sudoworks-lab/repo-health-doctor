"""Normalize caller-supplied Gitleaks-compatible reports to evidence.

This module does not execute Gitleaks, install Gitleaks, implement secret
detection, persist raw scanner output, or authorize execution.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from repo_health_doctor.evidence.validation import EVIDENCE_KIND, EVIDENCE_SCHEMA_VERSION


ADAPTER_NAME = "gitleaks_imported_evidence_adapter"
ADAPTER_VERSION = "0.1-draft"
TOOL_NAME = "gitleaks"
DEFAULT_TOOL_VERSION = "imported-synthetic"
GITLEAKS_JSON_FIELDS = {
    "Author",
    "Commit",
    "Date",
    "Description",
    "Email",
    "EndColumn",
    "EndLine",
    "Entropy",
    "File",
    "Fingerprint",
    "Line",
    "Match",
    "Message",
    "RuleID",
    "Secret",
    "StartColumn",
    "StartLine",
    "SymlinkFile",
    "Tags",
}
REDACTED_VALUES = {"<redacted>", "<redacted-secret>", "<redacted-secret-fingerprint>", "***REDACTED***"}
BASE_LIMITATIONS = [
    "gitleaks imported evidence only",
    "Gitleaks-compatible imported report support only",
    "not_execution_authorization",
    "no finding is not proof of safety",
    "raw output not retained",
]
BASE_RESIDUAL_RISKS = [
    "Gitleaks compatibility is limited to tested imported fixture shapes",
    "scanner was not executed by repo-health-doctor",
]


def normalize_gitleaks_report_to_evidence(
    report: object,
    *,
    subject: Mapping[str, Any] | None = None,
    tool_version: str | None = None,
) -> list[Mapping[str, Any]]:
    """Normalize a supplied Gitleaks JSON or SARIF-like report."""
    subject_data = _subject(subject)
    active_tool_version = tool_version or DEFAULT_TOOL_VERSION
    if isinstance(report, Mapping) and _looks_like_sarif(report):
        return _normalize_sarif(report, subject=subject_data, tool_version=active_tool_version)
    if not isinstance(report, Sequence) or isinstance(report, (str, bytes, bytearray)):
        return [_base_evidence(
            evidence_id="gitleaks-import-parse-failure",
            subject=subject_data,
            tool_version=active_tool_version,
            subcategory="scanner_output_parse_failed",
            severity="block",
            confidence="low",
            finding_present=True,
            finding_count=1,
            locations=[],
            redacted_summary="Supplied Gitleaks-like report was not a JSON array.",
            redaction_status="validated",
            redaction_failures=[],
            trust_level="schema_validated",
            limitations=BASE_LIMITATIONS + ["scanner output parse failed"],
            residual_risks=BASE_RESIDUAL_RISKS + ["scanner_output_parse_failed"],
            recommended_gate_effect="block",
        )]

    findings = [item for item in report if isinstance(item, Mapping)]
    if not findings:
        return [_base_evidence(
            evidence_id="gitleaks-import-no-findings",
            subject=subject_data,
            tool_version=active_tool_version,
            subcategory="no_findings_in_scope",
            severity="info",
            confidence="medium",
            finding_present=False,
            finding_count=0,
            locations=[],
            redacted_summary="Synthetic Gitleaks-like report contains no findings in declared scope.",
            redaction_status="validated",
            redaction_failures=[],
            trust_level="schema_validated",
            limitations=BASE_LIMITATIONS + ["gitleaks no finding is scoped evidence only"],
            residual_risks=BASE_RESIDUAL_RISKS,
            recommended_gate_effect="warn",
        )]

    evidence: list[Mapping[str, Any]] = []
    for index, finding in enumerate(findings, start=1):
        secret_value = finding.get("Secret")
        redaction_failures = [] if _is_redacted_secret(secret_value) else ["unredacted Secret field in imported Gitleaks-like report"]
        redaction_status = "validated" if not redaction_failures else "failed"
        limitations = BASE_LIMITATIONS + ["gitleaks verification status is not imported as proof"]
        unknown_fields = _unknown_gitleaks_fields(finding)
        if unknown_fields:
            limitations.append(f"ignored unknown Gitleaks fields: {', '.join(unknown_fields)}")
        evidence.append(_base_evidence(
            evidence_id=f"gitleaks-import-{index}",
            subject=subject_data,
            tool_version=active_tool_version,
            subcategory="secret_candidate",
            severity="block",
            confidence="medium",
            finding_present=True,
            finding_count=1,
            locations=[_location(finding)],
            redacted_summary=_summary(finding, redaction_failed=bool(redaction_failures)),
            redaction_status=redaction_status,
            redaction_failures=redaction_failures,
            trust_level="redaction_validated" if not redaction_failures else "schema_validated",
            limitations=limitations,
            residual_risks=BASE_RESIDUAL_RISKS + (["imported_secret_redaction_failed"] if redaction_failures else []),
            recommended_gate_effect="block",
        ))
    return evidence


def _normalize_sarif(
    report: Mapping[str, Any],
    *,
    subject: Mapping[str, Any],
    tool_version: str,
) -> list[Mapping[str, Any]]:
    sarif_findings: list[Mapping[str, Any]] = []
    runs = report.get("runs")
    if not isinstance(runs, list):
        runs = []
    discovered_version = tool_version
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        tool = run.get("tool")
        if isinstance(tool, Mapping):
            driver = tool.get("driver")
            if isinstance(driver, Mapping) and isinstance(driver.get("semanticVersion"), str):
                discovered_version = str(driver["semanticVersion"])
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if isinstance(result, Mapping):
                sarif_findings.append(_sarif_result_to_gitleaks_finding(result))

    if not sarif_findings:
        return [_base_evidence(
            evidence_id="gitleaks-import-sarif-no-findings",
            subject=subject,
            tool_version=discovered_version,
            subcategory="no_findings_in_scope",
            severity="info",
            confidence="medium",
            finding_present=False,
            finding_count=0,
            locations=[],
            redacted_summary="Gitleaks SARIF report contains no findings in declared scope.",
            redaction_status="validated",
            redaction_failures=[],
            trust_level="schema_validated",
            limitations=BASE_LIMITATIONS + ["gitleaks SARIF no finding is scoped evidence only"],
            residual_risks=BASE_RESIDUAL_RISKS,
            recommended_gate_effect="warn",
        )]
    return normalize_gitleaks_report_to_evidence(sarif_findings, subject=subject, tool_version=discovered_version)


def _base_evidence(
    *,
    evidence_id: str,
    subject: Mapping[str, Any],
    tool_version: str,
    subcategory: str,
    severity: str,
    confidence: str,
    finding_present: bool,
    finding_count: int,
    locations: list[Mapping[str, Any]],
    redacted_summary: str,
    redaction_status: str,
    redaction_failures: list[str],
    trust_level: str,
    limitations: list[str],
    residual_risks: list[str],
    recommended_gate_effect: str,
) -> Mapping[str, Any]:
    return {
        "evidence_id": evidence_id,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_kind": EVIDENCE_KIND,
        "source": {
            "tool_name": TOOL_NAME,
            "tool_version": tool_version,
            "adapter_name": ADAPTER_NAME,
            "adapter_version": ADAPTER_VERSION,
            "execution_mode": "imported_report",
        },
        "subject": dict(subject),
        "classification": {
            "category": "secret",
            "subcategory": subcategory,
            "severity": severity,
            "confidence": confidence,
            "confidence_reason": "normalized from caller-supplied synthetic Gitleaks-like JSON; repo-health-doctor did not run Gitleaks",
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
            "redaction_failures": redaction_failures,
        },
        "trust": {
            "level": trust_level,
            "commit_bound": subject.get("binding_kind") == "commit_bound",
            "signature_verified": False,
            "binary_attested": False,
            "limitations": limitations,
        },
        "effects": {
            "can_lower_risk": False,
            "can_authorize_execution": False,
            "recommended_gate_effect": recommended_gate_effect,
        },
        "residual_risks": residual_risks,
    }


def _subject(subject: Mapping[str, Any] | None) -> Mapping[str, Any]:
    source = subject or {}
    return {
        "repo_identity": str(source.get("repo_identity", "<repo>")),
        "commit": source.get("commit") if isinstance(source.get("commit"), str) else None,
        "tree_hash": source.get("tree_hash") if isinstance(source.get("tree_hash"), str) else None,
        "path_scope": source.get("path_scope") if isinstance(source.get("path_scope"), list) else ["<repo>"],
        "binding_kind": str(source.get("binding_kind", "synthetic")),
    }


def _location(finding: Mapping[str, Any]) -> Mapping[str, Any]:
    line = finding.get("StartLine")
    path = finding.get("File") if isinstance(finding.get("File"), str) else "<repo>"
    return {"path": _redacted_repo_path(path), "line": line if isinstance(line, int) and line > 0 else None}


def _looks_like_sarif(report: Mapping[str, Any]) -> bool:
    return isinstance(report.get("runs"), list) and (
        report.get("version") == "2.1.0" or "sarif" in str(report.get("$schema", "")).lower()
    )


def _sarif_result_to_gitleaks_finding(result: Mapping[str, Any]) -> Mapping[str, Any]:
    location = _first_sarif_location(result)
    properties = result.get("properties") if isinstance(result.get("properties"), Mapping) else {}
    message = result.get("message") if isinstance(result.get("message"), Mapping) else {}
    secret = properties.get("Secret", properties.get("secret"))
    return {
        "Description": message.get("text") if isinstance(message.get("text"), str) else "Gitleaks SARIF finding",
        "RuleID": result.get("ruleId") if isinstance(result.get("ruleId"), str) else "unknown-rule",
        "File": location["path"],
        "StartLine": location["line"],
        "EndLine": location["line"],
        "Secret": secret,
        "Fingerprint": result.get("fingerprints", {}).get("gitleaksFingerprint")
        if isinstance(result.get("fingerprints"), Mapping)
        else None,
    }


def _first_sarif_location(result: Mapping[str, Any]) -> Mapping[str, Any]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return {"path": "<repo>", "line": None}
    first = locations[0]
    if not isinstance(first, Mapping):
        return {"path": "<repo>", "line": None}
    physical = first.get("physicalLocation") if isinstance(first.get("physicalLocation"), Mapping) else {}
    artifact = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), Mapping) else {}
    region = physical.get("region") if isinstance(physical.get("region"), Mapping) else {}
    path = artifact.get("uri") if isinstance(artifact.get("uri"), str) else "<repo>"
    line = region.get("startLine")
    return {"path": path, "line": line if isinstance(line, int) and line > 0 else None}


def _unknown_gitleaks_fields(finding: Mapping[str, Any]) -> list[str]:
    return sorted(str(field) for field in finding if isinstance(field, str) and field not in GITLEAKS_JSON_FIELDS)


def _redacted_repo_path(path: str) -> str:
    clean = path.replace("\\", "/").lstrip("/")
    if clean.startswith("<repo>/"):
        return clean
    return f"<repo>/{clean}" if clean else "<repo>"


def _summary(finding: Mapping[str, Any], *, redaction_failed: bool) -> str:
    rule_id = finding.get("RuleID") if isinstance(finding.get("RuleID"), str) else "unknown-rule"
    description = finding.get("Description") if isinstance(finding.get("Description"), str) else "Secret candidate"
    if redaction_failed:
        return f"Gitleaks-like finding {rule_id}: {description}; imported Secret field failed redaction validation."
    return f"Gitleaks-like finding {rule_id}: {description}; secret value omitted."


def _is_redacted_secret(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    return normalized in REDACTED_VALUES or normalized.startswith("<redacted-")
