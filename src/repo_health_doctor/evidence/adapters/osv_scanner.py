"""Normalize caller-supplied OSV-Scanner-compatible reports to evidence.

This module does not execute OSV-Scanner, install scanners, contact the OSV
database, maintain vulnerability data, persist raw scanner output, or authorize
execution.
"""

from __future__ import annotations

from typing import Any, Mapping

from repo_health_doctor.evidence.validation import EVIDENCE_KIND, EVIDENCE_SCHEMA_VERSION


ADAPTER_NAME = "osv_scanner_imported_evidence_adapter"
ADAPTER_VERSION = "0.1-draft"
TOOL_NAME = "osv-scanner"
DEFAULT_TOOL_VERSION = "imported-synthetic"
BASE_LIMITATIONS = [
    "OSV-Scanner-compatible imported JSON support only",
    "imported evidence only",
    "not_execution_authorization",
    "no finding is not proof of safety",
    "raw output not retained",
]
BASE_RESIDUAL_RISKS = [
    "OSV-Scanner compatibility is limited to tested imported fixture shapes",
    "OSV database freshness is outside repo-health-doctor",
    "scanner was not executed by repo-health-doctor",
]
SOURCE_FIELDS = {"path", "type"}
PACKAGE_FIELDS = {"package", "vulnerabilities", "groups"}
PACKAGE_META_FIELDS = {"name", "version", "ecosystem", "purl"}
VULNERABILITY_FIELDS = {
    "id",
    "summary",
    "details",
    "aliases",
    "modified",
    "published",
    "database_specific",
    "severity",
    "affected",
    "references",
}


def normalize_osv_report_to_evidence(
    report: object,
    *,
    subject: Mapping[str, Any] | None = None,
    tool_version: str | None = None,
) -> list[Mapping[str, Any]]:
    """Normalize a supplied OSV-Scanner JSON-like report."""
    subject_data = _subject(subject)
    active_tool_version = tool_version or DEFAULT_TOOL_VERSION
    if not isinstance(report, Mapping):
        return [_base_evidence(
            evidence_id="osv-import-parse-failure",
            subject=subject_data,
            tool_version=active_tool_version,
            subcategory="scanner_output_parse_failed",
            severity="block",
            confidence="low",
            finding_present=True,
            finding_count=1,
            locations=[],
            redacted_summary="Supplied OSV-like report was not a JSON object.",
            limitations=BASE_LIMITATIONS + ["scanner output parse failed"],
            residual_risks=BASE_RESIDUAL_RISKS + ["scanner_output_parse_failed"],
            recommended_gate_effect="block",
        )]

    evidence: list[Mapping[str, Any]] = []
    for result_index, result in enumerate(_mappings(report.get("results")), start=1):
        source = result.get("source") if isinstance(result.get("source"), Mapping) else {}
        path = source.get("path") if isinstance(source.get("path"), str) else "package-lock.json"
        source_type = source.get("type") if isinstance(source.get("type"), str) else "unknown_source"
        source_limitations = _unknown_field_limitations("OSV source", source, SOURCE_FIELDS)
        for package_index, package in enumerate(_mappings(result.get("packages")), start=1):
            package_meta = package.get("package") if isinstance(package.get("package"), Mapping) else {}
            package_name = package_meta.get("name") if isinstance(package_meta.get("name"), str) else "example-package"
            ecosystem = package_meta.get("ecosystem") if isinstance(package_meta.get("ecosystem"), str) else "unknown"
            package_limitations = (
                source_limitations
                + _unknown_field_limitations("OSV package", package, PACKAGE_FIELDS)
                + _unknown_field_limitations("OSV package metadata", package_meta, PACKAGE_META_FIELDS)
            )
            for vuln_index, vulnerability in enumerate(_mappings(package.get("vulnerabilities")), start=1):
                score = _cvss_score(vulnerability.get("severity"))
                severity, subcategory, effect = _severity(score)
                vuln_id = vulnerability.get("id") if isinstance(vulnerability.get("id"), str) else "synthetic-vulnerability"
                summary = vulnerability.get("summary") if isinstance(vulnerability.get("summary"), str) else "Synthetic vulnerability"
                vuln_limitations = package_limitations + _unknown_field_limitations("OSV vulnerability", vulnerability, VULNERABILITY_FIELDS)
                evidence.append(_base_evidence(
                    evidence_id=f"osv-import-{result_index}-{package_index}-{vuln_index}",
                    subject=subject_data,
                    tool_version=active_tool_version,
                    subcategory=subcategory,
                    severity=severity,
                    confidence="medium",
                    finding_present=True,
                    finding_count=1,
                    locations=[{"path": _redacted_repo_path(path), "line": None}],
                    redacted_summary=f"OSV-Scanner finding {vuln_id} for {package_name} ({ecosystem}, {source_type}): {summary}; CVSS score {score if score is not None else 'unknown'}.",
                    limitations=BASE_LIMITATIONS + ["vulnerability database lookup was not performed by repo-health-doctor"] + vuln_limitations,
                    residual_risks=BASE_RESIDUAL_RISKS,
                    recommended_gate_effect=effect,
                ))

    if evidence:
        return evidence
    return [_base_evidence(
        evidence_id="osv-import-no-vulnerabilities",
        subject=subject_data,
        tool_version=active_tool_version,
        subcategory="no_vulnerabilities_in_scope",
        severity="info",
        confidence="medium",
        finding_present=False,
        finding_count=0,
        locations=[],
        redacted_summary="Synthetic OSV-like report contains no vulnerabilities in declared scope.",
        limitations=BASE_LIMITATIONS + ["OSV-like no finding is scoped evidence only"],
        residual_risks=BASE_RESIDUAL_RISKS,
        recommended_gate_effect="warn",
    )]


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
            "category": "known_vulnerability",
            "subcategory": subcategory,
            "severity": severity,
            "confidence": confidence,
            "confidence_reason": "normalized from caller-supplied synthetic OSV-like JSON; repo-health-doctor did not run OSV-Scanner",
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
            "redaction_status": "validated",
            "redaction_failures": [],
        },
        "trust": {
            "level": "schema_validated",
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


def _mappings(value: object) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _redacted_repo_path(path: str) -> str:
    clean = path.replace("\\", "/").lstrip("/")
    if clean.startswith("<repo>/"):
        return clean
    return f"<repo>/{clean}" if clean else "<repo>"


def _cvss_score(severity: object) -> float | None:
    for item in _mappings(severity):
        score = item.get("score")
        if isinstance(score, str) and score.startswith("CVSS:3."):
            return _cvss_v3_base_score(score)
        try:
            return float(score) if score is not None else None
        except (TypeError, ValueError):
            return None
    return None


def _severity(score: float | None) -> tuple[str, str, str]:
    if score is None:
        return ("warn", "vulnerability_unknown_severity", "warn")
    if score >= 9.0:
        return ("block", "known_critical_vulnerability", "block")
    if score >= 7.0:
        return ("warn", "high_vulnerability", "warn")
    if score >= 4.0:
        return ("warn", "medium_vulnerability", "warn")
    return ("info", "low_vulnerability", "warn")


def _unknown_field_limitations(label: str, data: Mapping[str, Any], known_fields: set[str]) -> list[str]:
    unknown = sorted(str(field) for field in data if isinstance(field, str) and field not in known_fields)
    return [f"ignored unknown {label} fields: {', '.join(unknown)}"] if unknown else []


def _cvss_v3_base_score(vector: str) -> float | None:
    metrics = _cvss_metrics(vector)
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if (set(metrics) & required) != required:
        return None
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope = metrics["S"]
        pr = {
            "N": 0.85,
            "L": 0.62 if scope == "U" else 0.68,
            "H": 0.27 if scope == "U" else 0.5,
        }[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
        c = impact_values[metrics["C"]]
        i = impact_values[metrics["I"]]
        a = impact_values[metrics["A"]]
    except KeyError:
        return None
    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    elif scope == "C":
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        return None
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _round_up_1(min(impact + exploitability, 10))
    return _round_up_1(min(1.08 * (impact + exploitability), 10))


def _cvss_metrics(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part or part.startswith("CVSS:"):
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    return metrics


def _round_up_1(value: float) -> float:
    scaled = int(value * 100000)
    return ((scaled + 9999) // 10000) / 10.0
