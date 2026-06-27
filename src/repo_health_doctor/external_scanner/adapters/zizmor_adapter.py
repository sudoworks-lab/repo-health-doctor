"""zizmor-style GitHub Actions adapter foundation.

This module handles synthetic, already-supplied zizmor-style data only. It does
not execute zizmor, install scanners, start Docker, contact a network, execute
target code, persist raw scanner output, or authorize live execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..plan_validator import (
    EXTERNAL_SCANNER_PLAN_SCHEMA_VERSION,
    PLAN_KIND_EXTERNAL_SCANNER_NO_NETWORK,
)
from ..result_validator import (
    EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
    REPORT_KIND_EXTERNAL_SCANNER_RESULT,
)
from .base import ExternalScannerAdapterCapability, ExternalScannerCommandPlan


ADAPTER_VERSION = "0.1"
ZIZMOR_STYLE_SCANNER_NAME = "zizmor-style"
ZIZMOR_STYLE_OUTPUT_KIND = "synthetic_zizmor_style_v0"
DEFAULT_REPO_COMMIT = "0123456789abcdef0123456789abcdef01234567"
DEFAULT_INPUT_FINGERPRINT = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
DEFAULT_SOURCE_REPORT_FINGERPRINT = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
DEFAULT_POLICY_FINGERPRINT = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
DEFAULT_ADAPTER_FINGERPRINT = "sha256:4444444444444444444444444444444444444444444444444444444444444444"

LIMITATIONS = (
    "scanner_scope_only",
    "not_execution_authorization",
    "external_result_trust_limited",
    "raw_output_not_retained",
    "scanner_binary_trust_boundary",
    "scanner_version_specific",
)
RESIDUAL_RISKS = (
    "zizmor_style_output_schema_unconfirmed",
    "synthetic_fixture_not_real_scanner_output",
    "local_runner_unimplemented",
)


@dataclass(frozen=True)
class ZizmorStyleFinding:
    rule_id: str
    kind: str
    path: str
    line: int | None
    title: str
    description: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class ZizmorStyleParsedOutput:
    status: str
    scanner_version: str
    unsupported_version: bool
    findings: tuple[ZizmorStyleFinding, ...]
    redaction_status: Mapping[str, bool]
    unknown_reason: str | None
    claims_no_findings: bool


class ZizmorStyleAdapter:
    """Adapter foundation for synthetic zizmor-style GitHub Actions evidence."""

    def capability(self) -> ExternalScannerAdapterCapability:
        return ExternalScannerAdapterCapability(
            scanner_name=ZIZMOR_STYLE_SCANNER_NAME,
            scanner_category="ci_cd_risk",
            supported_mode="local_static_no_network",
            allowed_input_paths=("<repo>/.github/workflows", ".github/workflows/"),
            requires_network=False,
            executes_target_code=False,
            docker_needed=False,
            raw_output_retention=False,
            expected_output_kind=ZIZMOR_STYLE_OUTPUT_KIND,
            limitations=LIMITATIONS,
            residual_risks=RESIDUAL_RISKS,
        )

    def build_plan(self) -> ExternalScannerCommandPlan:
        return ExternalScannerCommandPlan(
            argv=("zizmor", "--format", "json", ".github/workflows"),
            execution_authorized=False,
            scanner_executed=False,
            network_allowed=False,
            target_code_execution_allowed=False,
            docker_allowed=False,
            raw_output_retention=False,
            requires_human_approval=True,
            limitations=LIMITATIONS,
            residual_risks=RESIDUAL_RISKS,
        )

    def build_no_network_plan(self) -> dict[str, object]:
        return {
            "schema_version": EXTERNAL_SCANNER_PLAN_SCHEMA_VERSION,
            "plan_kind": PLAN_KIND_EXTERNAL_SCANNER_NO_NETWORK,
            "scanner": {
                "name": ZIZMOR_STYLE_SCANNER_NAME,
                "mode": "local_static_no_network",
                "version_pin_required": True,
                "version_pin": "0.0.0-fixture",
                "binary_hash_required": True,
                "binary_hash": None,
                "binary_trust_requirement": "human_verified_before_execution",
                "allowed_input_scope": "github_actions_workflows",
            },
            "input_scope": {
                "scope": "workflow",
                "included_paths": ["<repo>/.github/workflows"],
                "excluded_paths": [],
            },
            "execution_constraints": {
                "network_allowed": False,
                "target_code_execution_allowed": False,
                "docker_allowed": False,
                "timeout_seconds": 30,
                "max_output_bytes": 131072,
                "raw_output_retention": False,
                "redaction_before_persistence": True,
            },
            "approval": {
                "requires_human_approval": True,
                "approval_artifact_generated": False,
                "approval_reference": None,
            },
            "failure_policy": {
                "failure_effect": "requires_human_review",
                "scanner_unavailable_effect": "requires_human_review",
                "parse_failure_effect": "blocks_live_execution",
            },
            "limitations": [
                "planner_only",
                "not_execution_authorization",
                "raw_output_not_retained",
                "scanner_binary_trust_boundary",
                "scanner_version_specific",
            ],
            "residual_risks": [
                "local_runner_unimplemented",
                "scanner_binary_attestation_unimplemented",
                "zizmor_style_output_schema_unconfirmed",
            ],
            "execution_authorized": False,
            "scanner_execution_planned": True,
            "scanner_executed": False,
        }

    def parse_synthetic_output(self, data: Mapping[str, Any]) -> ZizmorStyleParsedOutput:
        if data.get("fixture_kind") != ZIZMOR_STYLE_OUTPUT_KIND:
            return ZizmorStyleParsedOutput(
                status="parse_failure",
                scanner_version=str(data.get("scanner_version", "unknown")),
                unsupported_version=False,
                findings=(),
                redaction_status=_redaction_status(data.get("redaction_status")),
                unknown_reason="parse_failure",
                claims_no_findings=False,
            )
        status = str(data.get("status", "ok"))
        unsupported = data.get("unsupported_version") is True or status == "unsupported_version"
        unknown_reason = _unknown_reason_for_status(status)
        findings = tuple(_parse_finding(index, item) for index, item in enumerate(_list_of_mappings(data.get("findings")), start=1))
        return ZizmorStyleParsedOutput(
            status=status,
            scanner_version=str(data.get("scanner_version", "unknown")),
            unsupported_version=unsupported,
            findings=findings,
            redaction_status=_redaction_status(data.get("redaction_status")),
            unknown_reason=unknown_reason,
            claims_no_findings=data.get("claims_no_findings") is True,
        )

    def normalize_synthetic_output(
        self,
        data: Mapping[str, Any],
        *,
        repo_commit: str = DEFAULT_REPO_COMMIT,
        input_fingerprint: str = DEFAULT_INPUT_FINGERPRINT,
        source_report_fingerprint: str = DEFAULT_SOURCE_REPORT_FINGERPRINT,
        trust_level: str = "schema_validated_import",
    ) -> dict[str, object]:
        parsed = self.parse_synthetic_output(data)
        findings = [_normalized_finding(index, finding) for index, finding in enumerate(parsed.findings, start=1)]
        nodes = [_normalized_node(index, finding) for index, finding in enumerate(parsed.findings, start=1)]
        edges = _normalized_edges(parsed.findings)
        outcome = _outcome(parsed)
        gate_effects = _default_gate_effects(parsed, findings)
        risk_effect = _default_risk_effect(parsed, findings)
        summary: dict[str, object] = {
            "outcome": outcome,
            "finding_count": len(findings),
            "highest_risk_tier_effect": risk_effect,
            "gate_effects": gate_effects,
        }
        if outcome == "unknown" and parsed.unknown_reason is not None:
            summary["unknown_reason"] = parsed.unknown_reason
        return {
            "schema_version": EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
            "report_kind": REPORT_KIND_EXTERNAL_SCANNER_RESULT,
            "scanner": {
                "name": ZIZMOR_STYLE_SCANNER_NAME,
                "version": parsed.scanner_version,
                "adapter_version": ADAPTER_VERSION,
                "category": "ci_cd_risk",
                "mode": "imported_report",
                "scanner_source": "internal_adapter",
                "trusted_binary_status": "not_applicable",
                "unsupported_version": parsed.unsupported_version,
            },
            "input_scope": {
                "scope": "workflow",
                "source_type": "imported_report",
                "repo_commit": repo_commit,
                "dirty_state": "not_applicable",
                "input_fingerprint": input_fingerprint,
                "included_paths": ["<repo>/.github/workflows"],
                "excluded_paths": [],
            },
            "execution_context": {
                "network_used": False,
                "target_code_executed": False,
                "docker_used": False,
                "scanner_downloaded_dependencies": False,
                "raw_output_available": False,
                "raw_output_retained": False,
                "timeout_occurred": parsed.status == "scanner_failure",
                "scanner_completed": parsed.status not in {"scanner_failure", "parse_failure"},
            },
            "trust_level": trust_level,
            "execution_authorized": False,
            "findings": findings,
            "evidence_nodes": nodes,
            "evidence_edges": edges,
            "summary": summary,
            "mapping_result": {
                "risk_tier_effect": risk_effect,
                "gate_effects": gate_effects,
                "rules_fired": _rules_fired_from_findings(findings),
                "risk_lowering_allowed": False,
            },
            "redaction_status": dict(parsed.redaction_status),
            "limitations": [_limitation(item) for item in LIMITATIONS],
            "residual_risks": [_residual_risk(item) for item in RESIDUAL_RISKS],
            "binding": {
                "repo_commit": repo_commit,
                "input_fingerprint": input_fingerprint,
                "source_report_fingerprint": source_report_fingerprint,
                "policy_fingerprint": DEFAULT_POLICY_FINGERPRINT,
                "adapter_fingerprint": DEFAULT_ADAPTER_FINGERPRINT,
            },
        }


def default_zizmor_style_adapter() -> ZizmorStyleAdapter:
    return ZizmorStyleAdapter()


def _parse_finding(index: int, data: Mapping[str, Any]) -> ZizmorStyleFinding:
    evidence = data.get("evidence", [])
    return ZizmorStyleFinding(
        rule_id=str(data.get("rule_id", f"zizmor-style.synthetic.{index}")),
        kind=str(data.get("kind", "unknown")),
        path=str(data.get("path", "<repo>/.github/workflows/ci.yml")),
        line=data.get("line") if isinstance(data.get("line"), int) else None,
        title=str(data.get("title", "Synthetic zizmor-style finding")),
        description=str(data.get("description", "Synthetic GitHub Actions scanner finding.")),
        evidence=tuple(item for item in evidence if isinstance(item, str)) if isinstance(evidence, list) else (),
    )


def _normalized_finding(index: int, finding: ZizmorStyleFinding) -> dict[str, object]:
    primary, secondary, risk_effect, rule_ids, gate_effect = _mapping_for_kind(finding.kind)
    return {
        "finding_id": f"zizmor-style-{index}",
        "scanner_rule_id": finding.rule_id,
        "primary_category": primary,
        "secondary_category": secondary,
        "scanner_severity": "synthetic",
        "normalized_severity": "block" if primary == "scanner_failure" else "warn",
        "confidence": "medium",
        "title": finding.title,
        "redacted_description": finding.description,
        "location": {"path": finding.path, "line": finding.line, "column": 1 if finding.line is not None else None},
        "evidence": list(finding.evidence),
        "risk_mapping": {"risk_tier_effect": risk_effect, "rule_ids": rule_ids},
        "gate_effect": gate_effect,
    }


def _normalized_node(index: int, finding: ZizmorStyleFinding) -> dict[str, object]:
    primary, secondary, _, _, _ = _mapping_for_kind(finding.kind)
    return {
        "node_id": f"zizmor-style-node-{index}",
        "primary_category": primary,
        "secondary_category": secondary,
        "title": finding.title,
        "redacted_summary": finding.description,
        "location": {"path": finding.path, "line": finding.line, "column": 1 if finding.line is not None else None},
        "confidence": "medium",
    }


def _normalized_edges(findings: tuple[ZizmorStyleFinding, ...]) -> list[dict[str, object]]:
    kinds = {finding.kind for finding in findings}
    edges: list[dict[str, object]] = []
    if "pull_request_target_untrusted_checkout" in kinds or "ci_token_untrusted_code_chain" in kinds:
        edges.append({
            "edge_id": "zizmor-style-edge-ci-token-untrusted-code",
            "from_node": "zizmor-style-node-1",
            "to_node": "zizmor-style-node-1",
            "relation": "ci_token_to_untrusted_code",
        })
    if {"broad_token_permission", "unpinned_action"}.issubset(kinds):
        edges.append({
            "edge_id": "zizmor-style-edge-same-workflow",
            "from_node": "zizmor-style-node-1",
            "to_node": "zizmor-style-node-2",
            "relation": "same_workflow",
        })
    return edges


def _mapping_for_kind(kind: str) -> tuple[str, str, str, list[str], str]:
    if kind in {"pull_request_target_untrusted_checkout", "ci_token_untrusted_code_chain"}:
        return ("ci_cd_risk", "pull_request_target_misuse", "raise_to_T4", ["RISK011"], "requires_human_review")
    if kind == "broad_token_permission":
        return ("ci_cd_risk", "broad_token_permission", "raise_to_T4", ["RISK012"], "requires_human_review")
    if kind == "unpinned_action":
        return ("ci_cd_risk", "unpinned_action", "raise_to_T4", ["RISK012"], "requires_human_review")
    if kind == "scanner_failure":
        return ("scanner_failure", "scanner_timeout", "raise_to_T5", ["RISK017"], "quarantine")
    return ("ci_cd_risk", "unknown", "none", [], "requires_human_review")


def _outcome(parsed: ZizmorStyleParsedOutput) -> str:
    if parsed.claims_no_findings:
        return "no_findings_in_scope"
    if parsed.status in {"scanner_failure", "parse_failure", "unsupported_version"}:
        return "unknown"
    if parsed.findings:
        return "findings_present"
    return "no_findings_in_scope"


def _default_gate_effects(parsed: ZizmorStyleParsedOutput, findings: list[dict[str, object]]) -> list[str]:
    if parsed.redaction_status.get("raw_scanner_output_included") is True:
        return ["quarantine"]
    if parsed.status in {"scanner_failure", "parse_failure", "unsupported_version"}:
        return ["requires_human_review"]
    if findings:
        return ["requires_human_review"]
    return ["evidence_only"]


def _default_risk_effect(parsed: ZizmorStyleParsedOutput, findings: list[dict[str, object]]) -> str:
    if parsed.redaction_status.get("raw_scanner_output_included") is True or parsed.status == "unsupported_version":
        return "T5_candidate"
    effects = [
        finding["risk_mapping"]["risk_tier_effect"]
        for finding in findings
        if isinstance(finding.get("risk_mapping"), Mapping)
    ]
    if "raise_to_T4" in effects:
        return "raise_to_T4"
    return "none"


def _rules_fired_from_findings(findings: list[dict[str, object]]) -> list[str]:
    rules: list[str] = []
    for finding in findings:
        mapping = finding.get("risk_mapping")
        if isinstance(mapping, Mapping):
            rule_ids = mapping.get("rule_ids")
            if isinstance(rule_ids, list):
                rules.extend(item for item in rule_ids if isinstance(item, str))
    return list(dict.fromkeys(rules))


def _unknown_reason_for_status(status: str) -> str | None:
    if status == "scanner_failure":
        return "timeout"
    if status == "parse_failure":
        return "parse_failure"
    if status == "unsupported_version":
        return "unsupported_version"
    return None


def _redaction_status(value: object) -> Mapping[str, bool]:
    source = value if isinstance(value, Mapping) else {}
    return {
        "raw_secret_present": source.get("raw_secret_present") is True,
        "raw_host_path_present": source.get("raw_host_path_present") is True,
        "raw_scanner_output_included": source.get("raw_scanner_output_included") is True,
        "raw_stdout_stderr_included": source.get("raw_stdout_stderr_included") is True,
        "unredacted_snippet_present": source.get("unredacted_snippet_present") is True,
        "redaction_validated": source.get("redaction_validated") is not False,
    }


def _limitation(limitation_id: str) -> dict[str, str]:
    descriptions = {
        "scanner_scope_only": "Synthetic zizmor-style evidence only covers declared GitHub Actions workflow scope.",
        "not_execution_authorization": "The result is evidence and does not authorize live execution.",
        "external_result_trust_limited": "Synthetic adapter output is not proof of scanner completeness.",
        "raw_output_not_retained": "Raw scanner output is not retained or reported.",
        "scanner_binary_trust_boundary": "Scanner binary trust is outside this foundation phase.",
        "scanner_version_specific": "Real scanner CLI and output behavior are version-dependent and unconfirmed.",
    }
    return {"limitation_id": limitation_id, "description": descriptions[limitation_id]}


def _residual_risk(risk_id: str) -> dict[str, str]:
    descriptions = {
        "zizmor_style_output_schema_unconfirmed": "Real zizmor output schema and CLI behavior remain unconfirmed.",
        "synthetic_fixture_not_real_scanner_output": "Fixtures are synthetic and do not prove real scanner compatibility.",
        "local_runner_unimplemented": "No local scanner runner or scanner execution is implemented.",
    }
    return {"risk_id": risk_id, "description": descriptions[risk_id]}


def _list_of_mappings(value: object) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []
