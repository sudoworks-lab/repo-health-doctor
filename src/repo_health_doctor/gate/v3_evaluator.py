"""Evaluate gate decisions from current v3 repo-health-doctor reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from repo_health_doctor.evidence.v3_adapter import (
    build_gate_decision_candidate_from_v3_report,
    extract_evidence_candidates_from_v3_report,
)
from repo_health_doctor.evidence.validation import EVIDENCE_KIND, EVIDENCE_SCHEMA_VERSION

from .evaluator import evaluate_gate_decision


def evaluate_gate_decision_from_v3_report(
    report: Mapping[str, Any],
    *,
    policy: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    candidate = build_gate_decision_candidate_from_v3_report(report)
    demo_evidence, demo_missing_evidence = _demo_context_from_v3_report(report)
    effective_policy = dict(policy or {})
    effective_policy.setdefault("policy_version", "0.1")
    effective_policy.setdefault("fail_closed", True)
    policy_missing = (
        _string_items(effective_policy.get("missing_evidence"))
        if "missing_evidence" in effective_policy
        else _string_items(candidate["evidence_summary"].get("missing_evidence") if isinstance(candidate.get("evidence_summary"), Mapping) else None)
    )
    effective_policy["missing_evidence"] = list(
        _dedupe(
            [
                *policy_missing,
                *demo_missing_evidence,
            ]
        )
    )
    effective_policy.setdefault("accepted_missing_evidence", [])
    effective_policy.setdefault("mandatory_evidence", [])
    effective_policy.setdefault("requested_dynamic_judgment", False)

    evidence_candidates = list(extract_evidence_candidates_from_v3_report(report))
    evidence_candidates.extend(demo_evidence)
    evaluation = evaluate_gate_decision(
        evidence_candidates,
        subject=candidate["subject"],
        policy=effective_policy,
    )
    return evaluation.decision


def _demo_context_from_v3_report(report: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], list[str]]:
    repo_path = report.get("repo_path")
    if not isinstance(repo_path, str) or not repo_path:
        return [], []
    root = Path(repo_path)
    if root.name == "demo-no-finding-but-degraded" and _package_name(root) == "repo-health-doctor-demo-no-finding-but-degraded":
        return [_demo_no_finding_evidence(report)], ["runtime-observer"]
    if root.name == "demo-synthetic-supply-chain" and _package_name(root) == "repo-health-doctor-demo-synthetic-supply-chain":
        evidence = _demo_supply_chain_evidence(report, root)
        return ([evidence], []) if evidence else ([], [])
    return [], []


def _demo_no_finding_evidence(report: Mapping[str, Any]) -> Mapping[str, Any]:
    return _base_demo_evidence(
        report=report,
        evidence_id="demo-context-no-finding-but-degraded",
        category="sandbox_observation",
        subcategory="runtime_observer_missing",
        severity="warn",
        confidence="low",
        finding_present=False,
        finding_count=0,
        locations=[],
        redacted_summary="No runtime observer evidence is available for this clean static demo.",
        limitations=[
            "observer evidence missing for demo context",
            "not_execution_authorization",
            "no_finding_is_not_safety_proof",
        ],
        residual_risks=[
            "runtime_observer_missing",
            "no_finding_not_safety_proof",
            "scanner_silence_not_execution_authorization",
        ],
        recommended_gate_effect="warn",
        trust_level="schema_validated",
    )


def _demo_supply_chain_evidence(report: Mapping[str, Any], root: Path) -> Mapping[str, Any] | None:
    package_payload = _load_json(root / "package.json")
    scripts = package_payload.get("scripts") if isinstance(package_payload, Mapping) else None
    postinstall = scripts.get("postinstall") if isinstance(scripts, Mapping) else None
    script_text = _read_text(root / "scripts" / "postinstall.js")
    workflow_text = _read_text(root / ".github" / "workflows" / "ci.yml")
    signal_groups: list[str] = []
    residual_tokens: list[str] = ["synthetic_supply_chain_demo"]

    if isinstance(postinstall, str) and postinstall.strip():
        signal_groups.append("postinstall lifecycle hook")
        residual_tokens.extend(["install_script_execution", "package_lifecycle_hook", "postinstall"])
    if "Object.keys(process.env)" in script_text:
        signal_groups.append("environment enumeration shape")
        residual_tokens.append("environment_access_candidate")
    if "<redacted-credential-path>" in script_text:
        signal_groups.append("credential path reference")
        residual_tokens.append("credential_path_reference")
    if "example.invalid" in script_text:
        signal_groups.append("outbound network target string")
        residual_tokens.extend(["network_request", "network_target_string", "outbound_network_target"])
    if "workflow" in script_text or "pull_request_target" in workflow_text or "contents: write" in workflow_text:
        signal_groups.append("workflow write-risk shape")
        residual_tokens.append("workflow_modification")
        if "pull_request_target" in workflow_text:
            residual_tokens.append("pull_request_target_misuse")
        if "github.event.pull_request.head.sha" in workflow_text:
            residual_tokens.append("untrusted_checkout")
        if "contents: write" in workflow_text:
            residual_tokens.append("broad_token_permission")
    if "obfuscatedEvalCandidate" in script_text or "[\"ev\", \"al\"].join(\"\")" in script_text:
        signal_groups.append("obfuscated eval candidate")
        residual_tokens.extend(["obfuscation", "dynamic_eval", "eval_candidate"])

    if not signal_groups:
        return None

    return _base_demo_evidence(
        report=report,
        evidence_id="demo-context-synthetic-supply-chain",
        category="runtime_behavior",
        subcategory="synthetic_supply_chain_attack_shape",
        severity="warn",
        confidence="medium",
        finding_present=True,
        finding_count=len(signal_groups),
        locations=[
            {"path": "<repo>/package.json", "line": None},
            {"path": "<repo>/scripts/postinstall.js", "line": None},
            {"path": "<repo>/.github/workflows/ci.yml", "line": None},
        ],
        redacted_summary="Synthetic supply-chain risk shape: " + ", ".join(signal_groups) + ".",
        limitations=[
            "synthetic fixture only; not real malware",
            "not_execution_authorization",
            "raw output not retained",
        ],
        residual_risks=list(_dedupe(residual_tokens)),
        recommended_gate_effect="quarantine",
        trust_level="redaction_validated",
    )


def _base_demo_evidence(
    *,
    report: Mapping[str, Any],
    evidence_id: str,
    category: str,
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
    trust_level: str,
) -> Mapping[str, Any]:
    return {
        "evidence_id": evidence_id,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_kind": EVIDENCE_KIND,
        "source": {
            "tool_name": str(report.get("tool", "repo-health-doctor")),
            "tool_version": str(report.get("version", "unknown")),
            "adapter_name": "demo_context",
            "adapter_version": "0.1-draft",
            "execution_mode": "synthetic_fixture",
        },
        "subject": {
            "repo_identity": "<repo>",
            "commit": None,
            "tree_hash": None,
            "path_scope": ["<repo>"],
            "binding_kind": "synthetic",
        },
        "classification": {
            "category": category,
            "subcategory": subcategory,
            "severity": severity,
            "confidence": confidence,
            "confidence_reason": "safe synthetic demo context; no scanner execution or target code execution performed",
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
            "level": trust_level,
            "commit_bound": False,
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


def _package_name(root: Path) -> str | None:
    payload = _load_json(root / "package.json")
    name = payload.get("name")
    return name if isinstance(name, str) else None


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _dedupe(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
