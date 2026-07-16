"""Pre-execution gate evaluator.

The evaluator turns supplied evidence candidates into a gate decision. It does
not mutate v3 reports, change CLI defaults, run scanners, contact networks,
execute target code, or authorize execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from repo_health_doctor.evidence.validation import validate_evidence
from repo_health_doctor.external_scanner.risk_mapper import (
    ExternalScannerRiskMappingResult,
    map_external_scanner_risk,
)
from repo_health_doctor.external_scanner.result_validator import validate_external_scanner_result

from .external_evidence import ExternalSuiteEvidenceValidationResult
from .limitation_policy import highest_limitation_severity
from .policy import load_pre_execution_gate_policy
from .validation import DECISION_KIND, GATE_DECISION_SCHEMA_VERSION, validate_gate_decision
from .verdict import strongest_verdict


LOW_TRUST_LEVELS = {"untrusted_import", "schema_validated"}
BLOCKING_LIMITATION_MARKERS = {
    "raw secret leakage",
    "raw host path leak",
    "expected commit mismatch",
    "approval mismatch",
    "policy violation that attempted execution without approval",
    "network allowed during target scan",
    "docker socket mount",
    "host home mount",
    "credential mount",
}
QUARANTINE_MARKERS = {
    "verified_secret",
    "credential_access_network",
    "install_download_exec",
    "obfuscation_eval_network",
    "ci_token_abuse_chain",
    "pull_request_target_untrusted_checkout",
    "docker_socket_subprocess",
    "critical_vulnerability_runtime",
    "observer_degraded_risky_execution",
}
WARN_MARKERS = {
    "tool unavailable",
    "tool output parse failed",
    "known_vulnerability",
    "low_repo_posture",
    "unsupported_scanner_version",
    "dirty workspace binding",
    "content digest binding without commit",
}


@dataclass(frozen=True)
class GateEvaluationResult:
    decision: Mapping[str, Any]
    valid: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    verdict_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": dict(self.decision),
            "valid": self.valid,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "verdict_reasons": list(self.verdict_reasons),
        }


@dataclass(frozen=True)
class ExternalSuiteGateEvidence:
    """One suite report paired with its bounded validation result."""

    report: Mapping[str, Any]
    validation: ExternalSuiteEvidenceValidationResult


@dataclass(frozen=True)
class _ExternalSuiteGateSignals:
    verdict_candidates: tuple[str, ...]
    verdict_reasons: tuple[str, ...]
    blocking_evidence: tuple[str, ...]
    warning_evidence: tuple[str, ...]
    findings_count: int


def evaluate_gate_decision(
    evidence: Sequence[Mapping[str, Any]],
    *,
    subject: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    external_suite_evidence: Sequence[ExternalSuiteGateEvidence] = (),
) -> GateEvaluationResult:
    active_policy = policy or load_pre_execution_gate_policy()
    evidence_items = list(evidence)
    verdict_candidates: list[str] = []
    verdict_reasons: list[str] = []
    blocking_evidence: list[str] = []
    warning_evidence: list[str] = []
    missing_evidence = _missing_evidence(active_policy)
    degraded_observers: list[str] = []
    limitations: list[str] = ["not_execution_authorization", "allow_limited_is_not_safety_proof"]
    residual_risks: list[str] = ["execution_authorization_not_implemented"]
    findings_count = 0

    if not evidence_items:
        verdict_candidates.append("unknown")
        verdict_reasons.append("no_evidence")
        missing_evidence.append("all_evidence")
        limitations.append("no evidence available")

    all_low_trust = bool(evidence_items)
    any_runtime_observation = False
    any_binding_acceptable = False

    for item in evidence_items:
        evidence_id = str(item.get("evidence_id", "unknown_evidence"))
        validation = validate_evidence(item)
        if not validation.valid:
            verdict_candidates.append("block")
            verdict_reasons.append(f"invalid_evidence:{evidence_id}")
            blocking_evidence.append(evidence_id)
        limitations.extend(validation.limitations)
        residual_risks.extend(validation.residual_risks)

        source = _mapping(item.get("source"))
        subject_data = _mapping(item.get("subject"))
        classification = _mapping(item.get("classification"))
        finding = _mapping(item.get("finding"))
        raw_handling = _mapping(item.get("raw_handling"))
        trust = _mapping(item.get("trust"))
        effects = _mapping(item.get("effects"))

        if source.get("execution_mode") in {"sandbox_observer", "docker_isolated"}:
            any_runtime_observation = True
        if subject_data.get("binding_kind") in {"path_bound", "commit_bound", "tree_bound", "synthetic"}:
            any_binding_acceptable = True
        if trust.get("level") not in LOW_TRUST_LEVELS:
            all_low_trust = False

        if finding.get("present") is True and isinstance(finding.get("count"), int):
            findings_count += int(finding["count"])

        if item.get("execution_authorized") is True or effects.get("can_authorize_execution") is True:
            verdict_candidates.append("block")
            verdict_reasons.append(f"execution_authorization_attempt:{evidence_id}")
            blocking_evidence.append(evidence_id)
        if raw_handling.get("raw_output_retained") is True or raw_handling.get("raw_stdout_retained") is True or raw_handling.get("raw_stderr_retained") is True:
            verdict_candidates.append("block")
            verdict_reasons.append(f"raw_output_retained:{evidence_id}")
            blocking_evidence.append(evidence_id)
        if raw_handling.get("redaction_status") == "failed":
            verdict_candidates.append("block")
            verdict_reasons.append(f"redaction_failed:{evidence_id}")
            blocking_evidence.append(evidence_id)
        if effects.get("recommended_gate_effect") == "block":
            verdict_candidates.append("block")
            verdict_reasons.append(f"recommended_block:{evidence_id}")
            blocking_evidence.append(evidence_id)
        elif effects.get("recommended_gate_effect") == "quarantine":
            verdict_candidates.append("quarantine")
            verdict_reasons.append(f"recommended_quarantine:{evidence_id}")
            warning_evidence.append(evidence_id)
        elif effects.get("recommended_gate_effect") == "warn":
            verdict_candidates.append("warn")
            verdict_reasons.append(f"recommended_warn:{evidence_id}")
            warning_evidence.append(evidence_id)

        tokens = _tokens(item)
        if _has_any(tokens, BLOCKING_LIMITATION_MARKERS) or "raw_secret_leak" in tokens or "raw_host_path_leak" in tokens:
            verdict_candidates.append("block")
            verdict_reasons.append(f"blocking_marker:{evidence_id}")
            blocking_evidence.append(evidence_id)
        if _has_quarantine_signal(tokens, classification):
            verdict_candidates.append("quarantine")
            verdict_reasons.append(f"quarantine_signal:{evidence_id}")
            warning_evidence.append(evidence_id)
        if _has_warn_signal(tokens, classification):
            verdict_candidates.append("warn")
            verdict_reasons.append(f"warning_signal:{evidence_id}")
            warning_evidence.append(evidence_id)

        if finding.get("present") is False:
            verdict_candidates.append("warn")
            verdict_reasons.append(f"no_finding_not_safety_proof:{evidence_id}")
            warning_evidence.append(evidence_id)
        if trust.get("level") in LOW_TRUST_LEVELS and finding.get("present") is False:
            verdict_candidates.append("warn")
            verdict_reasons.append(f"low_trust_no_finding:{evidence_id}")
            warning_evidence.append(evidence_id)
        if subject_data.get("binding_kind") == "unbound":
            verdict_candidates.append("unknown")
            verdict_reasons.append(f"unbound_evidence:{evidence_id}")
            missing_evidence.append("commit_or_tree_binding")

        for limitation in validation.limitations:
            if _is_observer_limitation(limitation):
                degraded_observers.append(limitation)
            severity = _limitation_verdict(limitation, active_policy)
            if severity == "block":
                verdict_candidates.append("block")
                verdict_reasons.append(f"critical_limitation:{limitation}")
                blocking_evidence.append(evidence_id)
            elif severity == "quarantine":
                verdict_candidates.append("quarantine")
                verdict_reasons.append(f"high_limitation:{limitation}")
                warning_evidence.append(evidence_id)
                if "observer" in limitation.lower():
                    degraded_observers.append(limitation)
            elif severity == "warn":
                verdict_candidates.append("warn")
                verdict_reasons.append(f"medium_limitation:{limitation}")
                warning_evidence.append(evidence_id)

    external_signals = _external_suite_gate_signals(external_suite_evidence)
    verdict_candidates.extend(external_signals.verdict_candidates)
    verdict_reasons.extend(external_signals.verdict_reasons)
    blocking_evidence.extend(external_signals.blocking_evidence)
    warning_evidence.extend(external_signals.warning_evidence)
    findings_count += external_signals.findings_count
    if external_suite_evidence:
        limitations.append("external_scanner_suite_is_not_safety_proof")
        residual_risks.append("external_scanner_scope_and_binary_trust_remain_bounded")

    if all_low_trust and evidence_items and not any_runtime_observation and not verdict_candidates:
        verdict_candidates.append("unknown")
        verdict_reasons.append("all_evidence_low_trust_without_runtime_observation")
    if not any_binding_acceptable and evidence_items:
        verdict_candidates.append("unknown")
        verdict_reasons.append("binding_unbound_or_insufficient")

    missing_mandatory = [name for name in _mandatory_evidence(active_policy) if name not in _accepted_missing(active_policy)]
    for name in missing_mandatory:
        if name not in missing_evidence:
            missing_evidence.append(name)
    if missing_mandatory:
        verdict_candidates.append("unknown")
        verdict_reasons.append("missing_mandatory_evidence")
    nonmandatory_missing = [name for name in missing_evidence if name not in _accepted_missing(active_policy)]
    if nonmandatory_missing:
        if active_policy.get("requested_dynamic_judgment") is True and any("runtime" in name or "observer" in name for name in nonmandatory_missing):
            verdict_candidates.append("quarantine")
            verdict_reasons.append("missing_runtime_observer_for_dynamic_judgment")
            degraded_observers.extend(name for name in nonmandatory_missing if "runtime" in name or "observer" in name)
        else:
            verdict_candidates.append("warn")
            verdict_reasons.append("missing_evidence")

    if not verdict_candidates:
        verdict_candidates.append("allow_limited")
        verdict_reasons.append("strict_allow_limited_conditions_met")

    verdict = strongest_verdict(verdict_candidates)
    if verdict == "allow_limited":
        limitations.append("allow_limited is not proof of safety")
        required_actions = ["proceed only within the reviewed limited scope"]
        confidence = "medium"
    elif verdict == "block":
        required_actions = ["do not execute until blocking evidence is resolved"]
        confidence = "high"
    elif verdict == "quarantine":
        required_actions = ["do not run locally", "use dedicated VM or isolation if execution is necessary"]
        confidence = "medium"
    elif verdict == "unknown":
        required_actions = ["do not treat missing evidence as confidence", "collect or review missing evidence"]
        confidence = "unknown"
    else:
        required_actions = ["review warnings and limitations before execution"]
        confidence = "low"
    explanation = _build_explanation(
        verdict=verdict,
        findings_count=findings_count,
        missing_evidence=missing_evidence,
        degraded_observers=degraded_observers,
        any_binding_acceptable=any_binding_acceptable,
        evidence=evidence_items,
        limitations=limitations,
        verdict_reasons=verdict_reasons,
    )

    decision = {
        "decision_kind": DECISION_KIND,
        "schema_version": GATE_DECISION_SCHEMA_VERSION,
        "subject": _decision_subject(subject, evidence_items),
        "verdict": verdict,
        "execution_authorized": False,
        "confidence": confidence,
        "confidence_reason": "; ".join(_dedupe(verdict_reasons)) or "gate evaluator completed without authorizing execution",
        "explanation": explanation,
        "evidence_summary": {
            "findings_count": findings_count,
            "blocking_evidence": list(_dedupe(blocking_evidence)),
            "warning_evidence": list(_dedupe(warning_evidence)),
            "missing_evidence": list(_dedupe(missing_evidence)),
            "degraded_observers": list(_dedupe(degraded_observers)),
        },
        "required_actions": required_actions,
        "limitations": list(_dedupe(limitations)),
        "policy": {
            "policy_version": str(active_policy.get("policy_version", "unknown")),
            "fail_closed": active_policy.get("fail_closed") is not False,
        },
        "residual_risks": list(_dedupe(residual_risks)),
    }
    if external_suite_evidence:
        decision["evidence_refs"] = [
            dict(suite.validation.evidence_ref) for suite in external_suite_evidence
        ]
    gate_validation = validate_gate_decision(decision)
    blocking_errors = list(gate_validation.blocking_errors)
    if not gate_validation.valid:
        decision = {**decision, "verdict": "block", "confidence": "high"}
        blocking_errors.extend(gate_validation.blocking_errors)

    return GateEvaluationResult(
        decision=decision,
        valid=not blocking_errors,
        blocking_errors=tuple(_dedupe(blocking_errors)),
        warnings=tuple(_dedupe(list(gate_validation.warnings))),
        verdict_reasons=tuple(_dedupe(verdict_reasons)),
    )


def _external_suite_gate_signals(
    suites: Sequence[ExternalSuiteGateEvidence],
) -> _ExternalSuiteGateSignals:
    candidates: list[str] = []
    reasons: list[str] = []
    blocking: list[str] = []
    warning: list[str] = []
    findings_count = 0

    for suite_index, suite in enumerate(suites, start=1):
        suite_id = f"external_suite:{suite_index}"
        if not suite.validation.valid:
            candidates.append("unknown")
            reasons.append(f"external_suite_validation_failed:{suite_id}")
            warning.append(suite_id)
            continue

        entries = suite.report.get("entries")
        if not isinstance(entries, list):
            candidates.append("unknown")
            reasons.append(f"external_suite_entries_invalid:{suite_id}")
            warning.append(suite_id)
            continue

        for entry_index, entry in enumerate(entries, start=1):
            entry_id = f"{suite_id}:entry:{entry_index}"
            if not isinstance(entry, Mapping):
                candidates.append("unknown")
                reasons.append(f"external_suite_entry_invalid:{entry_id}")
                warning.append(entry_id)
                continue
            if entry.get("valid") is not True or entry.get("status") != "completed":
                candidates.append("unknown")
                reasons.append(f"external_suite_entry_not_completed:{entry_id}")
                warning.append(entry_id)
                continue

            normalized = entry.get("normalized_result")
            if not isinstance(normalized, Mapping):
                candidates.append("unknown")
                reasons.append(f"external_scanner_result_invalid:{entry_id}")
                warning.append(entry_id)
                continue

            scanner_validation = validate_external_scanner_result(normalized)
            mapping = map_external_scanner_risk(
                normalized,
                validation_result=scanner_validation,
            )
            entry_candidate = _external_mapping_verdict(mapping)
            entry_finding_count = entry.get("finding_count")
            if (
                isinstance(entry_finding_count, int)
                and not isinstance(entry_finding_count, bool)
                and entry_finding_count >= 0
            ):
                findings_count += entry_finding_count

            scanner = _mapping(normalized.get("scanner"))
            if scanner.get("trusted_binary_status") == "unverified":
                candidates.append("unknown")
                reasons.append(f"external_scanner_binary_unverified:{entry_id}")
                warning.append(entry_id)

            if not scanner_validation.valid:
                reasons.append(f"external_scanner_result_invalid:{entry_id}")
            for rule in mapping.fired_rules:
                reasons.append(f"external_scanner_rule:{rule.rule_id}")

            if entry_candidate is not None:
                candidates.append(entry_candidate)
                reasons.append(f"external_scanner_risk_mapped:{entry_id}")
                if entry_candidate == "block":
                    blocking.append(entry_id)
                else:
                    warning.append(entry_id)
            elif entry_finding_count:
                candidates.append("warn")
                reasons.append(f"external_scanner_finding_requires_review:{entry_id}")
                warning.append(entry_id)
            else:
                reasons.append(f"external_scanner_no_finding_not_safety_proof:{entry_id}")

    return _ExternalSuiteGateSignals(
        verdict_candidates=tuple(candidates),
        verdict_reasons=tuple(reasons),
        blocking_evidence=tuple(blocking),
        warning_evidence=tuple(warning),
        findings_count=findings_count,
    )


def _external_mapping_verdict(mapping: ExternalScannerRiskMappingResult) -> str | None:
    if mapping.quarantine or mapping.requires_dedicated_vm:
        return "quarantine"
    if mapping.blocks_live_execution:
        return "block"
    if mapping.requires_human_review:
        return "quarantine"
    if mapping.highest_risk_tier_effect != "none" or "raises_risk" in mapping.gate_effects:
        return "warn"
    return None


def _limitation_verdict(limitation: str, policy: Mapping[str, Any]) -> str:
    severity = highest_limitation_severity([limitation], policy)
    if severity == "critical":
        return "block"
    if severity == "high":
        return "quarantine"
    if severity == "medium":
        return "warn"
    return "allow_limited"


def _decision_subject(subject: Mapping[str, Any] | None, evidence: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    if subject is not None:
        return {
            "repo": str(subject.get("repo") or subject.get("repo_identity") or "<repo>"),
            "commit": subject.get("commit") if isinstance(subject.get("commit"), str) else None,
            "tree_hash": subject.get("tree_hash") if isinstance(subject.get("tree_hash"), str) else None,
            "binding_kind": str(subject.get("binding_kind", "unbound")),
        }
    for item in evidence:
        item_subject = _mapping(item.get("subject"))
        if item_subject:
            return {
                "repo": str(item_subject.get("repo_identity", "<repo>")),
                "commit": item_subject.get("commit") if isinstance(item_subject.get("commit"), str) else None,
                "tree_hash": item_subject.get("tree_hash") if isinstance(item_subject.get("tree_hash"), str) else None,
                "binding_kind": str(item_subject.get("binding_kind", "unbound")),
            }
    return {"repo": "<repo>", "commit": None, "tree_hash": None, "binding_kind": "unbound"}


def _build_explanation(
    *,
    verdict: str,
    findings_count: int,
    missing_evidence: list[str],
    degraded_observers: list[str],
    any_binding_acceptable: bool,
    evidence: Sequence[Mapping[str, Any]],
    limitations: list[str],
    verdict_reasons: list[str],
) -> Mapping[str, Any]:
    tokens = _explanation_tokens(
        evidence=evidence,
        limitations=limitations,
        missing_evidence=missing_evidence,
        degraded_observers=degraded_observers,
        verdict_reasons=verdict_reasons,
        any_binding_acceptable=any_binding_acceptable,
    )
    has_supply_chain_shape = any(
        _token_present(tokens, marker)
        for marker in (
            "install_script_execution",
            "package_lifecycle_hook",
            "postinstall",
            "credential_path_reference",
            "environment_access_candidate",
            "network_request",
            "network_target_string",
            "workflow_modification",
            "pull_request_target_misuse",
            "obfuscation",
            "dynamic_eval",
        )
    )
    has_no_finding = _token_present(tokens, "no_finding_not_safety_proof") or _token_present(tokens, "no_finding_scoped")
    has_missing_or_degraded = (
        bool(missing_evidence)
        or bool(degraded_observers)
        or _token_present(tokens, "missing_evidence")
        or _token_present(tokens, "runtime_observer")
        or _token_present(tokens, "observer_evidence_missing")
        or _token_present(tokens, "degraded")
        or _token_present(tokens, "unavailable")
    )
    has_observer_gap = (
        bool(degraded_observers)
        or _token_present(tokens, "runtime_observer")
        or _token_present(tokens, "observer_evidence_missing")
        or _token_present(tokens, "degraded_observer")
    )
    has_unbound = not any_binding_acceptable or _token_present(tokens, "unbound_evidence") or _token_present(tokens, "binding_unbound")
    has_raw_output_problem = _token_present(tokens, "raw_output_retained") or _token_present(tokens, "redaction_failed")
    has_critical_vulnerability = _token_present(tokens, "known_critical_vulnerability") or _token_present(tokens, "critical_vulnerability")

    if has_supply_chain_shape:
        chain_label = "synthetic supply-chain" if any("synthetic" in token for token in tokens) else "supply-chain"
        summary = (
            f"The static health report may pass, but the repository contains {chain_label} "
            "risk signals that prevent execution authorization."
        )
    elif has_missing_or_degraded and has_no_finding:
        summary = (
            "Static checks did not find blocking issues, but missing or degraded evidence "
            "prevents this from being an execution green light."
        )
    elif verdict == "block":
        summary = "Gate evidence blocks execution review; this is not execution authorization."
    elif verdict == "quarantine":
        summary = "Gate evidence requires quarantine or stronger isolation before any execution is considered."
    elif verdict == "allow_limited":
        summary = "The gate found only limited scoped evidence, but this is not a safety proof or execution authorization."
    elif verdict == "unknown":
        summary = "Static checks did not provide enough bound evidence to authorize execution."
    else:
        summary = "Static checks did not find blocking issues, but this is not enough to authorize execution."

    key_reasons: list[str] = []
    if _token_present(tokens, "install_script_execution") or _token_present(tokens, "package_lifecycle_hook") or _token_present(tokens, "postinstall"):
        key_reasons.append("A package install hook or postinstall-like script is present.")
    if (
        _token_present(tokens, "credential_path_reference")
        or _token_present(tokens, "credential_access_candidate")
        or _token_present(tokens, "environment_access_candidate")
        or _token_present(tokens, "host_home_reference")
    ):
        key_reasons.append("Credential-path or environment-access patterns are present.")
    if (
        _token_present(tokens, "network_request")
        or _token_present(tokens, "network_attempt")
        or _token_present(tokens, "network_target_string")
        or _token_present(tokens, "outbound_network_target")
        or _token_present(tokens, "network_exfiltration_indicator")
    ):
        key_reasons.append("An outbound network target or network-attempt string is present.")
    if (
        _token_present(tokens, "workflow_modification")
        or _token_present(tokens, "pull_request_target_misuse")
        or _token_present(tokens, "ci_token_abuse")
        or _token_present(tokens, "broad_token_permission")
        or _token_present(tokens, "unpinned_action")
        or _token_present(tokens, "persistence_like_behavior")
    ):
        key_reasons.append("Workflow write-risk or GitHub Actions token-abuse-like behavior is present.")
    if _token_present(tokens, "obfuscation") or _token_present(tokens, "dynamic_eval") or _token_present(tokens, "eval_candidate"):
        key_reasons.append("Obfuscation or dynamic eval-like code is present.")
    if has_critical_vulnerability:
        key_reasons.append("Critical vulnerability evidence requires review before execution.")
    if has_raw_output_problem:
        key_reasons.append("Raw scanner output retention or redaction failure blocks safe reporting.")
    if has_supply_chain_shape and has_no_finding:
        key_reasons.append("Scanner silence is not enough to authorize execution.")
    elif has_no_finding:
        key_reasons.append("No scanner finding is not proof of safety.")
    if _token_present(tokens, "low_trust_no_finding") and not (has_supply_chain_shape or (has_no_finding and has_observer_gap)):
        key_reasons.append("Low-trust no-finding evidence cannot lower repository risk.")
    if has_missing_or_degraded and not has_supply_chain_shape:
        key_reasons.append("Runtime or observer evidence is missing or degraded.")
    if has_unbound and not (has_supply_chain_shape or (has_no_finding and has_observer_gap)):
        key_reasons.append("Evidence is not bound to a commit or tree, so the gate cannot treat it as execution-ready.")
    if findings_count > 0 and not has_supply_chain_shape:
        key_reasons.append("Findings or warning evidence still require review before execution.")
    if has_no_finding and not has_supply_chain_shape:
        key_reasons.append("The gate cannot authorize execution from scanner silence alone.")
    if not key_reasons:
        key_reasons.extend(
            [
                "Evidence remains scoped to the reviewed inputs and limitations.",
                "Gate decisions and execution authorization are intentionally separate.",
            ]
        )

    next_actions: list[str] = []
    if has_supply_chain_shape:
        next_actions.append("Do not run install scripts locally.")
        if (
            _token_present(tokens, "install_script_execution")
            or _token_present(tokens, "workflow_modification")
            or _token_present(tokens, "pull_request_target_misuse")
        ):
            next_actions.append("Review the install script and workflow changes.")
        next_actions.append("Use a dedicated VM or stronger sandbox if execution is necessary.")
        if any("synthetic" in token for token in tokens):
            next_actions.append("Treat this as a quarantine-style demo, not a safety proof.")
    if has_raw_output_problem:
        next_actions.append("Discard raw output and fix redaction before sharing or relying on the report.")
    if has_critical_vulnerability:
        next_actions.append("Review or patch critical vulnerability evidence before execution.")
    if (has_missing_or_degraded or has_unbound) and not has_supply_chain_shape:
        next_actions.append("Review the limitations in the gate decision sidecar.")
        next_actions.append("Add stronger evidence or use a more isolated environment if execution is necessary.")
    if has_no_finding and not has_supply_chain_shape:
        next_actions.append("Do not run install scripts based only on a clean static report.")
    if not next_actions:
        next_actions.extend(
            [
                "Do not run install scripts locally based only on scanner silence.",
                "Review limitations and evidence gaps.",
                "Use a stronger isolated environment if execution is necessary.",
            ]
        )

    return {
        "summary": summary,
        "key_reasons": list(_dedupe(key_reasons)),
        "next_actions": list(_dedupe(next_actions)),
    }


def _explanation_tokens(
    *,
    evidence: Sequence[Mapping[str, Any]],
    limitations: list[str],
    missing_evidence: list[str],
    degraded_observers: list[str],
    verdict_reasons: list[str],
    any_binding_acceptable: bool,
) -> set[str]:
    tokens: set[str] = set()
    for item in evidence:
        tokens.update(_tokens(item))
        classification = _mapping(item.get("classification"))
        finding = _mapping(item.get("finding"))
        raw_handling = _mapping(item.get("raw_handling"))
        trust = _mapping(item.get("trust"))
        subject = _mapping(item.get("subject"))
        if classification.get("category") == "known_vulnerability" and classification.get("severity") == "block":
            tokens.add("critical_vulnerability")
        if finding.get("present") is False:
            tokens.add("no_finding_not_safety_proof")
            if trust.get("level") in LOW_TRUST_LEVELS:
                tokens.add("low_trust_no_finding")
        if subject.get("binding_kind") == "unbound":
            tokens.add("unbound_evidence")
        if raw_handling.get("raw_output_retained") is True or raw_handling.get("raw_stdout_retained") is True or raw_handling.get("raw_stderr_retained") is True:
            tokens.add("raw_output_retained")
        if raw_handling.get("redaction_status") == "failed":
            tokens.add("redaction_failed")
    for value in (*limitations, *missing_evidence, *degraded_observers, *verdict_reasons):
        tokens.add(_normalize_token(str(value)))
    if not any_binding_acceptable:
        tokens.add("binding_unbound_or_insufficient")
    if missing_evidence:
        tokens.add("missing_evidence")
    if degraded_observers:
        tokens.add("degraded_observer")
    return tokens


def _token_present(tokens: set[str], marker: str) -> bool:
    normalized = _normalize_token(marker)
    return any(normalized in token for token in tokens)


def _is_observer_limitation(limitation: str) -> bool:
    normalized = limitation.lower()
    return "observer" in normalized and (
        "missing" in normalized or "degraded" in normalized or "unavailable" in normalized
    )


def _has_quarantine_signal(tokens: set[str], classification: Mapping[str, Any]) -> bool:
    if _has_any(tokens, QUARANTINE_MARKERS):
        return True
    if classification.get("category") == "secret" and "verified_secret" in tokens:
        return True
    if "credential_path_reference" in tokens and ("network_request" in tokens or "network_attempt" in tokens):
        return True
    if {"install_script_execution", "download_exec_chain"}.issubset(tokens):
        return True
    if {"obfuscation", "dynamic_eval", "network_request"}.issubset(tokens):
        return True
    if {"pull_request_target_misuse", "untrusted_checkout"}.issubset(tokens) or any(
        "pull_request_target_misuse" in token and "untrusted_checkout" in token for token in tokens
    ):
        return True
    if {"broad_token_permission", "unpinned_action"}.issubset(tokens):
        return True
    if {"docker_socket_reference", "subprocess_indicator"}.issubset(tokens):
        return True
    if "known_critical_vulnerability" in tokens and "suspicious_runtime_behavior" in tokens:
        return True
    return False


def _has_warn_signal(tokens: set[str], classification: Mapping[str, Any]) -> bool:
    if _has_any(tokens, WARN_MARKERS):
        return True
    if classification.get("category") == "known_vulnerability":
        return True
    if classification.get("subcategory") in {"low_repo_posture", "unsupported_scanner_version"}:
        return True
    return False


def _tokens(item: Mapping[str, Any]) -> set[str]:
    values: list[str] = []
    classification = _mapping(item.get("classification"))
    finding = _mapping(item.get("finding"))
    trust = _mapping(item.get("trust"))
    raw_handling = _mapping(item.get("raw_handling"))
    effects = _mapping(item.get("effects"))
    for value in (
        classification.get("category"),
        classification.get("subcategory"),
        classification.get("severity"),
        finding.get("redacted_summary"),
        raw_handling.get("redaction_status"),
        effects.get("recommended_gate_effect"),
    ):
        if isinstance(value, str):
            values.append(value)
    values.extend(str(item) for item in trust.get("limitations", []) if isinstance(item, str))
    values.extend(str(item) for item in item.get("residual_risks", []) if isinstance(item, str))
    return {_normalize_token(value) for value in values}


def _normalize_token(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_").replace("/", "_")


def _has_any(tokens: set[str], markers: set[str]) -> bool:
    return any(marker.lower().replace(" ", "_") in token for marker in markers for token in tokens)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mandatory_evidence(policy: Mapping[str, Any]) -> list[str]:
    return [item for item in policy.get("mandatory_evidence", []) if isinstance(item, str)]


def _accepted_missing(policy: Mapping[str, Any]) -> list[str]:
    return [item for item in policy.get("accepted_missing_evidence", []) if isinstance(item, str)]


def _missing_evidence(policy: Mapping[str, Any]) -> list[str]:
    return [item for item in policy.get("missing_evidence", []) if isinstance(item, str)]


def _dedupe(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
