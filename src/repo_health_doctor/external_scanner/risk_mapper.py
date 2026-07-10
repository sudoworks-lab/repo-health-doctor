"""Map external scanner evidence to risk and gate effects.

The mapper consumes already supplied JSON-compatible evidence. It never runs or
installs scanners, contacts a network, starts Docker, calls remote APIs,
executes target code, persists raw scanner output, or authorizes live execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .result_validator import ExternalScannerValidationResult, validate_external_scanner_result
from .risk_policy import RISK_RULE_IDS, load_external_scanner_risk_policy, risk_rules_by_id


RISK_TIER_ORDER = {
    "none": 0,
    "raise_to_T2": 1,
    "raise_to_T3": 2,
    "raise_to_T4": 3,
    "T5_candidate": 4,
    "raise_to_T5": 5,
}
GATE_EFFECT_ORDER = {
    "evidence_only": 0,
    "raises_risk": 1,
    "requires_human_review": 2,
    "blocks_live_execution": 3,
    "requires_dedicated_vm": 4,
    "quarantine": 5,
}

KNOWN_PRIMARY_CATEGORIES = {
    "secret",
    "credential_access",
    "vulnerability",
    "malicious_behavior",
    "ci_cd_risk",
    "repo_posture",
    "dependency_risk",
    "sandbox_escape_risk",
    "scanner_failure",
    "redaction_failure",
    "unknown",
}
KNOWN_SECONDARY_CATEGORIES = {
    "verified_secret",
    "secret_like_value",
    "credential_path_reference",
    "host_home_reference",
    "known_critical_vulnerability",
    "install_script_execution",
    "download_exec_chain",
    "obfuscation",
    "dynamic_eval",
    "network_request",
    "network_exfiltration_indicator",
    "docker_socket_reference",
    "pull_request_target_misuse",
    "broad_token_permission",
    "unpinned_action",
    "dependency_confusion_signal",
    "low_security_posture",
    "unsupported_scanner_version",
    "scanner_timeout",
    "raw_secret_leak",
    "raw_host_path_leak",
    "unknown",
}
SUPPORTED_CHAIN_RELATIONS = {
    "same_execution_path",
    "credential_to_network",
    "ci_token_to_untrusted_code",
    "docker_to_host_access",
    "lifecycle_to_runtime",
}
ALLOWED_RISK_TIER_EFFECTS = set(RISK_TIER_ORDER)
ALLOWED_GATE_EFFECTS = set(GATE_EFFECT_ORDER)
LOW_TRUST_LEVELS = {"untrusted_import", "schema_validated_import"}
SUSPICIOUS_RUNTIME_SECONDARIES = {
    "download_exec_chain",
    "dynamic_eval",
    "network_request",
    "network_exfiltration_indicator",
    "docker_socket_reference",
}


@dataclass(frozen=True)
class FiredRiskRule:
    rule_id: str
    description: str
    risk_tier_effect: str
    gate_effects: tuple[str, ...]
    evidence: tuple[str, ...]
    requires_human_review: bool
    blocks_live_execution: bool
    cannot_lower_risk: bool
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "risk_tier_effect": self.risk_tier_effect,
            "gate_effects": list(self.gate_effects),
            "evidence": list(self.evidence),
            "requires_human_review": self.requires_human_review,
            "blocks_live_execution": self.blocks_live_execution,
            "cannot_lower_risk": self.cannot_lower_risk,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ExternalScannerRiskMappingResult:
    highest_risk_tier_effect: str
    gate_effects: tuple[str, ...]
    fired_rules: tuple[FiredRiskRule, ...]
    blocking_rules: tuple[str, ...]
    warnings: tuple[str, ...]
    cannot_lower_risk: bool
    requires_human_review: bool
    blocks_live_execution: bool
    requires_dedicated_vm: bool
    quarantine: bool
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]
    evidence_summary: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "highest_risk_tier_effect": self.highest_risk_tier_effect,
            "gate_effects": list(self.gate_effects),
            "fired_rules": [rule.to_dict() for rule in self.fired_rules],
            "blocking_rules": list(self.blocking_rules),
            "warnings": list(self.warnings),
            "cannot_lower_risk": self.cannot_lower_risk,
            "requires_human_review": self.requires_human_review,
            "blocks_live_execution": self.blocks_live_execution,
            "requires_dedicated_vm": self.requires_dedicated_vm,
            "quarantine": self.quarantine,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
            "evidence_summary": dict(self.evidence_summary),
        }


def map_external_scanner_risk(
    data: Mapping[str, Any],
    validation_result: ExternalScannerValidationResult | None = None,
    policy: Mapping[str, Any] | None = None,
) -> ExternalScannerRiskMappingResult:
    """Map supplied external scanner evidence into risk and gate effects."""
    validation = validation_result or validate_external_scanner_result(data)
    active_policy = policy or load_external_scanner_risk_policy()
    policy_rules = risk_rules_by_id(active_policy)

    fired: dict[str, FiredRiskRule] = {}
    blocking_rules: list[str] = []
    warnings: list[str] = list(validation.warnings)
    extra_gate_effects: list[str] = []
    extra_risk_effects: list[str] = []

    missing_rules = [rule_id for rule_id in RISK_RULE_IDS if rule_id not in policy_rules]
    if missing_rules:
        warnings.append("risk_policy_missing_required_rules")
        blocking_rules.extend(missing_rules)
        extra_gate_effects.append("quarantine")
        extra_risk_effects.append("T5_candidate")

    facts = _collect_facts(data)
    _check_interpretability(data, facts, warnings, blocking_rules, extra_gate_effects, extra_risk_effects)

    def fire(rule_id: str, evidence: Iterable[str]) -> None:
        rule = policy_rules.get(rule_id)
        if rule is None:
            warnings.append(f"risk_policy_rule_unavailable:{rule_id}")
            blocking_rules.append(rule_id)
            extra_gate_effects.append("quarantine")
            extra_risk_effects.append("T5_candidate")
            return
        if rule_id not in fired:
            gate_effects = tuple(_string_items(rule.get("gate_effects")))
            fired[rule_id] = FiredRiskRule(
                rule_id=rule_id,
                description=str(rule.get("description", "")),
                risk_tier_effect=str(rule.get("risk_tier_effect", "T5_candidate")),
                gate_effects=gate_effects,
                evidence=tuple(_dedupe(evidence)),
                requires_human_review=rule.get("requires_human_review") is True,
                blocks_live_execution=rule.get("blocks_live_execution") is True,
                cannot_lower_risk=rule.get("cannot_lower_risk") is not False,
                limitations=tuple(_string_items(rule.get("limitations"))),
            )

    secondary = facts["secondary_categories"]
    tokens = facts["evidence_tokens"]
    relations = facts["edge_relations"]

    if {"verified_secret", "secret_like_value"} & secondary:
        fire("RISK001", ("secondary_category:secret_or_secret_like",))
    if _redaction_flag(data, "raw_secret_present") or "raw_secret_leak" in secondary:
        fire("RISK002", ("redaction_status.raw_secret_present", "secondary_category:raw_secret_leak"))
    if "credential_path_reference" in secondary:
        fire("RISK003", ("secondary_category:credential_path_reference",))
    if _has_credential_network_chain(secondary, relations):
        fire("RISK004", ("credential_access", "network_request", "credential_to_network"))
    if {"install_script_execution", "download_exec_chain"}.issubset(secondary):
        fire("RISK005", ("install_script_execution", "download_exec_chain"))
    if {"obfuscation", "dynamic_eval"}.issubset(secondary):
        fire("RISK006", ("obfuscation", "dynamic_eval"))
    if {"obfuscation", "dynamic_eval"}.issubset(secondary) and _has_network_signal(secondary, relations):
        fire("RISK007", ("obfuscation", "dynamic_eval", "network_request"))
    if "docker_socket_reference" in secondary:
        fire("RISK008", ("secondary_category:docker_socket_reference",))
    if "docker_socket_reference" in secondary and ("docker_to_host_access" in relations or "subprocess_indicator" in tokens):
        fire("RISK009", ("docker_socket_reference", "subprocess_indicator", "docker_to_host_access"))
    if "host_home_reference" in secondary or _redaction_flag(data, "raw_host_path_present") or "raw_host_path_leak" in secondary:
        fire("RISK010", ("host_home_reference", "raw_host_path_present"))
    if "pull_request_target_misuse" in secondary and ("untrusted_checkout" in tokens or "ci_token_to_untrusted_code" in relations):
        fire("RISK011", ("pull_request_target_misuse", "untrusted_checkout"))
    if {"broad_token_permission", "unpinned_action"}.issubset(secondary):
        fire("RISK012", ("broad_token_permission", "unpinned_action"))
    if "verified_secret" in secondary and ("ci_exposure" in tokens or "ci_token_to_untrusted_code" in relations):
        fire("RISK013", ("verified_secret", "ci_exposure"))
    if "known_critical_vulnerability" in secondary:
        fire("RISK014", ("known_critical_vulnerability",))
    if "known_critical_vulnerability" in secondary and (SUSPICIOUS_RUNTIME_SECONDARIES & secondary or "lifecycle_to_runtime" in relations):
        fire("RISK015", ("known_critical_vulnerability", "suspicious_runtime_behavior"))
    if "low_security_posture" in secondary:
        fire("RISK016", ("low_security_posture",))
    if "scanner_failure_claims_no_findings" in validation.blocking_errors or (
        "scanner_failure" in facts["primary_categories"] and _summary_value(data, "outcome") == "no_findings_in_scope"
    ):
        fire("RISK017", ("scanner_failure", "no_findings_in_scope"))
    if _scanner_unsupported(data) or "unsupported_version_claims_no_findings" in validation.blocking_errors:
        fire("RISK018", ("scanner.unsupported_version",))
    if not validation.limitations or "limitations_empty" in validation.blocking_errors or "limitations_must_be_array" in validation.blocking_errors:
        fire("RISK019", ("limitations",))
    if _is_low_trust_no_finding(data):
        fire("RISK020", ("low_trust", "no_findings_in_scope"))

    if not validation.valid:
        warnings.append("invalid_validation_result_fail_closed")
        blocking_rules.extend(validation.blocking_errors)
        extra_gate_effects.append("quarantine")
        extra_risk_effects.append("T5_candidate")

    gate_effects = _merge_gate_effects(rule.gate_effects for rule in fired.values())
    gate_effects.extend(effect for effect in extra_gate_effects if effect in ALLOWED_GATE_EFFECTS)
    if not gate_effects:
        gate_effects.append("evidence_only")
    gate_effects = _dedupe(gate_effects)

    risk_effects = [rule.risk_tier_effect for rule in fired.values() if rule.risk_tier_effect in ALLOWED_RISK_TIER_EFFECTS]
    risk_effects.extend(effect for effect in extra_risk_effects if effect in ALLOWED_RISK_TIER_EFFECTS)
    highest_risk = _highest_risk_tier_effect(risk_effects)

    normalized_gates = tuple(sorted(gate_effects, key=lambda item: GATE_EFFECT_ORDER[item]))
    blocking_rule_ids = [
        rule.rule_id
        for rule in fired.values()
        if rule.blocks_live_execution or "quarantine" in rule.gate_effects or "blocks_live_execution" in rule.gate_effects
    ]
    blocking_rule_ids.extend(blocking_rules)
    requires_human_review = any(rule.requires_human_review for rule in fired.values()) or "requires_human_review" in normalized_gates
    blocks_live_execution = any(rule.blocks_live_execution for rule in fired.values()) or "blocks_live_execution" in normalized_gates or "quarantine" in normalized_gates
    return ExternalScannerRiskMappingResult(
        highest_risk_tier_effect=highest_risk,
        gate_effects=normalized_gates,
        fired_rules=tuple(sorted(fired.values(), key=lambda rule: rule.rule_id)),
        blocking_rules=tuple(_dedupe(blocking_rule_ids)),
        warnings=tuple(_dedupe(warnings)),
        cannot_lower_risk=True,
        requires_human_review=requires_human_review,
        blocks_live_execution=blocks_live_execution,
        requires_dedicated_vm="requires_dedicated_vm" in normalized_gates,
        quarantine="quarantine" in normalized_gates,
        limitations=validation.limitations,
        residual_risks=validation.residual_risks,
        evidence_summary={
            "outcome": _summary_value(data, "outcome"),
            "trust_level": data.get("trust_level"),
            "execution_authorized": data.get("execution_authorized") is True,
            "finding_count": len(data.get("findings", [])) if isinstance(data.get("findings"), list) else 0,
            "primary_categories": sorted(facts["primary_categories"]),
            "secondary_categories": sorted(facts["secondary_categories"]),
            "edge_relations": sorted(facts["edge_relations"]),
        },
    )


def _collect_facts(data: Mapping[str, Any]) -> dict[str, set[str]]:
    primary: set[str] = set()
    secondary: set[str] = set()
    tokens: set[str] = set()
    relations: set[str] = set()
    for item in _evidence_items(data):
        primary_value = item.get("primary_category")
        secondary_value = item.get("secondary_category")
        if isinstance(primary_value, str):
            primary.add(primary_value)
        if isinstance(secondary_value, str):
            secondary.add(secondary_value)
        for field in ("evidence", "title", "redacted_description", "redacted_summary"):
            value = item.get(field)
            if isinstance(value, list):
                tokens.update(item for item in value if isinstance(item, str))
            elif isinstance(value, str):
                tokens.add(value)
    for edge in _list_of_mappings(data.get("evidence_edges")):
        relation = edge.get("relation")
        if isinstance(relation, str):
            relations.add(relation)
    return {
        "primary_categories": primary,
        "secondary_categories": secondary,
        "evidence_tokens": tokens,
        "edge_relations": relations,
    }


def _evidence_items(data: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    yield from _list_of_mappings(data.get("findings"))
    yield from _list_of_mappings(data.get("evidence_nodes"))


def _check_interpretability(
    data: Mapping[str, Any],
    facts: Mapping[str, set[str]],
    warnings: list[str],
    blocking_rules: list[str],
    gate_effects: list[str],
    risk_effects: list[str],
) -> None:
    unknown_primary = facts["primary_categories"] - KNOWN_PRIMARY_CATEGORIES
    unknown_secondary = facts["secondary_categories"] - KNOWN_SECONDARY_CATEGORIES
    if "unknown" in facts["primary_categories"] or "unknown" in facts["secondary_categories"] or unknown_primary or unknown_secondary:
        warnings.append("unknown_safety_relevant_category")
        blocking_rules.append("unknown_safety_relevant_category")
        gate_effects.append("requires_human_review")
        risk_effects.append("T5_candidate")

    for relation in facts["edge_relations"]:
        if relation not in SUPPORTED_CHAIN_RELATIONS:
            warnings.append(f"unsupported_evidence_relation:{relation}")
            gate_effects.append("requires_human_review")

    for finding in _list_of_mappings(data.get("findings")):
        gate_effect = finding.get("gate_effect")
        if isinstance(gate_effect, str) and gate_effect not in ALLOWED_GATE_EFFECTS:
            warnings.append("unknown_gate_effect")
            blocking_rules.append("unknown_gate_effect")
            gate_effects.append("quarantine")
            risk_effects.append("T5_candidate")
        risk_mapping = finding.get("risk_mapping")
        if isinstance(risk_mapping, Mapping):
            risk_effect = risk_mapping.get("risk_tier_effect")
            if isinstance(risk_effect, str) and risk_effect not in ALLOWED_RISK_TIER_EFFECTS:
                warnings.append("unknown_risk_tier_effect")
                blocking_rules.append("unknown_risk_tier_effect")
                gate_effects.append("quarantine")
                risk_effects.append("T5_candidate")
            for rule_id in _string_items(risk_mapping.get("rule_ids")):
                if rule_id not in RISK_RULE_IDS:
                    warnings.append("unknown_risk_rule_id")
                    blocking_rules.append("unknown_risk_rule_id")
                    gate_effects.append("quarantine")
                    risk_effects.append("T5_candidate")


def _has_credential_network_chain(secondary: set[str], relations: set[str]) -> bool:
    credential = bool({"credential_path_reference", "host_home_reference"} & secondary)
    network = _has_network_signal(secondary, relations)
    return credential and network


def _has_network_signal(secondary: set[str], relations: set[str]) -> bool:
    return bool({"network_request", "network_exfiltration_indicator"} & secondary) or "credential_to_network" in relations


def _redaction_flag(data: Mapping[str, Any], field: str) -> bool:
    redaction = data.get("redaction_status")
    return isinstance(redaction, Mapping) and redaction.get(field) is True


def _scanner_unsupported(data: Mapping[str, Any]) -> bool:
    scanner = data.get("scanner")
    return isinstance(scanner, Mapping) and scanner.get("unsupported_version") is True


def _is_low_trust_no_finding(data: Mapping[str, Any]) -> bool:
    return data.get("trust_level") in LOW_TRUST_LEVELS and _summary_value(data, "outcome") == "no_findings_in_scope"


def _summary_value(data: Mapping[str, Any], field: str) -> object:
    summary = data.get("summary")
    return summary.get(field) if isinstance(summary, Mapping) else None


def _list_of_mappings(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _string_items(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _merge_gate_effects(effect_groups: Iterable[Iterable[str]]) -> list[str]:
    effects: list[str] = []
    for group in effect_groups:
        effects.extend(effect for effect in group if effect in ALLOWED_GATE_EFFECTS)
    return effects


def _highest_risk_tier_effect(effects: Iterable[str]) -> str:
    values = [effect for effect in effects if effect in RISK_TIER_ORDER]
    if not values:
        return "none"
    return max(values, key=lambda item: RISK_TIER_ORDER[item])


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
