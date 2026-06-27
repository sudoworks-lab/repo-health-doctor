from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
RESULT_FIXTURES = FIXTURE_ROOT / "external-scanner-results"
RISK_FIXTURES = FIXTURE_ROOT / "external-scanner-risk-rules"
RISK_EXPECTED_FIXTURES = RISK_FIXTURES / "expected"
IMPORTED_REPORT_FIXTURES = FIXTURE_ROOT / "imported-external-scanner-reports"
SCANNER_PLAN_FIXTURES = FIXTURE_ROOT / "external-scanner-plans"
ZIZMOR_STYLE_FIXTURES = FIXTURE_ROOT / "zizmor-style"
SCANNER_READINESS_FIXTURES = FIXTURE_ROOT / "external-scanner-readiness"
ZIZMOR_DOCKER_FIXTURES = FIXTURE_ROOT / "zizmor-docker"
SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"


def load_json(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    assert isinstance(data, dict)
    return data


def load_external_scanner_result_fixture(name: str) -> dict[str, object]:
    return load_json(RESULT_FIXTURES / name)


def load_external_scanner_risk_fixture(name: str) -> dict[str, object]:
    return load_json(RISK_FIXTURES / name)


def load_external_scanner_risk_expected(name: str) -> dict[str, object]:
    return load_json(RISK_EXPECTED_FIXTURES / f"{name}.expected.json")


def load_imported_external_report_fixture(name: str) -> dict[str, object]:
    return load_json(IMPORTED_REPORT_FIXTURES / name)


def load_external_scanner_plan_fixture(name: str) -> dict[str, object]:
    return load_json(SCANNER_PLAN_FIXTURES / name)


def load_zizmor_style_fixture(name: str) -> dict[str, object]:
    return load_json(ZIZMOR_STYLE_FIXTURES / name)


def load_external_scanner_readiness_fixture(name: str) -> dict[str, object]:
    return load_json(SCANNER_READINESS_FIXTURES / name)


def load_zizmor_docker_fixture(name: str) -> dict[str, object]:
    return load_json(ZIZMOR_DOCKER_FIXTURES / name)


def base_external_scanner_result() -> dict[str, object]:
    return load_external_scanner_result_fixture("benign_minimal.json")


def build_external_scanner_risk_result(scenario: dict[str, object]) -> dict[str, object]:
    data = deepcopy(base_external_scanner_result())
    for section in ("scanner", "execution_context", "summary", "mapping_result", "redaction_status", "binding", "input_scope"):
        override = scenario.get(section)
        if isinstance(override, dict):
            data[section].update(override)  # type: ignore[index, union-attr]
    if "trust_level" in scenario:
        data["trust_level"] = scenario["trust_level"]
    if scenario.get("remove_limitations") is True:
        data.pop("limitations")

    findings = [_finding(index, item) for index, item in enumerate(_list_of_dicts(scenario.get("findings")), start=1)]
    data["findings"] = findings
    data["evidence_nodes"] = [_node(index, item) for index, item in enumerate(_list_of_dicts(scenario.get("evidence_nodes")), start=1)]
    data["evidence_edges"] = [_edge(index, item) for index, item in enumerate(_list_of_dicts(scenario.get("evidence_edges")), start=1)]

    summary = data["summary"]  # type: ignore[assignment]
    if isinstance(summary, dict):
        summary["finding_count"] = len(findings)
        if findings and "outcome" not in scenario.get("summary", {}):
            summary["outcome"] = "findings_present"
    mapping_result = data["mapping_result"]  # type: ignore[assignment]
    if isinstance(mapping_result, dict):
        mapping_result["risk_tier_effect"] = "none"
        mapping_result["gate_effects"] = ["evidence_only"]
        mapping_result["rules_fired"] = []
        mapping_result["risk_lowering_allowed"] = False
    return data


def fired_rule_ids(result: object) -> list[str]:
    return [rule.rule_id for rule in result.fired_rules]


def _finding(index: int, item: dict[str, object]) -> dict[str, object]:
    primary = str(item.get("primary_category", "unknown"))
    secondary = str(item.get("secondary_category", "unknown"))
    evidence = item.get("evidence", [])
    return {
        "finding_id": f"risk-fixture-{index}",
        "scanner_rule_id": f"fixture.{secondary}",
        "primary_category": primary,
        "secondary_category": secondary,
        "scanner_severity": "fixture",
        "normalized_severity": "block" if primary in {"secret", "scanner_failure", "redaction_failure"} else "warn",
        "confidence": "high",
        "title": str(item.get("title", f"Fixture {secondary}")),
        "redacted_description": str(item.get("redacted_description", "Synthetic fixture evidence.")),
        "location": {
            "path": "<repo>/fixture",
            "line": index,
            "column": 1,
        },
        "evidence": evidence if isinstance(evidence, list) else [],
        "risk_mapping": {
            "risk_tier_effect": str(item.get("risk_tier_effect", "none")),
            "rule_ids": item.get("rule_ids", []),
        },
        "gate_effect": str(item.get("gate_effect", "evidence_only")),
    }


def _node(index: int, item: dict[str, object]) -> dict[str, object]:
    return {
        "node_id": str(item.get("node_id", f"node-{index}")),
        "primary_category": str(item.get("primary_category", "unknown")),
        "secondary_category": str(item.get("secondary_category", "unknown")),
        "title": str(item.get("title", "Synthetic evidence node")),
        "redacted_summary": str(item.get("redacted_summary", "Synthetic fixture node.")),
        "location": {
            "path": "<repo>/fixture",
            "line": index,
            "column": 1,
        },
        "confidence": str(item.get("confidence", "high")),
    }


def _edge(index: int, item: dict[str, object]) -> dict[str, object]:
    return {
        "edge_id": str(item.get("edge_id", f"edge-{index}")),
        "from_node": str(item.get("from_node", "node-1")),
        "to_node": str(item.get("to_node", "node-2")),
        "relation": str(item.get("relation", "same_execution_path")),
    }


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
