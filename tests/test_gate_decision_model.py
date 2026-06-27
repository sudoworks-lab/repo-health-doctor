from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.gate.validation import validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]


def _valid_gate_decision() -> dict[str, object]:
    return {
        "decision_kind": "repo_health_gate_decision",
        "schema_version": "0.1-draft",
        "subject": {
            "repo": "<repo>",
            "commit": None,
            "tree_hash": None,
            "binding_kind": "unbound",
        },
        "verdict": "warn",
        "execution_authorized": False,
        "confidence": "low",
        "confidence_reason": "synthetic unit test gate decision candidate",
        "explanation": {
            "summary": "Static checks did not find blocking issues, but this is not enough to authorize execution.",
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
        },
        "evidence_summary": {
            "findings_count": 0,
            "blocking_evidence": [],
            "warning_evidence": [],
            "missing_evidence": ["commit_binding_missing"],
            "degraded_observers": [],
        },
        "required_actions": ["review limitations before execution"],
        "limitations": ["not_execution_authorization", "candidate_only"],
        "policy": {
            "policy_version": "test-policy",
            "fail_closed": True,
        },
        "residual_risks": ["gate_evaluator_not_implemented"],
    }


class GateDecisionModelTests(unittest.TestCase):
    def test_schema_file_parses_and_is_closed(self) -> None:
        schema = json.loads((ROOT / "schemas" / "gate-decision.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["enum"], ["0.1-draft"])
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(schema["properties"]["execution_authorized"]["const"], False)
        self.assertIn("explanation", schema["required"])

    def test_valid_gate_decision_candidate_passes_validation(self) -> None:
        decision = _valid_gate_decision()
        result = validate_gate_decision(decision)
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("not_execution_authorization", result.limitations)
        explanation = decision["explanation"]
        assert isinstance(explanation, dict)
        self.assertIn("No scanner finding is not proof of safety.", explanation["key_reasons"])

    def test_execution_authorization_is_forbidden(self) -> None:
        data = _valid_gate_decision()
        data["execution_authorized"] = True
        result = validate_gate_decision(data)
        self.assertFalse(result.valid)
        self.assertIn("execution_authorized_must_be_false", result.blocking_errors)

    def test_limitations_are_required(self) -> None:
        data = _valid_gate_decision()
        data["limitations"] = []
        result = validate_gate_decision(data)
        self.assertFalse(result.valid)
        self.assertIn("limitations_empty", result.blocking_errors)

    def test_human_readable_explanation_is_required(self) -> None:
        data = _valid_gate_decision()
        data["explanation"] = {"summary": "", "key_reasons": [], "next_actions": []}
        result = validate_gate_decision(data)
        self.assertFalse(result.valid)
        self.assertIn("explanation_summary_required", result.blocking_errors)
        self.assertIn("explanation_key_reasons_required", result.blocking_errors)
        self.assertIn("explanation_next_actions_required", result.blocking_errors)

    def test_allow_limited_is_not_execution_authorization(self) -> None:
        data = _valid_gate_decision()
        data["verdict"] = "allow_limited"
        result = validate_gate_decision(data)
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("allow_limited_is_not_execution_authorization", result.warnings)
        self.assertFalse(data["execution_authorized"])

    def test_validator_rejects_unknown_top_level_field(self) -> None:
        data = copy.deepcopy(_valid_gate_decision())
        data["safe"] = True
        result = validate_gate_decision(data)
        self.assertFalse(result.valid)
        self.assertIn("gate_decision_top_level_required_or_unknown_field", result.blocking_errors)


if __name__ == "__main__":
    unittest.main()
