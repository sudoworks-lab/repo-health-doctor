from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.evidence.validation import validate_evidence


ROOT = Path(__file__).resolve().parents[1]


def _valid_evidence() -> dict[str, object]:
    return {
        "evidence_id": "ev-test-001",
        "schema_version": "0.1-draft",
        "evidence_kind": "repo_health_evidence",
        "source": {
            "tool_name": "repo-health-doctor",
            "tool_version": "0.1.0",
            "adapter_name": "unit-test",
            "adapter_version": "0.1-draft",
            "execution_mode": "native_static",
        },
        "subject": {
            "repo_identity": "<repo>",
            "commit": None,
            "tree_hash": None,
            "path_scope": ["<repo>"],
            "binding_kind": "unbound",
        },
        "classification": {
            "category": "repo_posture",
            "subcategory": "missing_readme",
            "severity": "warn",
            "confidence": "low",
            "confidence_reason": "synthetic unit test fixture",
        },
        "finding": {
            "present": True,
            "count": 1,
            "locations": [{"path": "<repo>/README.md", "line": None}],
            "redacted_summary": "README is missing.",
        },
        "raw_handling": {
            "raw_output_retained": False,
            "raw_stdout_retained": False,
            "raw_stderr_retained": False,
            "redaction_status": "not_applicable",
            "redaction_failures": [],
        },
        "trust": {
            "level": "schema_validated",
            "commit_bound": False,
            "signature_verified": False,
            "binary_attested": False,
            "limitations": ["synthetic_fixture", "not_execution_authorization"],
        },
        "effects": {
            "can_lower_risk": False,
            "can_authorize_execution": False,
            "recommended_gate_effect": "requires_human_review",
        },
        "residual_risks": ["commit_binding_missing"],
    }


class EvidenceModelTests(unittest.TestCase):
    def test_schema_file_parses_and_is_closed(self) -> None:
        schema = json.loads((ROOT / "schemas" / "evidence.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["enum"], ["0.1-draft"])
        self.assertIs(schema["additionalProperties"], False)
        self.assertFalse(schema["properties"]["raw_handling"]["$ref"] == "")

    def test_valid_evidence_candidate_passes_validation(self) -> None:
        result = validate_evidence(_valid_evidence())
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("synthetic_fixture", result.limitations)

    def test_execution_authorization_is_forbidden(self) -> None:
        data = _valid_evidence()
        data["effects"]["can_authorize_execution"] = True  # type: ignore[index]
        result = validate_evidence(data)
        self.assertFalse(result.valid)
        self.assertIn("effects_can_authorize_execution_must_be_false", result.blocking_errors)

    def test_no_finding_cannot_lower_risk(self) -> None:
        data = _valid_evidence()
        data["finding"] = {"present": False, "count": 0, "locations": [], "redacted_summary": "No finding in scope."}
        data["effects"]["can_lower_risk"] = True  # type: ignore[index]
        result = validate_evidence(data)
        self.assertFalse(result.valid)
        self.assertIn("no_finding_cannot_lower_risk", result.blocking_errors)

    def test_low_trust_cannot_lower_risk(self) -> None:
        data = _valid_evidence()
        data["trust"]["level"] = "untrusted_import"  # type: ignore[index]
        data["effects"]["can_lower_risk"] = True  # type: ignore[index]
        result = validate_evidence(data)
        self.assertFalse(result.valid)
        self.assertIn("low_trust_cannot_lower_risk", result.blocking_errors)

    def test_limitations_are_required(self) -> None:
        data = _valid_evidence()
        data["trust"]["limitations"] = []  # type: ignore[index]
        result = validate_evidence(data)
        self.assertFalse(result.valid)
        self.assertIn("limitations_empty", result.blocking_errors)

    def test_raw_output_retention_is_blocking(self) -> None:
        data = _valid_evidence()
        data["raw_handling"]["raw_output_retained"] = True  # type: ignore[index]
        result = validate_evidence(data)
        self.assertFalse(result.valid)
        self.assertIn("raw_output_retained_must_be_false", result.blocking_errors)

    def test_validator_rejects_unknown_top_level_field(self) -> None:
        data = copy.deepcopy(_valid_evidence())
        data["raw_secret"] = "dummy-redacted"
        result = validate_evidence(data)
        self.assertFalse(result.valid)
        self.assertIn("evidence_top_level_required_or_unknown_field", result.blocking_errors)


if __name__ == "__main__":
    unittest.main()
