from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.doctor import diagnose_repo
from repo_health_doctor.gate import evaluate_gate_decision_from_v3_report, validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]


class GateEvaluatorV3CompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = diagnose_repo(ROOT / "tests" / "fixtures" / "demo-repo", public_safety=True)

    def test_v3_report_generates_valid_gate_decision(self) -> None:
        decision = evaluate_gate_decision_from_v3_report(self.report)
        validation = validate_gate_decision(decision)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertFalse(decision["execution_authorized"])
        self.assertTrue(decision["limitations"])
        self.assertTrue(decision["explanation"]["summary"])
        self.assertIn(decision["verdict"], {"warn", "unknown"})

    def test_existing_v3_report_is_not_mutated(self) -> None:
        before = json.dumps(self.report, sort_keys=True)
        evaluate_gate_decision_from_v3_report(self.report)
        after = json.dumps(self.report, sort_keys=True)
        self.assertEqual(before, after)
        self.assertEqual(self.report["schema_version"], "1.1")
        self.assertNotIn("gate_decision", self.report)

    def test_v3_block_report_blocks_gate_decision(self) -> None:
        report = {
            "tool": "repo-health-doctor",
            "version": "0.1.0",
            "schema_version": "1.1",
            "repo_path": "<repo>",
            "overall_status": "block",
            "summary": {"pass": 0, "warn": 0, "block": 1},
            "checks": [
                {
                    "name": "secrets_scan",
                    "status": "block",
                    "summary": "Secret-like findings should be reviewed.",
                    "details": {
                        "findings": [
                            {
                                "rule_id": "rhd.secret.generic_api_key",
                                "severity": "block",
                                "file": "<repo>/app.py",
                                "pattern": "generic_api_key",
                                "redacted": True,
                            }
                        ]
                    },
                }
            ],
        }
        decision = evaluate_gate_decision_from_v3_report(report)
        self.assertEqual(decision["verdict"], "block")
        self.assertFalse(decision["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
