from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from repo_health_doctor.doctor import diagnose_repo
from repo_health_doctor.gate import evaluate_gate_decision_from_v3_report, validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
SUPPLY_CHAIN_COMPOUND = ROOT / "tests" / "fixtures" / "supply-chain-shape-compound"
SUPPLY_CHAIN_SINGLE = ROOT / "tests" / "fixtures" / "supply-chain-shape-single"
FORBIDDEN_PATTERNS = (
    "/home/",
    "/Users/",
    "C:\\Users\\",
    ".ssh",
    ".aws",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "AKIA",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "sk-",
    "-----BEGIN",
    "password=",
    "token=",
)


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

    def test_general_supply_chain_compound_shape_quarantines(self) -> None:
        report = diagnose_repo(SUPPLY_CHAIN_COMPOUND, public_safety=True)
        decision = evaluate_gate_decision_from_v3_report(report, repo_root=SUPPLY_CHAIN_COMPOUND)

        self.assertEqual(decision["verdict"], "quarantine")
        self.assertFalse(decision["execution_authorized"])
        self.assertIn("static-supply-chain-shape", decision["evidence_summary"]["warning_evidence"])
        reasons = decision["explanation"]["key_reasons"]
        self.assertIn("A package install hook or postinstall-like script is present.", reasons)
        self.assertIn("Credential-path or environment-access patterns are present.", reasons)
        self.assertIn("An outbound network target or network-attempt string is present.", reasons)
        self.assertIn("Workflow write-risk or GitHub Actions token-abuse-like behavior is present.", reasons)
        self.assertIn("Obfuscation or dynamic eval-like code is present.", reasons)

    def test_general_supply_chain_compound_shape_quarantines_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            copied = Path(tmp_dir) / "any-name"
            shutil.copytree(SUPPLY_CHAIN_COMPOUND, copied)
            report = diagnose_repo(copied, public_safety=True)
            decision = evaluate_gate_decision_from_v3_report(report, repo_root=copied)

        self.assertEqual(decision["verdict"], "quarantine")
        self.assertFalse(decision["execution_authorized"])
        rendered = json.dumps(decision, sort_keys=True)
        self.assertNotIn(str(copied), rendered)

    def test_general_supply_chain_single_axis_warns(self) -> None:
        report = diagnose_repo(SUPPLY_CHAIN_SINGLE, public_safety=True)
        decision = evaluate_gate_decision_from_v3_report(report, repo_root=SUPPLY_CHAIN_SINGLE)

        self.assertEqual(decision["verdict"], "warn")
        self.assertFalse(decision["execution_authorized"])
        self.assertIn("recommended_warn:static-supply-chain-shape", decision["confidence_reason"])
        self.assertIn(
            "A package install hook or postinstall-like script is present.",
            decision["explanation"]["key_reasons"],
        )

    def test_supply_chain_shape_fixtures_remain_redacted(self) -> None:
        rendered = "\n".join(
            path.read_text(encoding="utf-8")
            for fixture in (SUPPLY_CHAIN_COMPOUND, SUPPLY_CHAIN_SINGLE)
            for path in sorted(item for item in fixture.rglob("*") if item.is_file())
        )
        for pattern in FORBIDDEN_PATTERNS:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, rendered)


if __name__ == "__main__":
    unittest.main()
