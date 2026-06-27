from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.doctor import diagnose_repo
from repo_health_doctor.evidence import (
    build_gate_decision_candidate_from_v3_report,
    extract_evidence_candidates_from_v3_report,
    validate_evidence,
)
from repo_health_doctor.gate import validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
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


class V3OutputEvidenceGapCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = diagnose_repo(ROOT / "tests" / "fixtures" / "demo-repo", public_safety=True)

    def test_v3_report_shape_is_not_changed_by_adapter(self) -> None:
        before = json.dumps(self.report, sort_keys=True)
        extract_evidence_candidates_from_v3_report(self.report)
        build_gate_decision_candidate_from_v3_report(self.report)
        after = json.dumps(self.report, sort_keys=True)
        self.assertEqual(before, after)
        self.assertEqual(self.report["schema_version"], "1.1")
        self.assertNotIn("execution_authorized", self.report)

    def test_current_v3_report_can_build_valid_gate_decision_candidate(self) -> None:
        gate = build_gate_decision_candidate_from_v3_report(self.report)
        validation = validate_gate_decision(gate)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertEqual(gate["verdict"], "warn")
        self.assertFalse(gate["execution_authorized"])
        self.assertTrue(gate["limitations"])
        self.assertTrue(gate["explanation"]["summary"])
        self.assertIn("v3_report_lacks_commit_binding", gate["evidence_summary"]["missing_evidence"])

    def test_v3_no_finding_does_not_become_allow_limited_or_authorization(self) -> None:
        gate = build_gate_decision_candidate_from_v3_report(self.report)
        self.assertEqual(self.report["overall_status"], "pass")
        self.assertNotEqual(gate["verdict"], "allow_limited")
        self.assertFalse(gate["execution_authorized"])

    def test_evidence_candidates_are_valid_and_cannot_authorize_execution(self) -> None:
        candidates = extract_evidence_candidates_from_v3_report(self.report)
        self.assertGreater(len(candidates), 0)
        for candidate in candidates:
            with self.subTest(evidence_id=candidate["evidence_id"]):
                validation = validate_evidence(candidate)
                self.assertTrue(validation.valid, validation.to_dict())
                self.assertFalse(candidate["effects"]["can_authorize_execution"])
                self.assertFalse(candidate["effects"]["can_lower_risk"])
                self.assertFalse(candidate["raw_handling"]["raw_output_retained"])
                self.assertFalse(candidate["raw_handling"]["raw_stdout_retained"])
                self.assertFalse(candidate["raw_handling"]["raw_stderr_retained"])
                self.assertTrue(candidate["trust"]["limitations"])

    def test_blocking_v3_report_maps_to_block_gate_candidate(self) -> None:
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
        gate = build_gate_decision_candidate_from_v3_report(report)
        evidence = extract_evidence_candidates_from_v3_report(report)
        self.assertEqual(gate["verdict"], "block")
        self.assertFalse(gate["execution_authorized"])
        self.assertEqual(gate["evidence_summary"]["findings_count"], 1)
        self.assertEqual(evidence[0]["classification"]["category"], "secret")
        self.assertEqual(evidence[0]["classification"]["severity"], "block")

    def test_candidates_do_not_contain_forbidden_leak_patterns(self) -> None:
        payloads = [
            build_gate_decision_candidate_from_v3_report(self.report),
            *extract_evidence_candidates_from_v3_report(self.report),
        ]
        rendered = json.dumps(payloads, sort_keys=True)
        for pattern in FORBIDDEN_PATTERNS:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, rendered)


if __name__ == "__main__":
    unittest.main()
