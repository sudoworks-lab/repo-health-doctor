from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.evidence.adapters import normalize_osv_report_to_evidence
from repo_health_doctor.evidence.validation import validate_evidence
from repo_health_doctor.external_scanner import assess_osv_scanner_version
from repo_health_doctor.gate import evaluate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "real-compatibility" / "osv"
DOC = ROOT / "docs" / "real-osv-compatibility.md"
FORBIDDEN = (
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


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class RealOsvCompatibilityTests(unittest.TestCase):
    def test_fixture_exact_version_is_the_only_tested_version(self) -> None:
        fixture_version = (FIXTURES / "osv-scanner-version.txt").read_text(encoding="utf-8")
        exact = assess_osv_scanner_version(fixture_version)
        same_family = assess_osv_scanner_version("osv-scanner 2.0.4")

        self.assertEqual(exact.status, "tested")
        self.assertEqual(exact.version, "2.0.3")
        self.assertEqual(same_family.status, "compatible_family_unverified")
        self.assertNotEqual(same_family.status, "tested")

    def test_real_compatible_json_fixture_parses_to_valid_evidence(self) -> None:
        expected = _load("expected-evidence.json")["vulnerability"]  # type: ignore[index]
        evidence = normalize_osv_report_to_evidence(_load("vulnerabilities.real.json"), tool_version="2.0.3")

        self.assertEqual(len(evidence), expected["expected_count"])  # type: ignore[index]
        result = validate_evidence(evidence[0])
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(evidence[0]["classification"]["category"], expected["category"])  # type: ignore[index]
        self.assertEqual(evidence[0]["classification"]["subcategory"], expected["subcategory"])  # type: ignore[index]
        self.assertEqual(evidence[0]["classification"]["severity"], expected["severity"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]

    def test_no_vulnerabilities_cannot_lower_risk_or_authorize(self) -> None:
        evidence = normalize_osv_report_to_evidence(_load("no-vulnerabilities.real.json"), tool_version="2.0.3")

        self.assertEqual(len(evidence), 1)
        self.assertFalse(evidence[0]["finding"]["present"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_lower_risk"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]
        result = validate_evidence(evidence[0])
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("no_finding_is_not_safety_proof", result.warnings)

    def test_malformed_or_empty_input_is_blocking_evidence(self) -> None:
        evidence = normalize_osv_report_to_evidence(_load("malformed-or-empty.real.json"), tool_version="2.0.3")

        self.assertEqual(evidence[0]["classification"]["subcategory"], "scanner_output_parse_failed")  # type: ignore[index]
        self.assertEqual(evidence[0]["effects"]["recommended_gate_effect"], "block")  # type: ignore[index]
        self.assertTrue(validate_evidence(evidence[0]).valid)

    def test_generated_evidence_connects_to_gate_without_authorization(self) -> None:
        evidence = normalize_osv_report_to_evidence(_load("vulnerabilities.real.json"), tool_version="2.0.3")
        decision = evaluate_gate_decision(evidence).decision

        self.assertIn(decision["verdict"], {"warn", "quarantine", "block"})
        self.assertFalse(decision["execution_authorized"])

    def test_fixtures_outputs_and_docs_do_not_contain_forbidden_leaks(self) -> None:
        payloads = [
            normalize_osv_report_to_evidence(_load("vulnerabilities.real.json"), tool_version="2.0.3"),
            normalize_osv_report_to_evidence(_load("no-vulnerabilities.real.json"), tool_version="2.0.3"),
            DOC.read_text(encoding="utf-8"),
        ]
        rendered = json.dumps(payloads, sort_keys=True)
        for pattern in FORBIDDEN:
            self.assertNotIn(pattern, rendered)

    def test_docs_compatibility_matrix_exists(self) -> None:
        content = DOC.read_text(encoding="utf-8")
        self.assertIn("Compatibility Matrix", content)
        self.assertIn("OSV-Scanner", content)
        self.assertIn("Severity mapping", content)


if __name__ == "__main__":
    unittest.main()
