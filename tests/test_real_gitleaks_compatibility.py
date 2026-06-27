from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.evidence.adapters import normalize_gitleaks_report_to_evidence
from repo_health_doctor.evidence.validation import validate_evidence
from repo_health_doctor.gate import evaluate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "real-compatibility" / "gitleaks"
DOC = ROOT / "docs" / "real-gitleaks-compatibility.md"
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


class RealGitleaksCompatibilityTests(unittest.TestCase):
    def test_real_compatible_json_fixture_parses_to_valid_evidence(self) -> None:
        expected = _load("expected-evidence.json")["redacted_finding"]  # type: ignore[index]
        evidence = normalize_gitleaks_report_to_evidence(_load("findings-redacted.real.json"), tool_version="8.27.2")

        self.assertEqual(len(evidence), expected["expected_count"])  # type: ignore[index]
        result = validate_evidence(evidence[0])
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(evidence[0]["classification"]["category"], expected["category"])  # type: ignore[index]
        self.assertEqual(evidence[0]["classification"]["subcategory"], expected["subcategory"])  # type: ignore[index]
        self.assertEqual(evidence[0]["classification"]["severity"], expected["severity"])  # type: ignore[index]
        self.assertEqual(evidence[0]["raw_handling"]["redaction_status"], expected["redaction_status"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]

    def test_no_findings_cannot_lower_risk_or_authorize(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_load("no-findings.real.json"), tool_version="8.27.2")

        self.assertEqual(len(evidence), 1)
        self.assertFalse(evidence[0]["finding"]["present"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_lower_risk"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]
        result = validate_evidence(evidence[0])
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("no_finding_is_not_safety_proof", result.warnings)

    def test_unredacted_secret_field_blocks_without_emitting_value(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_load("findings-unredacted-blocked.real.json"), tool_version="8.27.2")
        rendered = json.dumps(evidence, sort_keys=True)
        result = validate_evidence(evidence[0])

        self.assertFalse(result.valid)
        self.assertIn("redaction_status_failed", result.blocking_errors)
        self.assertNotIn("plain-text-fixture-value", rendered)
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]

    def test_optional_sarif_redacted_fixture_is_supported(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_load("optional-sarif-redacted.real.sarif"))

        self.assertEqual(len(evidence), 1)
        self.assertTrue(validate_evidence(evidence[0]).valid)
        self.assertEqual(evidence[0]["source"]["tool_version"], "8.27.2")  # type: ignore[index]

    def test_generated_evidence_connects_to_gate_without_authorization(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_load("findings-redacted.real.json"), tool_version="8.27.2")
        decision = evaluate_gate_decision(evidence).decision

        self.assertIn(decision["verdict"], {"warn", "quarantine", "block"})
        self.assertFalse(decision["execution_authorized"])

    def test_fixtures_outputs_and_docs_do_not_contain_forbidden_leaks(self) -> None:
        payloads = [
            normalize_gitleaks_report_to_evidence(_load("findings-redacted.real.json"), tool_version="8.27.2"),
            normalize_gitleaks_report_to_evidence(_load("no-findings.real.json"), tool_version="8.27.2"),
            DOC.read_text(encoding="utf-8"),
        ]
        rendered = json.dumps(payloads, sort_keys=True)
        for pattern in FORBIDDEN:
            self.assertNotIn(pattern, rendered)

    def test_docs_compatibility_matrix_exists(self) -> None:
        content = DOC.read_text(encoding="utf-8")
        self.assertIn("Compatibility Matrix", content)
        self.assertIn("JSON required", content)
        self.assertIn("SARIF", content)


if __name__ == "__main__":
    unittest.main()
