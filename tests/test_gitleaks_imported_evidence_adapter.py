from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.evidence.adapters import normalize_gitleaks_report_to_evidence
from repo_health_doctor.evidence.validation import validate_evidence
from repo_health_doctor.gate import evaluate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "evidence" / "gitleaks"
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


def _fixture(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class GitleaksImportedEvidenceAdapterTests(unittest.TestCase):
    def test_synthetic_gitleaks_fixture_generates_schema_valid_evidence(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_fixture("synthetic-finding.json"))

        self.assertEqual(len(evidence), 1)
        result = validate_evidence(evidence[0])
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(evidence[0]["classification"]["category"], "secret")  # type: ignore[index]
        self.assertEqual(evidence[0]["classification"]["subcategory"], "secret_candidate")  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]
        self.assertFalse(evidence[0]["raw_handling"]["raw_output_retained"])  # type: ignore[index]

    def test_secret_value_is_not_emitted(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_fixture("synthetic-finding.json"))
        rendered = json.dumps(evidence, sort_keys=True)

        self.assertNotIn("plain-text-fixture-value", rendered)
        self.assertNotIn("Secret", rendered)
        for pattern in FORBIDDEN:
            self.assertNotIn(pattern, rendered)

    def test_no_findings_cannot_lower_risk(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_fixture("no-findings.json"))

        self.assertEqual(len(evidence), 1)
        self.assertFalse(evidence[0]["finding"]["present"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_lower_risk"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]
        result = validate_evidence(evidence[0])
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("no_finding_is_not_safety_proof", result.warnings)

    def test_unredacted_secret_field_is_blocked_by_validation(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_fixture("unredacted-secret-field.json"))

        rendered = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("plain-text-fixture-value", rendered)
        result = validate_evidence(evidence[0])
        self.assertFalse(result.valid)
        self.assertIn("redaction_status_failed", result.blocking_errors)

    def test_generated_evidence_drives_non_authorizing_gate_decision(self) -> None:
        evidence = normalize_gitleaks_report_to_evidence(_fixture("synthetic-finding.json"))
        decision = evaluate_gate_decision(evidence).decision

        self.assertIn(decision["verdict"], {"warn", "quarantine", "block"})
        self.assertFalse(decision["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
