from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.evidence.adapters import normalize_osv_report_to_evidence
from repo_health_doctor.evidence.validation import validate_evidence
from repo_health_doctor.gate import evaluate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "evidence" / "osv"
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


class OsvImportedEvidenceAdapterTests(unittest.TestCase):
    def test_synthetic_osv_fixture_generates_schema_valid_evidence(self) -> None:
        evidence = normalize_osv_report_to_evidence(_fixture("synthetic-critical.json"))

        self.assertEqual(len(evidence), 1)
        result = validate_evidence(evidence[0])
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(evidence[0]["classification"]["category"], "known_vulnerability")  # type: ignore[index]
        self.assertEqual(evidence[0]["classification"]["subcategory"], "known_critical_vulnerability")  # type: ignore[index]
        self.assertEqual(evidence[0]["classification"]["severity"], "block")  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]
        self.assertFalse(evidence[0]["raw_handling"]["raw_output_retained"])  # type: ignore[index]

    def test_no_vulnerabilities_cannot_lower_risk(self) -> None:
        evidence = normalize_osv_report_to_evidence(_fixture("no-vulnerabilities.json"))

        self.assertEqual(len(evidence), 1)
        self.assertFalse(evidence[0]["finding"]["present"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_lower_risk"])  # type: ignore[index]
        self.assertFalse(evidence[0]["effects"]["can_authorize_execution"])  # type: ignore[index]
        result = validate_evidence(evidence[0])
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("no_finding_is_not_safety_proof", result.warnings)

    def test_generated_evidence_drives_non_authorizing_gate_decision(self) -> None:
        evidence = normalize_osv_report_to_evidence(_fixture("synthetic-critical.json"))
        decision = evaluate_gate_decision(evidence).decision

        self.assertIn(decision["verdict"], {"warn", "quarantine", "block"})
        self.assertFalse(decision["execution_authorized"])
        self.assertIn("Critical vulnerability evidence requires review before execution.", decision["explanation"]["key_reasons"])

    def test_fixtures_and_outputs_do_not_contain_forbidden_leaks(self) -> None:
        payloads = [
            _fixture("synthetic-critical.json"),
            _fixture("no-vulnerabilities.json"),
            normalize_osv_report_to_evidence(_fixture("synthetic-critical.json")),
            normalize_osv_report_to_evidence(_fixture("no-vulnerabilities.json")),
        ]
        rendered = json.dumps(payloads, sort_keys=True)
        for pattern in FORBIDDEN:
            self.assertNotIn(pattern, rendered)


if __name__ == "__main__":
    unittest.main()
