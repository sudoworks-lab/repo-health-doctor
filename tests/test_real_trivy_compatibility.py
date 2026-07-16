from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

from repo_health_doctor.external_scanner import (
    assess_trivy_version,
    normalize_trivy_json_object,
    validate_external_scanner_result,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "real-scanners" / "trivy"
DOC = ROOT / "docs" / "real-trivy-compatibility.md"
REGENERATION_DOC = ROOT / "docs" / "compatibility-regeneration.md"
REGENERATION_SCRIPT = ROOT / "scripts" / "regenerate_real_scanner_fixtures.py"
FORBIDDEN_TEXT = (
    "/home/",
    "/Users/",
    "C:\\Users\\",
    ".ssh",
    "/.aws",
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
FORBIDDEN_RAW_FIELDS = {
    "Code",
    "Description",
    "Layer",
    "Match",
    "PrimaryURL",
    "References",
}


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_keys(item) for item in value))
    return set()


class RealTrivyCompatibilityTests(unittest.TestCase):
    def _normalized_license_result(self) -> dict[str, object]:
        version_record = (FIXTURES / "trivy-version.txt").read_text(encoding="utf-8")
        version = assess_trivy_version(version_record, "")
        self.assertTrue(version.supported_for_live_scan)
        self.assertEqual(version.version, "0.69.3")
        return dict(
            normalize_trivy_json_object(
                _load("licenses-redacted.real.json"),
                scanner_version=version.version,
                repo_commit="0" * 40,
                dirty_state="clean",
            )
        )

    def test_recorded_version_and_redacted_fixture_produce_expected_evidence(self) -> None:
        expected = _load("expected-evidence.json")["license"]  # type: ignore[index]
        result = self._normalized_license_result()
        validation = validate_external_scanner_result(result)

        self.assertTrue(validation.valid, validation.to_dict())
        findings = result["findings"]
        self.assertEqual(len(findings), expected["expected_count"])  # type: ignore[arg-type,index]
        finding = findings[0]  # type: ignore[index]
        for field in (
            "primary_category",
            "secondary_category",
            "scanner_rule_id",
            "scanner_severity",
            "normalized_severity",
            "gate_effect",
        ):
            self.assertEqual(finding[field], expected[field])
        self.assertEqual(result["summary"]["outcome"], expected["outcome"])  # type: ignore[index]
        self.assertEqual(result["redaction_status"]["redaction_validated"], expected["redaction_validated"])  # type: ignore[index]
        self.assertEqual(result["redaction_status"]["raw_scanner_output_included"], expected["raw_scanner_output_included"])  # type: ignore[index]
        self.assertEqual(result["execution_context"]["raw_output_retained"], expected["raw_output_retained"])  # type: ignore[index]
        self.assertEqual(result["mapping_result"]["risk_lowering_allowed"], expected["risk_lowering_allowed"])  # type: ignore[index]
        self.assertEqual(result["execution_authorized"], expected["execution_authorized"])

    def test_license_evidence_is_review_only_and_never_authorizes(self) -> None:
        result = self._normalized_license_result()

        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["mapping_result"]["risk_lowering_allowed"])  # type: ignore[index]
        self.assertIn("requires_human_review", result["summary"]["gate_effects"])  # type: ignore[index]

    def test_fixture_expected_evidence_and_docs_exclude_raw_or_private_values(self) -> None:
        fixture = _load("licenses-redacted.real.json")
        self.assertTrue(FORBIDDEN_RAW_FIELDS.isdisjoint(_keys(fixture)))

        payloads = (
            fixture,
            _load("expected-evidence.json"),
            self._normalized_license_result(),
            DOC.read_text(encoding="utf-8"),
            REGENERATION_DOC.read_text(encoding="utf-8"),
        )
        rendered = json.dumps(payloads, sort_keys=True)
        for pattern in FORBIDDEN_TEXT:
            self.assertNotIn(pattern, rendered)

    def test_regeneration_script_reproduces_expected_evidence(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(REGENERATION_SCRIPT), "--scanner", "trivy", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "Trivy expected evidence is current.")

    def test_docs_record_fixture_version_and_regeneration_boundary(self) -> None:
        compatibility = DOC.read_text(encoding="utf-8")
        regeneration = REGENERATION_DOC.read_text(encoding="utf-8")

        self.assertIn("0.69.3", compatibility)
        self.assertIn("licenses-redacted.real.json", compatibility)
        self.assertIn("regenerate_real_scanner_fixtures.py", compatibility)
        self.assertIn("--scanner trivy --check", regeneration)
        self.assertIn("Human-approved", regeneration)
        self.assertIn("Do not commit raw scanner output", regeneration)


if __name__ == "__main__":
    unittest.main()
