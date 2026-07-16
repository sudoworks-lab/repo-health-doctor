from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.evidence.adapters import normalize_gitleaks_report_to_evidence
from repo_health_doctor.external_scanner import (
    assess_gitleaks_version,
    assess_osv_scanner_version,
    assess_trivy_version,
    interpret_osv_exit_code,
    normalize_gitleaks_json_array,
    normalize_osv_json_object,
    normalize_trivy_json_object,
)


ROOT = Path(__file__).resolve().parents[1]
COMPATIBILITY_ROOT = ROOT / "tests" / "fixtures" / "real-compatibility"
TRIVY_ADDITIONAL_ROOT = ROOT / "tests" / "fixtures" / "real-scanners" / "trivy"
REGENERATION_DOC = ROOT / "docs" / "compatibility-regeneration.md"
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION_STATUSES = (
    "tested",
    "compatible_family_unverified",
    "unsupported",
    "denylisted",
    "unparseable",
)
SCANNERS = {
    "gitleaks": {
        "doc": ROOT / "docs" / "real-gitleaks-compatibility.md",
        "version": "8.27.2",
        "version_record": COMPATIBILITY_ROOT / "gitleaks" / "gitleaks-version.txt",
        "expected_evidence": COMPATIBILITY_ROOT / "gitleaks" / "expected-evidence.json",
        "scenario_terms": ("Dirty worktree", "SARIF", "Version parse failure"),
        "regeneration_command": "regenerate-gitleaks-compat-fixtures.sh",
    },
    "osv-scanner": {
        "doc": ROOT / "docs" / "real-osv-compatibility.md",
        "version": "2.0.3",
        "version_record": COMPATIBILITY_ROOT / "osv" / "osv-scanner-version.txt",
        "expected_evidence": COMPATIBILITY_ROOT / "osv" / "expected-evidence.json",
        "scenario_terms": ("Exit 128", "Exit/report mismatch", "Version parse failure"),
        "regeneration_command": "regenerate-osv-compat-fixtures.sh",
    },
    "trivy": {
        "doc": ROOT / "docs" / "real-trivy-compatibility.md",
        "version": "0.69.3",
        "version_record": TRIVY_ADDITIONAL_ROOT / "trivy-version.txt",
        "expected_evidence": TRIVY_ADDITIONAL_ROOT / "expected-evidence.json",
        "scenario_terms": ("Licenses", "Exit/report mismatch", "Version parse failure"),
        "regeneration_command": "regenerate_real_scanner_fixtures.py --scanner trivy",
    },
}


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class RealScannerCompatibilityMatrixTests(unittest.TestCase):
    def test_fixture_version_and_expected_evidence_are_symmetric(self) -> None:
        for scanner, row in SCANNERS.items():
            with self.subTest(scanner=scanner):
                version_record = row["version_record"]
                expected_evidence = row["expected_evidence"]
                self.assertIsInstance(version_record, Path)
                self.assertIsInstance(expected_evidence, Path)
                self.assertTrue(version_record.is_file())
                self.assertIn(str(row["version"]), version_record.read_text(encoding="utf-8"))
                self.assertIsInstance(_load(expected_evidence), dict)

    def test_additional_scenarios_reuse_existing_redacted_fixtures(self) -> None:
        gitleaks_root = COMPATIBILITY_ROOT / "gitleaks"
        no_findings = _load(gitleaks_root / "no-findings.real.json")
        dirty_result = normalize_gitleaks_json_array(
            no_findings,
            scanner_version="8.27.2",
            repo_commit="0" * 40,
            dirty_state="dirty",
        )
        self.assertEqual(dirty_result["summary"]["unknown_reason"], "scope_ambiguous")
        sarif_evidence = normalize_gitleaks_report_to_evidence(
            _load(gitleaks_root / "optional-sarif-redacted.real.sarif")
        )
        self.assertEqual(sarif_evidence[0]["source"]["tool_version"], "8.27.2")

        osv_root = COMPATIBILITY_ROOT / "osv"
        no_vulnerabilities = _load(osv_root / "no-vulnerabilities.real.json")
        vulnerabilities = _load(osv_root / "vulnerabilities.real.json")
        exit_128 = interpret_osv_exit_code(128)
        self.assertFalse(exit_128.consume_report)
        self.assertEqual(exit_128.blocking_error, "no_packages_found")
        osv_mismatch = normalize_osv_json_object(
            vulnerabilities,
            scanner_version="2.0.3",
            repo_commit="0" * 40,
            dirty_state="clean",
            outcome="no_findings_in_scope",
        )
        self.assertEqual(osv_mismatch["summary"]["unknown_reason"], "parse_failure")
        self.assertEqual(no_vulnerabilities, {"results": []})

        trivy_vulnerabilities = _load(COMPATIBILITY_ROOT / "trivy" / "vulnerabilities.real.json")
        trivy_mismatch = normalize_trivy_json_object(
            trivy_vulnerabilities,
            scanner_version="0.69.3",
            repo_commit="0" * 40,
            dirty_state="clean",
            outcome="no_findings_in_scope",
        )
        self.assertEqual(trivy_mismatch["summary"]["unknown_reason"], "parse_failure")
        trivy_license = normalize_trivy_json_object(
            _load(TRIVY_ADDITIONAL_ROOT / "licenses-redacted.real.json"),
            scanner_version="0.69.3",
            repo_commit="0" * 40,
            dirty_state="clean",
        )
        expected_license = _load(TRIVY_ADDITIONAL_ROOT / "expected-evidence.json")["license"]  # type: ignore[index]
        license_finding = trivy_license["findings"][0]
        self.assertEqual(license_finding["secondary_category"], expected_license["secondary_category"])
        self.assertEqual(license_finding["scanner_rule_id"], expected_license["scanner_rule_id"])

    def test_version_parse_failure_is_fail_closed_for_all_scanners(self) -> None:
        self.assertEqual(assess_gitleaks_version("version unavailable").status, "unparseable")
        self.assertEqual(assess_osv_scanner_version("version unavailable").status, "unparseable")
        trivy = assess_trivy_version("version unavailable", "")
        self.assertFalse(trivy.supported_for_live_scan)
        self.assertTrue(trivy.unsupported_version)

    def test_compatibility_docs_have_symmetric_coverage_sections(self) -> None:
        required_sections = (
            "## Tested Versions",
            "## Additional Compatibility Scenarios",
            "## Regeneration",
            "## Not Covered",
        )
        for scanner, row in SCANNERS.items():
            content = row["doc"].read_text(encoding="utf-8")
            with self.subTest(scanner=scanner):
                for section in required_sections:
                    self.assertIn(section, content)
                for status in VERSION_STATUSES:
                    self.assertIn(status, content)
                self.assertIn(str(row["version"]), content)
                self.assertIn(str(row["regeneration_command"]), content)
                for scenario in row["scenario_terms"]:
                    self.assertIn(scenario, content)

    def test_regeneration_runbook_and_changelog_cover_the_same_matrix(self) -> None:
        regeneration = REGENERATION_DOC.read_text(encoding="utf-8")
        changelog = CHANGELOG.read_text(encoding="utf-8")
        for content in (regeneration, changelog):
            self.assertIn("Tested Versions", content)
            self.assertIn("Not Covered", content)
            for status in VERSION_STATUSES:
                self.assertIn(status, content)
            for row in SCANNERS.values():
                self.assertIn(str(row["version"]), content)


if __name__ == "__main__":
    unittest.main()
