from __future__ import annotations

from copy import deepcopy
import json
import re
import unittest

from repo_health_doctor.external_scanner import validate_imported_external_report
from tests.external_scanner_fixture_helpers import load_imported_external_report_fixture


EXPECTED_COMMIT = "0123456789abcdef0123456789abcdef01234567"
LEAK_PATTERNS = (
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"C:\\Users\\"),
    re.compile(r"\.ssh"),
    re.compile(r"\.aws"),
    re.compile(r"\.npmrc"),
    re.compile(r"\.pypirc"),
    re.compile(r"\.netrc"),
    re.compile(r"BEGIN OPENSSH PRIVATE KEY"),
    re.compile(r"BEGIN RSA PRIVATE KEY"),
    re.compile(r"AKIA[0-9A-Z]{4,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{6,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{6,}"),
    re.compile(r"xoxb-[A-Za-z0-9-]{6,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b"),
    re.compile(r"-----BEGIN"),
    re.compile(r"password="),
    re.compile(r"token="),
)


def _valid_report() -> dict[str, object]:
    return load_imported_external_report_fixture("valid_commit_bound_report.json")


class ImportedExternalReportValidatorTests(unittest.TestCase):
    def test_valid_commit_bound_report_is_valid(self) -> None:
        result = validate_imported_external_report(_valid_report(), expected_commit=EXPECTED_COMMIT)
        self.assertTrue(result.valid)
        self.assertEqual(result.blocking_errors, ())
        self.assertEqual(result.trust_level, "commit_bound_import")
        self.assertTrue(result.commit_bound)
        self.assertFalse(result.commit_mismatch)
        self.assertFalse(result.execution_authorized)
        self.assertTrue(result.cannot_lower_risk)
        self.assertIn("RISK014", result.fired_rules)
        self.assertIn("raises_risk", result.gate_effects)
        self.assertIn("scanner_scope_only", result.limitations)
        self.assertIn("scanner_scope_only", result.residual_risks)

    def test_expected_commit_mismatch_fails_closed(self) -> None:
        result = validate_imported_external_report(
            load_imported_external_report_fixture("commit_mismatch_report.json"),
            expected_commit=EXPECTED_COMMIT,
        )
        self.assertFalse(result.valid)
        self.assertTrue(result.commit_mismatch)
        self.assertIn("binding_commit_mismatch", result.blocking_errors)
        self.assertIn("expected_commit_mismatch", result.blocking_errors)
        self.assertFalse(result.execution_authorized)

    def test_low_trust_no_finding_cannot_lower_risk(self) -> None:
        result = validate_imported_external_report(
            load_imported_external_report_fixture("low_trust_no_finding_report.json"),
            expected_commit=EXPECTED_COMMIT,
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.cannot_lower_risk)
        self.assertFalse(result.execution_authorized)
        self.assertEqual(result.highest_risk_tier_effect, "none")
        self.assertEqual(result.gate_effects, ("evidence_only",))
        self.assertIn("RISK020", result.fired_rules)
        self.assertIn("low_trust_no_finding_import_cannot_lower_risk", result.warnings)

    def test_raw_output_retained_report_fails_closed(self) -> None:
        data = _valid_report()
        data["execution_context"]["raw_output_retained"] = True  # type: ignore[index]
        result = validate_imported_external_report(data, expected_commit=EXPECTED_COMMIT)
        self.assertFalse(result.valid)
        self.assertIn("imported_report_raw_output_retained", result.blocking_errors)
        self.assertFalse(result.execution_authorized)

    def test_scanner_failure_no_findings_fails_closed(self) -> None:
        data = _valid_report()
        data["summary"]["outcome"] = "no_findings_in_scope"  # type: ignore[index]
        data["summary"]["finding_count"] = 1  # type: ignore[index]
        data["execution_context"]["scanner_completed"] = False  # type: ignore[index]
        data["findings"] = [
            {
                "finding_id": "imported-fixture-failure",
                "scanner_rule_id": "fixture.scanner_timeout",
                "primary_category": "scanner_failure",
                "secondary_category": "scanner_timeout",
                "scanner_severity": "fixture",
                "normalized_severity": "block",
                "confidence": "high",
                "title": "Synthetic scanner failure fixture",
                "redacted_description": "Synthetic timeout evidence.",
                "location": {"path": "<repo>/fixture", "line": 1, "column": 1},
                "evidence": [],
                "risk_mapping": {"risk_tier_effect": "none", "rule_ids": []},
                "gate_effect": "evidence_only",
            }
        ]
        result = validate_imported_external_report(data, expected_commit=EXPECTED_COMMIT)
        self.assertFalse(result.valid)
        self.assertIn("scanner_failure_claims_no_findings", result.blocking_errors)
        self.assertIn("RISK017", result.fired_rules)
        self.assertFalse(result.execution_authorized)

    def test_redaction_failure_report_fails_closed(self) -> None:
        data = _valid_report()
        data["redaction_status"]["raw_secret_present"] = True  # type: ignore[index]
        result = validate_imported_external_report(data, expected_commit=EXPECTED_COMMIT)
        self.assertFalse(result.valid)
        self.assertIn("raw_secret_present", result.blocking_errors)
        self.assertIn("RISK002", result.fired_rules)
        self.assertFalse(result.execution_authorized)

    def test_limitations_missing_fails_closed(self) -> None:
        data = _valid_report()
        data.pop("limitations")
        result = validate_imported_external_report(data, expected_commit=EXPECTED_COMMIT)
        self.assertFalse(result.valid)
        self.assertIn("imported_report_limitations_missing", result.blocking_errors)
        self.assertIn("RISK019", result.fired_rules)
        self.assertFalse(result.execution_authorized)

    def test_result_and_fixtures_do_not_contain_obvious_leak_patterns(self) -> None:
        reports = [
            _valid_report(),
            load_imported_external_report_fixture("commit_mismatch_report.json"),
            load_imported_external_report_fixture("low_trust_no_finding_report.json"),
        ]
        for report in reports:
            result = validate_imported_external_report(report, expected_commit=EXPECTED_COMMIT)
            for content in (json.dumps(report, sort_keys=True), json.dumps(result.to_dict(), sort_keys=True)):
                for pattern in LEAK_PATTERNS:
                    self.assertIsNone(pattern.search(content), pattern.pattern)


if __name__ == "__main__":
    unittest.main()
