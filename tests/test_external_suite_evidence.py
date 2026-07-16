from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

from repo_health_doctor.gate.external_evidence import (
    EXTERNAL_EVIDENCE_DUPLICATE,
    EXTERNAL_EVIDENCE_FINGERPRINT_MISMATCH,
    EXTERNAL_EVIDENCE_INVALID,
    EXTERNAL_EVIDENCE_OVER_BUDGET,
    EXTERNAL_EVIDENCE_STALE,
    EXTERNAL_EVIDENCE_SUBJECT_MISMATCH,
    EXTERNAL_EVIDENCE_TRUNCATED,
    EXTERNAL_SUITE_EVIDENCE_MAX_AGE_SECONDS,
    EXTERNAL_SUITE_EVIDENCE_MAX_BYTES,
    external_suite_report_fingerprint,
    validate_external_suite_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
GOLDEN_PATH = ROOT / "tests" / "fixtures" / "golden" / "real-scanner-suite.json"
NOW = datetime(2026, 7, 16, 3, 0, tzinfo=timezone.utc)
SUBJECT = {"repo_commit": "a" * 40, "dirty_state": "clean"}


def _report() -> dict[str, object]:
    report = deepcopy(json.loads(GOLDEN_PATH.read_text(encoding="utf-8")))
    report["generated_at"] = (NOW - timedelta(minutes=5)).isoformat()
    report["subject"] = dict(SUBJECT)
    report["report_fingerprint"] = external_suite_report_fingerprint(report)
    return report


class ExternalSuiteEvidenceTests(unittest.TestCase):
    def test_valid_evidence_returns_valid_status_and_bounded_reference(self) -> None:
        result = validate_external_suite_evidence(
            _report(),
            expected_subject=SUBJECT,
            now=NOW,
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.reasons, ())
        self.assertEqual(result.validation_errors, ())
        self.assertEqual(result.evidence_ref["validation_status"], "valid")
        self.assertEqual(result.evidence_ref["subject"], SUBJECT)
        self.assertNotIn("entries", result.evidence_ref)
        self.assertNotIn("normalized_result", json.dumps(result.to_dict(), sort_keys=True))

    def test_invalid_schema_returns_external_evidence_invalid_reason(self) -> None:
        report = _report()
        report["unexpected"] = "bounded"
        report["report_fingerprint"] = external_suite_report_fingerprint(report)

        result = validate_external_suite_evidence(
            report,
            expected_subject=SUBJECT,
            now=NOW,
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.status, "invalid")
        self.assertIn(EXTERNAL_EVIDENCE_INVALID, result.reasons)
        self.assertIn("schema_top_level_required_or_unknown_field", result.validation_errors)

    def test_fingerprint_mismatch_returns_external_evidence_invalid_reason(self) -> None:
        report = _report()
        report["suite_status"] = "completed"

        result = validate_external_suite_evidence(
            report,
            expected_subject=SUBJECT,
            now=NOW,
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.reasons,
            (EXTERNAL_EVIDENCE_INVALID, EXTERNAL_EVIDENCE_FINGERPRINT_MISMATCH),
        )

    def test_stale_returns_external_evidence_stale_reason(self) -> None:
        report = _report()
        report["generated_at"] = (
            NOW - timedelta(seconds=EXTERNAL_SUITE_EVIDENCE_MAX_AGE_SECONDS + 1)
        ).isoformat()
        report["report_fingerprint"] = external_suite_report_fingerprint(report)

        result = validate_external_suite_evidence(
            report,
            expected_subject=SUBJECT,
            now=NOW,
        )

        self.assertEqual(result.reasons, (EXTERNAL_EVIDENCE_STALE,))

    def test_subject_mismatch_returns_external_evidence_subject_mismatch_reason(self) -> None:
        result = validate_external_suite_evidence(
            _report(),
            expected_subject={"repo_commit": "b" * 40, "dirty_state": "clean"},
            now=NOW,
        )

        self.assertEqual(result.reasons, (EXTERNAL_EVIDENCE_SUBJECT_MISMATCH,))

    def test_over_budget_returns_external_evidence_over_budget_reason(self) -> None:
        result = validate_external_suite_evidence(
            _report(),
            expected_subject=SUBJECT,
            now=NOW,
            source_size_bytes=EXTERNAL_SUITE_EVIDENCE_MAX_BYTES + 1,
        )

        self.assertEqual(result.reasons, (EXTERNAL_EVIDENCE_OVER_BUDGET,))
        self.assertEqual(
            result.evidence_ref["size_bytes"],
            EXTERNAL_SUITE_EVIDENCE_MAX_BYTES + 1,
        )

    def test_duplicate_returns_external_evidence_duplicate_reason(self) -> None:
        report = _report()

        result = validate_external_suite_evidence(
            report,
            expected_subject=SUBJECT,
            now=NOW,
            seen_fingerprints={str(report["report_fingerprint"])},
        )

        self.assertEqual(result.reasons, (EXTERNAL_EVIDENCE_DUPLICATE,))

    def test_truncated_returns_external_evidence_truncated_reason(self) -> None:
        report = _report()
        entry = report["entries"][0]
        entry["truncated"] = True
        entry["omitted_finding_count"] = 1
        report["limitations"].append("report_truncated")
        report["report_fingerprint"] = external_suite_report_fingerprint(report)

        result = validate_external_suite_evidence(report, expected_subject=SUBJECT, now=NOW)

        self.assertEqual(result.reasons, (EXTERNAL_EVIDENCE_TRUNCATED,))
        self.assertTrue(result.evidence_ref["truncated"])


if __name__ == "__main__":
    unittest.main()
