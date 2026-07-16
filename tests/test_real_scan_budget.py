from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from repo_health_doctor.cli import main
from repo_health_doctor.external_scanner import (
    GitleaksRunResult,
    REAL_SCANNER_ADAPTER_NAMES,
    RealScannerSuiteReport,
    run_real_scanner_suite,
)


ROOT = Path(__file__).resolve().parents[1]


def _run_result(finding_count: int, *, description_size: int = 12) -> GitleaksRunResult:
    findings = [
        {"finding_id": f"finding-{index}", "description": "x" * description_size}
        for index in range(finding_count)
    ]
    normalized = {
        "findings": findings,
        "evidence_nodes": [{"node_id": finding["finding_id"]} for finding in findings],
        "summary": {
            "outcome": "findings_present",
            "finding_count": finding_count,
            "highest_risk_tier_effect": "T5_candidate",
        },
        "mapping_result": {
            "risk_tier_effect": "T5_candidate",
            "gate_effects": ["requires_human_review"],
            "risk_lowering_allowed": False,
        },
    }
    return GitleaksRunResult(
        valid=True,
        scanner_executed=True,
        blocking_errors=(),
        warnings=(),
        normalized_result=normalized,
    )


class RealScanBudgetTests(unittest.TestCase):
    def test_per_scanner_and_suite_finding_budgets_are_recorded(self) -> None:
        with mock.patch.multiple(
            "repo_health_doctor.external_scanner.real_scanner_suite",
            run_gitleaks_scan=mock.Mock(return_value=_run_result(4)),
            run_osv_scan=mock.Mock(return_value=_run_result(4)),
        ):
            report = run_real_scanner_suite(
                ROOT,
                scanners=("gitleaks", "osv-scanner"),
                max_findings_per_scanner=2,
                max_findings=3,
            )

        self.assertEqual(report.suite_status, "degraded")
        self.assertEqual(tuple(entry.finding_count for entry in report.entries), (2, 1))
        self.assertEqual(tuple(entry.omitted_finding_count for entry in report.entries), (2, 3))
        self.assertTrue(all(entry.truncated for entry in report.entries))
        self.assertIn("per_scanner_finding_budget_exceeded", report.limitations)
        self.assertIn("suite_finding_budget_exceeded", report.limitations)
        self.assertFalse(report.execution_authorized)

    def test_report_byte_budget_truncates_without_retaining_raw_output(self) -> None:
        with mock.patch(
            "repo_health_doctor.external_scanner.real_scanner_suite.run_gitleaks_scan",
            return_value=_run_result(8, description_size=400),
        ):
            report = run_real_scanner_suite(
                ROOT,
                scanners=("gitleaks",),
                max_findings_per_scanner=8,
                max_findings=8,
                max_report_bytes=1800,
            )

        entry = report.entries[0]
        self.assertEqual(report.suite_status, "degraded")
        self.assertTrue(entry.truncated)
        self.assertGreater(entry.omitted_finding_count, 0)
        self.assertIn("report_byte_budget_exceeded", report.limitations)
        self.assertNotIn("raw_output", entry.normalized_result)
        compact_report_bytes = len(json.dumps(report.to_dict(), separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        self.assertLessEqual(compact_report_bytes, 1800)

    def test_fail_on_degraded_returns_one_after_printing_bounded_report(self) -> None:
        with mock.patch(
            "repo_health_doctor.cli.run_real_scanner_suite_sequential",
            return_value=RealScannerSuiteReport(
                suite_status="degraded",
                entries=(),
                limitations=("suite_degraded_requires_review",),
                execution_authorized=False,
                report_fingerprint="sha256:" + "1" * 64,
                generated_at="2026-07-16T00:00:00+00:00",
                subject={"repo_commit": None, "dirty_state": "unknown"},
            ),
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["real-scan", str(ROOT), "--fail-on-degraded", "--format", "json"])

        self.assertEqual(exit_code, 1)
        self.assertIn('"suite_status": "degraded"', stdout.getvalue())

    def test_default_scanner_order_remains_fixed(self) -> None:
        self.assertEqual(REAL_SCANNER_ADAPTER_NAMES, ("gitleaks", "osv-scanner", "trivy"))


if __name__ == "__main__":
    unittest.main()
