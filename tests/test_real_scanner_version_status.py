from __future__ import annotations

from pathlib import Path
import unittest
from unittest import mock

from repo_health_doctor.external_scanner import (
    GitleaksCommandResult,
    assess_gitleaks_version,
    assess_osv_scanner_version,
    run_real_scanner_suite,
)
from repo_health_doctor.external_scanner.adapters import gitleaks_adapter


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "real-compatibility"


class RealScannerVersionStatusTests(unittest.TestCase):
    def test_gitleaks_distinguishes_all_version_statuses(self) -> None:
        fixture_version = (FIXTURES / "gitleaks" / "gitleaks-version.txt").read_text(encoding="utf-8")
        cases = (
            (fixture_version, "tested"),
            ("gitleaks 8.99.0", "compatible_family_unverified"),
            ("gitleaks 9.0.0", "unsupported"),
            ("gitleaks 0.0.0", "denylisted"),
            ("not a version", "unparseable"),
        )

        for output, expected in cases:
            with self.subTest(expected=expected):
                assessment = assess_gitleaks_version(output)
                self.assertEqual(assessment.status, expected)
                self.assertEqual(assessment.supported_for_live_scan, expected in {"tested", "compatible_family_unverified"})

    def test_osv_scanner_distinguishes_all_version_statuses(self) -> None:
        fixture_version = (FIXTURES / "osv" / "osv-scanner-version.txt").read_text(encoding="utf-8")
        cases = (
            (fixture_version, "tested"),
            ("osv-scanner version: 2.99.0", "compatible_family_unverified"),
            ("osv-scanner version: 3.0.0", "unsupported"),
            ("osv-scanner version: 0.0.0", "denylisted"),
            ("version unavailable", "unparseable"),
        )

        for output, expected in cases:
            with self.subTest(expected=expected):
                assessment = assess_osv_scanner_version(output)
                self.assertEqual(assessment.status, expected)
                self.assertEqual(assessment.supported_for_live_scan, expected in {"tested", "compatible_family_unverified"})

    def test_compatible_family_is_executable_but_suite_is_degraded(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            command = tuple(str(item) for item in argv)
            if command == ("gitleaks", "version"):
                return GitleaksCommandResult(returncode=0, stdout="gitleaks 8.99.0\n", stderr="")
            report_index = command.index("--report-path") + 1
            Path(command[report_index]).write_text("[]", encoding="utf-8")
            return GitleaksCommandResult(returncode=0, stdout="", stderr="")

        with mock.patch.object(gitleaks_adapter, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
            report = run_real_scanner_suite(ROOT, runner=runner, scanners=("gitleaks",))

        self.assertEqual(report.suite_status, "degraded")
        self.assertTrue(report.entries[0].valid)
        self.assertEqual(report.entries[0].status, "completed")
        self.assertIn("scanner_version_compatible_family_unverified", report.entries[0].warnings)


if __name__ == "__main__":
    unittest.main()
