from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from repo_health_doctor.cli import build_parser, main
from repo_health_doctor.external_scanner import (
    REAL_SCANNER_ADAPTER_NAMES,
    RealScannerSuiteEntry,
    RealScannerSuiteReport,
)


ROOT = Path(__file__).resolve().parents[1]


def _report(status: str = "degraded") -> RealScannerSuiteReport:
    entry = RealScannerSuiteEntry(
        scanner_name="gitleaks",
        executed=False,
        valid=False,
        status="unknown",
        blocking_errors=("scanner_unavailable",),
        warnings=(),
        risk_summary={
            "outcome": "unknown",
            "highest_risk_tier_effect": "T5_candidate",
            "risk_tier_effect": "T5_candidate",
            "gate_effects": ["quarantine"],
            "risk_lowering_allowed": False,
        },
        normalized_result={
            "summary": {"outcome": "unknown"},
            "mapping_result": {"risk_tier_effect": "T5_candidate", "gate_effects": ["quarantine"]},
        },
        finding_count=0,
        omitted_finding_count=0,
        truncated=False,
    )
    return RealScannerSuiteReport(
        suite_status=status,
        entries=(entry,),
        limitations=("suite_degraded_requires_review",),
        execution_authorized=False,
        report_fingerprint="sha256:" + "1" * 64,
        generated_at="2026-07-16T00:00:00+00:00",
        subject={"repo_commit": None, "dirty_state": "unknown"},
    )


class RealScanCliTests(unittest.TestCase):
    def test_parser_dispatches_real_scan_and_defaults_to_all_scanners(self) -> None:
        args = build_parser("real-scan").parse_args(["."])

        self.assertIsNone(args.scanners)
        self.assertFalse(args.offline)
        self.assertEqual(args.timeout_seconds, 120)

        with mock.patch("repo_health_doctor.cli.run_real_scanner_suite_sequential", return_value=_report()) as run:
            with redirect_stdout(io.StringIO()):
                exit_code = main(["real-scan", str(ROOT)])

        self.assertEqual(exit_code, 0)
        run.assert_called_once_with(
            ROOT,
            timeout_seconds=120,
            offline=False,
            scanners=REAL_SCANNER_ADAPTER_NAMES,
        )

    def test_scanner_selection_offline_and_timeout_are_forwarded(self) -> None:
        with mock.patch("repo_health_doctor.cli.run_real_scanner_suite_sequential", return_value=_report()) as run:
            with redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "real-scan",
                        str(ROOT),
                        "--scanner",
                        "gitleaks",
                        "--scanner",
                        "trivy",
                        "--offline",
                        "--timeout",
                        "9",
                    ]
                )

        self.assertEqual(exit_code, 0)
        run.assert_called_once_with(
            ROOT,
            timeout_seconds=9,
            offline=True,
            scanners=("gitleaks", "trivy"),
        )

    def test_unknown_scanner_is_a_usage_error(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(["real-scan", str(ROOT), "--scanner", "unknown"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("invalid choice", stderr.getvalue())

    def test_timeout_must_be_positive(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(["real-scan", str(ROOT), "--timeout-seconds", "0"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("greater than 0", stderr.getvalue())

    def test_formats_and_output_file_use_the_same_bounded_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "real-scan.json"
            with mock.patch("repo_health_doctor.cli.run_real_scanner_suite_sequential", return_value=_report()):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = main(
                        [
                            "real-scan",
                            str(ROOT),
                            "--format",
                            "json",
                            "--output",
                            str(output_path),
                        ]
                    )

            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), json.loads(stdout.getvalue()))

            for output_format, marker in (("text", "Real Scanner Suite"), ("markdown", "# Repo Health Doctor Real Scanner Suite")):
                with mock.patch("repo_health_doctor.cli.run_real_scanner_suite_sequential", return_value=_report()):
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        exit_code = main(["real-scan", str(ROOT), "--format", output_format])
                self.assertEqual(exit_code, 0)
                self.assertIn(marker, stdout.getvalue())

    def test_degraded_report_is_normal_exit_but_output_failure_is_exit_two(self) -> None:
        with mock.patch("repo_health_doctor.cli.run_real_scanner_suite_sequential", return_value=_report()):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["real-scan", str(ROOT)]), 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            stderr = io.StringIO()
            with mock.patch("repo_health_doctor.cli.run_real_scanner_suite_sequential", return_value=_report()):
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    exit_code = main(["real-scan", str(ROOT), "--output", temp_dir])

        self.assertEqual(exit_code, 2)
        self.assertIn("unable to write report", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
