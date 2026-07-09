from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import unittest
from unittest import mock

from repo_health_doctor.external_scanner import (
    OsvScannerCommandResult,
    build_osv_scan_argv,
    interpret_osv_exit_code,
    map_external_scanner_risk,
    normalize_osv_json_object,
    run_osv_scan,
    validate_external_scanner_result,
)
from repo_health_doctor.external_scanner.adapters import osv_scanner_adapter


ROOT = Path(__file__).resolve().parents[1]
OSV_FIXTURES = ROOT / "tests" / "fixtures" / "real-compatibility" / "osv"
ABSOLUTE_POSIX = "/" + "synthetic-root" + "/" + "repo" + "/" + "package-lock.json"
RELATIVE_PATH = "package-lock.json"
RAW_DETAIL = "Advisory details are intentionally omitted from normalized evidence."
RAW_REFERENCE = "https://example.invalid/osv/raw-reference"
RAW_STDOUT = "scanner stdout that should not be retained"
RAW_STDERR = "scanner stderr that should not be retained"
SECRET_LIKE_RELATIVE_PATH = "token" + "=" + "synthetic" + "/" + "package-lock.json"


def _load(name: str) -> object:
    return json.loads((OSV_FIXTURES / name).read_text(encoding="utf-8"))


def _report_path(argv: object) -> Path:
    assert isinstance(argv, (list, tuple))
    index = list(argv).index("--output-file")
    return Path(str(list(argv)[index + 1]))


def _runner_with_report(report: object, *, scan_returncode: int = 0):
    calls: list[tuple[str, ...]] = []

    def runner(argv, timeout_seconds):
        del timeout_seconds
        command = tuple(str(item) for item in argv)
        calls.append(command)
        if command == ("osv-scanner", "--version"):
            return OsvScannerCommandResult(returncode=0, stdout="osv-scanner version: 2.4.0\n", stderr="")
        _report_path(command).write_text(json.dumps(report), encoding="utf-8")
        return OsvScannerCommandResult(returncode=scan_returncode, stdout=RAW_STDOUT, stderr=RAW_STDERR)

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


class OsvScannerRealAdapterTests(unittest.TestCase):
    def test_command_builder_uses_exact_argv_without_shell_shape(self) -> None:
        argv = build_osv_scan_argv("/repo", "/tmp/osv.json")

        self.assertEqual(
            argv,
            (
                "osv-scanner",
                "scan",
                "source",
                "--recursive",
                "--format",
                "json",
                "--output-file",
                "/tmp/osv.json",
                "/repo",
            ),
        )
        self.assertIsInstance(argv, tuple)
        self.assertNotIsInstance(argv, str)

    def test_runner_receives_argv_sequence_not_shell_string(self) -> None:
        runner = _runner_with_report({"results": []}, scan_returncode=0)
        with mock.patch.object(osv_scanner_adapter, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
            result = run_osv_scan(ROOT, runner=runner)

        self.assertTrue(result.valid, result.to_dict())
        for call in runner.calls:  # type: ignore[attr-defined]
            self.assertIsInstance(call, tuple)
            self.assertNotIsInstance(call, str)

    def test_exit_code_interpretation_is_fail_closed_except_0_and_1(self) -> None:
        cases = {
            0: ("completed_no_vulnerabilities", True, None),
            1: ("completed_with_vulnerabilities", True, None),
            2: ("tool_unknown_error", False, "tool_unknown_error"),
            126: ("tool_unknown_error", False, "tool_unknown_error"),
            127: ("tool_error", False, "tool_error"),
            128: ("no_packages_found", False, "no_packages_found"),
            129: ("tool_unknown_error", False, "tool_unknown_error"),
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                interpreted = interpret_osv_exit_code(code)
                self.assertEqual((interpreted.status, interpreted.consume_report, interpreted.blocking_error), expected)

    def test_no_vulnerabilities_report_normalizes_to_limited_evidence(self) -> None:
        runner = _runner_with_report({"results": []}, scan_returncode=0)
        with mock.patch.object(osv_scanner_adapter, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
            result = run_osv_scan(ROOT, runner=runner)

        self.assertTrue(result.valid, result.to_dict())
        self.assertTrue(result.scanner_executed)
        self.assertEqual(result.normalized_result["scanner"]["name"], "osv-scanner")  # type: ignore[index]
        self.assertEqual(result.normalized_result["scanner"]["category"], "vulnerability")  # type: ignore[index]
        self.assertEqual(result.normalized_result["scanner"]["mode"], "local_static_network")  # type: ignore[index]
        self.assertTrue(result.normalized_result["execution_context"]["network_used"])  # type: ignore[index]
        self.assertFalse(result.normalized_result["execution_authorized"])  # type: ignore[index]
        self.assertEqual(result.normalized_result["summary"]["outcome"], "no_findings_in_scope")  # type: ignore[index]
        self.assertFalse(result.normalized_result["mapping_result"]["risk_lowering_allowed"])  # type: ignore[index]
        validation = validate_external_scanner_result(result.normalized_result)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertIn("no_findings_in_scope_is_not_safety_proof", validation.warnings)

    def test_unbound_or_non_clean_no_vulnerabilities_are_scope_ambiguous(self) -> None:
        cases = (
            ("dirty", "a" * 40),
            ("unknown", "a" * 40),
            ("unknown", None),
        )
        for dirty_state, repo_commit in cases:
            with self.subTest(dirty_state=dirty_state, repo_commit=repo_commit):
                runner = _runner_with_report({"results": []}, scan_returncode=0)
                with mock.patch.object(osv_scanner_adapter, "_repo_commit_and_dirty_state", return_value=(repo_commit, dirty_state)):
                    result = run_osv_scan(ROOT, runner=runner)

                self.assertFalse(result.valid)
                self.assertIn("dirty_worktree_scope_ambiguous", result.blocking_errors)
                self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]
                self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "scope_ambiguous")  # type: ignore[index]

    def test_missing_report_fails_closed(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("osv-scanner", "--version"):
                return OsvScannerCommandResult(returncode=0, stdout="2.4.0\n", stderr="")
            return OsvScannerCommandResult(returncode=0, stdout="", stderr="")

        result = run_osv_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertIn("missing_report", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]

    def test_invalid_json_fails_closed(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("osv-scanner", "--version"):
                return OsvScannerCommandResult(returncode=0, stdout="2.4.0\n", stderr="")
            _report_path(argv).write_text("not json", encoding="utf-8")
            return OsvScannerCommandResult(returncode=0, stdout="", stderr="")

        result = run_osv_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertIn("parse_failure", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]

    def test_schema_mismatch_fails_closed(self) -> None:
        reports: tuple[object, ...] = (
            [],
            {},
            {"results": {}},
            {"results": [1]},
            {"results": [{"source": {"path": 1}, "packages": []}]},
            {"results": [{"source": {"path": RELATIVE_PATH}, "packages": [{}]}]},
        )
        for report in reports:
            with self.subTest(report=report):
                runner = _runner_with_report(report)
                result = run_osv_scan(ROOT, runner=runner)

                self.assertFalse(result.valid)
                self.assertIn("parse_failure", result.blocking_errors)
                self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]

    def test_empty_results_array_parses_as_no_vulnerabilities(self) -> None:
        result = normalize_osv_json_object({"results": []}, scanner_version="2.4.0", repo_commit="0" * 40, dirty_state="clean")

        validation = validate_external_scanner_result(result)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertEqual(result["summary"]["outcome"], "no_findings_in_scope")  # type: ignore[index]
        self.assertEqual(result["summary"]["finding_count"], 0)  # type: ignore[index]

    def test_helper_exit_code_report_content_mismatch_fails_closed(self) -> None:
        vulnerable_report = _load("vulnerabilities.real.json")
        cases = (
            ("no_findings_in_scope", vulnerable_report),
            ("findings_present", {"results": []}),
        )
        for outcome, report in cases:
            with self.subTest(outcome=outcome):
                result = normalize_osv_json_object(
                    report,
                    scanner_version="2.4.0",
                    repo_commit="0" * 40,
                    dirty_state="clean",
                    outcome=outcome,
                )

                self.assertEqual(result["summary"]["outcome"], "unknown")  # type: ignore[index]
                self.assertEqual(result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]
                self.assertFalse(result["mapping_result"]["risk_lowering_allowed"])  # type: ignore[index]

    def test_helper_invalid_outcome_fails_closed(self) -> None:
        result = normalize_osv_json_object(
            {"results": []},
            scanner_version="2.4.0",
            repo_commit="0" * 40,
            dirty_state="clean",
            outcome="pass",
        )

        self.assertEqual(result["summary"]["outcome"], "unknown")  # type: ignore[index]
        self.assertEqual(result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]
        self.assertFalse(result["execution_authorized"])  # type: ignore[index]

    def test_vulnerable_package_report_normalizes_without_raw_advisory(self) -> None:
        report = _load("vulnerabilities.real.json")
        result = normalize_osv_json_object(report, scanner_version="2.4.0", repo_commit="0" * 40, dirty_state="dirty")

        validation = validate_external_scanner_result(result)
        mapping = map_external_scanner_risk(result, validation_result=validation)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertEqual(result["summary"]["outcome"], "findings_present")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["scanner_rule_id"], "GHSA-vh95-rmgr-6w4m")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["location"]["path"], "<repo>/package-lock.json")  # type: ignore[index]
        self.assertIn("package_name:minimist", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("package_version:0.0.8", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("package_ecosystem:npm", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("aliases_count:1", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("RISK014", [rule.rule_id for rule in mapping.fired_rules])
        self.assertFalse(mapping.blocks_live_execution)
        self.assertIn("raises_risk", mapping.gate_effects)

        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("details", rendered)
        self.assertNotIn("references", rendered)
        self.assertNotIn("database_specific", rendered)
        self.assertNotIn("https://example.invalid/osv/redacted-advisory", rendered)

    def test_no_packages_found_is_not_pass_or_safety_proof(self) -> None:
        runner = _runner_with_report({"results": []}, scan_returncode=128)
        result = run_osv_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertIn("no_packages_found", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "scope_ambiguous")  # type: ignore[index]
        self.assertFalse(result.normalized_result["mapping_result"]["risk_lowering_allowed"])  # type: ignore[index]

    def test_raw_advisory_absolute_paths_and_stdout_stderr_are_not_retained(self) -> None:
        report = {
            "results": [
                {
                    "source": {"path": ABSOLUTE_POSIX, "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "minimist", "version": "0.0.8", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-vh95-rmgr-6w4m",
                                    "summary": "Prototype pollution in minimist",
                                    "details": RAW_DETAIL,
                                    "aliases": ["CVE-2020-7598"],
                                    "database_specific": {"severity": "CRITICAL", "raw": RAW_DETAIL},
                                    "references": [{"type": "ADVISORY", "url": RAW_REFERENCE}],
                                }
                            ],
                            "groups": [{"ids": ["GHSA-vh95-rmgr-6w4m"]}],
                        }
                    ],
                }
            ]
        }
        runner = _runner_with_report(report, scan_returncode=1)
        result = run_osv_scan(ROOT, runner=runner)

        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("<repo>/<redacted-host-path>", rendered)
        self.assertNotIn(ABSOLUTE_POSIX, rendered)
        self.assertNotIn(RAW_DETAIL, rendered)
        self.assertNotIn(RAW_REFERENCE, rendered)
        self.assertNotIn(RAW_STDOUT, rendered)
        self.assertNotIn(RAW_STDERR, rendered)

    def test_secret_like_relative_source_paths_are_redacted(self) -> None:
        report = {
            "results": [
                {
                    "source": {"path": SECRET_LIKE_RELATIVE_PATH, "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "minimist", "version": "0.0.8", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-vh95-rmgr-6w4m",
                                    "aliases": ["CVE-2020-7598"],
                                    "database_specific": {"severity": "CRITICAL"},
                                }
                            ],
                            "groups": [],
                        }
                    ],
                }
            ]
        }

        result = normalize_osv_json_object(report, scanner_version="2.4.0", repo_commit="0" * 40, dirty_state="clean")

        rendered = json.dumps(result, sort_keys=True)
        self.assertTrue(validate_external_scanner_result(result).valid)
        self.assertIn("<repo>/<redacted-sensitive-path>", rendered)
        self.assertNotIn(SECRET_LIKE_RELATIVE_PATH, rendered)
        self.assertNotIn("token=", rendered)

    def test_no_vulnerabilities_cannot_lower_risk_or_authorize_execution(self) -> None:
        result = normalize_osv_json_object({"results": []}, scanner_version="2.4.0", repo_commit="0" * 40, dirty_state="clean")

        self.assertEqual(result["summary"]["outcome"], "no_findings_in_scope")  # type: ignore[index]
        self.assertFalse(result["mapping_result"]["risk_lowering_allowed"])  # type: ignore[index]
        self.assertFalse(result["execution_authorized"])  # type: ignore[index]
        validation = validate_external_scanner_result(result)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertIn("no_findings_in_scope_is_not_safety_proof", validation.warnings)

    def test_binary_unavailable_fails_closed_before_scan(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(argv, timeout_seconds):
            del timeout_seconds
            calls.append(tuple(argv))
            raise FileNotFoundError("osv-scanner")

        result = run_osv_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertFalse(result.scanner_executed)
        self.assertEqual(calls, [("osv-scanner", "--version")])
        self.assertIn("scanner_unavailable", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "scanner_unavailable")  # type: ignore[index]

    def test_untrusted_version_output_is_not_persisted(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("osv-scanner", "--version"):
                return OsvScannerCommandResult(returncode=0, stdout="/" + "synthetic-root" + "/tool\n", stderr="")
            _report_path(argv).write_text('{"results":[]}', encoding="utf-8")
            return OsvScannerCommandResult(returncode=0, stdout="", stderr="")

        with mock.patch.object(osv_scanner_adapter, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
            result = run_osv_scan(ROOT, runner=runner)

        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.normalized_result["scanner"]["version"], "unknown")  # type: ignore[index]
        self.assertNotIn("/" + "synthetic-root" + "/tool", rendered)

    @unittest.skipUnless(
        shutil.which("osv-scanner") and os.environ.get("RHD_LIVE_OSV_TEST") == "1",
        "optional live OSV-Scanner test requires osv-scanner binary and RHD_LIVE_OSV_TEST=1",
    )
    def test_optional_live_osv_scan_returns_no_raw_output(self) -> None:
        result = run_osv_scan(ROOT, timeout_seconds=30)

        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertTrue(result.scanner_executed)
        self.assertNotIn('"details"', rendered)
        self.assertNotIn('"references"', rendered)
        self.assertFalse(result.normalized_result["execution_context"]["raw_output_retained"])  # type: ignore[index]
        self.assertFalse(result.normalized_result["execution_authorized"])  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
