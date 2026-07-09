from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import unittest
from unittest import mock

from repo_health_doctor.external_scanner import (
    TrivyCommandResult,
    assess_trivy_version,
    build_trivy_scan_argv,
    interpret_trivy_exit_code,
    map_external_scanner_risk,
    normalize_trivy_json_object,
    run_trivy_scan,
    validate_external_scanner_result,
)
from repo_health_doctor.external_scanner.adapters import trivy_adapter


ROOT = Path(__file__).resolve().parents[1]
TRIVY_FIXTURES = ROOT / "tests" / "fixtures" / "real-compatibility" / "trivy"
ABSOLUTE_POSIX = "/" + "synthetic-root" + "/" + "repo" + "/" + "package-lock.json"
LOCAL_IP_TARGET = ".".join(("192", "168", "10", "20")) + "/config.yaml"
RAW_DESCRIPTION = "Long vulnerability description that must be omitted from normalized evidence."
RAW_REFERENCE = "https://" + "example.invalid" + "/trivy/raw-reference"
RAW_STDOUT = "trivy stdout that should not be retained"
RAW_STDERR = "trivy stderr that should not be retained"
RAW_SECRET_MATCH = "placeholder secret match text that must be omitted"
RAW_CODE_SNIPPET = "placeholder code snippet that must be omitted"


def _load(name: str) -> object:
    return json.loads((TRIVY_FIXTURES / name).read_text(encoding="utf-8"))


def _report_path(argv: object) -> Path:
    assert isinstance(argv, (list, tuple))
    index = list(argv).index("--output")
    return Path(str(list(argv)[index + 1]))


def _runner_with_report(report: object, *, scan_returncode: int = 0, version: str = "Version: 0.69.3\n"):
    calls: list[tuple[str, ...]] = []

    def runner(argv, timeout_seconds):
        del timeout_seconds
        command = tuple(str(item) for item in argv)
        calls.append(command)
        if command == ("trivy", "--version"):
            return TrivyCommandResult(returncode=0, stdout=version, stderr="")
        _report_path(command).write_text(json.dumps(report), encoding="utf-8")
        return TrivyCommandResult(returncode=scan_returncode, stdout=RAW_STDOUT, stderr=RAW_STDERR)

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


class TrivyRealAdapterTests(unittest.TestCase):
    def test_command_builder_uses_exact_argv_without_shell_shape(self) -> None:
        argv = build_trivy_scan_argv("/repo", "/tmp/trivy.json")

        self.assertEqual(
            argv,
            (
                "trivy",
                "fs",
                "--scanners",
                "vuln,misconfig",
                "--format",
                "json",
                "--output",
                "/tmp/trivy.json",
                "--exit-code",
                "1",
                "/repo",
            ),
        )
        self.assertIsInstance(argv, tuple)
        self.assertNotIsInstance(argv, str)

    def test_runner_receives_preflight_and_argv_sequence_not_shell_string(self) -> None:
        runner = _runner_with_report({"Results": []}, scan_returncode=0)
        with mock.patch.object(trivy_adapter, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
            result = run_trivy_scan(ROOT, runner=runner)

        self.assertTrue(result.valid, result.to_dict())
        self.assertGreaterEqual(len(runner.calls), 2)  # type: ignore[attr-defined]
        self.assertEqual(runner.calls[0], ("trivy", "--version"))  # type: ignore[attr-defined]
        for call in runner.calls:  # type: ignore[attr-defined]
            self.assertIsInstance(call, tuple)
            self.assertNotIsInstance(call, str)
        scan_argv = runner.calls[1]  # type: ignore[attr-defined]
        self.assertIn("--cache-dir", scan_argv)
        self.assertIn("--exit-code", scan_argv)

    def test_known_unsafe_or_unknown_version_stops_live_scan(self) -> None:
        cases = (
            "Version: 0.69.4\n",
            "Version: v0.69.4\n",
            "/" + "synthetic-root" + "/" + "tool\n",
        )
        for version in cases:
            with self.subTest(version=version):
                runner = _runner_with_report({"Results": []}, scan_returncode=0, version=version)
                result = run_trivy_scan(ROOT, runner=runner)

                self.assertFalse(result.valid)
                self.assertFalse(result.scanner_executed)
                self.assertEqual(runner.calls, [("trivy", "--version")])  # type: ignore[attr-defined]
                self.assertIn("tool_unsafe_or_untrusted", result.blocking_errors)
                self.assertTrue(result.normalized_result["scanner"]["unsupported_version"])  # type: ignore[index]
                self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "unsupported_version")  # type: ignore[index]
                self.assertIn("RISK018", result.normalized_result["mapping_result"]["rules_fired"])  # type: ignore[index]
                self.assertNotIn("/" + "synthetic-root" + "/", json.dumps(result.to_dict(), sort_keys=True))

    def test_version_assessment_accepts_clear_non_denylisted_versions(self) -> None:
        safe = assess_trivy_version("Version: 0.69.3\n", "")
        unsafe = assess_trivy_version("Version: 0.69.5\n", "")

        self.assertTrue(safe.supported_for_live_scan)
        self.assertEqual(safe.version, "0.69.3")
        self.assertFalse(unsafe.supported_for_live_scan)
        self.assertEqual(unsafe.blocking_error, "tool_unsafe_or_untrusted")

    def test_exit_code_interpretation_is_fail_closed_except_0_and_1(self) -> None:
        cases = {
            0: ("completed_no_findings", True, None),
            1: ("completed_with_findings", True, None),
            2: ("tool_error", False, "tool_error"),
            126: ("tool_error", False, "tool_error"),
            127: ("tool_unavailable", False, "scanner_unavailable"),
            128: ("tool_unknown_error", False, "tool_unknown_error"),
            255: ("tool_unknown_error", False, "tool_unknown_error"),
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                interpreted = interpret_trivy_exit_code(code)
                self.assertEqual((interpreted.status, interpreted.consume_report, interpreted.blocking_error), expected)

    def test_no_findings_report_normalizes_to_limited_evidence(self) -> None:
        runner = _runner_with_report({"Results": []}, scan_returncode=0)
        with mock.patch.object(trivy_adapter, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
            result = run_trivy_scan(ROOT, runner=runner)

        self.assertTrue(result.valid, result.to_dict())
        self.assertTrue(result.scanner_executed)
        self.assertEqual(result.normalized_result["scanner"]["name"], "trivy")  # type: ignore[index]
        self.assertEqual(result.normalized_result["scanner"]["mode"], "local_static_network")  # type: ignore[index]
        self.assertTrue(result.normalized_result["execution_context"]["network_used"])  # type: ignore[index]
        self.assertTrue(result.normalized_result["execution_context"]["scanner_downloaded_dependencies"])  # type: ignore[index]
        self.assertFalse(result.normalized_result["execution_authorized"])  # type: ignore[index]
        self.assertEqual(result.normalized_result["summary"]["outcome"], "no_findings_in_scope")  # type: ignore[index]
        self.assertFalse(result.normalized_result["mapping_result"]["risk_lowering_allowed"])  # type: ignore[index]
        validation = validate_external_scanner_result(result.normalized_result)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertIn("no_findings_in_scope_is_not_safety_proof", validation.warnings)

    def test_unbound_or_non_clean_no_findings_are_scope_ambiguous(self) -> None:
        cases = (
            ("dirty", "a" * 40),
            ("unknown", "a" * 40),
            ("unknown", None),
        )
        for dirty_state, repo_commit in cases:
            with self.subTest(dirty_state=dirty_state, repo_commit=repo_commit):
                runner = _runner_with_report({"Results": []}, scan_returncode=0)
                with mock.patch.object(trivy_adapter, "_repo_commit_and_dirty_state", return_value=(repo_commit, dirty_state)):
                    result = run_trivy_scan(ROOT, runner=runner)

                self.assertFalse(result.valid)
                self.assertIn("dirty_worktree_scope_ambiguous", result.blocking_errors)
                self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]
                self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "scope_ambiguous")  # type: ignore[index]

    def test_timeout_fails_closed(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("trivy", "--version"):
                return TrivyCommandResult(returncode=0, stdout="Version: 0.69.3\n", stderr="")
            return TrivyCommandResult(returncode=124, stdout=RAW_STDOUT, stderr=RAW_STDERR, timed_out=True)

        result = run_trivy_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertTrue(result.scanner_executed)
        self.assertIn("scanner_timeout", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "timeout")  # type: ignore[index]
        self.assertTrue(result.normalized_result["execution_context"]["timeout_occurred"])  # type: ignore[index]
        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(RAW_STDOUT, rendered)
        self.assertNotIn(RAW_STDERR, rendered)

    def test_missing_report_fails_closed(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("trivy", "--version"):
                return TrivyCommandResult(returncode=0, stdout="Version: 0.69.3\n", stderr="")
            return TrivyCommandResult(returncode=0, stdout="", stderr="")

        result = run_trivy_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertIn("missing_report", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]

    def test_invalid_json_fails_closed(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("trivy", "--version"):
                return TrivyCommandResult(returncode=0, stdout="Version: 0.69.3\n", stderr="")
            _report_path(argv).write_text("not json", encoding="utf-8")
            return TrivyCommandResult(returncode=0, stdout="", stderr="")

        result = run_trivy_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertIn("parse_failure", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]

    def test_schema_mismatch_fails_closed(self) -> None:
        reports: tuple[object, ...] = (
            [],
            {},
            {"Results": {}},
            {"Results": [1]},
            {"Results": [{"Target": 1}]},
            {"Results": [{"Vulnerabilities": [{}]}]},
            {"Results": [{"Misconfigurations": [{"Severity": 1}]}]},
            {"Results": [{"Secrets": [{"RuleID": "generic-secret", "StartLine": "2"}]}]},
        )
        for report in reports:
            with self.subTest(report=report):
                runner = _runner_with_report(report)
                result = run_trivy_scan(ROOT, runner=runner)

                self.assertFalse(result.valid)
                self.assertIn("parse_failure", result.blocking_errors)
                self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]

    def test_empty_results_array_parses_as_no_findings(self) -> None:
        result = normalize_trivy_json_object({"Results": []}, scanner_version="0.69.3", repo_commit="0" * 40, dirty_state="clean")

        validation = validate_external_scanner_result(result)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertEqual(result["summary"]["outcome"], "no_findings_in_scope")  # type: ignore[index]
        self.assertEqual(result["summary"]["finding_count"], 0)  # type: ignore[index]

    def test_helper_exit_code_report_content_mismatch_fails_closed(self) -> None:
        vulnerable_report = _load("vulnerabilities.real.json")
        cases = (
            ("no_findings_in_scope", vulnerable_report),
            ("findings_present", {"Results": []}),
        )
        for outcome, report in cases:
            with self.subTest(outcome=outcome):
                result = normalize_trivy_json_object(
                    report,
                    scanner_version="0.69.3",
                    repo_commit="0" * 40,
                    dirty_state="clean",
                    outcome=outcome,
                )

                self.assertEqual(result["summary"]["outcome"], "unknown")  # type: ignore[index]
                self.assertEqual(result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]
                self.assertFalse(result["mapping_result"]["risk_lowering_allowed"])  # type: ignore[index]

    def test_vulnerability_report_normalizes_without_raw_advisory(self) -> None:
        result = normalize_trivy_json_object(_load("vulnerabilities.real.json"), scanner_version="0.69.3", repo_commit="0" * 40, dirty_state="dirty")

        validation = validate_external_scanner_result(result)
        mapping = map_external_scanner_risk(result, validation_result=validation)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertEqual(result["summary"]["outcome"], "findings_present")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["scanner_rule_id"], "CVE-2020-7598")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["location"]["path"], "<repo>/package-lock.json")  # type: ignore[index]
        self.assertIn("package_name:minimist", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("installed_version:0.0.8", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("fixed_versions_count:1", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("RISK014", [rule.rule_id for rule in mapping.fired_rules])
        self.assertIn("raises_risk", mapping.gate_effects)
        self.assertNotIn("Prototype pollution in minimist", json.dumps(result, sort_keys=True))

    def test_misconfiguration_report_normalizes_without_raw_code_or_message(self) -> None:
        result = normalize_trivy_json_object(_load("misconfigurations.real.json"), scanner_version="0.69.3", repo_commit="0" * 40, dirty_state="clean")

        validation = validate_external_scanner_result(result)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertEqual(result["summary"]["outcome"], "findings_present")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["primary_category"], "repo_posture")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["secondary_category"], "low_security_posture")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["location"]["line"], 3)  # type: ignore[index]
        self.assertIn("misconfiguration_id:DS002", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("title:present_omitted", result["findings"][0]["evidence"])  # type: ignore[index]
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("Image user should not be root", rendered)
        self.assertNotIn("CauseMetadata", rendered)

    def test_secret_report_normalizes_without_secret_values_or_line_content(self) -> None:
        result = normalize_trivy_json_object(_load("secrets.real.json"), scanner_version="0.69.3", repo_commit="0" * 40, dirty_state="clean")

        validation = validate_external_scanner_result(result)
        mapping = map_external_scanner_risk(result, validation_result=validation)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertEqual(result["summary"]["outcome"], "findings_present")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["primary_category"], "secret")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["secondary_category"], "verified_secret")  # type: ignore[index]
        self.assertIn("secret_rule_id:generic-secret", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("secret_value:redacted", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("RISK001", [rule.rule_id for rule in mapping.fired_rules])
        self.assertTrue(mapping.blocks_live_execution)
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("Match", rendered)
        self.assertNotIn("Code", rendered)

    def test_raw_references_descriptions_paths_secret_matches_and_stdout_stderr_are_not_retained(self) -> None:
        report = {
            "Results": [
                {
                    "Target": ABSOLUTE_POSIX,
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2020-7598",
                            "PkgName": "minimist",
                            "InstalledVersion": "0.0.8",
                            "FixedVersion": "0.2.1",
                            "Severity": "CRITICAL",
                            "Description": RAW_DESCRIPTION,
                            "References": [RAW_REFERENCE],
                        }
                    ],
                },
                {
                    "Target": LOCAL_IP_TARGET,
                    "Class": "secret",
                    "Type": "text",
                    "Secrets": [
                        {
                            "RuleID": "generic-secret",
                            "Category": "General",
                            "Severity": "HIGH",
                            "StartLine": 4,
                            "Match": RAW_SECRET_MATCH,
                            "Code": {"Lines": [{"Content": RAW_CODE_SNIPPET}]},
                        }
                    ],
                },
            ]
        }
        runner = _runner_with_report(report, scan_returncode=1)
        result = run_trivy_scan(ROOT, runner=runner)

        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn("<repo>/<redacted-host-path>", rendered)
        self.assertIn("<repo>/<redacted-sensitive-path>", rendered)
        for forbidden in (ABSOLUTE_POSIX, LOCAL_IP_TARGET, RAW_DESCRIPTION, RAW_REFERENCE, RAW_SECRET_MATCH, RAW_CODE_SNIPPET, RAW_STDOUT, RAW_STDERR):
            self.assertNotIn(forbidden, rendered)

    def test_secret_match_and_code_do_not_affect_source_report_fingerprint(self) -> None:
        def report(match_text: str, code_text: str) -> dict[str, object]:
            return {
                "Results": [
                    {
                        "Target": "config/example.txt",
                        "Class": "secret",
                        "Type": "text",
                        "Secrets": [
                            {
                                "RuleID": "generic-secret",
                                "Category": "General",
                                "Severity": "HIGH",
                                "StartLine": 4,
                                "Match": match_text,
                                "Code": {"Lines": [{"Content": code_text}]},
                            }
                        ],
                    }
                ]
            }

        first = normalize_trivy_json_object(report("first omitted match", "first omitted code"), scanner_version="0.69.3", repo_commit="0" * 40, dirty_state="clean")
        second = normalize_trivy_json_object(report("second omitted match", "second omitted code"), scanner_version="0.69.3", repo_commit="0" * 40, dirty_state="clean")

        first_fingerprint = first["binding"]["source_report_fingerprint"]  # type: ignore[index]
        second_fingerprint = second["binding"]["source_report_fingerprint"]  # type: ignore[index]
        self.assertIsNotNone(first_fingerprint)
        self.assertEqual(first_fingerprint, second_fingerprint)
        rendered = json.dumps(first, sort_keys=True) + json.dumps(second, sort_keys=True)
        for forbidden in ("first omitted match", "first omitted code", "second omitted match", "second omitted code"):
            self.assertNotIn(forbidden, rendered)

    def test_no_findings_cannot_lower_risk_or_authorize_execution(self) -> None:
        result = normalize_trivy_json_object({"Results": []}, scanner_version="0.69.3", repo_commit="0" * 40, dirty_state="clean")

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
            raise FileNotFoundError("trivy")

        result = run_trivy_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertFalse(result.scanner_executed)
        self.assertEqual(calls, [("trivy", "--version")])
        self.assertIn("scanner_unavailable", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "scanner_unavailable")  # type: ignore[index]

    @unittest.skipUnless(
        shutil.which("trivy") and os.environ.get("RHD_LIVE_TRIVY_TEST") == "1",
        "optional live Trivy test requires trivy binary and RHD_LIVE_TRIVY_TEST=1",
    )
    def test_optional_live_trivy_scan_returns_no_raw_output(self) -> None:
        result = run_trivy_scan(ROOT, timeout_seconds=60)

        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertTrue(result.scanner_executed)
        self.assertNotIn('"Match"', rendered)
        self.assertNotIn('"Code"', rendered)
        self.assertNotIn('"References"', rendered)
        self.assertFalse(result.normalized_result["execution_context"]["raw_output_retained"])  # type: ignore[index]
        self.assertFalse(result.normalized_result["execution_authorized"])  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
