from __future__ import annotations

import json
from pathlib import Path
import shutil
import unittest
from unittest import mock

from repo_health_doctor.external_scanner import (
    GitleaksCommandResult,
    build_gitleaks_scan_argv,
    interpret_gitleaks_exit_code,
    map_external_scanner_risk,
    normalize_gitleaks_json_array,
    run_gitleaks_scan,
    validate_external_scanner_result,
)
from repo_health_doctor.external_scanner.adapters import gitleaks_adapter


ROOT = Path(__file__).resolve().parents[1]
GITLEAKS_FIXTURES = ROOT / "tests" / "fixtures" / "real-compatibility" / "gitleaks"
FORBIDDEN_FIELDS = ("Secret", "Match", "Author", "Email", "Message")
FORBIDDEN_VALUES = (
    "plain" + "-text-fixture-value",
    "redacted" + "@" + "example.invalid",
    "synthetic" + " compatibility fixture",
)
ABSOLUTE_POSIX = "/" + "synthetic-root" + "/" + "repo" + "/" + "config.txt"
ABSOLUTE_DRIVE = "C:" + "\\synthetic-root" + "\\repo" + "\\config.txt"
RELATIVE_PATH = "config/example.txt"


def _load(name: str) -> object:
    return json.loads((GITLEAKS_FIXTURES / name).read_text(encoding="utf-8"))


def _report_path(argv: object) -> Path:
    assert isinstance(argv, (list, tuple))
    index = list(argv).index("--report-path")
    return Path(str(list(argv)[index + 1]))


def _runner_with_report(report: object, *, scan_returncode: int = 0):
    calls: list[tuple[str, ...]] = []

    def runner(argv, timeout_seconds):
        del timeout_seconds
        command = tuple(str(item) for item in argv)
        calls.append(command)
        if command == ("gitleaks", "version"):
            return GitleaksCommandResult(returncode=0, stdout="8.27.2\n", stderr="")
        _report_path(command).write_text(json.dumps(report), encoding="utf-8")
        return GitleaksCommandResult(returncode=scan_returncode, stdout="", stderr="")

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


class GitleaksRealAdapterTests(unittest.TestCase):
    def test_command_builder_uses_exact_argv_without_shell_shape(self) -> None:
        argv = build_gitleaks_scan_argv("/repo", "/tmp/report.json")

        self.assertEqual(
            argv,
            (
                "gitleaks",
                "git",
                "--report-format",
                "json",
                "--report-path",
                "/tmp/report.json",
                "--redact",
                "--exit-code",
                "2",
                "--no-banner",
                "--log-level",
                "error",
                "/repo",
            ),
        )
        self.assertIsInstance(argv, tuple)
        self.assertNotIsInstance(argv, str)

    def test_exit_code_interpretation_is_fail_closed_except_0_and_2(self) -> None:
        cases = {
            0: ("completed_no_findings", True, None),
            2: ("completed_with_findings", True, None),
            1: ("tool_error", False, "scan_error"),
            126: ("tool_interface_error", False, "tool_interface_error"),
            99: ("tool_unknown_error", False, "tool_unknown_error"),
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                interpreted = interpret_gitleaks_exit_code(code)
                self.assertEqual((interpreted.status, interpreted.consume_report, interpreted.blocking_error), expected)

    def test_no_findings_report_normalizes_to_valid_external_scanner_result(self) -> None:
        runner = _runner_with_report([], scan_returncode=0)
        with mock.patch.object(gitleaks_adapter, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
            result = run_gitleaks_scan(ROOT, runner=runner)

        self.assertTrue(result.valid, result.to_dict())
        self.assertTrue(result.scanner_executed)
        self.assertEqual(result.normalized_result["scanner"]["name"], "gitleaks")  # type: ignore[index]
        self.assertEqual(result.normalized_result["scanner"]["category"], "secret_detection")  # type: ignore[index]
        self.assertEqual(result.normalized_result["scanner"]["mode"], "local_static_no_network")  # type: ignore[index]
        self.assertEqual(result.normalized_result["scanner"]["scanner_source"], "external_binary")  # type: ignore[index]
        self.assertEqual(result.normalized_result["summary"]["outcome"], "no_findings_in_scope")  # type: ignore[index]
        self.assertEqual(result.normalized_result["input_scope"]["source_type"], "git_commit")  # type: ignore[index]
        self.assertEqual(result.normalized_result["input_scope"]["dirty_state"], "clean")  # type: ignore[index]
        validation = validate_external_scanner_result(result.normalized_result)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertIn("no_findings_in_scope_is_not_safety_proof", validation.warnings)

    def test_unbound_or_non_clean_no_findings_are_scope_ambiguous_not_pass(self) -> None:
        cases = (
            ("dirty", "a" * 40),
            ("unknown", "a" * 40),
            ("unknown", None),
        )
        for dirty_state, repo_commit in cases:
            with self.subTest(dirty_state=dirty_state, repo_commit=repo_commit):
                runner = _runner_with_report([], scan_returncode=0)
                with mock.patch.object(gitleaks_adapter, "_repo_commit_and_dirty_state", return_value=(repo_commit, dirty_state)):
                    result = run_gitleaks_scan(ROOT, runner=runner)

                self.assertFalse(result.valid)
                self.assertIn("dirty_worktree_scope_ambiguous", result.blocking_errors)
                self.assertEqual(result.normalized_result["input_scope"]["repo_commit"], repo_commit)  # type: ignore[index]
                self.assertEqual(result.normalized_result["input_scope"]["dirty_state"], dirty_state)  # type: ignore[index]
                self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]
                self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "scope_ambiguous")  # type: ignore[index]
                residual_ids = {item["risk_id"] for item in result.normalized_result["residual_risks"]}  # type: ignore[index]
                if dirty_state == "dirty":
                    self.assertIn("dirty_worktree_not_clean_commit_evidence", residual_ids)

    def test_helper_no_findings_requires_clean_commit_binding(self) -> None:
        cases = (
            ("clean", None),
            ("dirty", "a" * 40),
            ("unknown", "a" * 40),
        )
        for dirty_state, repo_commit in cases:
            with self.subTest(dirty_state=dirty_state, repo_commit=repo_commit):
                result = normalize_gitleaks_json_array([], repo_commit=repo_commit, dirty_state=dirty_state)

                validation = validate_external_scanner_result(result)
                self.assertTrue(validation.valid, validation.to_dict())
                self.assertEqual(result["summary"]["outcome"], "unknown")  # type: ignore[index]
                self.assertEqual(result["summary"]["unknown_reason"], "scope_ambiguous")  # type: ignore[index]

    def test_findings_report_omits_forbidden_raw_fields_and_values(self) -> None:
        report = _load("findings-redacted.real.json")
        result = normalize_gitleaks_json_array(report, scanner_version="8.27.2", repo_commit="0" * 40, dirty_state="dirty")

        validation = validate_external_scanner_result(result)
        mapping = map_external_scanner_risk(result, validation_result=validation)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertEqual(result["summary"]["outcome"], "findings_present")  # type: ignore[index]
        self.assertEqual(result["findings"][0]["scanner_rule_id"], "generic-api-key")  # type: ignore[index]
        self.assertIn("secret_redacted:unknown", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("description:present_omitted", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("tags:present_count:2", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertEqual(result["input_scope"]["dirty_state"], "dirty")  # type: ignore[index]
        self.assertIn("RISK001", [rule.rule_id for rule in mapping.fired_rules])
        self.assertTrue(mapping.blocks_live_execution)

        rendered = json.dumps(result, sort_keys=True)
        for field in FORBIDDEN_FIELDS:
            self.assertNotIn(field, rendered)
        for value in FORBIDDEN_VALUES:
            self.assertNotIn(value, rendered)

    def test_rule_metadata_is_not_persisted_as_raw_evidence(self) -> None:
        unsafe_description = "private " + "/" + "synthetic-root" + "/" + "policy"
        unsafe_tag = "policy " + "owner" + "@" + "example.invalid"
        report = [
            {
                "RuleID": "generic-api-key",
                "Description": unsafe_description,
                "File": RELATIVE_PATH,
                "StartLine": 1,
                "StartColumn": 1,
                "Tags": [unsafe_tag],
            }
        ]

        result = normalize_gitleaks_json_array(report, scanner_version="8.27.2", repo_commit="0" * 40, dirty_state="clean")

        validation = validate_external_scanner_result(result)
        rendered = json.dumps(result, sort_keys=True)
        self.assertTrue(validation.valid, validation.to_dict())
        self.assertNotIn(unsafe_description, rendered)
        self.assertNotIn(unsafe_tag, rendered)
        self.assertIn("description:present_omitted", result["findings"][0]["evidence"])  # type: ignore[index]
        self.assertIn("tags:present_count:1", result["findings"][0]["evidence"])  # type: ignore[index]

    def test_absolute_host_paths_are_redacted_but_relative_paths_are_preserved(self) -> None:
        report = [
            {
                "RuleID": "generic-api-key",
                "Description": "Absolute POSIX path",
                "File": ABSOLUTE_POSIX,
                "StartLine": 1,
                "StartColumn": 1,
                "Fingerprint": f"abc:{ABSOLUTE_POSIX}:generic-api-key:1",
            },
            {
                "RuleID": "generic-api-key",
                "Description": "Drive path",
                "File": ABSOLUTE_DRIVE,
                "StartLine": 2,
                "StartColumn": 1,
                "Fingerprint": f"abc:{ABSOLUTE_DRIVE}:generic-api-key:2",
            },
            {
                "RuleID": "generic-api-key",
                "Description": "Relative path",
                "File": RELATIVE_PATH,
                "StartLine": 3,
                "StartColumn": 1,
                "Fingerprint": f"abc:{RELATIVE_PATH}:generic-api-key:3",
            },
        ]
        result = normalize_gitleaks_json_array(report, scanner_version="8.27.2", repo_commit="0" * 40, dirty_state="clean")

        rendered = json.dumps(result, sort_keys=True)
        for forbidden in (ABSOLUTE_POSIX, ABSOLUTE_DRIVE):
            self.assertNotIn(forbidden, rendered)
        paths = [finding["location"]["path"] for finding in result["findings"]]  # type: ignore[index]
        self.assertEqual(paths[:2], ["<repo>/<redacted-host-path>"] * 2)
        self.assertEqual(paths[2], f"<repo>/{RELATIVE_PATH}")

    def test_missing_report_fails_closed(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("gitleaks", "version"):
                return GitleaksCommandResult(returncode=0, stdout="8.27.2\n", stderr="")
            return GitleaksCommandResult(returncode=0, stdout="", stderr="")

        result = run_gitleaks_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertIn("missing_report", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]

    def test_invalid_json_fails_closed(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("gitleaks", "version"):
                return GitleaksCommandResult(returncode=0, stdout="8.27.2\n", stderr="")
            _report_path(argv).write_text("not json", encoding="utf-8")
            return GitleaksCommandResult(returncode=0, stdout="", stderr="")

        result = run_gitleaks_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertIn("parse_failure", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]

    def test_top_level_object_and_array_schema_mismatch_fail_closed(self) -> None:
        for report in ({}, [1], [{}], [{"RuleID": "generic-api-key"}], [{"RuleID": "generic-api-key", "File": RELATIVE_PATH, "StartLine": "1"}]):
            with self.subTest(report=report):
                runner = _runner_with_report(report)
                result = run_gitleaks_scan(ROOT, runner=runner)

                self.assertFalse(result.valid)
                self.assertIn("parse_failure", result.blocking_errors)
                self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]

    def test_helper_malformed_findings_fail_closed(self) -> None:
        reports: tuple[Sequence[dict[str, object]], ...] = (
            ({},),
            ({"RuleID": "generic-api-key"},),
            ({"File": RELATIVE_PATH},),
            ({"RuleID": "generic-api-key", "File": RELATIVE_PATH, "StartLine": "1"},),
        )
        for report in reports:
            with self.subTest(report=report):
                result = normalize_gitleaks_json_array(report, scanner_version="8.27.2", repo_commit="0" * 40, dirty_state="clean")
                validation = validate_external_scanner_result(result)

                self.assertTrue(validation.valid, validation.to_dict())
                self.assertEqual(result["summary"]["outcome"], "unknown")  # type: ignore[index]
                self.assertEqual(result["summary"]["unknown_reason"], "parse_failure")  # type: ignore[index]
                self.assertEqual(result["summary"]["gate_effects"], ["quarantine"])  # type: ignore[index]

    def test_exit_code_report_content_mismatch_fails_closed(self) -> None:
        finding = {
            "RuleID": "generic-api-key",
            "Description": "Generic API key",
            "File": RELATIVE_PATH,
            "StartLine": 1,
            "StartColumn": 1,
        }
        cases = (
            (0, [finding]),
            (2, []),
        )
        for returncode, report in cases:
            with self.subTest(returncode=returncode):
                runner = _runner_with_report(report, scan_returncode=returncode)
                result = run_gitleaks_scan(ROOT, runner=runner)

                self.assertFalse(result.valid)
                self.assertIn("report_exit_code_mismatch", result.blocking_errors)
                self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]

    def test_binary_unavailable_fails_closed_before_scan(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(argv, timeout_seconds):
            del timeout_seconds
            calls.append(tuple(argv))
            raise FileNotFoundError("gitleaks")

        result = run_gitleaks_scan(ROOT, runner=runner)

        self.assertFalse(result.valid)
        self.assertFalse(result.scanner_executed)
        self.assertEqual(calls, [("gitleaks", "version")])
        self.assertIn("scanner_unavailable", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["unknown_reason"], "scanner_unavailable")  # type: ignore[index]

    def test_untrusted_version_output_is_not_persisted(self) -> None:
        def runner(argv, timeout_seconds):
            del timeout_seconds
            if tuple(argv) == ("gitleaks", "version"):
                return GitleaksCommandResult(returncode=0, stdout="/" + "home" + "/synthetic/path\n", stderr="")
            _report_path(argv).write_text("[]", encoding="utf-8")
            return GitleaksCommandResult(returncode=0, stdout="", stderr="")

        with mock.patch.object(gitleaks_adapter, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
            result = run_gitleaks_scan(ROOT, runner=runner)

        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.normalized_result["scanner"]["version"], "unknown")  # type: ignore[index]
        self.assertNotIn("/" + "home" + "/", rendered)

    @unittest.skipUnless(shutil.which("gitleaks"), "optional live Gitleaks test requires gitleaks binary")
    def test_optional_live_gitleaks_scan_returns_no_raw_output(self) -> None:
        result = run_gitleaks_scan(ROOT, timeout_seconds=30)

        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertTrue(result.scanner_executed)
        self.assertNotIn('"Secret"', rendered)
        self.assertNotIn('"Match"', rendered)
        self.assertFalse(result.normalized_result["execution_context"]["network_used"])  # type: ignore[index]
        self.assertFalse(result.normalized_result["execution_context"]["raw_output_retained"])  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
