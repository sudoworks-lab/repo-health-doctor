from __future__ import annotations

from copy import deepcopy
import json
import re
import unittest

from repo_health_doctor.external_scanner import evaluate_scanner_execution_readiness
from tests.external_scanner_fixture_helpers import (
    SCHEMAS,
    load_external_scanner_readiness_fixture,
    load_json,
)


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


def _valid() -> dict[str, object]:
    return load_external_scanner_readiness_fixture("valid_plan_with_synthetic_approval.json")


class ExternalScannerExecutionReadinessTests(unittest.TestCase):
    def test_readiness_schema_contract(self) -> None:
        schema = load_json(SCHEMAS / "external-scanner-readiness-result.schema.json")
        self.assertIs(schema["additionalProperties"], False)
        self.assertIn("schema_version", schema["required"])
        self.assertEqual(schema["properties"]["execution_authorized"]["const"], False)

    def test_valid_plan_without_approval_is_not_ready(self) -> None:
        fixture = _valid()
        result = evaluate_scanner_execution_readiness(fixture["plan"])  # type: ignore[arg-type]
        self.assertFalse(result.ready)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.approval_present)
        self.assertIn("approval_missing", result.blocking_errors)

    def test_valid_plan_with_synthetic_approval_is_ready_but_not_execution_authorization(self) -> None:
        fixture = _valid()
        result = evaluate_scanner_execution_readiness(fixture["plan"], approval=fixture["approval"])  # type: ignore[arg-type]
        self.assertTrue(result.ready)
        self.assertFalse(result.execution_authorized)
        self.assertTrue(result.approval_present)
        self.assertFalse(result.scanner_executed)
        self.assertFalse(result.network_allowed)
        self.assertFalse(result.target_code_execution_allowed)
        self.assertFalse(result.raw_output_retention)
        self.assertTrue(result.raw_output_discard_required)

    def test_invalid_fixture_cases_fail_closed(self) -> None:
        base = _valid()
        cases = [
            "invalid_network_allowed.json",
            "invalid_docker_socket_mount.json",
            "invalid_host_home_mount.json",
            "invalid_raw_output_retention.json",
            "invalid_shell_string_command.json",
            "invalid_approval_command_mismatch.json",
        ]
        for fixture_name in cases:
            with self.subTest(fixture=fixture_name):
                fixture = load_external_scanner_readiness_fixture(fixture_name)
                plan = deepcopy(base["plan"])
                approval = deepcopy(base["approval"])
                plan.update(fixture.get("mutations", {}))  # type: ignore[union-attr]
                approval.update(fixture.get("approval_mutations", {}))  # type: ignore[union-attr]
                result = evaluate_scanner_execution_readiness(plan, approval=approval)  # type: ignore[arg-type]
                self.assertFalse(result.ready)
                self.assertFalse(result.execution_authorized)
                self.assertIn(fixture["expected_error"], result.blocking_errors)

    def test_target_code_shell_interpreter_limitations_and_residuals_fail_closed(self) -> None:
        fixture = _valid()
        plan = deepcopy(fixture["plan"])
        approval = deepcopy(fixture["approval"])
        plan["target_code_execution_allowed"] = True
        plan["scanner_argv"] = ["sh", "-c", "zizmor"]
        plan["limitations"] = []
        plan["residual_risks"] = []
        approval["scanner_argv"] = plan["scanner_argv"]  # type: ignore[index]
        result = evaluate_scanner_execution_readiness(plan, approval=approval)  # type: ignore[arg-type]
        self.assertFalse(result.ready)
        self.assertIn("target_code_execution_allowed_must_be_false", result.blocking_errors)
        self.assertIn("scanner_shell_interpreter_command_forbidden", result.blocking_errors)
        self.assertIn("limitations_empty", result.blocking_errors)
        self.assertIn("residual_risks_empty", result.blocking_errors)

    def test_readiness_fixtures_and_results_do_not_contain_obvious_leak_patterns(self) -> None:
        fixtures = [
            "valid_plan_with_synthetic_approval.json",
            "invalid_missing_approval.json",
            "invalid_network_allowed.json",
            "invalid_docker_socket_mount.json",
            "invalid_host_home_mount.json",
            "invalid_raw_output_retention.json",
            "invalid_shell_string_command.json",
            "invalid_approval_command_mismatch.json",
        ]
        for fixture_name in fixtures:
            with self.subTest(fixture=fixture_name):
                fixture = load_external_scanner_readiness_fixture(fixture_name)
                if "plan" in fixture:
                    result = evaluate_scanner_execution_readiness(
                        fixture["plan"],  # type: ignore[arg-type]
                        approval=fixture.get("approval") if isinstance(fixture.get("approval"), dict) else None,
                    )
                else:
                    base = _valid()
                    plan = deepcopy(base["plan"])
                    plan.update(fixture.get("mutations", {}))  # type: ignore[union-attr]
                    result = evaluate_scanner_execution_readiness(plan, approval=base["approval"])  # type: ignore[arg-type]
                for content in (json.dumps(fixture, sort_keys=True), json.dumps(result.to_dict(), sort_keys=True)):
                    for pattern in LEAK_PATTERNS:
                        self.assertIsNone(pattern.search(content), pattern.pattern)


if __name__ == "__main__":
    unittest.main()
