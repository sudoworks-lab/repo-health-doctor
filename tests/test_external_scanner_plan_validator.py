from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import unittest

from repo_health_doctor.external_scanner import load_external_scanner_plan_schema, validate_external_scanner_plan
from tests.external_scanner_fixture_helpers import load_external_scanner_plan_fixture


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "policies" / "external-scanner-execution-policy.v0.1.json"
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


def _valid_plan() -> dict[str, object]:
    return load_external_scanner_plan_fixture("zizmor_no_network_plan.json")


class ExternalScannerPlanValidatorTests(unittest.TestCase):
    def test_valid_no_network_plans_are_valid(self) -> None:
        for fixture in ("zizmor_no_network_plan.json", "semgrep_custom_no_network_plan.json"):
            with self.subTest(fixture=fixture):
                result = validate_external_scanner_plan(load_external_scanner_plan_fixture(fixture))
                self.assertTrue(result.valid)
                self.assertEqual(result.blocking_errors, ())
                self.assertTrue(result.scanner_execution_planned)
                self.assertFalse(result.scanner_executed)
                self.assertFalse(result.execution_authorized)
                self.assertFalse(result.network_allowed)
                self.assertFalse(result.target_code_execution_allowed)
                self.assertFalse(result.raw_output_retention)
                self.assertTrue(result.requires_human_approval)
                self.assertIn("planner_only", result.limitations)
                self.assertIn("local_runner_unimplemented", result.residual_risks)

    def test_invalid_plan_fixtures_fail_closed(self) -> None:
        cases = {
            "invalid_network_allowed_plan.json": "network_allowed_must_be_false",
            "invalid_target_code_execution_allowed_plan.json": "target_code_execution_allowed_must_be_false",
            "invalid_raw_output_retention_plan.json": "raw_output_retention_must_be_false",
            "invalid_execution_authorized_plan.json": "plan_execution_authorized_must_be_false",
            "invalid_missing_approval_plan.json": "requires_human_approval_must_be_true",
        }
        for fixture, invariant in cases.items():
            with self.subTest(fixture=fixture):
                result = validate_external_scanner_plan(load_external_scanner_plan_fixture(fixture))
                self.assertFalse(result.valid)
                self.assertIn(invariant, result.blocking_errors)
                self.assertFalse(result.scanner_executed)

    def test_scanner_executed_true_fails_closed(self) -> None:
        data = _valid_plan()
        data["scanner_executed"] = True
        result = validate_external_scanner_plan(data)
        self.assertFalse(result.valid)
        self.assertIn("scanner_executed_must_be_false", result.blocking_errors)

    def test_limitations_empty_fails_closed(self) -> None:
        data = _valid_plan()
        data["limitations"] = []
        result = validate_external_scanner_plan(data)
        self.assertFalse(result.valid)
        self.assertIn("plan_limitations_empty", result.blocking_errors)

    def test_schema_and_policy_draft_parse(self) -> None:
        schema = load_external_scanner_plan_schema()
        self.assertIs(schema["additionalProperties"], False)
        self.assertIn("schema_version", schema["required"])
        self.assertEqual(schema["properties"]["execution_authorized"]["const"], False)
        self.assertEqual(schema["properties"]["scanner_executed"]["const"], False)
        with POLICY_PATH.open(encoding="utf-8") as handle:
            policy = json.load(handle)
        self.assertEqual(policy["policy_kind"], "external_scanner_execution_policy")
        self.assertFalse(policy["default_behavior"]["scanner_execution_enabled"])
        self.assertTrue(policy["default_behavior"]["requires_human_approval"])

    def test_plan_fixtures_and_results_do_not_contain_obvious_leak_patterns(self) -> None:
        fixtures = [
            "zizmor_no_network_plan.json",
            "semgrep_custom_no_network_plan.json",
            "invalid_network_allowed_plan.json",
            "invalid_target_code_execution_allowed_plan.json",
            "invalid_raw_output_retention_plan.json",
            "invalid_execution_authorized_plan.json",
            "invalid_missing_approval_plan.json",
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                plan = load_external_scanner_plan_fixture(fixture)
                result = validate_external_scanner_plan(deepcopy(plan))
                for content in (json.dumps(plan, sort_keys=True), json.dumps(result.to_dict(), sort_keys=True)):
                    for pattern in LEAK_PATTERNS:
                        self.assertIsNone(pattern.search(content), pattern.pattern)


if __name__ == "__main__":
    unittest.main()
