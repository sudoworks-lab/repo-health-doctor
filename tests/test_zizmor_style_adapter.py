from __future__ import annotations

import json
import re
import unittest

from repo_health_doctor.external_scanner import (
    default_zizmor_style_adapter,
    map_external_scanner_risk,
    validate_external_scanner_plan,
    validate_external_scanner_result,
    validate_imported_external_report,
)
from tests.external_scanner_fixture_helpers import load_zizmor_style_fixture


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


def _adapter():
    return default_zizmor_style_adapter()


def _normalized(fixture_name: str) -> dict[str, object]:
    return _adapter().normalize_synthetic_output(load_zizmor_style_fixture(fixture_name))


def _fired_rule_ids(result: object) -> list[str]:
    return [rule.rule_id for rule in result.fired_rules]


class ZizmorStyleAdapterTests(unittest.TestCase):
    def test_capability_declares_no_network_no_target_code_no_docker_no_raw_retention(self) -> None:
        capability = _adapter().capability()
        self.assertEqual(capability.scanner_name, "zizmor-style")
        self.assertEqual(capability.scanner_category, "ci_cd_risk")
        self.assertEqual(capability.supported_mode, "local_static_no_network")
        self.assertIn("<repo>/.github/workflows", capability.allowed_input_paths)
        self.assertFalse(capability.requires_network)
        self.assertFalse(capability.executes_target_code)
        self.assertFalse(capability.docker_needed)
        self.assertFalse(capability.raw_output_retention)
        self.assertIn("not_execution_authorization", capability.limitations)
        self.assertIn("zizmor_style_output_schema_unconfirmed", capability.residual_risks)

    def test_command_plan_is_argv_only_and_matches_no_network_plan_validator(self) -> None:
        adapter = _adapter()
        command_plan = adapter.build_plan()
        self.assertIsInstance(command_plan.argv, tuple)
        self.assertNotIsInstance(command_plan.argv, str)
        self.assertEqual(command_plan.argv[0], "zizmor")
        self.assertFalse(command_plan.execution_authorized)
        self.assertFalse(command_plan.scanner_executed)
        self.assertFalse(command_plan.network_allowed)
        self.assertFalse(command_plan.target_code_execution_allowed)
        self.assertFalse(command_plan.docker_allowed)
        self.assertFalse(command_plan.raw_output_retention)
        self.assertTrue(command_plan.requires_human_approval)

        validated = validate_external_scanner_plan(adapter.build_no_network_plan())
        self.assertTrue(validated.valid)
        self.assertEqual(validated.blocking_errors, ())
        self.assertEqual(validated.scanner_name, "zizmor-style")
        self.assertFalse(validated.execution_authorized)
        self.assertFalse(validated.scanner_executed)
        self.assertFalse(validated.network_allowed)
        self.assertFalse(validated.target_code_execution_allowed)
        self.assertFalse(validated.raw_output_retention)
        self.assertTrue(validated.requires_human_approval)

    def test_no_findings_is_valid_but_not_execution_authorization_or_risk_lowering(self) -> None:
        data = _normalized("no_findings.json")
        validation = validate_external_scanner_result(data)
        mapping = map_external_scanner_risk(data, validation_result=validation)
        imported = validate_imported_external_report(data, expected_commit=EXPECTED_COMMIT)

        self.assertTrue(validation.valid)
        self.assertTrue(imported.valid)
        self.assertIn("no_findings_in_scope_is_not_safety_proof", validation.warnings)
        self.assertIn("RISK020", _fired_rule_ids(mapping))
        self.assertEqual(mapping.highest_risk_tier_effect, "none")
        self.assertEqual(mapping.gate_effects, ("evidence_only",))
        self.assertTrue(mapping.cannot_lower_risk)
        self.assertFalse(data["execution_authorized"])
        self.assertFalse(imported.execution_authorized)

    def test_pull_request_target_untrusted_checkout_maps_to_risk011_t4(self) -> None:
        data = _normalized("pull_request_target_untrusted_checkout.json")
        validation = validate_external_scanner_result(data)
        mapping = map_external_scanner_risk(data, validation_result=validation)
        imported = validate_imported_external_report(data, expected_commit=EXPECTED_COMMIT)

        self.assertTrue(validation.valid)
        self.assertTrue(imported.valid)
        self.assertIn("RISK011", _fired_rule_ids(mapping))
        self.assertEqual(mapping.highest_risk_tier_effect, "raise_to_T4")
        self.assertIn("requires_human_review", mapping.gate_effects)
        self.assertFalse(imported.execution_authorized)

    def test_broad_token_unpinned_action_maps_to_risk012_t4(self) -> None:
        data = _normalized("broad_token_unpinned_action.json")
        validation = validate_external_scanner_result(data)
        mapping = map_external_scanner_risk(data, validation_result=validation)

        self.assertTrue(validation.valid)
        self.assertIn("RISK012", _fired_rule_ids(mapping))
        self.assertEqual(mapping.highest_risk_tier_effect, "raise_to_T4")
        self.assertIn("requires_human_review", mapping.gate_effects)

    def test_ci_token_untrusted_code_chain_requires_review(self) -> None:
        data = _normalized("ci_token_untrusted_code_chain.json")
        validation = validate_external_scanner_result(data)
        mapping = map_external_scanner_risk(data, validation_result=validation)

        self.assertTrue(validation.valid)
        self.assertIn("RISK011", _fired_rule_ids(mapping))
        self.assertIn("ci_token_to_untrusted_code", mapping.evidence_summary["edge_relations"])
        self.assertTrue(mapping.requires_human_review)

    def test_scanner_failure_claiming_no_findings_is_not_pass(self) -> None:
        data = _normalized("scanner_failure.json")
        validation = validate_external_scanner_result(data)
        mapping = map_external_scanner_risk(data, validation_result=validation)

        self.assertFalse(validation.valid)
        self.assertIn("scanner_incomplete_claims_no_findings", validation.blocking_errors)
        self.assertIn("scanner_failure_claims_no_findings", validation.blocking_errors)
        self.assertIn("RISK017", _fired_rule_ids(mapping))
        self.assertIn("quarantine", mapping.gate_effects)
        self.assertTrue(mapping.blocks_live_execution)

    def test_unsupported_version_maps_to_risk018_or_unknown_block(self) -> None:
        data = _normalized("unsupported_version.json")
        validation = validate_external_scanner_result(data)
        mapping = map_external_scanner_risk(data, validation_result=validation)

        self.assertTrue(validation.valid)
        self.assertEqual(data["summary"]["outcome"], "unknown")  # type: ignore[index]
        self.assertIn("RISK018", _fired_rule_ids(mapping))
        self.assertIn("quarantine", mapping.gate_effects)
        self.assertFalse(data["execution_authorized"])

    def test_redaction_failure_flag_blocks(self) -> None:
        data = _normalized("redaction_failure_flag.json")
        validation = validate_external_scanner_result(data)
        mapping = map_external_scanner_risk(data, validation_result=validation)

        self.assertFalse(validation.valid)
        self.assertIn("raw_scanner_output_included", validation.blocking_errors)
        self.assertIn("quarantine", mapping.gate_effects)
        self.assertTrue(mapping.blocks_live_execution)

    def test_fixtures_and_results_do_not_contain_obvious_leak_patterns(self) -> None:
        fixtures = [
            "no_findings.json",
            "pull_request_target_untrusted_checkout.json",
            "broad_token_unpinned_action.json",
            "ci_token_untrusted_code_chain.json",
            "scanner_failure.json",
            "unsupported_version.json",
            "redaction_failure_flag.json",
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                raw_fixture = load_zizmor_style_fixture(fixture)
                normalized = _adapter().normalize_synthetic_output(raw_fixture)
                validation = validate_external_scanner_result(normalized)
                mapping = map_external_scanner_risk(normalized, validation_result=validation)
                imported = validate_imported_external_report(normalized, expected_commit=EXPECTED_COMMIT)
                rendered = (
                    json.dumps(raw_fixture, sort_keys=True),
                    json.dumps(normalized, sort_keys=True),
                    json.dumps(validation.to_dict(), sort_keys=True),
                    json.dumps(mapping.to_dict(), sort_keys=True),
                    json.dumps(imported.to_dict(), sort_keys=True),
                )
                for content in rendered:
                    for pattern in LEAK_PATTERNS:
                        self.assertIsNone(pattern.search(content), pattern.pattern)


if __name__ == "__main__":
    unittest.main()
