from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from repo_health_doctor.external_scanner import RISK_RULE_IDS, map_external_scanner_risk, validate_external_scanner_result
from tests.external_scanner_fixture_helpers import (
    RISK_EXPECTED_FIXTURES,
    RISK_FIXTURES,
    build_external_scanner_risk_result,
    fired_rule_ids,
    load_external_scanner_risk_expected,
    load_external_scanner_risk_fixture,
)


FIXTURE_NAMES = (
    "RISK001_verified_secret",
    "RISK002_raw_secret_leak",
    "RISK003_credential_path",
    "RISK004_credential_network_chain",
    "RISK005_install_download_exec",
    "RISK006_obfuscation_eval",
    "RISK007_obfuscation_eval_network",
    "RISK008_docker_socket",
    "RISK009_docker_socket_subprocess",
    "RISK010_host_home_reference",
    "RISK011_pr_target_untrusted",
    "RISK012_broad_token_unpinned_action",
    "RISK013_verified_secret_ci_exposure",
    "RISK014_critical_vuln",
    "RISK015_critical_vuln_runtime",
    "RISK016_low_repo_posture",
    "RISK017_scanner_failure_claims_no_findings",
    "RISK018_unsupported_version",
    "RISK019_missing_limitations",
    "RISK020_low_trust_no_finding",
    "benign_minimal",
)
REQUIRED_EXPECTED_FIELDS = {
    "expected_validation_valid",
    "expected_highest_risk",
    "expected_gate_effects",
    "expected_rules_fired",
    "must_not_leak",
    "expected_outcome",
    "expected_limitations",
    "expected_cannot_lower_risk",
    "expected_execution_authorized",
}
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
DOCS_WITH_FIXTURE_REFERENCES = (
    Path("docs/external-scanner-adapter-design.md"),
    Path("docs/README.md"),
)


class ExternalScannerGoldenFixtureTests(unittest.TestCase):
    def test_contract_completeness(self) -> None:
        for name in FIXTURE_NAMES:
            with self.subTest(name=name):
                expected_path = RISK_EXPECTED_FIXTURES / f"{name}.expected.json"
                self.assertTrue(expected_path.exists(), expected_path.as_posix())
                expected = load_external_scanner_risk_expected(name)
                self.assertTrue(REQUIRED_EXPECTED_FIELDS.issubset(expected))
                self.assertTrue(bool(expected["expected_highest_risk"]))
                self.assertTrue(expected["expected_gate_effects"])
                if name != "benign_minimal":
                    self.assertTrue(expected["expected_rules_fired"])
                self.assertFalse(expected["expected_execution_authorized"])
                self.assertTrue(expected["expected_limitations"])
                self.assertTrue(expected["must_not_leak"])

    def test_validator_and_mapper_match_golden_contracts(self) -> None:
        for name in FIXTURE_NAMES:
            with self.subTest(name=name):
                scenario = load_external_scanner_risk_fixture(f"{name}.json")
                expected = load_external_scanner_risk_expected(name)
                data = build_external_scanner_risk_result(scenario)
                validation = validate_external_scanner_result(data)
                mapping = map_external_scanner_risk(data, validation_result=validation)
                rendered = mapping.to_dict()

                self.assertEqual(validation.valid, expected["expected_validation_valid"])
                self.assertEqual(mapping.highest_risk_tier_effect, expected["expected_highest_risk"])
                self.assertFalse(rendered["evidence_summary"]["execution_authorized"])
                self.assertEqual(rendered["evidence_summary"]["outcome"], expected["expected_outcome"])
                self.assertEqual(mapping.cannot_lower_risk, expected["expected_cannot_lower_risk"])
                self.assertEqual(mapping.requires_human_review, expected.get("expected_requires_human_review", mapping.requires_human_review))
                self.assertEqual(mapping.blocks_live_execution, expected.get("expected_blocks_live_execution", mapping.blocks_live_execution))
                self.assertEqual(mapping.requires_dedicated_vm, expected.get("expected_requires_dedicated_vm", mapping.requires_dedicated_vm))
                self.assertEqual(mapping.quarantine, expected.get("expected_quarantine", mapping.quarantine))

                for gate_effect in expected["expected_gate_effects"]:
                    self.assertIn(gate_effect, mapping.gate_effects)
                for rule_id in expected["expected_rules_fired"]:
                    self.assertIn(rule_id, fired_rule_ids(mapping))
                for warning in expected.get("expected_warnings", []):
                    self.assertIn(warning, mapping.warnings)
                for blocking_rule in expected.get("expected_blocking_rules", []):
                    self.assertIn(blocking_rule, mapping.blocking_rules)
                for residual_risk in expected.get("expected_residual_risks", []):
                    self.assertIn(residual_risk, mapping.residual_risks)

                summary = expected.get("expected_evidence_summary_contains", {})
                if isinstance(summary, dict):
                    for key, value in summary.items():
                        self.assertEqual(rendered["evidence_summary"][key], value)

                if expected["expected_validation_valid"]:
                    for limitation in expected["expected_limitations"]:
                        self.assertIn(limitation, mapping.limitations)
                else:
                    self.assertFalse(validation.valid)
                    self.assertTrue(mapping.quarantine or mapping.blocks_live_execution)
                    self.assertTrue(mapping.cannot_lower_risk)

    def test_leak_safety_for_inputs_expected_and_rendered_results(self) -> None:
        for name in FIXTURE_NAMES:
            with self.subTest(name=name):
                scenario = load_external_scanner_risk_fixture(f"{name}.json")
                expected = load_external_scanner_risk_expected(name)
                data = build_external_scanner_risk_result(scenario)
                validation = validate_external_scanner_result(data)
                mapping = map_external_scanner_risk(data, validation_result=validation)
                contents = (
                    json.dumps(scenario, sort_keys=True),
                    json.dumps(expected, sort_keys=True),
                    json.dumps(validation.to_dict(), sort_keys=True),
                    json.dumps(mapping.to_dict(), sort_keys=True),
                )
                for content in contents:
                    for pattern in LEAK_PATTERNS:
                        self.assertIsNone(pattern.search(content), pattern.pattern)

        for path in DOCS_WITH_FIXTURE_REFERENCES:
            with self.subTest(path=path.as_posix()):
                content = path.read_text(encoding="utf-8")
                for pattern in LEAK_PATTERNS:
                    self.assertIsNone(pattern.search(content), pattern.pattern)

    def test_coverage_summary(self) -> None:
        covered_rules: set[str] = set()
        for name in FIXTURE_NAMES:
            expected = load_external_scanner_risk_expected(name)
            covered_rules.update(expected["expected_rules_fired"])
        self.assertEqual(covered_rules, set(RISK_RULE_IDS))
        self.assertIn("benign_minimal", FIXTURE_NAMES)
        self.assertIn("RISK002", covered_rules)
        self.assertIn("RISK017", covered_rules)
        self.assertIn("RISK020", covered_rules)
        self.assertTrue({"RISK004", "RISK007", "RISK009", "RISK011", "RISK012", "RISK013", "RISK015"}.issubset(covered_rules))

    def test_expected_directory_matches_flat_fixture_set(self) -> None:
        flat = {path.stem for path in RISK_FIXTURES.glob("*.json")}
        expected = {path.name.removesuffix(".expected.json") for path in RISK_EXPECTED_FIXTURES.glob("*.expected.json")}
        self.assertEqual(flat, expected)


if __name__ == "__main__":
    unittest.main()
