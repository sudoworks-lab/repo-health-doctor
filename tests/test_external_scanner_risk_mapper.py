from __future__ import annotations

import unittest

from repo_health_doctor.external_scanner import (
    RISK_RULE_IDS,
    ExternalScannerValidationResult,
    load_external_scanner_risk_policy,
    map_external_scanner_risk,
)
from tests.external_scanner_fixture_helpers import (
    SCHEMAS,
    base_external_scanner_result,
    build_external_scanner_risk_result,
    fired_rule_ids,
    load_external_scanner_risk_fixture,
    load_json,
)


def _scenario(name: str) -> dict[str, object]:
    return load_external_scanner_risk_fixture(name)


class ExternalScannerRiskMapperTests(unittest.TestCase):
    def test_policy_file_defines_risk001_to_risk020(self) -> None:
        policy = load_external_scanner_risk_policy()
        self.assertEqual(policy["schema_version"], "0.1-draft")
        self.assertEqual(policy["policy_version"], "0.1")
        self.assertEqual(policy["policy_kind"], "external_scanner_risk_policy")
        rule_ids = [item["rule_id"] for item in policy["risk_rules"]]  # type: ignore[index]
        self.assertEqual(rule_ids, list(RISK_RULE_IDS))

    def test_policy_schema_parse_and_contract(self) -> None:
        schema = load_json(SCHEMAS / "external-scanner-risk-policy.schema.json")
        self.assertIs(schema["additionalProperties"], False)
        self.assertIn("schema_version", schema["required"])
        self.assertNotIn("report_kind", schema["properties"])

    def test_risk_rule_fixtures_map_to_expected_effects(self) -> None:
        cases = [
            "RISK001_verified_secret.json",
            "RISK002_raw_secret_leak.json",
            "RISK003_credential_path.json",
            "RISK004_credential_network_chain.json",
            "RISK005_install_download_exec.json",
            "RISK006_obfuscation_eval.json",
            "RISK007_obfuscation_eval_network.json",
            "RISK008_docker_socket.json",
            "RISK009_docker_socket_subprocess.json",
            "RISK010_host_home_reference.json",
            "RISK011_pr_target_untrusted.json",
            "RISK012_broad_token_unpinned_action.json",
            "RISK013_verified_secret_ci_exposure.json",
            "RISK014_critical_vuln.json",
            "RISK015_critical_vuln_runtime.json",
            "RISK016_low_repo_posture.json",
            "RISK017_scanner_failure_claims_no_findings.json",
            "RISK018_unsupported_version.json",
            "RISK019_missing_limitations.json",
            "RISK020_low_trust_no_finding.json",
            "benign_minimal.json",
        ]
        for case in cases:
            with self.subTest(case=case):
                scenario = _scenario(case)
                expected = scenario["expected"]  # type: ignore[index]
                assert isinstance(expected, dict)
                result = map_external_scanner_risk(build_external_scanner_risk_result(scenario))
                self.assertEqual(result.highest_risk_tier_effect, expected["highest_risk_tier_effect"])
                for gate_effect in expected["gate_effects"]:  # type: ignore[index]
                    self.assertIn(gate_effect, result.gate_effects)
                for rule_id in expected["rules_fired"]:  # type: ignore[index]
                    self.assertIn(rule_id, fired_rule_ids(result))
                self.assertTrue(result.cannot_lower_risk)
                self.assertFalse(result.evidence_summary.get("execution_authorized", False))

    def test_low_trust_no_finding_is_evidence_only_not_risk_lowering(self) -> None:
        result = map_external_scanner_risk(build_external_scanner_risk_result(_scenario("RISK020_low_trust_no_finding.json")))
        self.assertEqual(result.highest_risk_tier_effect, "none")
        self.assertEqual(result.gate_effects, ("evidence_only",))
        self.assertTrue(result.cannot_lower_risk)
        self.assertFalse(result.blocks_live_execution)
        self.assertIn("RISK020", fired_rule_ids(result))

    def test_secret_like_value_fires_risk001_and_blocks_live_execution(self) -> None:
        result = map_external_scanner_risk(
            build_external_scanner_risk_result(
                {
                    "findings": [
                        {
                            "primary_category": "secret",
                            "secondary_category": "secret_like_value",
                        }
                    ]
                }
            )
        )

        self.assertIn("RISK001", fired_rule_ids(result))
        self.assertEqual(result.highest_risk_tier_effect, "raise_to_T5")
        self.assertIn("blocks_live_execution", result.gate_effects)
        self.assertTrue(result.blocks_live_execution)
        self.assertTrue(result.cannot_lower_risk)

    def test_mapper_tracks_rules_limitations_residual_risks_and_evidence_summary(self) -> None:
        result = map_external_scanner_risk(build_external_scanner_risk_result(_scenario("RISK004_credential_network_chain.json")))
        self.assertIn("RISK004", fired_rule_ids(result))
        self.assertIn("scanner_scope_only", result.limitations)
        self.assertIn("scanner_scope_only", result.residual_risks)
        self.assertIn("credential_to_network", result.evidence_summary["edge_relations"])
        rendered = result.to_dict()
        self.assertIn("fired_rules", rendered)
        self.assertIn("evidence_summary", rendered)

    def test_invalid_validation_result_fails_closed_in_mapper(self) -> None:
        validation = ExternalScannerValidationResult(
            valid=False,
            blocking_errors=("synthetic_invalid_validation",),
            warnings=(),
            fired_invariants=("synthetic_invalid_validation",),
            highest_gate_effect="quarantine",
            execution_authorized=False,
            limitations=("scanner_scope_only",),
            residual_risks=("synthetic_invalid_validation",),
        )
        result = map_external_scanner_risk(base_external_scanner_result(), validation_result=validation)
        self.assertEqual(result.highest_risk_tier_effect, "T5_candidate")
        self.assertIn("quarantine", result.gate_effects)
        self.assertIn("synthetic_invalid_validation", result.blocking_rules)
        self.assertIn("invalid_validation_result_fail_closed", result.warnings)
        self.assertTrue(result.blocks_live_execution)

    def test_unknown_safety_relevant_category_is_not_safe_evidence(self) -> None:
        data = base_external_scanner_result()
        data["findings"] = [
            {
                "finding_id": "risk-fixture-1",
                "scanner_rule_id": "fixture.unknown",
                "primary_category": "unknown",
                "secondary_category": "unknown",
                "scanner_severity": "fixture",
                "normalized_severity": "warn",
                "confidence": "high",
                "title": "Fixture unknown",
                "redacted_description": "Synthetic fixture evidence.",
                "location": {"path": "<repo>/fixture", "line": 1, "column": 1},
                "evidence": ["synthetic_unknown_signal"],
                "risk_mapping": {"risk_tier_effect": "none", "rule_ids": []},
                "gate_effect": "evidence_only",
            }
        ]
        data["summary"]["outcome"] = "findings_present"  # type: ignore[index]
        data["summary"]["finding_count"] = 1  # type: ignore[index]
        result = map_external_scanner_risk(data)
        self.assertEqual(result.highest_risk_tier_effect, "T5_candidate")
        self.assertIn("requires_human_review", result.gate_effects)
        self.assertIn("unknown_safety_relevant_category", result.blocking_rules)
        self.assertIn("unknown_safety_relevant_category", result.warnings)


if __name__ == "__main__":
    unittest.main()
