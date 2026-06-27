from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.external_scanner import (
    EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
    REPORT_KIND_EXTERNAL_SCANNER_RESULT,
    load_external_scanner_result_schema,
    validate_external_scanner_result,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "external-scanner-results"


def _load_fixture(name: str) -> dict[str, object]:
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        data = json.load(handle)
    assert isinstance(data, dict)
    return data


def _synthetic_host_path() -> str:
    return "".join(("/ho", "me", "/synthetic-user/example"))


class ExternalScannerResultValidatorTests(unittest.TestCase):
    def test_schema_file_parse_and_contract(self) -> None:
        schema = load_external_scanner_result_schema()
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_EXTERNAL_SCANNER_RESULT])
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(schema["properties"]["execution_authorized"]["const"], False)
        self.assertNotIn("pass", schema["$defs"]["summary"]["properties"]["outcome"]["enum"])
        self.assertNotIn("pass", schema["$defs"]["gate_effect"]["enum"])
        self.assertNotIn("pass", schema["$defs"]["risk_tier_effect"]["enum"])

    def test_benign_minimal_fixture_is_valid_but_not_safety_proof(self) -> None:
        result = validate_external_scanner_result(_load_fixture("benign_minimal.json"))
        self.assertTrue(result.valid)
        self.assertEqual(result.blocking_errors, ())
        self.assertEqual(result.highest_gate_effect, "evidence_only")
        self.assertFalse(result.execution_authorized)
        self.assertIn("not_execution_authorization", result.limitations)
        self.assertIn("no_findings_in_scope_is_not_safety_proof", result.warnings)

    def test_invalid_fixture_cases_fail_closed(self) -> None:
        cases = {
            "malformed_missing_limitations.json": "limitations_empty",
            "scanner_failure_claims_no_findings.json": "scanner_failure_claims_no_findings",
            "raw_secret_leak_flag.json": "raw_secret_present",
            "raw_host_path_leak_flag.json": "raw_host_path_present",
            "imported_report_raw_output_retained.json": "imported_report_raw_output_retained",
            "local_no_network_but_network_used.json": "local_static_no_network_used_network",
            "unknown_without_reason.json": "unknown_reason_missing",
            "execution_authorized_true.json": "external_result_cannot_authorize_execution",
            "unsupported_version_no_findings.json": "unsupported_version_claims_no_findings",
            "outcome_pass.json": "outcome_pass_is_forbidden",
        }
        for fixture, expected in cases.items():
            with self.subTest(fixture=fixture):
                result = validate_external_scanner_result(_load_fixture(fixture))
                self.assertFalse(result.valid)
                self.assertIn(expected, result.blocking_errors)
                self.assertEqual(result.highest_gate_effect, "quarantine")
                self.assertFalse(result.valid)

    def test_low_trust_no_finding_import_cannot_lower_risk(self) -> None:
        result = validate_external_scanner_result(_load_fixture("low_trust_no_finding.json"))
        self.assertTrue(result.valid)
        self.assertEqual(result.highest_gate_effect, "evidence_only")
        self.assertIn("low_trust_no_finding_import_cannot_lower_risk", result.warnings)
        self.assertIn("low_trust_no_finding_import_cannot_lower_risk", result.fired_invariants)

        lowered = _load_fixture("low_trust_no_finding.json")
        lowered["mapping_result"]["risk_tier_effect"] = "raise_to_T2"  # type: ignore[index]
        lowered["summary"]["highest_risk_tier_effect"] = "raise_to_T2"  # type: ignore[index]
        invalid = validate_external_scanner_result(lowered)
        self.assertFalse(invalid.valid)
        self.assertIn("low_trust_no_finding_attempts_to_lower_or_clear_risk", invalid.blocking_errors)

    def test_schema_validation_rejects_unknown_or_missing_top_level_fields(self) -> None:
        extra = _load_fixture("benign_minimal.json")
        extra["new_safety_signal"] = True
        result = validate_external_scanner_result(extra)
        self.assertFalse(result.valid)
        self.assertIn("schema_top_level_required_or_unknown_field", result.blocking_errors)

        missing = _load_fixture("benign_minimal.json")
        missing.pop("report_kind")
        result = validate_external_scanner_result(missing)
        self.assertFalse(result.valid)
        self.assertIn("schema_top_level_required_or_unknown_field", result.blocking_errors)
        self.assertIn("report_kind_unsupported", result.blocking_errors)

    def test_scanner_incomplete_no_findings_fails_closed(self) -> None:
        data = _load_fixture("benign_minimal.json")
        data["execution_context"]["scanner_completed"] = False  # type: ignore[index]
        result = validate_external_scanner_result(data)
        self.assertFalse(result.valid)
        self.assertIn("scanner_incomplete_claims_no_findings", result.blocking_errors)

    def test_local_no_network_target_execution_fails_closed(self) -> None:
        data = _load_fixture("benign_minimal.json")
        data["scanner"]["mode"] = "local_static_no_network"  # type: ignore[index]
        data["execution_context"]["target_code_executed"] = True  # type: ignore[index]
        result = validate_external_scanner_result(data)
        self.assertFalse(result.valid)
        self.assertIn("local_static_no_network_executed_target_code", result.blocking_errors)

    def test_redaction_flags_fail_closed(self) -> None:
        for field in (
            "raw_secret_present",
            "raw_host_path_present",
            "raw_scanner_output_included",
            "raw_stdout_stderr_included",
            "unredacted_snippet_present",
        ):
            with self.subTest(field=field):
                data = _load_fixture("benign_minimal.json")
                data["redaction_status"][field] = True  # type: ignore[index]
                result = validate_external_scanner_result(data)
                self.assertFalse(result.valid)
                self.assertIn(field, result.blocking_errors)

    def test_redaction_validator_detects_synthetic_raw_host_path_pattern(self) -> None:
        data = _load_fixture("benign_minimal.json")
        data["residual_risks"][0]["description"] = _synthetic_host_path()  # type: ignore[index]
        result = validate_external_scanner_result(data)
        self.assertFalse(result.valid)
        self.assertIn("raw_host_path_pattern_present", result.blocking_errors)

    def test_result_model_has_required_fields(self) -> None:
        result = validate_external_scanner_result(_load_fixture("benign_minimal.json"))
        rendered = result.to_dict()
        self.assertEqual(
            set(rendered),
            {
                "valid",
                "blocking_errors",
                "warnings",
                "fired_invariants",
                "highest_gate_effect",
                "execution_authorized",
                "limitations",
                "residual_risks",
            },
        )
        self.assertFalse(rendered["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
