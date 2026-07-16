from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest

from repo_health_doctor.gate.evaluator import (
    ExternalSuiteGateEvidence,
    evaluate_gate_decision,
)
from repo_health_doctor.gate.external_evidence import (
    external_suite_report_fingerprint,
    validate_external_suite_evidence,
)
from repo_health_doctor.gate.verdict import VERDICT_ORDER
from tests.external_scanner_fixture_helpers import (
    base_external_scanner_result,
    build_external_scanner_risk_result,
    load_external_scanner_risk_fixture,
)


NOW = datetime(2026, 7, 16, 3, 0, tzinfo=timezone.utc)
SUBJECT = {"repo_commit": "a" * 40, "dirty_state": "clean"}


def _gate_evidence(recommended_gate_effect: str = "allow_limited") -> dict[str, object]:
    return {
        "evidence_id": "base-gate-evidence",
        "schema_version": "0.1-draft",
        "evidence_kind": "repo_health_evidence",
        "source": {
            "tool_name": "repo-health-doctor",
            "tool_version": "0.1.0",
            "adapter_name": "unit-test",
            "adapter_version": "0.1-draft",
            "execution_mode": "native_static",
        },
        "subject": {
            "repo_identity": "<repo>",
            "commit": "abc123",
            "tree_hash": None,
            "path_scope": ["<repo>"],
            "binding_kind": "commit_bound",
        },
        "classification": {
            "category": "repo_posture",
            "subcategory": "trusted_static_evidence",
            "severity": "info",
            "confidence": "medium",
            "confidence_reason": "safe synthetic gate mapping fixture",
        },
        "finding": {
            "present": True,
            "count": 1,
            "locations": [{"path": "<repo>/fixture", "line": None}],
            "redacted_summary": "trusted_static_evidence",
        },
        "raw_handling": {
            "raw_output_retained": False,
            "raw_stdout_retained": False,
            "raw_stderr_retained": False,
            "redaction_status": "validated",
            "redaction_failures": [],
        },
        "trust": {
            "level": "commit_bound",
            "commit_bound": True,
            "signature_verified": False,
            "binary_attested": False,
            "limitations": ["not_execution_authorization"],
        },
        "effects": {
            "can_lower_risk": False,
            "can_authorize_execution": False,
            "recommended_gate_effect": recommended_gate_effect,
        },
        "residual_risks": ["synthetic_fixture_not_safety_proof"],
    }


def _suite_report(
    normalized_result: dict[str, object],
    *,
    entry_valid: bool = True,
    entry_status: str = "completed",
) -> dict[str, object]:
    summary = normalized_result["summary"]
    mapping = normalized_result["mapping_result"]
    findings = normalized_result["findings"]
    assert isinstance(summary, dict)
    assert isinstance(mapping, dict)
    assert isinstance(findings, list)
    report: dict[str, object] = {
        "schema_version": "0.1-draft",
        "report_kind": "real_scanner_suite",
        "suite_status": "completed" if entry_valid and entry_status == "completed" else "degraded",
        "entries": [
            {
                "scanner_name": "synthetic-scanner",
                "executed": entry_valid,
                "valid": entry_valid,
                "status": entry_status,
                "blocking_errors": [] if entry_valid else ["scanner_unavailable"],
                "warnings": [],
                "risk_summary": {
                    "outcome": summary["outcome"],
                    "highest_risk_tier_effect": summary["highest_risk_tier_effect"],
                    "risk_tier_effect": mapping["risk_tier_effect"],
                    "gate_effects": list(mapping["gate_effects"]),
                    "risk_lowering_allowed": False,
                },
                "normalized_result": deepcopy(normalized_result),
                "finding_count": len(findings),
                "omitted_finding_count": 0,
                "truncated": False,
            }
        ],
        "limitations": ["not_execution_authorization"],
        "execution_authorized": False,
        "generated_at": NOW.isoformat(),
        "subject": dict(SUBJECT),
    }
    report["report_fingerprint"] = external_suite_report_fingerprint(report)
    return report


def _gate_input(report: dict[str, object]) -> ExternalSuiteGateEvidence:
    validation = validate_external_suite_evidence(report, expected_subject=SUBJECT, now=NOW)
    return ExternalSuiteGateEvidence(report=report, validation=validation)


def _baseline_cases() -> list[tuple[list[dict[str, object]], str]]:
    return [
        ([_gate_evidence("allow_limited")], "allow_limited"),
        ([_gate_evidence("warn")], "warn"),
        ([], "unknown"),
        ([_gate_evidence("quarantine")], "quarantine"),
        ([_gate_evidence("block")], "block"),
    ]


class ExternalSuiteGateMappingTests(unittest.TestCase):
    def test_completed_no_finding_keeps_every_existing_verdict_unchanged(self) -> None:
        suite = _gate_input(_suite_report(base_external_scanner_result()))
        self.assertTrue(suite.validation.valid)

        for evidence, expected_verdict in _baseline_cases():
            with self.subTest(verdict=expected_verdict):
                baseline = evaluate_gate_decision(evidence)
                combined = evaluate_gate_decision(
                    evidence,
                    external_suite_evidence=[suite],
                )
                self.assertEqual(baseline.decision["verdict"], expected_verdict)
                self.assertEqual(combined.decision["verdict"], expected_verdict)
                self.assertFalse(combined.decision["execution_authorized"])

    def test_invalid_unavailable_unverified_and_finding_signals_are_monotonic(self) -> None:
        no_finding = base_external_scanner_result()

        invalid_report = _suite_report(no_finding)
        invalid_report["report_fingerprint"] = "sha256:" + "0" * 64
        invalid = _gate_input(invalid_report)
        self.assertFalse(invalid.validation.valid)

        unavailable = _gate_input(
            _suite_report(no_finding, entry_valid=False, entry_status="unknown")
        )
        self.assertTrue(unavailable.validation.valid)

        unverified_result = deepcopy(no_finding)
        unverified_result["scanner"]["trusted_binary_status"] = "unverified"  # type: ignore[index]
        unverified = _gate_input(_suite_report(unverified_result))
        self.assertTrue(unverified.validation.valid)

        vulnerability_result = build_external_scanner_risk_result(
            load_external_scanner_risk_fixture("RISK014_critical_vuln.json")
        )
        vulnerability = _gate_input(_suite_report(vulnerability_result))
        self.assertTrue(vulnerability.validation.valid)

        for signal_name, suite in (
            ("invalid", invalid),
            ("unavailable", unavailable),
            ("unverified", unverified),
            ("finding", vulnerability),
        ):
            for evidence, expected_verdict in _baseline_cases():
                with self.subTest(signal=signal_name, verdict=expected_verdict):
                    baseline = evaluate_gate_decision(evidence)
                    combined = evaluate_gate_decision(
                        evidence,
                        external_suite_evidence=[suite],
                    )
                    self.assertGreaterEqual(
                        VERDICT_ORDER[combined.decision["verdict"]],
                        VERDICT_ORDER[baseline.decision["verdict"]],
                    )
                    self.assertFalse(combined.decision["execution_authorized"])

    def test_validated_secret_like_finding_uses_risk001_and_fails_closed(self) -> None:
        marker = "synthetic-suite-only-marker"
        secret_like_result = build_external_scanner_risk_result(
            {
                "findings": [
                    {
                        "primary_category": "secret",
                        "secondary_category": "secret_like_value",
                        "redacted_description": marker,
                    }
                ]
            }
        )
        suite = _gate_input(_suite_report(secret_like_result))
        self.assertTrue(suite.validation.valid)

        combined = evaluate_gate_decision(
            [_gate_evidence()],
            external_suite_evidence=[suite],
        )

        self.assertEqual(combined.decision["verdict"], "block")
        self.assertIn("external_scanner_rule:RISK001", combined.verdict_reasons)
        self.assertFalse(combined.decision["execution_authorized"])
        rendered = json.dumps(combined.decision, sort_keys=True)
        self.assertNotIn(marker, rendered)
        self.assertNotIn("normalized_result", rendered)
        self.assertNotIn('"entries"', rendered)


if __name__ == "__main__":
    unittest.main()
