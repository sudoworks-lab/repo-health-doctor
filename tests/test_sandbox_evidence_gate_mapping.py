from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from repo_health_doctor.evidence.sandbox_run import (
    DECISION_BINDING_MISMATCH,
    DECISION_INVALID,
    DECISION_OVER_BUDGET,
    DECISION_STALE,
)
from repo_health_doctor.gate.evaluator import evaluate_gate_decision
from repo_health_doctor.gate.verdict import VERDICT_ORDER


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "sandbox-run-evidence.json"


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


def _baseline_cases() -> list[tuple[list[dict[str, object]], str]]:
    return [
        ([_gate_evidence("allow_limited")], "allow_limited"),
        ([_gate_evidence("warn")], "warn"),
        ([], "unknown"),
        ([_gate_evidence("quarantine")], "quarantine"),
        ([_gate_evidence("block")], "block"),
    ]


def _sandbox_evidence(*signals: str) -> dict[str, object]:
    evidence = json.loads(GOLDEN.read_text(encoding="utf-8"))
    evidence["decision_signals"] = list(signals)
    return evidence


class SandboxEvidenceGateMappingTests(unittest.TestCase):
    def test_success_keeps_every_existing_verdict_unchanged(self) -> None:
        success = _sandbox_evidence()

        for evidence, expected_verdict in _baseline_cases():
            with self.subTest(verdict=expected_verdict):
                baseline = evaluate_gate_decision(evidence)
                combined = evaluate_gate_decision(evidence, sandbox_evidence=[success])

                self.assertEqual(baseline.decision["verdict"], expected_verdict)
                self.assertEqual(combined.decision["verdict"], expected_verdict)
                self.assertFalse(combined.decision["execution_authorized"])

    def test_problem_signals_are_same_or_worse_for_every_existing_verdict(self) -> None:
        invalid = deepcopy(_sandbox_evidence())
        invalid["schema_version"] = "invalid"
        cases = (
            ("invalid", invalid),
            ("explicit-invalid", _sandbox_evidence(DECISION_INVALID)),
            ("stale", _sandbox_evidence(DECISION_STALE)),
            ("mismatch", _sandbox_evidence(DECISION_BINDING_MISMATCH)),
            ("over-budget", _sandbox_evidence(DECISION_OVER_BUDGET)),
        )

        for signal_name, sandbox in cases:
            for evidence, _ in _baseline_cases():
                with self.subTest(signal=signal_name, baseline=evidence):
                    baseline = evaluate_gate_decision(evidence)
                    combined = evaluate_gate_decision(
                        evidence,
                        sandbox_evidence=[sandbox],
                    )

                    self.assertGreaterEqual(
                        VERDICT_ORDER[combined.decision["verdict"]],
                        VERDICT_ORDER[baseline.decision["verdict"]],
                    )
                    self.assertFalse(combined.decision["execution_authorized"])
                    self.assertTrue(
                        any(
                            reason.startswith("sandbox_signal:")
                            for reason in combined.verdict_reasons
                        )
                    )

    def test_omitting_sandbox_evidence_preserves_existing_output(self) -> None:
        for evidence, _ in _baseline_cases():
            with self.subTest(evidence=evidence):
                existing = evaluate_gate_decision(evidence)
                explicit_empty = evaluate_gate_decision(evidence, sandbox_evidence=[])

                self.assertEqual(explicit_empty, existing)


if __name__ == "__main__":
    unittest.main()
