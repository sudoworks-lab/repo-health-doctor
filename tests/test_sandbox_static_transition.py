from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.static_transition import (
    REPORT_KIND_STATIC_TRANSITION_VALIDATION,
    STATIC_TRANSITION_SCHEMA_VERSION,
    build_controlled_static_transition_inputs,
    run_controlled_static_transition,
)


FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-static-transition-validation.schema.json"


def _synthetic_host_path(*parts: str) -> str:
    return "".join(parts)


class ControlledStaticTransitionTests(unittest.TestCase):
    def _fixture(self, name: str) -> Path:
        return FIXTURES_ROOT / f"sandbox-unknown-profile-{name}"

    def _inputs(self, name: str, **kwargs: object) -> dict[str, object]:
        return build_controlled_static_transition_inputs(self._fixture(name), **kwargs)

    def _report(self, name: str, inputs: dict[str, object] | None = None, **kwargs: object) -> dict[str, object]:
        return run_controlled_static_transition(self._fixture(name), fixture_name=name, inputs=inputs, **kwargs)

    def _blocked(self, name: str, mutate: object) -> None:
        inputs = self._inputs(name)
        assert callable(mutate)
        mutate(inputs)
        report = self._report(name, inputs)
        self.assertEqual(report["transition_status"], "block")
        self.assertFalse(report["approved"])
        self.assertFalse(report["execution_permitted"])
        self.assertFalse(report["runner_connected"])
        self.assertFalse(report["docker_contacted"])
        self.assertFalse(report["observer_capture_performed"])
        self.assertFalse(report["approval_artifact_generated"])

    def test_schema_and_static_execution_contract(self) -> None:
        report = self._report("t1")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [STATIC_TRANSITION_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_STATIC_TRANSITION_VALIDATION])
        for field in schema["required"]:
            self.assertIn(field, report)
        self.assertEqual(report["mode"], "static_transition_test")
        self.assertFalse(report["approved"])
        self.assertFalse(report["execution_permitted"])
        self.assertFalse(report["runner_connected"])
        self.assertFalse(report["docker_contacted"])
        self.assertFalse(report["observer_capture_performed"])
        self.assertFalse(report["approval_artifact_generated"])

    def test_tier_transitions_are_fixture_only_and_non_executable(self) -> None:
        expected = {"t0": ("T0", "warn", False), "t1": ("T1", "pass", True), "t2": ("T2", "warn", True), "t3": ("T3", "warn", True), "t4": ("T4", "block", False), "t5": ("T5", "block", False)}
        for name, (tier, status, candidate) in expected.items():
            with self.subTest(name=name):
                report = self._report(name)
                self.assertEqual(report["source_risk_tier"], tier)
                self.assertEqual(report["transition_status"], status)
                self.assertEqual(report["live_candidate_generated"], candidate)
                self.assertFalse(report["approved"])
                self.assertFalse(report["execution_permitted"])
                self.assertFalse(report["approval_artifact_generated"])

    def test_ambiguous_and_parse_error_remain_review_only(self) -> None:
        for name in ("ambiguous", "parse-error"):
            with self.subTest(name=name):
                report = self._report(name)
                self.assertIn(report["transition_status"], {"warn", "block"})
                self.assertFalse(report["execution_permitted"])

    def test_t1_component_bindings_pass_with_in_memory_approval_only(self) -> None:
        report = self._report("t1")
        components = report["component_results"]
        self.assertEqual(components["profile"]["risk_tier"], "T1")
        self.assertTrue(components["approval_validation"]["valid"])
        self.assertTrue(components["image_lock_validation"]["valid"])
        self.assertEqual(components["image_lock_binding_validation"]["verdict"], "pass")
        self.assertTrue(components["observer_evidence_validation"]["valid"])
        self.assertEqual(components["behavior_policy_binding_validation"]["verdict"], "pass")
        self.assertEqual(components["behavior_policy_verdict"]["verdict"], "pass")

    def test_t2_keeps_phase1_and_phase15_review_requirement(self) -> None:
        report = self._report("t2")
        self.assertEqual(report["transition_status"], "warn")
        self.assertIn("phase1_and_phase1_5_requirements_remain_unverified", report["warnings"])
        self.assertEqual(report["component_results"]["approval_validation"]["verdict"], "pass")

    def test_t3_requires_complete_exception_metadata(self) -> None:
        report = run_controlled_static_transition(self._fixture("t3"), fixture_name="t3", t3_exception_present=False)
        self.assertEqual(report["transition_status"], "block")
        self.assertFalse(report["component_results"]["approval_validation"]["valid"])

    def test_fail_closed_component_mutations(self) -> None:
        cases = (
            ("approval missing field", lambda values: values["approval"].pop("command")),
            ("approval expired", lambda values: values["approval"]["lifecycle"].update({"expires_at": "2000-01-01T00:00:00Z"})),
            ("image lock mismatch", lambda values: values["image_lock"].update({"lock_id": "other-lock"})),
            ("behavior policy mismatch", lambda values: values["approval"]["behavior_policy_binding"].update({"binding_fingerprint": "sha256:" + "e" * 64})),
            ("observer command mismatch", lambda values: values["observer_evidence"]["command"].update({"kind": "other_probe"})),
            ("observer degraded", lambda values: values["observer_evidence"]["source"].update({"observer_degraded": True, "degraded_reasons": ["observer_partial"]})),
            ("observer parse failure", lambda values: values["observer_evidence"]["source"].update({"strace_parse_success": False})),
            ("incomplete evidence", lambda values: values["observer_evidence"]["flags"].update({"evidence_complete": False})),
            ("behavior policy verdict block", lambda values: values["observer_evidence"]["counts"].update({"network_event_count": 1})),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                self._blocked("t1", mutate)

    def test_phase2_inputs_cannot_validate_as_phase3(self) -> None:
        self._blocked("t1", lambda values: values["observer_evidence"]["command"].update({"phase": "phase3_runtime_probe"}))

    def test_raw_path_and_secret_like_input_do_not_leak(self) -> None:
        for raw in (_synthetic_host_path("/ho", "me", "/private/transition"), "sk-" + "transition_0123456789abcdef"):
            with self.subTest(raw=raw):
                inputs = self._inputs("t1")
                inputs["observer_evidence"]["summaries"]["file_summary"] = [raw]
                payload = json.dumps(self._report("t1", inputs))
                self.assertNotIn(raw, payload)
                self.assertEqual(self._report("t1", inputs)["transition_status"], "block")

    def test_controlled_fixture_guard_rejects_other_paths(self) -> None:
        report = run_controlled_static_transition(FIXTURES_ROOT / "demo-repo")
        self.assertEqual(report["transition_status"], "block")
        self.assertIn("controlled_fixture_required", report["blockers"])
