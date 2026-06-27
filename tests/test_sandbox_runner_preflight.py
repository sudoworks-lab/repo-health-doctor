from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.runner_preflight import (
    REPORT_KIND_RUNNER_PREFLIGHT,
    RUNNER_PREFLIGHT_SCHEMA_VERSION,
    run_non_executing_runner_preflight,
)
from repo_health_doctor.sandbox.static_transition import build_controlled_static_transition_inputs, run_controlled_static_transition


FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-runner-preflight.schema.json"


def _synthetic_host_path(*parts: str) -> str:
    return "".join(parts)


class SandboxRunnerPreflightTests(unittest.TestCase):
    def _fixture(self, name: str) -> Path:
        return FIXTURES_ROOT / f"sandbox-unknown-profile-{name}"

    def _inputs(self, name: str = "t1", **kwargs: object) -> dict[str, object]:
        values = build_controlled_static_transition_inputs(self._fixture(name), **kwargs)
        transition = run_controlled_static_transition(self._fixture(name), fixture_name=name, inputs=values)
        return {
            "approval": values["approval"],
            "image_lock": values["image_lock"],
            "behavior_policy": values["behavior_policy"],
            "observer_evidence": values["observer_evidence"],
            "image_lock_material": values["image_lock_material"],
            "behavior_policy_material": values["behavior_policy_material"],
            "static_transition_report": transition,
        }

    def _report(self, inputs: dict[str, object] | None = None) -> dict[str, object]:
        return run_non_executing_runner_preflight(inputs or self._inputs())

    def _assert_non_executing(self, report: dict[str, object]) -> None:
        for field in (
            "execution_permitted",
            "runner_connected",
            "docker_contacted",
            "docker_pull_performed",
            "docker_inspect_performed",
            "docker_run_performed",
            "network_contacted",
            "observer_capture_performed",
            "phase_live_performed",
            "approval_artifact_generated",
        ):
            self.assertFalse(report[field], field)

    def _blocked(self, mutate: object, *, name: str = "t1", **kwargs: object) -> dict[str, object]:
        inputs = self._inputs(name, **kwargs)
        assert callable(mutate)
        mutate(inputs)
        report = self._report(inputs)
        self.assertEqual(report["verdict"], "block")
        self._assert_non_executing(report)
        return report

    def test_schema_and_valid_static_inputs_pass_without_execution(self) -> None:
        report = self._report()
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [RUNNER_PREFLIGHT_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_RUNNER_PREFLIGHT])
        for field in schema["required"]:
            self.assertIn(field, report)
        self.assertEqual(report["schema_version"], RUNNER_PREFLIGHT_SCHEMA_VERSION)
        self.assertEqual(report["report_kind"], REPORT_KIND_RUNNER_PREFLIGHT)
        self.assertEqual(report["mode"], "non_executing_preflight")
        self.assertEqual(report["verdict"], "pass")
        self._assert_non_executing(report)
        self.assertEqual(
            report["checked_gates"],
            [
                "approval_validation",
                "image_lock_validation",
                "image_lock_binding_validation",
                "behavior_policy_validation",
                "observer_evidence_validation",
                "behavior_policy_binding_validation",
                "static_transition_validation",
            ],
        )

    def test_each_static_gate_blocks_preflight(self) -> None:
        cases = (
            ("approval validation", lambda values: values["approval"].pop("command")),
            ("image lock validation", lambda values: values["image_lock"]["required_runtime_flags"].update({"network": "bridge"})),
            ("image lock binding", lambda values: values["approval"]["image_lock_binding"].update({"lock_id": "other-lock"})),
            ("behavior policy validation", lambda values: values["behavior_policy"]["binding"].update({"network_policy": "bridge"})),
            ("observer evidence validation", lambda values: values["observer_evidence"]["flags"].update({"raw_logs_included": True})),
            ("behavior policy binding", lambda values: values["observer_evidence"]["command"].update({"kind": "other_probe"})),
            ("static transition validation", lambda values: values["static_transition_report"].update({"transition_status": "block", "blockers": ["controlled_static_transition_block"]})),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                report = self._blocked(mutate)
                self.assertTrue(report["blockers"])

    def test_required_input_missing_or_unknown_blocks(self) -> None:
        self._blocked(lambda values: values.pop("approval"))
        self._blocked(lambda values: values.update({"unexpected": {"safety": "relevant"}}))

    def test_expired_t4_t5_and_t3_incomplete_approval_block(self) -> None:
        self._blocked(lambda values: values["approval"]["lifecycle"].update({"expires_at": "2000-01-01T00:00:00Z"}))
        for tier in ("T4", "T5"):
            with self.subTest(tier=tier):
                self._blocked(lambda values, tier=tier: values["approval"].update({"source_risk_tier": tier}))

        report = self._report(self._inputs("t3", t3_exception_present=False))
        self.assertEqual(report["verdict"], "block")
        self._assert_non_executing(report)

    def test_observer_degraded_or_incomplete_blocks(self) -> None:
        self._blocked(lambda values: values["observer_evidence"]["source"].update({"observer_degraded": True, "degraded_reasons": ["observer_partial"]}))
        self._blocked(lambda values: values["observer_evidence"]["flags"].update({"evidence_complete": False}))

    def test_schema_version_and_report_kind_mismatch_block(self) -> None:
        self._blocked(lambda values: values["approval"].update({"schema_version": "99.0"}))
        self._blocked(lambda values: values["observer_evidence"].update({"report_kind": "sandbox_other_evidence"}))
        self._blocked(lambda values: values["static_transition_report"].update({"schema_version": "99.0"}))
        self._blocked(lambda values: values["static_transition_report"].update({"report_kind": "sandbox_other_transition"}))

    def test_static_transition_warn_yields_preflight_warn_not_execution(self) -> None:
        inputs = self._inputs("t2")
        report = self._report(inputs)
        self.assertEqual(report["verdict"], "warn")
        self._assert_non_executing(report)

    def test_raw_host_path_and_secret_like_values_do_not_leak(self) -> None:
        for raw in (_synthetic_host_path("/ho", "me", "/private/preflight"), "sk-" + "preflight_0123456789abcdef"):
            with self.subTest(raw=raw):
                inputs = self._inputs()
                inputs["observer_evidence"]["summaries"]["file_summary"] = [raw]
                report = self._report(inputs)
                payload = json.dumps(report, sort_keys=True)
                self.assertEqual(report["verdict"], "block")
                self.assertNotIn(raw, payload)
                self._assert_non_executing(report)

    def test_component_inputs_are_not_mutated_by_report_callers(self) -> None:
        inputs = self._inputs()
        original = copy.deepcopy(inputs)
        report = self._report(inputs)
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(inputs, original)


if __name__ == "__main__":
    unittest.main()
