from __future__ import annotations

import json
from pathlib import Path
import unittest


SCHEMAS_ROOT = Path(__file__).resolve().parents[1] / "schemas"

EXPECTED_SCHEMA_METADATA = {
    "evidence.schema.json": ("0.1-draft", None),
    "execution-authorization.schema.json": (
        ("0.1-draft", "0.2-draft", "0.3-draft"),
        None,
    ),
    "external-scanner-plan.schema.json": ("0.1-draft", None),
    "external-scanner-readiness-result.schema.json": ("0.1-draft", "external_scanner_execution_readiness"),
    "external-scanner-result.schema.json": ("0.1-draft", "external_scanner_result"),
    "external-scanner-risk-policy.schema.json": ("0.1-draft", None),
    "gate-decision.schema.json": ("0.1-draft", None),
    "policy-config.schema.json": (None, None),
    "pre-execution-gate-policy.schema.json": ("0.1-draft", None),
    "public-safety-report.schema.json": ("1.1", None),
    "real-scanner-suite.schema.json": ("0.1-draft", "real_scanner_suite"),
    "release-check-report.schema.json": ("1.1", "release_check"),
    "report-diff.schema.json": ("1.1", "report_diff"),
    "sandbox-approval-draft.schema.json": ("0.1-draft", "sandbox_approval_draft"),
    "sandbox-behavior-policy-binding-validation.schema.json": (
        "0.1-draft",
        "sandbox_behavior_policy_binding_validation",
    ),
    "sandbox-behavior-policy.schema.json": ("0.1-draft", "sandbox_command_behavior_policy"),
    "sandbox-image-attestation.schema.json": ("0.1-draft", "sandbox_image_attestation"),
    "sandbox-image-lock-binding-validation.schema.json": (
        "0.1-draft",
        "sandbox_image_lock_binding_validation",
    ),
    "sandbox-image-lock.schema.json": ("0.1-draft", "sandbox_image_lock"),
    "sandbox-normalized-observer-evidence.schema.json": (
        "0.1-draft",
        "sandbox_normalized_observer_evidence",
    ),
    "sandbox-report.schema.json": ("1.1", "sandbox"),
    "sandbox-run.schema.json": ("0.1-draft", "sandbox_run"),
    "sandbox-runner-preflight.schema.json": ("0.1-draft", "sandbox_runner_preflight"),
    "sandbox-single-command-live-gate.schema.json": (
        "0.1-draft",
        "sandbox_single_command_live_gate",
    ),
    "sandbox-static-transition-validation.schema.json": (
        "0.1-draft",
        "sandbox_static_transition_validation",
    ),
    "sandbox-unknown-repo-command-approval.schema.json": (
        "0.1-draft",
        "sandbox_unknown_repo_command_approval",
    ),
    "sandbox-unknown-repo-profile.schema.json": (
        "0.1-draft",
        "sandbox_unknown_repo_profile",
    ),
    "verified-snapshot.schema.json": ("1.0", None),
}

NON_EXECUTING_FALSE_FIELDS = {
    "external-scanner-plan.schema.json": (
        "execution_authorized",
        "scanner_executed",
    ),
    "external-scanner-readiness-result.schema.json": (
        "execution_authorized",
    ),
    "external-scanner-result.schema.json": (
        "execution_authorized",
    ),
    "real-scanner-suite.schema.json": (
        "execution_authorized",
    ),
    "gate-decision.schema.json": (
        "execution_authorized",
    ),
    "sandbox-approval-draft.schema.json": (
        "approved",
        "execution_permitted",
    ),
    "sandbox-behavior-policy-binding-validation.schema.json": (
        "execution_permitted",
        "runner_connected",
        "docker_contacted",
        "observer_capture_performed",
    ),
    "sandbox-image-lock-binding-validation.schema.json": (
        "execution_permitted",
        "runner_connected",
        "docker_contacted",
    ),
    "sandbox-runner-preflight.schema.json": (
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
    ),
    "sandbox-static-transition-validation.schema.json": (
        "approved",
        "execution_permitted",
        "runner_connected",
        "docker_contacted",
        "observer_capture_performed",
        "approval_artifact_generated",
    ),
    "sandbox-unknown-repo-profile.schema.json": (
        "execution_permitted",
    ),
}


def _load_schema(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _single_enum_value(properties: dict[str, object], field: str) -> object:
    field_schema = properties[field]
    assert isinstance(field_schema, dict)
    enum_values = field_schema.get("enum")
    if enum_values is None and "const" in field_schema:
        enum_values = [field_schema["const"]]
    assert isinstance(enum_values, list)
    return enum_values[0] if len(enum_values) == 1 else enum_values


class SchemaContractTests(unittest.TestCase):
    def _schemas(self) -> dict[str, dict[str, object]]:
        return {path.name: _load_schema(path) for path in sorted(SCHEMAS_ROOT.glob("*.schema.json"))}

    def test_schema_inventory_is_explicit(self) -> None:
        self.assertEqual(set(self._schemas()), set(EXPECTED_SCHEMA_METADATA))

    def test_all_schemas_parse_as_top_level_closed_objects(self) -> None:
        for name, schema in self._schemas().items():
            with self.subTest(schema=name):
                self.assertEqual(schema.get("type"), "object")
                self.assertIs(schema.get("additionalProperties"), False)
                self.assertIsInstance(schema.get("properties"), dict)

    def test_schema_version_contract_is_required_except_policy_config(self) -> None:
        for name, (schema_version, _report_kind) in EXPECTED_SCHEMA_METADATA.items():
            schema = self._schemas()[name]
            required = schema.get("required", [])
            properties = schema["properties"]
            assert isinstance(properties, dict)
            with self.subTest(schema=name):
                if schema_version is None:
                    self.assertNotIn("schema_version", required)
                    self.assertNotIn("schema_version", properties)
                else:
                    self.assertIn("schema_version", required)
                    actual_version = _single_enum_value(properties, "schema_version")
                    if isinstance(schema_version, tuple):
                        self.assertEqual(actual_version, list(schema_version))
                    else:
                        self.assertEqual(actual_version, schema_version)

    def test_report_kind_contract_is_required_except_documented_exceptions(self) -> None:
        for name, (_schema_version, report_kind) in EXPECTED_SCHEMA_METADATA.items():
            schema = self._schemas()[name]
            required = schema.get("required", [])
            properties = schema["properties"]
            assert isinstance(properties, dict)
            with self.subTest(schema=name):
                if report_kind is None:
                    self.assertNotIn("report_kind", required)
                    self.assertNotIn("report_kind", properties)
                else:
                    self.assertIn("report_kind", required)
                    self.assertEqual(_single_enum_value(properties, "report_kind"), report_kind)

    def test_non_executing_schema_flags_remain_const_or_enum_false(self) -> None:
        for name, fields in NON_EXECUTING_FALSE_FIELDS.items():
            schema = self._schemas()[name]
            required = schema["required"]
            properties = schema["properties"]
            assert isinstance(required, list)
            assert isinstance(properties, dict)
            for field in fields:
                with self.subTest(schema=name, field=field):
                    self.assertIn(field, required)
                    self.assertEqual(_single_enum_value(properties, field), False)


if __name__ == "__main__":
    unittest.main()
