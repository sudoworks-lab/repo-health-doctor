from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.image_attestation import (
    IMAGE_ATTESTATION_SCHEMA_VERSION,
    REPORT_KIND_IMAGE_ATTESTATION,
    REPORT_KIND_IMAGE_ATTESTATION_VALIDATION,
    validate_sandbox_image_attestation,
    validate_sandbox_image_attestation_report,
)
from repo_health_doctor.sandbox.image_lock import build_registry_image_lock, validate_sandbox_image_lock_report


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-image-attestation.schema.json"


def _synthetic_host_path(*parts: str) -> str:
    return "".join(parts)


def _attestation(lock: dict[str, object]) -> dict[str, object]:
    image = lock["images"][0]  # type: ignore[index]
    platform = image["expected_platform"]  # type: ignore[index]
    registry_digest = image["registry_digest"]  # type: ignore[index]
    full_image_id = image["expected_image_id"]  # type: ignore[index]
    local = full_image_id is not None
    tools = image["tool_versions"]  # type: ignore[index]
    return {
        "schema_version": IMAGE_ATTESTATION_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_IMAGE_ATTESTATION,
        "attestation_id": "attestation-static-only",
        "mode": "static_attestation_input",
        "image": {
            "image_logical_name": image["logical_name"],
            "image_reference": image["registry_reference"],
            "image_reference_kind": "local_image_id" if local else "registry_digest",
            "registry_digest": registry_digest,
            "full_image_id": full_image_id,
            "platform": platform,
            "architecture": platform["architecture"],
            "os": platform["os"],
            "variant": None,
        },
        "lock_binding": {
            "image_lock_schema_version": lock["schema_version"],
            "image_lock_report_kind": lock["report_kind"],
            "image_lock_id": lock["lock_id"],
            "expected_registry_digest": registry_digest,
            "expected_full_image_id": full_image_id,
            "expected_platform": platform,
        },
        "tool_inventory": {
            "python": tools["python"],
            "node": tools["node"],
            "pip": tools["pip"],
            "npm": tools["npm"],
            "strace": tools["strace"],
            "other_tools": [] if tools["other"] == "none" else [tools["other"]],
        },
        "runtime_flags_attested": {
            "pull_policy": "never",
            "network": "none",
            "shell": False,
            "no_host_home": True,
            "no_docker_socket": True,
            "no_credentials": True,
            "read_only_rootfs": True,
            "non_root_user": True,
            "no_new_privileges": True,
        },
        "operator_attestation": {
            "attested_by": "human_operator",
            "attested_at": "2099-01-01T00:00:00Z",
            "source": "controlled_static_input",
            "method": "manual_review_record",
            "docker_engine_version": "not_contacted",
            "docker_desktop_version": "not_contacted",
            "runc_version": "not_contacted",
            "containerd_version": "not_contacted",
            "notes": [],
        },
        "local_sanctioned": {
            "allowed": local,
            "dev_only": local,
            "portability_limitation": ["dev_only_not_portable"] if local else [],
        },
        "limitations": ["static_attestation_input_only"],
        "residual_risks": ["future_docker_inspect_required"],
        "redaction": {"raw_host_path_present": False, "raw_secret_like_value_present": False},
    }


def _local_lock() -> dict[str, object]:
    lock = build_registry_image_lock()
    image = lock["images"][0]  # type: ignore[index]
    image.update(
        {
            "distribution": "local_dev_only",
            "registry_reference": "rhd-python312-strace:local",
            "registry_digest": None,
            "expected_image_id": "sha256:" + "b" * 64,
            "purpose": "controlled_fixture_dev_only",
            "local_sanctioned_allowed": True,
            "local_sanctioned_limitations": ["dev_only_not_portable"],
        }
    )
    return lock


class SandboxImageAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = build_registry_image_lock()
        self.attestation = _attestation(self.lock)

    def _report(self, attestation: dict[str, object] | None = None, lock: dict[str, object] | None = None, lock_result: dict[str, object] | None = None) -> dict[str, object]:
        return validate_sandbox_image_attestation_report(
            attestation or self.attestation,
            image_lock=lock if lock is not None else self.lock,
            image_lock_validation_result=lock_result,
        )

    def _blocked(self, mutate: object, *, lock: dict[str, object] | None = None) -> dict[str, object]:
        attestation = copy.deepcopy(_attestation(lock or self.lock))
        image_lock = copy.deepcopy(lock or self.lock)
        assert callable(mutate)
        mutate(attestation, image_lock)
        report = self._report(attestation, image_lock)
        self.assertEqual(report["verdict"], "block")
        self.assertFalse(report["valid"])
        self.assertFalse(report["execution_permitted"])
        self.assertFalse(report["runner_connected"])
        self.assertFalse(report["docker_contacted"])
        self.assertFalse(report["docker_inspect_performed"])
        self.assertFalse(report["docker_pull_performed"])
        self.assertFalse(report["docker_run_performed"])
        return report

    def test_valid_registry_digest_attestation_passes_without_docker(self) -> None:
        validate_sandbox_image_attestation(self.attestation, image_lock=self.lock)
        report = self._report()
        self.assertEqual(report["schema_version"], IMAGE_ATTESTATION_SCHEMA_VERSION)
        self.assertEqual(report["report_kind"], REPORT_KIND_IMAGE_ATTESTATION_VALIDATION)
        self.assertEqual(report["verdict"], "pass")
        self.assertTrue(report["valid"])
        self.assertEqual(report["attestation_status"], "matched")
        self.assertFalse(report["execution_permitted"])
        self.assertFalse(report["docker_contacted"])
        self.assertFalse(report["docker_inspect_performed"])
        self.assertFalse(report["docker_pull_performed"])
        self.assertFalse(report["docker_run_performed"])

    def test_schema_is_closed_and_matches_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [IMAGE_ATTESTATION_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_IMAGE_ATTESTATION])
        for field in schema["required"]:
            self.assertIn(field, self.attestation)

    def test_missing_schema_kind_required_or_unknown_field_blocks(self) -> None:
        self._blocked(lambda attestation, _lock: attestation.pop("schema_version"))
        self._blocked(lambda attestation, _lock: attestation.update({"schema_version": "99.0"}))
        self._blocked(lambda attestation, _lock: attestation.update({"report_kind": "sandbox_other_attestation"}))
        self._blocked(lambda attestation, _lock: attestation["image"].pop("image_reference"))
        self._blocked(lambda attestation, _lock: attestation.update({"unknown_safety_field": True}))

    def test_registry_identity_mismatches_block(self) -> None:
        self._blocked(lambda attestation, _lock: attestation["image"].update({"image_reference": "registry.example.invalid/rhd/python312:stable"}))
        self._blocked(lambda attestation, _lock: attestation["image"].update({"registry_digest": None}))
        self._blocked(lambda attestation, _lock: attestation["lock_binding"].update({"expected_registry_digest": "sha256:" + "c" * 64}))
        self._blocked(lambda attestation, _lock: attestation["image"].update({"platform": {"os": "linux", "architecture": "arm64"}, "architecture": "arm64"}))
        self._blocked(lambda attestation, _lock: attestation["tool_inventory"].update({"python": "3.11.x"}))

    def test_runtime_flags_and_operator_attestation_block_when_unsafe(self) -> None:
        cases = (
            ("pull_policy", "always"),
            ("network", "host"),
            ("shell", True),
            ("no_host_home", False),
            ("no_docker_socket", False),
            ("no_credentials", False),
            ("read_only_rootfs", False),
            ("non_root_user", False),
            ("no_new_privileges", False),
        )
        for field, value in cases:
            with self.subTest(field=field):
                self._blocked(lambda attestation, _lock, field=field, value=value: attestation["runtime_flags_attested"].update({field: value}))
        self._blocked(lambda attestation, _lock: attestation.pop("operator_attestation"))
        self._blocked(lambda attestation, _lock: attestation["tool_inventory"].pop("strace"))

    def test_local_sanctioned_image_warns_with_dev_only_limitation(self) -> None:
        lock = _local_lock()
        attestation = _attestation(lock)
        report = self._report(attestation, lock)
        self.assertEqual(report["verdict"], "warn")
        self.assertTrue(report["valid"])
        self.assertEqual(report["attestation_status"], "matched_with_local_limitations")
        self.assertIn("local_sanctioned_image_dev_only", report["warnings"])
        self.assertIn("development-only", " ".join(report["limitations"]))

    def test_local_sanctioned_image_missing_full_id_blocks(self) -> None:
        lock = _local_lock()
        self._blocked(lambda attestation, _lock: attestation["image"].update({"full_image_id": None}), lock=lock)
        self._blocked(lambda attestation, _lock: attestation["image"].update({"full_image_id": "sha256:" + "c" * 64}), lock=lock)
        self._blocked(lambda attestation, _lock: attestation["local_sanctioned"].update({"portability_limitation": []}), lock=lock)

    def test_image_lock_validation_block_blocks_attestation(self) -> None:
        bad_lock = copy.deepcopy(self.lock)
        bad_lock["required_runtime_flags"]["network"] = "host"
        bad_result = validate_sandbox_image_lock_report(bad_lock)
        report = self._report(self.attestation, self.lock, bad_result)
        self.assertEqual(report["verdict"], "block")
        self.assertIn("invalid_or_mismatched_image_attestation", report["blockers"])

    def test_raw_host_path_or_secret_like_value_does_not_leak(self) -> None:
        for raw in (_synthetic_host_path("/ho", "me", "/private/attestation"), "sk-" + "attestation_0123456789abcdef"):
            with self.subTest(raw=raw):
                attestation = copy.deepcopy(self.attestation)
                attestation["operator_attestation"]["notes"] = [raw]
                payload = json.dumps(self._report(attestation, self.lock))
                self.assertNotIn(raw, payload)
                self.assertIn("invalid_or_mismatched_image_attestation", payload)


if __name__ == "__main__":
    unittest.main()
