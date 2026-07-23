from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from repo_health_doctor.gate.authorization import (
    IMAGE_BOUND_AUTHORIZATION_SCHEMA_VERSION,
    LEGACY_AUTHORIZATION_SCHEMA_VERSION,
    validate_execution_authorization,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "execution-authorization"
SCHEMA = json.loads((ROOT / "schemas" / "execution-authorization.schema.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 6, 26, tzinfo=timezone.utc)
IMAGE_REFERENCE = "python:3.12-slim@sha256:" + "c" * 64
IMAGE_ID = "sha256:" + "b" * 64


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _argv() -> list[str]:
    return list(_fixture("argv.json"))  # type: ignore[arg-type]


class ExecutionAuthorizationImageBindingTests(unittest.TestCase):
    def test_old_and_new_golden_are_schema_valid_and_version_specific(self) -> None:
        validator = Draft202012Validator(SCHEMA)
        old = _fixture("approved-exact.json")
        new = _fixture("approved-exact-0.2.json")

        self.assertEqual(old["schema_version"], LEGACY_AUTHORIZATION_SCHEMA_VERSION)
        self.assertEqual(
            new["schema_version"],
            IMAGE_BOUND_AUTHORIZATION_SCHEMA_VERSION,
        )
        self.assertEqual(list(validator.iter_errors(old)), [])
        self.assertEqual(list(validator.iter_errors(new)), [])

        old_with_new_field = deepcopy(old)
        old_with_new_field["approved_image"] = new["approved_image"]
        self.assertTrue(list(validator.iter_errors(old_with_new_field)))

        new_without_image = deepcopy(new)
        new_without_image.pop("approved_image")
        self.assertEqual(list(validator.iter_errors(new_without_image)), [])

    def test_legacy_artifact_remains_authorizable_with_limitation(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        result = validate_execution_authorization(
            _fixture("approved-exact.json"), gate, _argv(), now=NOW
        )

        self.assertTrue(result.valid, result.to_dict())
        self.assertTrue(result.execution_authorized)
        self.assertFalse(result.image_binding_present)
        self.assertIn("authorization_not_image_bound", result.limitations)

    def test_digest_reference_and_local_image_id_are_bound_separately(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        result = validate_execution_authorization(
            _fixture("approved-exact-0.2.json"),
            gate,
            _argv(),
            now=NOW,
            runtime_image_reference=IMAGE_REFERENCE,
            runtime_image_id=IMAGE_ID,
        )

        self.assertTrue(result.valid, result.to_dict())
        self.assertTrue(result.execution_authorized)
        self.assertTrue(result.image_binding_present)
        self.assertTrue(result.image_reference_matches)
        self.assertTrue(result.image_id_matches)

    def test_reference_and_local_id_mismatches_fail_closed_independently(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        auth = _fixture("approved-exact-0.2.json")

        reference_mismatch = validate_execution_authorization(
            auth,
            gate,
            _argv(),
            now=NOW,
            runtime_image_reference="python:3.12-slim@sha256:" + "d" * 64,
            runtime_image_id=IMAGE_ID,
        )
        self.assertFalse(reference_mismatch.valid)
        self.assertIn("approved_image_reference_mismatch", reference_mismatch.blocking_errors)
        self.assertNotIn("approved_image_id_mismatch", reference_mismatch.blocking_errors)

        id_mismatch = validate_execution_authorization(
            auth,
            gate,
            _argv(),
            now=NOW,
            runtime_image_reference=IMAGE_REFERENCE,
            runtime_image_id="sha256:" + "e" * 64,
        )
        self.assertFalse(id_mismatch.valid)
        self.assertIn("approved_image_id_mismatch", id_mismatch.blocking_errors)
        self.assertNotIn("approved_image_reference_mismatch", id_mismatch.blocking_errors)

    def test_unpinned_reference_and_unresolved_local_id_are_rejected(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        auth = deepcopy(_fixture("approved-exact-0.2.json"))
        auth["approved_image"]["requested_reference"] = "python:3.12-slim"  # type: ignore[index]

        result = validate_execution_authorization(
            auth,
            gate,
            _argv(),
            now=NOW,
            runtime_image_reference="python:3.12-slim",
            runtime_image_id=None,
        )

        self.assertFalse(result.valid)
        self.assertIn("approved_image_digest_unpinned", result.blocking_errors)
        self.assertIn("runtime_image_id_unresolved", result.blocking_errors)

    def test_repo_digests_are_not_accepted_as_local_image_id(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        auth = _fixture("approved-exact-0.2.json")
        result = validate_execution_authorization(
            auth,
            gate,
            _argv(),
            now=NOW,
            runtime_image_reference=IMAGE_REFERENCE,
            runtime_image_id=IMAGE_REFERENCE,
        )

        self.assertFalse(result.valid)
        self.assertIn("runtime_image_id_unresolved", result.blocking_errors)


if __name__ == "__main__":
    unittest.main()
