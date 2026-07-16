from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import unittest

from repo_health_doctor import cli
from repo_health_doctor.gate.authorization import (
    AUTHORIZATION_REFUSAL_REASONS,
    validate_execution_authorization,
)
from repo_health_doctor.gate.authorization_discovery import (
    AUTHORIZATION_DISCOVERY_REFUSAL_REASONS,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "execution-authorization"
CONTRACT = ROOT / "docs" / "authorization-contract.md"


def _fixture(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class ExecutionAuthorizationExpiryTests(unittest.TestCase):
    def _draft_arguments(self, *expiry_arguments: str) -> list[str]:
        return [
            "authorization",
            "draft",
            "--gate-decision",
            str(FIXTURES / "gate-allow-limited.json"),
            "--argv-json",
            str(FIXTURES / "argv.json"),
            *expiry_arguments,
        ]

    def _run_draft(self, *expiry_arguments: str) -> dict[str, object]:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            return_code = cli.main(self._draft_arguments(*expiry_arguments))
        self.assertEqual(return_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIsInstance(payload, dict)
        return payload

    def test_expiry_options_are_mutually_exclusive(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            cli.main(
                self._draft_arguments(
                    "--expires-in-minutes",
                    "30",
                    "--expires-at",
                    "2026-07-16T12:00:00Z",
                )
            )

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("not allowed with argument", stderr.getvalue())

    def test_expires_in_minutes_sets_a_future_utc_timestamp(self) -> None:
        before = datetime.now(timezone.utc)
        draft = self._run_draft("--expires-in-minutes", "61")
        after = datetime.now(timezone.utc)

        value = draft["expires_at"]
        self.assertIsInstance(value, str)
        expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
        self.assertGreaterEqual(expiry, before + timedelta(minutes=61, seconds=-2))
        self.assertLessEqual(expiry, after + timedelta(minutes=61, seconds=1))

    def test_invalid_explicit_timestamp_is_rejected(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            cli.main(self._draft_arguments("--expires-at", "not-a-timestamp"))

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("must be an ISO 8601 timestamp", stderr.getvalue())

    def test_non_positive_expiry_minutes_are_rejected(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            cli.main(self._draft_arguments("--expires-in-minutes", "0"))

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("must be greater than 0", stderr.getvalue())

    def test_explicit_expired_timestamp_is_refused_by_validator(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        argv = _fixture("argv.json")
        self.assertIsInstance(gate, dict)
        self.assertIsInstance(argv, list)
        authorization = deepcopy(
            self._run_draft("--expires-at", "2026-07-16T00:00:00Z")
        )
        authorization["approved"] = True
        authorization["approved_by"] = "redacted@example.invalid"
        authorization["approved_at"] = "2026-07-16T00:00:00Z"

        result = validate_execution_authorization(
            authorization,
            gate,
            argv,
            now=datetime(2026, 7, 16, 1, 0, tzinfo=timezone.utc),
        )

        self.assertFalse(result.valid)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.not_expired)
        self.assertIn("authorization_expired", result.blocking_errors)

    def test_omitted_expiry_preserves_null_and_requires_preapproval_edit(self) -> None:
        draft = self._run_draft()

        self.assertIsNone(draft["expires_at"])
        self.assertIn(
            "expires_at_must_be_set_before_approval",
            draft["limitations"],
        )

    def test_refusal_reason_registries_are_documented(self) -> None:
        contract = CONTRACT.read_text(encoding="utf-8")

        for reason in sorted(
            AUTHORIZATION_REFUSAL_REASONS | AUTHORIZATION_DISCOVERY_REFUSAL_REASONS
        ):
            with self.subTest(reason=reason):
                self.assertIn(f"`{reason}`", contract)

    def test_t0_subject_binding_sources_and_gaps_are_documented(self) -> None:
        contract = CONTRACT.read_text(encoding="utf-8")

        for term in (
            "T0",
            "repo",
            "commit",
            "tree_hash",
            "dirty",
            "binding_kind",
            "path_bound",
            "_decision_subject",
            "_gate_subject",
            "sandbox-run",
        ):
            with self.subTest(term=term):
                self.assertIn(term, contract)


if __name__ == "__main__":
    unittest.main()
