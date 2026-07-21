from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from repo_health_doctor.gate import (
    build_execution_authorization_draft,
    validate_gate_decision,
    validate_execution_authorization,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "execution-authorization"
FORBIDDEN = (
    "/home/",
    "/Users/",
    "C:\\Users\\",
    ".ssh",
    ".aws",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "AKIA",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "sk-",
    "-----BEGIN",
    "password=",
    "token=",
)


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _argv() -> list[str]:
    payload = json.loads((FIXTURES / "argv.json").read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    return [str(item) for item in payload]


def _now() -> datetime:
    return datetime(2026, 6, 26, tzinfo=timezone.utc)


class ExecutionAuthorizationTests(unittest.TestCase):
    def test_draft_is_not_approved_and_not_authorized(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        self.assertTrue(validate_gate_decision(gate).valid)
        draft = build_execution_authorization_draft(gate, _argv(), expires_at="2099-01-01T00:00:00Z")
        result = validate_execution_authorization(draft, gate, _argv(), now=_now())

        self.assertFalse(draft["approved"])
        self.assertFalse(result.approved)
        self.assertFalse(result.execution_authorized)
        self.assertIn("approval_missing", result.blocking_errors)

    def test_approved_false_is_not_executable(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        auth = deepcopy(_fixture("approved-exact.json"))
        auth["approved"] = False
        auth["approved_by"] = None
        auth["approved_at"] = None
        result = validate_execution_authorization(auth, gate, _argv(), now=_now())

        self.assertFalse(result.valid)
        self.assertFalse(result.execution_authorized)

    def test_expired_approval_is_invalid(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        auth = deepcopy(_fixture("approved-exact.json"))
        auth["expires_at"] = "2020-01-01T00:00:00Z"
        result = validate_execution_authorization(auth, gate, _argv(), now=_now())

        self.assertFalse(result.valid)
        self.assertFalse(result.not_expired)
        self.assertIn("authorization_expired", result.blocking_errors)

    def test_argv_scope_policy_and_gate_mismatches_are_invalid(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        cases: list[tuple[str, dict[str, object], list[str]]] = []

        auth = deepcopy(_fixture("approved-exact.json"))
        cases.append(("argv", auth, ["python3", "-m", "pytest", "other-tests"]))

        auth = deepcopy(_fixture("approved-exact.json"))
        scope = dict(auth["approved_scope"])  # type: ignore[arg-type]
        scope["commit"] = "1111111111111111111111111111111111111111"
        auth["approved_scope"] = scope
        cases.append(("scope", auth, _argv()))

        auth = deepcopy(_fixture("approved-exact.json"))
        auth["approved_policy_version"] = "other-policy"
        cases.append(("policy", auth, _argv()))

        auth = deepcopy(_fixture("approved-exact.json"))
        based_on = dict(auth["based_on_gate_decision"])  # type: ignore[arg-type]
        based_on["fingerprint"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        auth["based_on_gate_decision"] = based_on
        cases.append(("gate", auth, _argv()))

        for label, auth_case, argv in cases:
            with self.subTest(label=label):
                result = validate_execution_authorization(auth_case, gate, argv, now=_now())
                self.assertFalse(result.valid)
                self.assertFalse(result.execution_authorized)

    def test_block_quarantine_unknown_decisions_cannot_be_authorized(self) -> None:
        for verdict in ("block", "quarantine", "unknown"):
            gate = deepcopy(_fixture("gate-allow-limited.json"))
            gate["verdict"] = verdict
            auth = build_execution_authorization_draft(gate, _argv(), expires_at="2099-01-01T00:00:00Z")
            auth = dict(auth)
            auth["approved"] = True
            auth["approved_by"] = "redacted@example.invalid"
            auth["approved_at"] = "2026-01-01T00:00:00Z"
            result = validate_execution_authorization(auth, gate, _argv(), now=_now())
            with self.subTest(verdict=verdict):
                self.assertFalse(result.valid)
                self.assertFalse(result.execution_authorized)
                self.assertIn(f"gate_verdict_{verdict}_cannot_be_authorized", result.blocking_errors)

    def test_allow_limited_does_not_auto_authorize_without_approved_artifact(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        draft = build_execution_authorization_draft(gate, _argv(), expires_at="2099-01-01T00:00:00Z")
        result = validate_execution_authorization(draft, gate, _argv(), now=_now())

        self.assertEqual(gate["verdict"], "allow_limited")
        self.assertFalse(result.execution_authorized)

    def test_approved_exact_match_authorizes_execution(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        auth = _fixture("approved-exact.json")
        result = validate_execution_authorization(auth, gate, _argv(), now=_now())

        self.assertTrue(result.valid, result.to_dict())
        self.assertTrue(result.approved)
        self.assertTrue(result.execution_authorized)
        self.assertTrue(result.scope_matches)
        self.assertTrue(result.argv_matches)
        self.assertTrue(result.policy_matches)
        self.assertTrue(result.not_expired)
        self.assertTrue(result.based_on_gate_decision_matches)

    def test_benign_disk_filename_is_not_mistaken_for_a_secret_token(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        auth = deepcopy(_fixture("approved-exact.json"))
        command = [
            "python3",
            "-c",
            "from pathlib import Path; Path('/out/rhd-bounded-disk-probe.bin').write_bytes(b'x')",
        ]
        auth["approved_argv"] = command
        result = validate_execution_authorization(auth, gate, command, now=_now())

        self.assertNotIn("authorization_contains_forbidden_raw_pattern", result.blocking_errors)
        self.assertTrue(result.execution_authorized, result.to_dict())

    def test_fixtures_and_results_do_not_contain_forbidden_patterns(self) -> None:
        gate = _fixture("gate-allow-limited.json")
        auth = _fixture("approved-exact.json")
        result = validate_execution_authorization(auth, gate, _argv(), now=_now())
        rendered = "\n".join(path.read_text(encoding="utf-8") for path in sorted(FIXTURES.glob("*.json")))
        rendered += json.dumps(result.to_dict(), sort_keys=True)
        for pattern in FORBIDDEN:
            self.assertNotIn(pattern, rendered)

    def test_cli_draft_and_validate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft_path = Path(tmp) / "authorization.json"
            draft = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor",
                    "authorization",
                    "draft",
                    "--gate-decision",
                    str(FIXTURES / "gate-allow-limited.json"),
                    "--argv-json",
                    str(FIXTURES / "argv.json"),
                    "--output",
                    str(draft_path),
                ],
                cwd=ROOT,
                env={"PYTHONPATH": str(ROOT / "src")},
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertFalse(json.loads(draft.stdout)["approved"])
            self.assertTrue(draft_path.is_file())

            validation = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor",
                    "authorization",
                    "validate",
                    "--authorization",
                    str(FIXTURES / "approved-exact.json"),
                    "--gate-decision",
                    str(FIXTURES / "gate-allow-limited.json"),
                    "--argv-json",
                    str(FIXTURES / "argv.json"),
                ],
                cwd=ROOT,
                env={"PYTHONPATH": str(ROOT / "src")},
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue(json.loads(validation.stdout)["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
