from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator, FormatChecker

from repo_health_doctor.gate.external_evidence import external_suite_report_fingerprint
from repo_health_doctor.gate.validation import validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "demo-repo"
GOLDEN_PATH = ROOT / "tests" / "fixtures" / "golden" / "real-scanner-suite.json"
GATE_SCHEMA_PATH = ROOT / "schemas" / "gate-decision.schema.json"
EVIDENCE_REF_FIELDS = {
    "report_kind",
    "report_fingerprint",
    "generated_at",
    "subject",
    "size_bytes",
    "truncated",
    "validation_status",
    "reasons",
}


def _cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return env


def _git_output(*argv: str) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(TARGET), *argv],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _subject() -> dict[str, object]:
    status = _git_output("status", "--short")
    return {
        "repo_commit": _git_output("rev-parse", "HEAD"),
        "dirty_state": "unknown" if status is None else ("dirty" if status else "clean"),
    }


def _report() -> dict[str, object]:
    report = deepcopy(json.loads(GOLDEN_PATH.read_text(encoding="utf-8")))
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    report["subject"] = _subject()
    report["report_fingerprint"] = external_suite_report_fingerprint(report)
    return report


def _run_gate_check(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "repo_health_doctor", "gate-check", str(TARGET), *argv],
        check=False,
        capture_output=True,
        text=True,
        env=_cli_env(),
    )


class ExternalEvidenceCliTests(unittest.TestCase):
    def test_multiple_reports_are_validated_and_gate_schema_keeps_only_bounded_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence_path = Path(tmp) / "suite.json"
            evidence_path.write_text(json.dumps(_report()), encoding="utf-8")
            result = _run_gate_check(
                "--external-evidence",
                str(evidence_path),
                "--external-evidence",
                str(evidence_path),
                "--format",
                "json",
                "--",
                "python3",
                "-c",
                "print('bounded')",
            )

        self.assertEqual(result.returncode, 2, result.stderr)
        payload = json.loads(result.stdout)
        gate_decision = payload["gate_decision"]
        evidence_refs = gate_decision["evidence_refs"]
        self.assertEqual(len(evidence_refs), 2)
        self.assertEqual(evidence_refs[0]["validation_status"], "valid")
        self.assertEqual(evidence_refs[1]["validation_status"], "invalid")
        self.assertIn("external_evidence_duplicate", evidence_refs[1]["reasons"])
        for evidence_ref in evidence_refs:
            self.assertEqual(set(evidence_ref), EVIDENCE_REF_FIELDS)

        schema = json.loads(GATE_SCHEMA_PATH.read_text(encoding="utf-8"))
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(gate_decision),
            key=lambda error: list(error.path),
        )
        self.assertEqual(errors, [])
        self.assertTrue(validate_gate_decision(gate_decision).valid)

        rendered = json.dumps(payload, sort_keys=True)
        self.assertNotIn('"entries"', rendered)
        self.assertNotIn("normalized_result", rendered)
        self.assertNotIn("scanner_unavailable", rendered)
        self.assertNotIn(str(evidence_path), rendered)

    def test_invalid_json_is_fail_closed_as_an_invalid_bounded_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence_path = Path(tmp) / "invalid.json"
            evidence_path.write_text("{invalid json", encoding="utf-8")
            result = _run_gate_check(
                "--external-evidence",
                str(evidence_path),
                "--format",
                "json",
            )

        self.assertEqual(result.returncode, 2, result.stderr)
        evidence_ref = json.loads(result.stdout)["gate_decision"]["evidence_refs"][0]
        self.assertEqual(evidence_ref["validation_status"], "invalid")
        self.assertIn("external_evidence_invalid", evidence_ref["reasons"])
        self.assertIsNone(evidence_ref["report_fingerprint"])

    def test_no_external_evidence_preserves_existing_gate_decision_shape(self) -> None:
        result = _run_gate_check("--format", "json")

        self.assertEqual(result.returncode, 2, result.stderr)
        payload = json.loads(result.stdout)
        self.assertNotIn("evidence_refs", payload["gate_decision"])
        self.assertEqual(
            set(payload),
            {
                "report_kind",
                "schema_version",
                "status",
                "execution_authorized",
                "fail_on_gate",
                "gate_decision",
                "authorization",
                "blocking_reasons",
                "limitations",
            },
        )

    def test_default_text_smoke_reports_reference_without_raw_report(self) -> None:
        report = _report()
        with tempfile.TemporaryDirectory() as tmp:
            evidence_path = Path(tmp) / "suite.json"
            evidence_path.write_text(json.dumps(report), encoding="utf-8")
            result = _run_gate_check(
                "--external-evidence",
                str(evidence_path),
                "--",
                "python3",
                "-c",
                "print('bounded')",
            )

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Evidence refs: 1", result.stdout)
        self.assertIn(str(report["report_fingerprint"]), result.stdout)
        self.assertNotIn("normalized_result", result.stdout)
        self.assertNotIn("scanner_unavailable", result.stdout)


if __name__ == "__main__":
    unittest.main()
