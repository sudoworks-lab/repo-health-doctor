from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from repo_health_doctor.evidence.sandbox_run import sandbox_run_report_fingerprint
from repo_health_doctor.gate.sandbox_evidence import (
    SANDBOX_EVIDENCE_MAX_BYTES,
    SANDBOX_EVIDENCE_MAX_COUNT,
    SANDBOX_EVIDENCE_MAX_TOTAL_BYTES,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "demo-repo"


def _run_cli(*argv: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "repo_health_doctor", *argv],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _sandbox_report() -> dict[str, object]:
    result = _run_cli(
        "sandbox-run",
        str(TARGET),
        "--dry-run",
        "--fail-on-gate",
        "block",
        "--format",
        "json",
        "--",
        "python3",
        "-c",
        "pass",
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def _write_report(path: Path, report: dict[str, object]) -> None:
    payload = deepcopy(report)
    payload["report_fingerprint"] = sandbox_run_report_fingerprint(payload)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _gate_check(*paths: Path) -> subprocess.CompletedProcess[str]:
    evidence_args = [item for path in paths for item in ("--sandbox-evidence", str(path))]
    return _run_cli("gate-check", str(TARGET), *evidence_args, "--format", "json")


def _assert_schema_valid(test: unittest.TestCase, schema_name: str, payload: object) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    try:
        from jsonschema import Draft202012Validator
    except ModuleNotFoundError:
        test.assertIsInstance(payload, dict)
        test.assertTrue(set(schema["required"]).issubset(payload))
    else:
        Draft202012Validator(schema).validate(payload)


class SandboxEvidenceCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _sandbox_report()

    def test_cli_and_schemas_cross_reference_only_bounded_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sandbox.json"
            _write_report(path, self.report)
            result = _gate_check(path)

        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stdout)
        evidence_ref = payload["gate_decision"]["evidence_refs"][0]
        self.assertEqual(evidence_ref["report_kind"], "sandbox_run")
        self.assertEqual(evidence_ref["report_fingerprint"], self.report["report_fingerprint"])
        self.assertEqual(evidence_ref["run_id"], self.report["run"]["run_id"])
        self.assertEqual(
            evidence_ref["gate_decision_fingerprint"],
            self.report["gate"]["decision_fingerprint"],
        )
        self.assertEqual(evidence_ref["validation_status"], "valid")
        self.assertEqual(
            set(evidence_ref),
            {
                "report_kind",
                "report_fingerprint",
                "run_id",
                "gate_decision_fingerprint",
                "validation_status",
                "reasons",
            },
        )
        self.assertNotIn("command", evidence_ref)
        self.assertNotIn("output_summary", evidence_ref)
        _assert_schema_valid(self, "sandbox-run.schema.json", self.report)
        _assert_schema_valid(self, "gate-decision.schema.json", payload["gate_decision"])

    def test_count_and_duplicate_fingerprint_are_rejected_boundedly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first.json"
            second = Path(tmp) / "second.json"
            _write_report(first, self.report)
            _write_report(second, self.report)
            duplicate_result = _gate_check(first, second)
            count_result = _gate_check(*([first] * (SANDBOX_EVIDENCE_MAX_COUNT + 1)))

        duplicate_refs = json.loads(duplicate_result.stdout)["gate_decision"]["evidence_refs"]
        self.assertEqual(len(duplicate_refs), 2)
        self.assertEqual(duplicate_refs[0]["validation_status"], "valid")
        self.assertEqual(duplicate_refs[1]["validation_status"], "invalid")
        self.assertIn("sandbox_evidence_duplicate", duplicate_refs[1]["reasons"])
        self.assertEqual(count_result.returncode, 2)
        self.assertIn(
            f"--sandbox-evidence accepts at most {SANDBOX_EVIDENCE_MAX_COUNT} reports",
            count_result.stderr,
        )

    def test_file_size_and_total_bytes_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            oversized = deepcopy(self.report)
            oversized["contract"] = {
                **oversized["contract"],
                "padding": "x" * SANDBOX_EVIDENCE_MAX_BYTES,
            }
            oversized_path = tmp_path / "oversized.json"
            _write_report(oversized_path, oversized)
            oversized_result = _gate_check(oversized_path)

            total_paths: list[Path] = []
            padding_size = SANDBOX_EVIDENCE_MAX_TOTAL_BYTES // 5
            for index in range(5):
                report = deepcopy(self.report)
                report["run"] = {**report["run"], "run_id": f"rhd-sandbox-run-total-{index}"}
                report["contract"] = {**report["contract"], "padding": "x" * padding_size}
                path = tmp_path / f"total-{index}.json"
                _write_report(path, report)
                total_paths.append(path)
            total_result = _gate_check(*total_paths)

        oversized_ref = json.loads(oversized_result.stdout)["gate_decision"]["evidence_refs"][0]
        self.assertIn("sandbox_evidence_over_budget", oversized_ref["reasons"])
        total_refs = json.loads(total_result.stdout)["gate_decision"]["evidence_refs"]
        self.assertTrue(
            any("sandbox_evidence_over_budget" in item["reasons"] for item in total_refs)
        )

    def test_stale_report_is_not_silently_accepted(self) -> None:
        stale = deepcopy(self.report)
        old = datetime.now(timezone.utc) - timedelta(days=2)
        stale["run"] = {
            **stale["run"],
            "started_at": old.isoformat().replace("+00:00", "Z"),
            "ended_at": (old + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stale.json"
            _write_report(path, stale)
            result = _gate_check(path)

        evidence_ref = json.loads(result.stdout)["gate_decision"]["evidence_refs"][0]
        self.assertEqual(evidence_ref["validation_status"], "invalid")
        self.assertIn("sandbox_evidence_stale", evidence_ref["reasons"])

    def test_schema_invalid_report_is_fail_closed(self) -> None:
        invalid = deepcopy(self.report)
        del invalid["command"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid-schema.json"
            _write_report(path, invalid)
            result = _gate_check(path)

        evidence_ref = json.loads(result.stdout)["gate_decision"]["evidence_refs"][0]
        self.assertEqual(evidence_ref["validation_status"], "invalid")
        self.assertIn("sandbox_evidence_invalid", evidence_ref["reasons"])

    def test_omitting_sandbox_evidence_preserves_existing_gate_shape(self) -> None:
        result = _run_cli("gate-check", str(TARGET), "--format", "json")

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("evidence_refs", json.loads(result.stdout)["gate_decision"])


if __name__ == "__main__":
    unittest.main()
