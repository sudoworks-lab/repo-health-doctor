from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from repo_health_doctor.gate import validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
DEMO_REPO = ROOT / "tests" / "fixtures" / "demo-repo"


class GateDecisionCliReportIntegrationTests(unittest.TestCase):
    def _cli_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return env

    def test_gate_decision_sidecar_does_not_change_default_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            gate_path = Path(tmp) / "gate-decision.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor.cli",
                    str(DEMO_REPO),
                    "--public-safety",
                    "--format",
                    "json",
                    "--output",
                    str(report_path),
                    "--gate-decision-output",
                    str(gate_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                env=self._cli_env(),
            )
            stdout_report = json.loads(result.stdout)
            written_report = json.loads(report_path.read_text(encoding="utf-8"))
            gate_decision = json.loads(gate_path.read_text(encoding="utf-8"))

        self.assertEqual(stdout_report, written_report)
        self.assertEqual(written_report["schema_version"], "1.1")
        self.assertNotIn("gate_decision", written_report)
        self.assertNotIn("execution_authorized", written_report)
        self.assertFalse(gate_decision["execution_authorized"])
        self.assertTrue(gate_decision["limitations"])
        self.assertIn("explanation", gate_decision)
        self.assertTrue(gate_decision["explanation"]["summary"])
        self.assertTrue(validate_gate_decision(gate_decision).valid)

    def test_default_cli_does_not_emit_gate_sidecar_without_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            gate_path = Path(tmp) / "gate-decision.json"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor.cli",
                    str(DEMO_REPO),
                    "--public-safety",
                    "--format",
                    "json",
                    "--output",
                    str(report_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                env=self._cli_env(),
            )
            self.assertTrue(report_path.is_file())
            self.assertFalse(gate_path.exists())


if __name__ == "__main__":
    unittest.main()
