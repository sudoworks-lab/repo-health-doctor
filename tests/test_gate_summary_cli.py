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
DEMO_NO_FINDING = ROOT / "examples" / "demo-no-finding-but-degraded"
DEMO_SUPPLY_CHAIN = ROOT / "examples" / "demo-synthetic-supply-chain"


class GateSummaryCliTests(unittest.TestCase):
    def _cli_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return env

    def test_default_output_does_not_emit_gate_summary(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                str(DEMO_SUPPLY_CHAIN),
                "--public-safety",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertIn("Repo Health Doctor: PASS", result.stdout)
        self.assertNotIn("Gate decision:", result.stdout)
        self.assertNotIn("Execution authorized:", result.stdout)

    def test_gate_summary_emits_human_readable_decision_without_sidecar(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                str(DEMO_SUPPLY_CHAIN),
                "--public-safety",
                "--gate-summary",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertIn("Static health: PASS", result.stdout)
        self.assertIn("Gate decision:", result.stdout)
        self.assertIn("Execution authorized: false", result.stdout)
        self.assertIn("A package install hook or postinstall-like script is present.", result.stdout)
        self.assertIn("An outbound network target or network-attempt string is present.", result.stdout)
        self.assertIn("Scanner silence is not enough to authorize execution.", result.stdout)

    def test_no_finding_gate_summary_explains_observer_gap(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                str(DEMO_NO_FINDING),
                "--public-safety",
                "--gate-summary",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertIn("Static health: PASS", result.stdout)
        self.assertIn("Gate decision: WARN", result.stdout)
        self.assertIn("Execution authorized: false", result.stdout)
        self.assertIn("No scanner finding is not proof of safety.", result.stdout)
        self.assertIn("Runtime or observer evidence is missing or degraded.", result.stdout)
        self.assertIn("The gate cannot authorize execution from scanner silence alone.", result.stdout)

    def test_gate_summary_and_sidecar_can_be_combined(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            gate_path = Path(tmp) / "gate.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor",
                    str(DEMO_SUPPLY_CHAIN),
                    "--public-safety",
                    "--format",
                    "json",
                    "--output",
                    str(report_path),
                    "--gate-decision-output",
                    str(gate_path),
                    "--gate-summary",
                ],
                check=True,
                capture_output=True,
                text=True,
                env=self._cli_env(),
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            decision = json.loads(gate_path.read_text(encoding="utf-8"))

        self.assertIn("Gate decision:", result.stdout)
        self.assertEqual(report["schema_version"], "1.1")
        self.assertNotIn("gate_summary", report)
        self.assertNotIn("gate_decision", report)
        self.assertNotIn("explanation", report)
        self.assertNotIn("execution_authorized", report)
        self.assertFalse(decision["execution_authorized"])
        self.assertIn("confidence_reason", decision)
        self.assertIn("explanation", decision)
        self.assertTrue(decision["confidence_reason"])
        self.assertTrue(validate_gate_decision(decision).valid)
        explanation = decision["explanation"]
        self.assertIsInstance(explanation["summary"], str)
        self.assertTrue(explanation["summary"])
        self.assertTrue(explanation["key_reasons"])
        self.assertTrue(explanation["next_actions"])
        self.assertIn("A package install hook or postinstall-like script is present.", explanation["key_reasons"])
        self.assertIn("Do not run install scripts locally.", explanation["next_actions"])

    def test_docs_use_implemented_gate_summary_option(self) -> None:
        for path in (ROOT / "README.md", ROOT / "docs" / "quickstart.md", ROOT / "docs" / "demo-runbook.md"):
            with self.subTest(path=path.relative_to(ROOT)):
                content = path.read_text(encoding="utf-8")
                self.assertIn("--gate-summary", content)


if __name__ == "__main__":
    unittest.main()
