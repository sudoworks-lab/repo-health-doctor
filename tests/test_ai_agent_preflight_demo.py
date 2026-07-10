from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "demo_agent_preflight.py"
DEMO_SUPPLY_CHAIN = ROOT / "examples" / "demo-synthetic-supply-chain"
DEMO_NO_FINDING = ROOT / "examples" / "demo-no-finding-but-degraded"


class AiAgentPreflightDemoTests(unittest.TestCase):
    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return env

    def test_help_describes_plan_only_safety_boundary(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            check=True,
            capture_output=True,
            text=True,
            env=self._env(),
        )

        self.assertIn("Plan-only AI agent preflight demo", result.stdout)
        self.assertIn("never executes that command", result.stdout)
        self.assertIn("global hook configuration are not changed", result.stdout)

    def test_quarantine_demo_never_executes_target_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "target-command-ran.txt"
            target = tmp_path / "target-command"
            target.write_text(f"#!/bin/sh\nprintf ran > {marker}\n", encoding="utf-8")
            target.chmod(target.stat().st_mode | stat.S_IXUSR)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(DEMO_SUPPLY_CHAIN),
                    "--",
                    str(target),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=self._env(),
            )
            marker_exists = marker.exists()

        self.assertEqual(result.returncode, 2)
        self.assertIn("Gate decision: QUARANTINE", result.stdout)
        self.assertIn("Action: DO NOT EXECUTE target command.", result.stdout)
        self.assertIn("Target command executed: false", result.stdout)
        self.assertIn("Intended target command (display only): <path>", result.stdout)
        self.assertFalse(marker_exists)
        self.assertNotIn(str(target), result.stdout)

    def test_no_finding_demo_is_still_not_authorization(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(DEMO_NO_FINDING),
                "--",
                "npm",
                "test",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._env(),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Target command executed: false", result.stdout)
        self.assertIn("Execution authorized: false", result.stdout)
        self.assertIn("Safety note: no findings is not proof of safety.", result.stdout)
        self.assertIn("Safety note: scanner unavailable or no evidence is not PASS.", result.stdout)
        self.assertIn("Safety note: a gate decision is not execution authorization.", result.stdout)

    def test_display_redacts_sensitive_target_arguments(self) -> None:
        sensitive_arg = "--" + "token" + "=example"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(DEMO_SUPPLY_CHAIN),
                "--",
                "npm",
                "run",
                sensitive_arg,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._env(),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("npm run <redacted>", result.stdout)
        self.assertNotIn(sensitive_arg, result.stdout)

    def test_display_redacts_separated_sensitive_target_values(self) -> None:
        sensitive_option = "--" + "token"
        sensitive_value = "demo-value"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(DEMO_SUPPLY_CHAIN),
                "--",
                "npm",
                "run",
                sensitive_option,
                sensitive_value,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._env(),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("npm run <redacted> <redacted>", result.stdout)
        self.assertNotIn(sensitive_option, result.stdout)
        self.assertNotIn(sensitive_value, result.stdout)

    def test_display_redacts_bearer_style_target_values(self) -> None:
        sensitive_value = "demo-value"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(DEMO_SUPPLY_CHAIN),
                "--",
                "curl",
                "Authorization:",
                "Bearer",
                sensitive_value,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._env(),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("curl <redacted> <redacted> <redacted>", result.stdout)
        self.assertNotIn(sensitive_value, result.stdout)


if __name__ == "__main__":
    unittest.main()
