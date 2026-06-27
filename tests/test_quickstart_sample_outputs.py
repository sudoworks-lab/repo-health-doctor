from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.gate import validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_OUTPUTS = ROOT / "docs" / "sample-outputs"
FORBIDDEN_PATTERNS = (
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


class QuickstartSampleOutputTests(unittest.TestCase):
    def test_all_sample_outputs_parse_as_json(self) -> None:
        files = sorted(SAMPLE_OUTPUTS.glob("*.json"))
        self.assertGreaterEqual(len(files), 6)
        for path in files:
            with self.subTest(path=path.name):
                json.loads(path.read_text(encoding="utf-8"))

    def test_gate_decision_sample_outputs_are_valid_and_non_authorizing(self) -> None:
        for path in sorted(SAMPLE_OUTPUTS.glob("*.gate-decision.json")):
            with self.subTest(path=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                result = validate_gate_decision(payload)
                self.assertTrue(result.valid, result.to_dict())
                self.assertFalse(payload["execution_authorized"])
                self.assertTrue(payload["limitations"])
                self.assertIn("explanation", payload)
                self.assertTrue(payload["explanation"]["summary"])
                self.assertTrue(payload["explanation"]["key_reasons"])
                self.assertTrue(payload["explanation"]["next_actions"])

    def test_v3_samples_do_not_embed_gate_decision_fields(self) -> None:
        for path in sorted(SAMPLE_OUTPUTS.glob("*.v3.json")):
            with self.subTest(path=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(payload["schema_version"], "1.1")
                self.assertNotIn("gate_decision", payload)
                self.assertNotIn("gate_summary", payload)
                self.assertNotIn("explanation", payload)
                self.assertNotIn("execution_authorized", payload)

    def test_sample_outputs_do_not_contain_forbidden_leak_patterns(self) -> None:
        rendered = "\n".join(path.read_text(encoding="utf-8") for path in sorted(SAMPLE_OUTPUTS.glob("*.json")))
        for pattern in FORBIDDEN_PATTERNS:
            self.assertNotIn(pattern, rendered)


if __name__ == "__main__":
    unittest.main()
