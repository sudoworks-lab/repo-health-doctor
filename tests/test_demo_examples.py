from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.gate import validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
DEMO_A = ROOT / "examples" / "demo-no-finding-but-degraded"
DEMO_B = ROOT / "examples" / "demo-synthetic-supply-chain"
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


class DemoExampleTests(unittest.TestCase):
    def test_demo_repositories_exist(self) -> None:
        for path in (DEMO_A, DEMO_B):
            with self.subTest(path=path):
                self.assertTrue(path.is_dir())
                self.assertTrue((path / "README.md").is_file())
                self.assertTrue((path / "package.json").is_file())
                self.assertTrue((path / ".github" / "workflows" / "ci.yml").is_file())

    def test_demo_files_do_not_contain_forbidden_leak_patterns(self) -> None:
        for demo in (DEMO_A, DEMO_B):
            for path in sorted(item for item in demo.rglob("*") if item.is_file()):
                with self.subTest(path=path.relative_to(ROOT)):
                    content = path.read_text(encoding="utf-8")
                    for pattern in FORBIDDEN_PATTERNS:
                        self.assertNotIn(pattern, content)

    def test_demo_sample_outputs_parse_and_gate_samples_are_valid(self) -> None:
        for name in (
            "demo-no-finding-but-degraded.v3.json",
            "demo-synthetic-supply-chain.v3.json",
            "demo-no-finding-but-degraded.gate-decision.json",
            "demo-synthetic-supply-chain.gate-decision.json",
        ):
            with self.subTest(name=name):
                payload = json.loads((SAMPLE_OUTPUTS / name).read_text(encoding="utf-8"))
                if name.endswith(".gate-decision.json"):
                    result = validate_gate_decision(payload)
                    self.assertTrue(result.valid, result.to_dict())
                    self.assertFalse(payload["execution_authorized"])
                    self.assertTrue(payload["limitations"])
                    self.assertTrue(payload["explanation"]["summary"])

    def test_no_finding_demo_is_not_allow_limited(self) -> None:
        payload = json.loads((SAMPLE_OUTPUTS / "demo-no-finding-but-degraded.gate-decision.json").read_text(encoding="utf-8"))

        self.assertNotEqual(payload["verdict"], "allow_limited")
        self.assertFalse(payload["execution_authorized"])
        self.assertIn("no scanner finding is not proof of safety", json.dumps(payload).lower())
        self.assertIn("Runtime or observer evidence is missing or degraded.", payload["explanation"]["key_reasons"])
        self.assertIn("The gate cannot authorize execution from scanner silence alone.", payload["explanation"]["key_reasons"])

    def test_synthetic_supply_chain_demo_quarantines_or_blocks(self) -> None:
        payload = json.loads((SAMPLE_OUTPUTS / "demo-synthetic-supply-chain.gate-decision.json").read_text(encoding="utf-8"))

        self.assertIn(payload["verdict"], {"quarantine", "block"})
        self.assertFalse(payload["execution_authorized"])
        self.assertTrue(payload["required_actions"])
        self.assertTrue(payload["limitations"])
        self.assertIn("A package install hook or postinstall-like script is present.", payload["explanation"]["key_reasons"])
        self.assertIn("An outbound network target or network-attempt string is present.", payload["explanation"]["key_reasons"])
        self.assertIn("Do not run install scripts locally.", payload["explanation"]["next_actions"])


if __name__ == "__main__":
    unittest.main()
