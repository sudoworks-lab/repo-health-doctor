from __future__ import annotations

from pathlib import Path
import unittest

from repo_health_doctor.gate.authorization_discovery import (
    AUTHORIZATION_DISCOVERY_FILENAME,
    AUTHORIZATION_DISCOVERY_MAX_BYTES,
    AUTHORIZATION_DISCOVERY_REFUSAL_REASONS,
)


ROOT = Path(__file__).resolve().parents[1]
AUTHORIZATION_DOC = ROOT / "docs" / "authorization-discovery.md"
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
PUBLIC_CONTRACTS = ROOT / "docs" / "public-contracts.md"
DOCS_INDEX = ROOT / "docs" / "README.md"
GITIGNORE = ROOT / ".gitignore"
CHANGELOG = ROOT / "CHANGELOG.md"


class AuthorizationDiscoveryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authorization_doc = AUTHORIZATION_DOC.read_text(encoding="utf-8")
        self.threat_model = THREAT_MODEL.read_text(encoding="utf-8")
        self.public_contracts = PUBLIC_CONTRACTS.read_text(encoding="utf-8")
        self.docs_index = DOCS_INDEX.read_text(encoding="utf-8")
        self.changelog = CHANGELOG.read_text(encoding="utf-8")

    def test_code_refusal_reasons_are_documented_without_drift(self) -> None:
        self.assertEqual(len(AUTHORIZATION_DISCOVERY_REFUSAL_REASONS), 8)
        for reason in sorted(AUTHORIZATION_DISCOVERY_REFUSAL_REASONS):
            with self.subTest(reason=reason):
                self.assertIn(f"`{reason}`", self.authorization_doc)

    def test_single_candidate_and_ignore_contract_are_documented(self) -> None:
        self.assertIn(AUTHORIZATION_DISCOVERY_FILENAME, self.authorization_doc)
        self.assertIn("exactly one candidate", self.authorization_doc)
        self.assertIn("There is one candidate and there is no fallback", self.authorization_doc)
        self.assertIn(AUTHORIZATION_DISCOVERY_FILENAME, GITIGNORE.read_text(encoding="utf-8").splitlines())
        self.assertIn("authorization-discovery.md", self.docs_index)
        self.assertIn("64 KiB", self.authorization_doc)
        self.assertEqual(AUTHORIZATION_DISCOVERY_MAX_BYTES, 64 * 1024)

    def test_cli_boundaries_and_toctou_residual_risk_are_synchronized(self) -> None:
        for content in (self.authorization_doc, self.threat_model, self.public_contracts):
            self.assertIn("TOCTOU", content)
        self.assertIn("--no-discover", self.authorization_doc)
        self.assertIn("--no-discover", self.public_contracts)
        self.assertIn("trailing argv", self.authorization_doc)
        self.assertIn("trailing argv", self.public_contracts)
        self.assertIn("no fallback", self.authorization_doc)
        self.assertIn("no-fallback", self.threat_model)
        self.assertIn("execution authorization", self.authorization_doc)
        self.assertIn("execution authorization", self.public_contracts)

    def test_changelog_preserves_experimental_and_fail_closed_boundaries(self) -> None:
        self.assertIn("Experimental `gate-check` authorization discovery", self.changelog)
        self.assertIn("Local-writer TOCTOU", self.changelog)
        self.assertIn("discovery remains separate from execution authorization", self.changelog)


if __name__ == "__main__":
    unittest.main()
