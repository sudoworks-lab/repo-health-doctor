from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_CONTRACTS = ROOT / "docs" / "public-contracts.md"
SECURITY_REVIEW = ROOT / "docs" / "security-review-needed.md"
README = ROOT / "README.md"
QUICKSTART = ROOT / "docs" / "quickstart.md"


class PublicContractTests(unittest.TestCase):
    def test_public_contract_doc_classifies_stability(self) -> None:
        content = PUBLIC_CONTRACTS.read_text(encoding="utf-8")

        self.assertIn("Default v3 JSON output compatibility remains stable", content)
        self.assertIn("`--gate-decision-output`", content)
        self.assertIn("`--gate-summary`", content)
        self.assertIn("Human-readable gate decision `explanation`", content)
        self.assertIn("Contextual gate explanation wording", content)
        self.assertIn("Contextual explanation wording may change", content)
        self.assertIn("`schemas/evidence.schema.json`", content)
        self.assertIn("Gitleaks imported evidence adapter", content)
        self.assertIn("OSV-Scanner imported evidence adapter", content)
        self.assertIn("Execution authorization artifact", content)
        self.assertIn("`sandbox-run`", content)
        self.assertIn("`schemas/sandbox-run.schema.json`", content)
        self.assertIn("Sandbox-run, its approval contract", content)
        self.assertIn("Real-output-compatible fixture coverage", content)
        self.assertIn("Docker integration CI path", content)
        self.assertIn("Third-party security review is not done", content)

    def test_readme_and_quickstart_state_stable_and_experimental_surfaces(self) -> None:
        required = (
            "The default v3 report remains the compatibility-stable output.",
            "The evidence schema, gate decision sidecar, `--gate-summary`, human-readable gate explanation",
            "imported evidence adapters",
            "execution authorization artifact",
            "sandbox-run",
            "Real-output-compatible fixture coverage",
        )
        for path in (README, QUICKSTART):
            content = " ".join(path.read_text(encoding="utf-8").split())
            with self.subTest(path=path.relative_to(ROOT)):
                for phrase in required:
                    self.assertIn(phrase, content)

    def test_security_review_is_explicitly_not_done(self) -> None:
        content = SECURITY_REVIEW.read_text(encoding="utf-8")

        self.assertIn("Third-party security review is not done.", content)
        self.assertIn("not_done / external_required", content)


if __name__ == "__main__":
    unittest.main()
