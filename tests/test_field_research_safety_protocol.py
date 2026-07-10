from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DOCS_INDEX = ROOT / "docs" / "README.md"
PUBLIC_CONTRACTS = ROOT / "docs" / "public-contracts.md"
RELEASE_NOTES = ROOT / "docs" / "release-notes" / "v0.1.0.md"
PROTOCOL = ROOT / "docs" / "field-research-safety-protocol.md"
COMPATIBILITY_REGENERATION = ROOT / "docs" / "compatibility-regeneration.md"
FIELD_REPORT_TEMPLATE = ROOT / "docs" / "field-report-template.md"
SYNTHETIC_FIELD_REPORT = ROOT / "docs" / "examples" / "synthetic-field-report.md"
PRIVATE_WORKFLOW = ROOT / "docs" / "private-candidate-review-workflow.md"
PUBLICATION_CHECKLIST = ROOT / "docs" / "publication-review-checklist.md"


class FieldResearchSafetyProtocolTests(unittest.TestCase):
    def test_protocol_doc_exists_and_is_routed_from_public_docs(self) -> None:
        self.assertTrue(PROTOCOL.is_file())

        for path in (README, DOCS_INDEX, PUBLIC_CONTRACTS, RELEASE_NOTES):
            with self.subTest(path=path.relative_to(ROOT)):
                content = path.read_text(encoding="utf-8")
                self.assertIn("field-research-safety-protocol.md", content)

    def test_protocol_routes_to_c_phase_artifacts(self) -> None:
        content = PROTOCOL.read_text(encoding="utf-8")

        for path in (FIELD_REPORT_TEMPLATE, SYNTHETIC_FIELD_REPORT, PRIVATE_WORKFLOW, PUBLICATION_CHECKLIST):
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertTrue(path.is_file())
                self.assertIn(str(path.relative_to(ROOT / "docs")), content)

    def test_protocol_preserves_evidence_and_language_boundaries(self) -> None:
        content = " ".join(PROTOCOL.read_text(encoding="utf-8").split())

        for phrase in (
            "repo-health-doctor is not a safety proof",
            "not a maliciousness classifier",
            "Use non-accusatory language",
            "do not write \"malicious\" as a conclusion",
            "No findings is not proof of safety",
            "Scanner unavailable is not PASS",
            "No evidence is not PASS",
            "A gate decision is not execution authorization",
            "require human review before publication",
            "consider private reporting, maintainer contact, or responsible disclosure",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, content)

    def test_protocol_requires_non_executing_collection_and_redaction(self) -> None:
        content = " ".join(PROTOCOL.read_text(encoding="utf-8").split())

        for phrase in (
            "do not automate clone, install, download",
            "do not run an unknown repository target command",
            "do not persist raw scanner reports, raw stdout, or raw stderr",
            "do not save raw secret values",
            "personal information",
            "token-like strings",
            "commit binding is unavailable",
            "treat the evidence as limited",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, content)

    def test_protocol_has_report_template_publication_gate_and_future_phases(self) -> None:
        content = PROTOCOL.read_text(encoding="utf-8")

        for heading in (
            "## Report Template",
            "## Publication Gate",
            "## Public Write-Up Checklist",
            "## C-Phase Completion",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, content)

        for future_phase in ("C-1", "C-2", "C-3", "C-4"):
            with self.subTest(future_phase=future_phase):
                self.assertIn(future_phase, content)

    def test_protocol_does_not_add_real_subject_examples_or_forbidden_values(self) -> None:
        content = PROTOCOL.read_text(encoding="utf-8")
        lowered = content.lower()

        forbidden_literals = (
            "http" + "://",
            "https" + "://",
            "github" + ".com/",
            "npmjs" + ".com/",
            "pypi" + ".org/",
            "docker" + ".io/",
            "ghcr" + ".io/",
            "@" + "example",
            "/" + "home" + "/",
            "/" + "Users" + "/",
            "C:" + "\\" + "Users" + "\\",
            ".".join(("127", "0", "0", "1")),
            ".".join(("192", "168", "")),
            ".".join(("10", "0", "0", "")),
            "A" + "KIA",
            "g" + "hp_",
            "github" + "_pat_",
            "xox" + "b-",
            "s" + "k-",
            "pass" + "word=",
            "to" + "ken=",
            ".bash" + "_history",
            ".zsh" + "_history",
        )
        for pattern in forbidden_literals:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern.lower(), lowered)

    def test_existing_compatibility_runbook_keeps_raw_output_temporary(self) -> None:
        content = " ".join(COMPATIBILITY_REGENERATION.read_text(encoding="utf-8").split())

        self.assertIn("Inspect temporary raw output only inside the isolated temporary location", content)
        self.assertIn("Do not copy raw output into notes, reports, docs, or committed files", content)
        self.assertIn("Delete the temporary raw output after redaction and normalization", content)


if __name__ == "__main__":
    unittest.main()
