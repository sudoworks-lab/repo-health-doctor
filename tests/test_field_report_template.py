from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DOCS_INDEX = ROOT / "docs" / "README.md"
PROTOCOL = ROOT / "docs" / "field-research-safety-protocol.md"
TEMPLATE = ROOT / "docs" / "field-report-template.md"
SYNTHETIC_EXAMPLE = ROOT / "docs" / "examples" / "synthetic-field-report.md"


class FieldReportTemplateTests(unittest.TestCase):
    def test_template_and_synthetic_example_exist_and_are_routed(self) -> None:
        for path in (TEMPLATE, SYNTHETIC_EXAMPLE):
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertTrue(path.is_file())

        for path in (README, DOCS_INDEX, PROTOCOL):
            content = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIn("field-report-template.md", content)
                self.assertIn("examples/synthetic-field-report.md", content)

    def test_template_contains_required_sections(self) -> None:
        content = TEMPLATE.read_text(encoding="utf-8")

        for heading in (
            "## Purpose",
            "## Required Sections",
            "## Template",
            "## Allowed Wording",
            "## Disallowed Wording",
            "## Publication Gate",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, content)

        for section in (
            "Report status",
            "Subject handling",
            "Reviewed material",
            "Bound commit / artifact",
            "Commands not executed",
            "Scanner availability",
            "Observed indicators",
            "Gate decision",
            "Confidence",
            "Limitations",
            "What was not tested",
            "Redaction checklist",
            "Human review status",
            "Publication status",
            "Responsible disclosure / maintainer contact status",
            "Final wording approval",
        ):
            with self.subTest(section=section):
                self.assertIn(section, content)

    def test_template_fixes_allowed_and_disallowed_wording(self) -> None:
        content = TEMPLATE.read_text(encoding="utf-8")

        for phrase in (
            "repo-health-doctor reported ...",
            "observed indicators",
            "review recommended",
            "quarantine recommended",
            "not enough evidence to lower risk",
            "not a safety proof",
            "not a maliciousness determination",
            "needs human review",
        ):
            with self.subTest(allowed=phrase):
                self.assertIn(phrase, content)

        for phrase in (
            "malicious confirmed",
            "scam",
            "criminal",
            "definitely malicious",
            "steals tokens",
            "safe",
            "clean",
            "proven safe",
            "no risk",
            "guaranteed",
        ):
            with self.subTest(disallowed=phrase):
                self.assertIn(f'"{phrase}"', content)

    def test_template_publication_gate_blocks_unsafe_publication(self) -> None:
        content = " ".join(TEMPLATE.read_text(encoding="utf-8").split())

        for phrase in (
            "publication_status: publish_blocked",
            "redaction is incomplete",
            "human review before publication is missing",
            "a real subject is named without review",
            "limitations are missing",
            "scanner unavailable, no evidence, no packages, no results, or no findings",
            "publication_status: publish_allowed_after_review",
            "human review before publication is complete",
            "final wording approval is recorded",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, content)

    def test_synthetic_example_is_internal_only_and_non_accusatory(self) -> None:
        content = " ".join(SYNTHETIC_EXAMPLE.read_text(encoding="utf-8").split())

        for phrase in (
            "Synthetic Candidate A",
            "report_status: reviewed",
            "publication_status: internal_only",
            "publication_note: internal example only / not for external publication",
            "target_command_executed: false",
            "No findings is not proof of safety",
            "repo-health-doctor is not a maliciousness determination",
            "publication_gate_decision: publish_blocked",
            "This report must remain internal example material",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, content)

    def test_synthetic_example_has_no_real_subject_or_forbidden_value_shape(self) -> None:
        content = SYNTHETIC_EXAMPLE.read_text(encoding="utf-8")
        lowered = content.lower()

        forbidden = (
            "http" + "://",
            "https" + "://",
            "github" + ".com/",
            "npmjs" + ".com/",
            "pypi" + ".org/",
            "docker" + ".io/",
            "ghcr" + ".io/",
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
            "malicious confirmed",
            "definitely malicious",
            "steals tokens",
            "proven safe",
            "no risk",
            "guaranteed safe",
        )

        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern.lower(), lowered)

    def test_template_has_no_real_subject_or_forbidden_value_shape(self) -> None:
        content = TEMPLATE.read_text(encoding="utf-8").lower()

        forbidden = (
            "http" + "://",
            "https" + "://",
            "github" + ".com/",
            "npmjs" + ".com/",
            "pypi" + ".org/",
            "docker" + ".io/",
            "ghcr" + ".io/",
            "/" + "home" + "/",
            "/" + "users" + "/",
            "c:" + "\\" + "users" + "\\",
            ".".join(("127", "0", "0", "1")),
            ".".join(("192", "168", "")),
            ".".join(("10", "0", "0", "")),
            "a" + "kia",
            "g" + "hp_",
            "github" + "_pat_",
            "xox" + "b-",
            "s" + "k-",
            "pass" + "word=",
            "to" + "ken=",
            ".bash" + "_history",
            ".zsh" + "_history",
        )

        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, content)


if __name__ == "__main__":
    unittest.main()
