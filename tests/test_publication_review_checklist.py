from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DOCS_INDEX = ROOT / "docs" / "README.md"
PROTOCOL = ROOT / "docs" / "field-research-safety-protocol.md"
CHECKLIST = ROOT / "docs" / "publication-review-checklist.md"


class PublicationReviewChecklistTests(unittest.TestCase):
    def test_checklist_exists_and_is_routed(self) -> None:
        self.assertTrue(CHECKLIST.is_file())

        for path in (README, DOCS_INDEX, PROTOCOL):
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIn("publication-review-checklist.md", path.read_text(encoding="utf-8"))

    def test_checklist_has_required_sections_and_checks(self) -> None:
        content = CHECKLIST.read_text(encoding="utf-8")

        for heading in (
            "## Purpose",
            "## Required Checks",
            "## Publication Statuses",
            "## SNS-Specific Guardrails",
            "## Reviewer Sign-Off",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, content)

        for check in (
            "evidence_bound_to_commit_or_artifact",
            "non_accusatory_language_used",
            "limitations_included",
            "raw_secret_present",
            "personal_information_present",
            "private_path_present",
            "local_address_present",
            "raw_scanner_output_present",
            "raw_stdout_or_stderr_present",
            "token_like_string_present",
            "exploit_instructions_present",
            "target_command_execution_steps_present",
            "scanner_unavailable_treated_as_pass",
            "no_findings_treated_as_safety_proof",
            "human_review_completed",
            "disclosure_or_maintainer_contact_considered",
            "final_wording_approved",
        ):
            with self.subTest(check=check):
                self.assertIn(check, content)

    def test_checklist_publication_statuses_and_gate_behavior(self) -> None:
        content = " ".join(CHECKLIST.read_text(encoding="utf-8").split())

        for status in (
            "internal_only",
            "private_report",
            "disclosure_pending",
            "publish_blocked",
            "publish_allowed_after_review",
        ):
            with self.subTest(status=status):
                self.assertIn(status, content)

        for phrase in (
            "human review is missing",
            "redaction is incomplete",
            "limitations are missing",
            "a real subject is named without review",
            "scanner unavailable, no evidence, no packages, no results, or no findings",
            "treated as PASS or safety proof",
            "publish_allowed_after_review only when",
            "the report is redacted",
            "the wording is non-accusatory",
            "disclosure or maintainer contact was considered",
            "a human reviewer approved the final wording",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, content)

    def test_checklist_safety_language_and_sns_guardrails(self) -> None:
        content = " ".join(CHECKLIST.read_text(encoding="utf-8").split())

        for phrase in (
            "Scanner unavailable is not PASS",
            "No findings is not proof of safety",
            "repo-health-doctor is not a maliciousness determination",
            "A gate decision is not execution authorization",
            "Human review before publication is required",
            "no quote-post dogpiling",
            "no naming without review",
            "no screenshots containing secrets",
            "no \"confirmed malicious\" style claims",
            "summarize observed evidence and limitations, not accusations",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, content)

    def test_checklist_has_no_real_subject_examples_or_forbidden_values(self) -> None:
        content = CHECKLIST.read_text(encoding="utf-8").lower()

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
            "malicious confirmed",
            "definitely malicious",
            "steals tokens",
            "proven safe",
            "no risk",
            "guaranteed safe",
        )

        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, content)


if __name__ == "__main__":
    unittest.main()
