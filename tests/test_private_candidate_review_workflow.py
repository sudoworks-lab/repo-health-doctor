from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DOCS_INDEX = ROOT / "docs" / "README.md"
PROTOCOL = ROOT / "docs" / "field-research-safety-protocol.md"
WORKFLOW = ROOT / "docs" / "private-candidate-review-workflow.md"


class PrivateCandidateReviewWorkflowTests(unittest.TestCase):
    def test_workflow_exists_and_is_routed(self) -> None:
        self.assertTrue(WORKFLOW.is_file())

        for path in (README, DOCS_INDEX, PROTOCOL):
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIn("private-candidate-review-workflow.md", path.read_text(encoding="utf-8"))

    def test_workflow_has_intake_fields_and_stages(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")

        for heading in (
            "## Purpose",
            "## Intake Fields",
            "## Workflow Stages",
            "## Hard Stops",
            "## Output",
            "## Future Automation Note",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, content)

        for field in (
            "candidate_id",
            "source_type",
            "source_reference_redacted",
            "why_reviewed",
            "who_requested_review",
            "review_scope",
            "allowed_actions",
            "prohibited_actions",
            "publication_status",
        ):
            with self.subTest(field=field):
                self.assertIn(field, content)

        for stage in (
            "intake_created",
            "scope_reviewed",
            "evidence_collected",
            "report_drafted",
            "redaction_reviewed",
            "human_reviewed",
            "disclosure_decision",
            "publication_decision",
        ):
            with self.subTest(stage=stage):
                self.assertIn(stage, content)

    def test_workflow_hard_stops_cover_non_execution_and_publication(self) -> None:
        content = " ".join(WORKFLOW.read_text(encoding="utf-8").split())

        for phrase in (
            "no clone automation",
            "no install",
            "no download automation",
            "no target command execution",
            "no package-manager execution",
            "no exploit reproduction",
            "publication is requested before human review",
            "a real subject is named without naming review",
            "scanner unavailable, no evidence, no packages, no results, or no findings",
            "maliciousness determination",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, content)

    def test_workflow_outputs_private_packet_and_no_auto_publish_boundary(self) -> None:
        content = " ".join(WORKFLOW.read_text(encoding="utf-8").split())

        for phrase in (
            "private candidate review packet",
            "synthetic or redacted field report",
            "publication gate decision",
            "next human action",
            "auto_publish: false",
            "auto_accuse: false",
            "auto_execute: false",
            "must not auto-publish",
            "auto-name a real subject",
            "run target commands",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, content)

    def test_workflow_has_no_real_subject_examples_or_forbidden_values(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8").lower()

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
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, content)


if __name__ == "__main__":
    unittest.main()
