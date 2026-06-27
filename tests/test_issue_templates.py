from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ISSUE_TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE"


class IssueTemplateTests(unittest.TestCase):
    def test_security_model_review_template_requests_needed_context(self) -> None:
        content = (ISSUE_TEMPLATE / "security-model-review.yml").read_text(encoding="utf-8")

        self.assertIn("Third-party security review has not been completed", content)
        self.assertIn("review-area", content)
        self.assertIn("reviewer-background", content)
        self.assertIn("threat-model-concern", content)
        self.assertIn("affected-docs-code", content)
        self.assertIn("severity", content)
        self.assertIn("suggested-change", content)
        self.assertIn("issue-kind", content)
        self.assertIn("Raw secret handling is involved", content)
        self.assertIn("Host private path handling is involved", content)
        self.assertIn("Docker or sandbox boundary is involved", content)
        self.assertIn("Raw scanner output handling is involved", content)

    def test_bug_report_template_protects_sensitive_data(self) -> None:
        content = (ISSUE_TEMPLATE / "bug_report.yml").read_text(encoding="utf-8")

        self.assertIn("Do not include raw secrets", content)
        self.assertIn("raw scanner output", content)
        self.assertIn("Safe reproduction", content)
        self.assertIn("Contract impact", content)
        self.assertIn("sandbox-run", content)

    def test_feature_request_template_avoids_scanner_reimplementation_bias(self) -> None:
        content = (ISSUE_TEMPLATE / "feature_request.yml").read_text(encoding="utf-8")

        self.assertIn("pre-execution safety gate", content)
        self.assertIn("evidence adapters", content)
        self.assertIn("gate evaluator", content)
        self.assertIn("not turn scanner no finding into proof of safety", content)
        self.assertIn("not merge gate decisions with execution authorization", content)
        self.assertIn("not persist or display raw scanner output", content)
        self.assertIn("sandbox-run", content)
        self.assertIn("not treat Docker or sandbox-run as proof of safety", content)

    def test_pull_request_template_covers_release_safety_contracts(self) -> None:
        content = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")

        self.assertIn("Default v3 JSON output compatibility", content)
        self.assertIn("Default CLI behavior", content)
        self.assertIn("No raw scanner output", content)
        self.assertIn("No host private path", content)
        self.assertIn("No finding is not described as proof of safety", content)
        self.assertIn("Gate decision and execution authorization remain separate", content)
        self.assertIn("Sandbox-run changes keep local-image-only", content)
        self.assertIn("Public contract impact", content)
        self.assertIn("Stable versus experimental surface impact", content)
        self.assertIn("No generated artifacts, caches, local config, or history files are committed", content)


if __name__ == "__main__":
    unittest.main()
