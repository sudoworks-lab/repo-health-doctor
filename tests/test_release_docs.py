from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseDocsTests(unittest.TestCase):
    def test_readme_has_release_badges_and_routing(self) -> None:
        content = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("actions/workflows/ci.yml/badge.svg?branch=main", content)
        self.assertIn("python-3.10%2B", content)
        self.assertIn("license-MIT", content)
        self.assertIn("version-0.1.0", content)
        self.assertIn("docs/release-notes/v0.1.0.md", content)
        self.assertIn("docs/versioning.md", content)
        self.assertIn("docs/compatibility-regeneration.md", content)
        self.assertIn("Third-party security review is not done", content)
        self.assertIn("sandbox-run", content)

    def test_pyproject_metadata_matches_positioning(self) -> None:
        content = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn('version = "0.1.0"', content)
        self.assertIn("pre-execution safety gate", content)
        self.assertIn("evidence normalizer", content)
        self.assertIn('requires-python = ">=3.10"', content)
        self.assertIn("[project.urls]", content)
        self.assertIn("https://github.com/sudoworks-lab/repo-health-doctor", content)
        self.assertIn("/issues", content)
        self.assertIn("/tree/main/docs", content)

    def test_release_docs_exist_and_preserve_security_status(self) -> None:
        paths = [
            ROOT / "CHANGELOG.md",
            ROOT / "docs" / "release-notes" / "v0.1.0.md",
            ROOT / "docs" / "versioning.md",
            ROOT / "docs" / "compatibility-regeneration.md",
        ]
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                content = path.read_text(encoding="utf-8")
                self.assertTrue(content.strip())
                self.assertIn("Third-party security review", content)
                self.assertNotIn("Third-party security review is done", content)

    def test_versioning_doc_keeps_stable_and_experimental_boundary(self) -> None:
        content = (ROOT / "docs" / "versioning.md").read_text(encoding="utf-8")

        self.assertIn("Default v3 JSON output compatibility is stable", content)
        self.assertIn("Default CLI behavior is stable", content)
        self.assertIn("Gate decision sidecar payloads", content)
        self.assertIn("`--gate-summary`", content)
        self.assertIn("Human-readable gate decision explanations", content)
        self.assertIn("Execution authorization artifacts", content)
        self.assertIn("Imported Gitleaks and OSV-Scanner evidence adapters", content)
        self.assertIn("A scanner no finding must not become safety proof", content)
        self.assertIn("A gate decision must not become execution authorization", content)

    def test_docs_index_lists_release_and_regeneration_docs(self) -> None:
        content = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")

        self.assertIn("compatibility-regeneration.md", content)
        self.assertIn("versioning.md", content)
        self.assertIn("release-notes/v0.1.0.md", content)
        self.assertIn("integration-claude-code.md", content)

    def test_release_workflow_uses_trusted_publishing(self) -> None:
        content = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

        self.assertIn("id-token: write", content)
        self.assertIn("pypa/gh-action-pypi-publish", content)
        self.assertNotIn("password:", content)
        self.assertNotIn("api-token", content)

    def test_release_notes_include_sandbox_run_boundary(self) -> None:
        content = " ".join(
            (ROOT / "docs" / "release-notes" / "v0.1.0.md").read_text(encoding="utf-8").split()
        )

        self.assertIn("Experimental Docker `sandbox-run` add-on", content)
        self.assertIn("local-image-only Docker mode", content)
        self.assertIn("does not pull images automatically", content)
        self.assertIn("not a safety", content)
        self.assertIn("not unrestricted execution authorization", content)


if __name__ == "__main__":
    unittest.main()
