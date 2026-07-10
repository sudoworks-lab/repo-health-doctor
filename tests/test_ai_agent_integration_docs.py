from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DOCS_INDEX = ROOT / "docs" / "README.md"
QUICKSTART = ROOT / "docs" / "quickstart.md"
AI_AGENT_DOC = ROOT / "docs" / "ai-agent-preflight.md"
CLAUDE_DOC = ROOT / "docs" / "integration-claude-code.md"
DEMO_RUNBOOK = ROOT / "docs" / "demo-runbook.md"
SANDBOX_RUN = ROOT / "docs" / "sandbox-run.md"
SANDBOX_ROADMAP = ROOT / "docs" / "sandbox-roadmap.md"


class AiAgentIntegrationDocsTests(unittest.TestCase):
    def test_readme_quickstart_and_docs_index_route_to_ai_agent_preflight(self) -> None:
        for path in (README, DOCS_INDEX, QUICKSTART, DEMO_RUNBOOK):
            with self.subTest(path=path.relative_to(ROOT)):
                content = path.read_text(encoding="utf-8")
                self.assertIn("ai-agent-preflight.md", content)
                self.assertIn("scripts/demo_agent_preflight.py", content)

    def test_ai_agent_doc_states_non_execution_and_future_hook_scope(self) -> None:
        content = AI_AGENT_DOC.read_text(encoding="utf-8")
        normalized_content = " ".join(content.split())

        for phrase in (
            "does not run the target command",
            "do not run the target command",
            "does not change global agent configuration",
            "does not modify Claude Code, Codex, Cursor, MCP, or hook settings",
            "Real hook integration is future scope",
            "No findings is not proof of safety",
            "Scanner unavailable is not PASS",
            "No evidence is not PASS",
            "A gate decision is a review result, not permission",
            "Gitleaks",
            "OSV-Scanner",
            "Trivy",
            "network, cache, and privacy limitations",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, normalized_content)

    def test_claude_integration_points_to_plan_only_demo_before_hooks(self) -> None:
        content = CLAUDE_DOC.read_text(encoding="utf-8")
        content_lower = content.lower()

        self.assertIn("Start with the plan-only AI agent demo", content)
        self.assertIn("never executes the target command", content)
        self.assertIn("Project-Local PreToolUse Sketch", content)
        self.assertIn("do not change global claude code configuration", content_lower)

    def test_docs_do_not_claim_hooks_are_installed_or_global_config_changed(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (AI_AGENT_DOC, CLAUDE_DOC, QUICKSTART, README, SANDBOX_RUN, SANDBOX_ROADMAP)
        )

        forbidden_claims = (
            "AI-agent-safe",
            "installs a hook",
            "updates global config",
            "changes global config",
            "automatically configures Claude Code",
            "automatically configures Codex",
            "automatically configures Cursor",
            "proves the repository is safe",
            "fully prevents malicious repositories",
        )
        for phrase in forbidden_claims:
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, combined)

    def test_new_docs_do_not_contain_private_path_or_local_ip_examples(self) -> None:
        combined = "\n".join(path.read_text(encoding="utf-8") for path in (AI_AGENT_DOC, DEMO_RUNBOOK, README, QUICKSTART))
        forbidden = (
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

        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, combined)


if __name__ == "__main__":
    unittest.main()
