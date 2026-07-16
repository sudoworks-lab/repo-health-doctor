from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DOCS_INDEX = ROOT / "docs" / "README.md"
QUICKSTART = ROOT / "docs" / "quickstart.md"
AI_AGENT_DOC = ROOT / "docs" / "ai-agent-preflight.md"
AGENT_CONTRACT = ROOT / "docs" / "agent-contract.md"
CODEX_DOC = ROOT / "docs" / "integration-codex.md"
CLAUDE_DOC = ROOT / "docs" / "integration-claude-code.md"
CURSOR_DOC = ROOT / "docs" / "integration-cursor.md"
PUBLIC_CONTRACTS = ROOT / "docs" / "public-contracts.md"
CHANGELOG = ROOT / "CHANGELOG.md"
DEMO_RUNBOOK = ROOT / "docs" / "demo-runbook.md"
SANDBOX_RUN = ROOT / "docs" / "sandbox-run.md"
SANDBOX_ROADMAP = ROOT / "docs" / "sandbox-roadmap.md"
DEMO_SCRIPT = ROOT / "scripts" / "demo_agent_preflight.py"
DEMO_SUPPLY_CHAIN = ROOT / "examples" / "demo-synthetic-supply-chain"
MARKDOWN_LINK = re.compile(r"\[[^]]+\]\(([^)]+)\)")


class AiAgentIntegrationDocsTests(unittest.TestCase):
    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return env

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

    def test_contract_docs_cross_link_and_all_local_links_resolve(self) -> None:
        central_docs = (README, DOCS_INDEX, PUBLIC_CONTRACTS, CHANGELOG)
        contract_names = (
            "agent-contract.md",
            "integration-codex.md",
            "integration-claude-code.md",
            "integration-cursor.md",
        )
        for path in central_docs:
            content = path.read_text(encoding="utf-8")
            for name in contract_names:
                with self.subTest(path=path.relative_to(ROOT), link=name):
                    self.assertIn(name, content)

        contract_content = AGENT_CONTRACT.read_text(encoding="utf-8")
        for binding in (CODEX_DOC, CLAUDE_DOC, CURSOR_DOC):
            with self.subTest(binding=binding.relative_to(ROOT)):
                self.assertIn(binding.name, contract_content)
                self.assertIn("agent-contract.md", binding.read_text(encoding="utf-8"))

        checked_docs = central_docs + (AGENT_CONTRACT, CODEX_DOC, CLAUDE_DOC, CURSOR_DOC)
        for path in checked_docs:
            for target in MARKDOWN_LINK.findall(path.read_text(encoding="utf-8")):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                local_target = target.split("#", 1)[0]
                if not local_target:
                    continue
                with self.subTest(path=path.relative_to(ROOT), target=target):
                    self.assertTrue((path.parent / local_target).resolve().is_file())

    def test_documented_plan_only_smoke_does_not_execute_target_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "target-command-ran.txt"
            target = tmp_path / "display-only-target"
            target.write_text(f"#!/bin/sh\nprintf ran > {marker}\n", encoding="utf-8")
            target.chmod(target.stat().st_mode | stat.S_IXUSR)

            result = subprocess.run(
                [
                    sys.executable,
                    str(DEMO_SCRIPT),
                    str(DEMO_SUPPLY_CHAIN),
                    "--",
                    str(target),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=self._env(),
            )
            marker_exists = marker.exists()

        self.assertEqual(result.returncode, 2)
        self.assertIn("Intended target command (display only): <path>", result.stdout)
        self.assertIn("Target command executed: false", result.stdout)
        self.assertFalse(marker_exists)


if __name__ == "__main__":
    unittest.main()
