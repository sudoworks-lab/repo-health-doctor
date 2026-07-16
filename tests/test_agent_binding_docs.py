from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PACKET = ROOT / "docs" / "human-review" / "agent-binding-official-sources.md"
DOCS = {
    "codex": ROOT / "docs" / "integration-codex.md",
    "claude-code": ROOT / "docs" / "integration-claude-code.md",
    "cursor": ROOT / "docs" / "integration-cursor.md",
}


class AgentBindingDocsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packet = SOURCE_PACKET.read_text(encoding="utf-8")
        cls.contents = {
            name: path.read_text(encoding="utf-8") for name, path in DOCS.items()
        }

    def test_human_source_packet_and_offline_provenance_are_recorded(self) -> None:
        self.assertTrue(SOURCE_PACKET.is_file())
        self.assertIn("verified_at: 2026-07-16 JST", self.packet)
        self.assertIn("network_contract: Goal Loop iteration中はnetwork accessを行わない", self.packet)

        for name, content in self.contents.items():
            with self.subTest(doc=name):
                self.assertIn("verified-as-of: 2026-07-16 JST", content)
                self.assertIn("human-review/agent-binding-official-sources.md", content)
                self.assertIn("offline", content)
                self.assertIn("network access", content)
                self.assertIn("## 確認済み事項", content)
                self.assertIn("## 未確認事項", content)

    def test_codex_uses_only_confirmed_agents_md_binding(self) -> None:
        content = self.contents["codex"]
        self.assertIn("https://developers.openai.com/codex/guides/agents-md", content)
        for fact in (
            "global scopeとproject scope",
            "project rootからcurrent directory",
            "current directoryに近いinstructionが後段",
            "AGENTS.mdはinstruction surface",
        ):
            with self.subTest(fact=fact):
                self.assertIn(fact, content)

        self.assertIn("強制hookとは確認していない", content)
        self.assertIn("instruction-based limitation", content.lower())
        self.assertNotIn("AGENTS.mdがtool callをblockする", content)

    def test_claude_pretooluse_exit_contract_matches_packet(self) -> None:
        content = self.contents["claude-code"]
        self.assertIn("https://code.claude.com/docs/en/hooks", content)
        for fact in (
            "`PreToolUse`はtool parameter作成後、tool call処理前",
            "`allow`、`deny`、`ask`、`defer`",
            "exit 2はtool callをblock",
            "exit 1はnon-blocking error",
            "exit 0とJSON output",
            "eventごとにexit behaviorが異なる",
        ):
            with self.subTest(fact=fact):
                self.assertIn(fact, content)

        self.assertIn("Humanが別途reviewする", content.replace("\n", ""))
        self.assertNotIn("exit 1をblocking errorとして扱う", content)

    def test_cursor_keeps_unconfirmed_enforcement_details_unconfirmed(self) -> None:
        content = self.contents["cursor"]
        for url in (
            "https://cursor.com/docs/rules",
            "https://cursor.com/docs/hooks",
            "https://cursor.com/docs/cli/overview",
        ):
            with self.subTest(url=url):
                self.assertIn(url, content)

        unconfirmed = content.split("## 未確認事項", 1)[1].split(
            "## Instruction-based limitation", 1
        )[0]
        for item in (
            "hook event名",
            "decision schema",
            "exit codeによるblock契約",
            "project ruleだけでcommand実行を技術的に停止できるか",
            "non-interactive CLIでの強制契約",
        ):
            with self.subTest(item=item):
                self.assertIn(item, unconfirmed)

        self.assertIn("instruction-based limitation", content.lower())
        self.assertNotIn("PreToolUse", content)
        self.assertNotIn("exit 2はtool callをblock", content)

    def test_missing_confirmed_enforcement_is_an_instruction_limitation(self) -> None:
        for name in ("codex", "cursor"):
            with self.subTest(doc=name):
                limitation = self.contents[name].split(
                    "## Instruction-based limitation", 1
                )[1]
                self.assertIn("instruction-based", limitation)
                self.assertIn("強制", limitation)


if __name__ == "__main__":
    unittest.main()
