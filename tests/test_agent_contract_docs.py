from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
AGENT_CONTRACT = ROOT / "docs" / "agent-contract.md"
PUBLIC_CONTRACTS = ROOT / "docs" / "public-contracts.md"


class AgentContractDocsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.content = AGENT_CONTRACT.read_text(encoding="utf-8")
        cls.normalized = " ".join(cls.content.split())
        cls.flow = cls.content.split("## Canonical flow", 1)[1].split("## Exit contract", 1)[0]

    def test_canonical_flow_is_ordered_and_exit_zero_only(self) -> None:
        stages = (
            "real-scan --fail-on-degraded",
            "gate-check --external-evidence",
            "Human review / Human-controlled authorization",
            "sandbox-run --authorization",
            "gate-check --sandbox-evidence",
        )
        offsets = [self.flow.index(stage) for stage in stages]

        self.assertEqual(offsets, sorted(offsets))
        self.assertGreaterEqual(self.content.count("exit 0 only"), 3)
        self.assertIn("--fail-on-degraded", self.content)

    def test_every_nonzero_or_unknown_exit_stops(self) -> None:
        for marker in ("exit 0", "exit 1", "exit 2", "unknown"):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.content)

        self.assertIn("Exit 1, exit 2, or any unknown exit code means STOP.", self.content)
        self.assertIn("exit 0へ読み替えない", self.content)
        self.assertIn("target command自身のexit 2", self.content)

    def test_gate_and_human_authorization_are_separate(self) -> None:
        for phrase in (
            "gate decisionはexecution authorizationではない",
            "gate decisionの`execution_authorized`は`false`",
            "Human-controlled authorization",
            "agentやrepository自身がHuman approvalを生成または代行してはならない",
            "authorization draftは`approved=false`",
            "artifact discoveryはapprovalではない",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.normalized)

        self.assertIn("BLOCK、QUARANTINE、UNKNOWN", self.normalized)
        self.assertIn("authorizationで上書きできず", self.normalized)
        self.assertIn("gate decision fingerprintが 異なる場合には流用できない", self.normalized)

    def test_sandbox_is_the_only_execution_surface_and_evidence_returns(self) -> None:
        for phrase in (
            "repositoryに由来するcommandをhostで直接実行してはならない",
            "disposable workspace",
            "`--pull=never`",
            "default-deny network",
            "--evidence-output",
            "--sandbox-evidence",
            "successful_execution_is_not_safety",
            "次のcommandをauthorizationしない",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.content)

    def test_fail_closed_evidence_states_are_normative(self) -> None:
        for state in (
            "degraded",
            "invalid",
            "mismatch",
            "stale",
            "duplicate",
            "truncated",
            "over-budget",
        ):
            with self.subTest(state=state):
                self.assertIn(state, self.content)

        self.assertIn("fail-closed", self.content)
        self.assertIn("gate verdictを改善", self.content)

    def test_public_contract_matches_canonical_flow_and_exit_table(self) -> None:
        public_contract = PUBLIC_CONTRACTS.read_text(encoding="utf-8")
        normalized_public_contract = " ".join(public_contract.split())
        stages = (
            "real-scan --fail-on-degraded",
            "gate-check --external-evidence",
            "Human-controlled authorization",
            "sandbox-run --authorization",
            "gate-check --sandbox-evidence",
        )
        offsets = [normalized_public_contract.index(stage) for stage in stages]

        self.assertEqual(offsets, sorted(offsets))
        for marker in ("exit 0", "exit 1", "exit 2", "unknown"):
            with self.subTest(marker=marker):
                self.assertIn(f"| {marker} |", public_contract)
        self.assertIn("Exit 1, exit 2, or any unknown exit code means STOP.", public_contract)
        self.assertIn(
            "A gate decision remains separate from execution authorization.",
            normalized_public_contract,
        )


if __name__ == "__main__":
    unittest.main()
