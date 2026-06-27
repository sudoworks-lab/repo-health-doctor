from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.gate import evaluate_gate_decision, validate_gate_decision


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "gate-evaluator"
FORBIDDEN_PATTERNS = (
    "/home/",
    "/Users/",
    "C:\\Users\\",
    ".ssh",
    ".aws",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "AKIA",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "sk-",
    "-----BEGIN",
    "password=",
    "token=",
)


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _evidence(
    *,
    evidence_id: str = "ev-test",
    category: str = "repo_posture",
    subcategory: str = "trusted_static_evidence",
    severity: str = "info",
    finding_present: bool = True,
    finding_count: int = 1,
    trust_level: str = "commit_bound",
    binding_kind: str = "commit_bound",
    limitations: list[str] | None = None,
    residual_risks: list[str] | None = None,
    recommended_gate_effect: str = "allow_limited",
) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "schema_version": "0.1-draft",
        "evidence_kind": "repo_health_evidence",
        "source": {
            "tool_name": "repo-health-doctor",
            "tool_version": "0.1.0",
            "adapter_name": "unit-test",
            "adapter_version": "0.1-draft",
            "execution_mode": "native_static",
        },
        "subject": {
            "repo_identity": "<repo>",
            "commit": "abc123",
            "tree_hash": None,
            "path_scope": ["<repo>"],
            "binding_kind": binding_kind,
        },
        "classification": {
            "category": category,
            "subcategory": subcategory,
            "severity": severity,
            "confidence": "medium",
            "confidence_reason": "safe synthetic gate evaluator fixture",
        },
        "finding": {
            "present": finding_present,
            "count": finding_count,
            "locations": [{"path": "<repo>/path/to/file", "line": None}] if finding_present else [],
            "redacted_summary": subcategory,
        },
        "raw_handling": {
            "raw_output_retained": False,
            "raw_stdout_retained": False,
            "raw_stderr_retained": False,
            "redaction_status": "validated",
            "redaction_failures": [],
        },
        "trust": {
            "level": trust_level,
            "commit_bound": binding_kind == "commit_bound",
            "signature_verified": False,
            "binary_attested": False,
            "limitations": limitations or ["low residual uncertainty", "not_execution_authorization"],
        },
        "effects": {
            "can_lower_risk": False,
            "can_authorize_execution": False,
            "recommended_gate_effect": recommended_gate_effect,
        },
        "residual_risks": residual_risks or ["synthetic_fixture_not_safety_proof"],
    }


class GateEvaluatorTests(unittest.TestCase):
    def test_allow_limited_but_not_authorized(self) -> None:
        fixture = _fixture("allow_limited_but_not_authorized.json")
        result = evaluate_gate_decision([_evidence()])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])
        self.assertFalse(result.decision["execution_authorized"])
        self.assertIn("explanation", result.decision)
        self.assertTrue(validate_gate_decision(result.decision).valid)

    def test_no_findings_with_observer_degraded_is_not_allow_limited(self) -> None:
        fixture = _fixture("no_findings_but_observer_degraded.json")
        result = evaluate_gate_decision([
            _evidence(
                finding_present=False,
                finding_count=0,
                limitations=["runtime observer degraded", "not_execution_authorization"],
            )
        ])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])
        self.assertFalse(result.decision["execution_authorized"])
        self.assertIn("No scanner finding is not proof of safety.", result.decision["explanation"]["key_reasons"])
        self.assertIn("Runtime or observer evidence is missing or degraded.", result.decision["explanation"]["key_reasons"])
        self.assertIn("The gate cannot authorize execution from scanner silence alone.", result.decision["explanation"]["key_reasons"])

    def test_supply_chain_shape_gets_contextual_explanation(self) -> None:
        result = evaluate_gate_decision([
            _evidence(
                category="runtime_behavior",
                subcategory="synthetic_supply_chain_attack_shape",
                severity="warn",
                finding_count=6,
                trust_level="redaction_validated",
                binding_kind="synthetic",
                limitations=["synthetic fixture only; not real malware", "not_execution_authorization"],
                residual_risks=[
                    "install_script_execution",
                    "package_lifecycle_hook",
                    "credential_path_reference",
                    "environment_access_candidate",
                    "network_request",
                    "network_target_string",
                    "workflow_modification",
                    "pull_request_target_misuse",
                    "untrusted_checkout",
                    "obfuscation",
                    "dynamic_eval",
                ],
                recommended_gate_effect="quarantine",
            )
        ])

        self.assertEqual(result.decision["verdict"], "quarantine")
        self.assertFalse(result.decision["execution_authorized"])
        reasons = result.decision["explanation"]["key_reasons"]
        actions = result.decision["explanation"]["next_actions"]
        self.assertIn("A package install hook or postinstall-like script is present.", reasons)
        self.assertIn("Credential-path or environment-access patterns are present.", reasons)
        self.assertIn("An outbound network target or network-attempt string is present.", reasons)
        self.assertIn("Workflow write-risk or GitHub Actions token-abuse-like behavior is present.", reasons)
        self.assertIn("Obfuscation or dynamic eval-like code is present.", reasons)
        self.assertIn("Do not run install scripts locally.", actions)
        self.assertIn("Review the install script and workflow changes.", actions)

    def test_no_evidence_is_unknown(self) -> None:
        fixture = _fixture("no_evidence_unknown.json")
        result = evaluate_gate_decision([])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])
        self.assertFalse(result.decision["execution_authorized"])

    def test_raw_secret_leak_blocks(self) -> None:
        fixture = _fixture("raw_secret_leak_block.json")
        result = evaluate_gate_decision([
            _evidence(category="secret", subcategory="raw_secret_leak", severity="block", recommended_gate_effect="requires_human_review")
        ])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])

    def test_raw_output_retained_blocks(self) -> None:
        fixture = _fixture("raw_output_retained_block.json")
        evidence = _evidence()
        evidence["raw_handling"]["raw_output_retained"] = True  # type: ignore[index]
        result = evaluate_gate_decision([evidence])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])
        self.assertIn("Raw scanner output retention or redaction failure blocks safe reporting.", result.decision["explanation"]["key_reasons"])

    def test_verified_secret_quarantines(self) -> None:
        fixture = _fixture("verified_secret_quarantine.json")
        result = evaluate_gate_decision([
            _evidence(category="secret", subcategory="verified_secret", severity="block", recommended_gate_effect="quarantine")
        ])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])

    def test_ci_token_abuse_chain_quarantines(self) -> None:
        fixture = _fixture("ci_token_abuse_quarantine.json")
        result = evaluate_gate_decision([
            _evidence(category="ci_cd", subcategory="ci_token_abuse_chain", severity="block", recommended_gate_effect="quarantine")
        ])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])

    def test_pull_request_target_untrusted_quarantines(self) -> None:
        fixture = _fixture("pull_request_target_untrusted_quarantine.json")
        result = evaluate_gate_decision([
            _evidence(category="ci_cd", subcategory="pull_request_target_misuse untrusted_checkout", severity="block", recommended_gate_effect="quarantine")
        ])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])

    def test_missing_gitleaks_warns(self) -> None:
        fixture = _fixture("missing_gitleaks_warn.json")
        result = evaluate_gate_decision([_evidence()], policy={"policy_version": "test", "fail_closed": True, "missing_evidence": ["gitleaks"]})
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])
        self.assertIn("gitleaks", result.decision["evidence_summary"]["missing_evidence"])

    def test_missing_runtime_observer_for_dynamic_judgment_quarantines(self) -> None:
        fixture = _fixture("missing_runtime_observer_quarantine.json")
        result = evaluate_gate_decision(
            [_evidence()],
            policy={
                "policy_version": "test",
                "fail_closed": True,
                "missing_evidence": ["runtime-observer"],
                "requested_dynamic_judgment": True,
            },
        )
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])

    def test_commit_mismatch_blocks(self) -> None:
        fixture = _fixture("commit_mismatch_block.json")
        result = evaluate_gate_decision([_evidence(limitations=["expected commit mismatch", "not_execution_authorization"])])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])

    def test_low_trust_no_finding_warns(self) -> None:
        fixture = _fixture("low_trust_no_finding_warn.json")
        result = evaluate_gate_decision([
            _evidence(finding_present=False, finding_count=0, trust_level="untrusted_import", binding_kind="synthetic")
        ])
        self.assertEqual(result.decision["verdict"], fixture["expected_verdict"])
        self.assertFalse(result.decision["execution_authorized"])

    def test_evidence_can_authorize_execution_blocks(self) -> None:
        evidence = _evidence()
        evidence["effects"]["can_authorize_execution"] = True  # type: ignore[index]
        result = evaluate_gate_decision([evidence])
        self.assertEqual(result.decision["verdict"], "block")
        self.assertFalse(result.decision["execution_authorized"])

    def test_evidence_execution_authorized_field_blocks(self) -> None:
        evidence = _evidence()
        evidence["execution_authorized"] = True
        result = evaluate_gate_decision([evidence])
        self.assertEqual(result.decision["verdict"], "block")
        self.assertFalse(result.decision["execution_authorized"])

    def test_fixture_and_result_leak_safety(self) -> None:
        payloads = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(FIXTURES.glob("*.json"))]
        payloads.append(evaluate_gate_decision([_evidence()]).decision)
        rendered = json.dumps(payloads, sort_keys=True)
        for pattern in FORBIDDEN_PATTERNS:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, rendered)


if __name__ == "__main__":
    unittest.main()
