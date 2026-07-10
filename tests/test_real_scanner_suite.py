from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest import mock

from repo_health_doctor.external_scanner import (
    REAL_SCANNER_ADAPTER_NAMES,
    REAL_SCANNER_SUITE_LIMITATIONS,
    default_real_scanner_adapters,
    real_scanner_capabilities,
    real_scanner_inventory,
    run_gitleaks_scan,
    run_osv_scan,
    run_trivy_scan,
)
from repo_health_doctor.external_scanner.adapters import gitleaks_adapter, osv_scanner_adapter, trivy_adapter


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


class RealScannerSuiteTests(unittest.TestCase):
    def test_public_exports_list_three_real_adapters(self) -> None:
        self.assertEqual(REAL_SCANNER_ADAPTER_NAMES, ("gitleaks", "osv-scanner", "trivy"))

        adapters = default_real_scanner_adapters()
        capabilities = real_scanner_capabilities()

        self.assertEqual(tuple(adapter.capability().scanner_name for adapter in adapters), REAL_SCANNER_ADAPTER_NAMES)
        self.assertEqual(tuple(capability.scanner_name for capability in capabilities), REAL_SCANNER_ADAPTER_NAMES)

    def test_capability_inventory_keeps_common_fail_closed_contract(self) -> None:
        inventory = real_scanner_inventory()
        by_name = {str(item["scanner_name"]): item for item in inventory}

        self.assertEqual(tuple(by_name), REAL_SCANNER_ADAPTER_NAMES)
        self.assertIn("scanner_unavailable_is_fail_closed_not_pass", REAL_SCANNER_SUITE_LIMITATIONS)
        self.assertIn("no_findings_not_safety_proof", REAL_SCANNER_SUITE_LIMITATIONS)

        for item in inventory:
            with self.subTest(scanner=item["scanner_name"]):
                self.assertFalse(item["default_cli_execution"])
                self.assertFalse(item["executes_target_code"])
                self.assertFalse(item["docker_needed"])
                self.assertFalse(item["raw_output_retention"])
                self.assertEqual(item["unavailable_result"], "fail_closed_unknown_not_pass")
                self.assertEqual(item["no_findings_result"], "limited_evidence_not_safety_proof")
                self.assertIn("raw_output_not_retained", item["limitations"])

        self.assertFalse(by_name["gitleaks"]["requires_network"])
        self.assertTrue(by_name["osv-scanner"]["requires_network"])
        self.assertTrue(by_name["trivy"]["requires_network"])
        json.dumps(inventory, sort_keys=True)

    def test_unavailable_real_scanners_are_fail_closed_not_pass(self) -> None:
        def missing_runner(argv, timeout_seconds):
            del timeout_seconds
            raise FileNotFoundError(str(tuple(argv)))

        cases = (
            ("gitleaks", run_gitleaks_scan, gitleaks_adapter),
            ("osv-scanner", run_osv_scan, osv_scanner_adapter),
            ("trivy", run_trivy_scan, trivy_adapter),
        )
        for scanner_name, run_scan, adapter_module in cases:
            with self.subTest(scanner=scanner_name):
                with mock.patch.object(adapter_module, "_repo_commit_and_dirty_state", return_value=("a" * 40, "clean")):
                    result = run_scan(ROOT, runner=missing_runner)

                normalized = result.normalized_result
                self.assertFalse(result.valid)
                self.assertFalse(result.scanner_executed)
                self.assertIn("scanner_unavailable", result.blocking_errors)
                self.assertEqual(normalized["summary"]["outcome"], "unknown")  # type: ignore[index]
                self.assertFalse(normalized["execution_authorized"])
                self.assertFalse(normalized["mapping_result"]["risk_lowering_allowed"])  # type: ignore[index]
                self.assertIn("quarantine", normalized["mapping_result"]["gate_effects"])  # type: ignore[index]

    def test_public_docs_present_real_scanner_suite_and_limits(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        docs_index = (DOCS / "README.md").read_text(encoding="utf-8")
        suite_doc = (DOCS / "real-scanner-suite.md").read_text(encoding="utf-8")
        combined = "\n".join((readme, docs_index, suite_doc))
        combined_lower = combined.lower()

        for name in ("Gitleaks", "OSV-Scanner", "Trivy"):
            with self.subTest(scanner=name):
                self.assertIn(name, readme)
                self.assertIn(name, docs_index)
                self.assertIn(name, suite_doc)

        self.assertIn("No findings is not proof of safety", combined)
        for phrase in (
            "scanner unavailable is fail-closed",
            "network",
            "cache",
            "privacy",
            "raw scanner report",
        ):
            self.assertIn(phrase, combined_lower)

        for compatibility_doc in (
            "real-gitleaks-compatibility.md",
            "real-osv-compatibility.md",
            "real-trivy-compatibility.md",
        ):
            self.assertIn(compatibility_doc, docs_index)
            self.assertIn(compatibility_doc, suite_doc)

    def test_public_docs_do_not_contain_private_path_or_token_like_examples(self) -> None:
        docs_payload = "\n".join(
            [
                (ROOT / "README.md").read_text(encoding="utf-8"),
                (DOCS / "real-scanner-suite.md").read_text(encoding="utf-8"),
            ]
        )
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
                self.assertNotIn(pattern, docs_payload)


if __name__ == "__main__":
    unittest.main()
