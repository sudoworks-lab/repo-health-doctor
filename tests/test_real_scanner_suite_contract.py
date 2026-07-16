from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

from repo_health_doctor.formatters import (
    format_real_scanner_suite_json,
    format_real_scanner_suite_markdown,
    format_real_scanner_suite_text,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "real-scanner-suite.schema.json"
GOLDEN_PATH = ROOT / "tests" / "fixtures" / "golden" / "real-scanner-suite.json"


class RealScannerSuiteContractTests(unittest.TestCase):
    def test_schema_and_golden_sample_are_valid(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))

        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(golden),
            key=lambda error: list(error.path),
        )
        self.assertEqual(errors, [])
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["execution_authorized"]["const"], False)

    def test_json_text_and_markdown_represent_the_same_bounded_report(self) -> None:
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))

        rendered_json = format_real_scanner_suite_json(golden)
        self.assertEqual(json.loads(rendered_json), golden)

        rendered_text = format_real_scanner_suite_text(golden)
        rendered_markdown = format_real_scanner_suite_markdown(golden)
        for scanner_name in ("gitleaks", "osv-scanner", "trivy"):
            with self.subTest(scanner=scanner_name):
                self.assertIn(scanner_name, rendered_text)
                self.assertIn(scanner_name, rendered_markdown)
        for rendered in (rendered_text, rendered_markdown):
            self.assertIn("degraded", rendered)
            self.assertIn("scanner_unavailable", rendered)
            self.assertIn("scanner_skipped_offline", rendered)
            self.assertIn("execution authorized", rendered.lower())

    def test_all_formatters_redact_raw_output_secret_like_values_and_private_paths(self) -> None:
        report = deepcopy(json.loads(GOLDEN_PATH.read_text(encoding="utf-8")))
        normalized = report["entries"][0]["normalized_result"]
        aws_like_value = "A" + "KIA" + "1" * 16
        github_like_value = "g" + "hp_" + "x" * 32
        private_path = "/" + "home" + "/alice/private/repository/secrets.txt"
        normalized.update(
            {
                "raw_output": "raw scanner output",
                "secret_like_value": aws_like_value,
                "token": github_like_value,
                "path": private_path,
            }
        )

        rendered = "\n".join(
            (
                format_real_scanner_suite_json(report),
                format_real_scanner_suite_text(report),
                format_real_scanner_suite_markdown(report),
            )
        )
        for forbidden in (
            "raw scanner output",
            aws_like_value,
            github_like_value,
            private_path,
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)
        self.assertIn("<redacted>", rendered)
        self.assertIn("<redacted-path>", rendered)


if __name__ == "__main__":
    unittest.main()
