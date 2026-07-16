#!/usr/bin/env python3
"""Regenerate bounded expected evidence from reviewed Trivy fixtures.

This script never runs a scanner and never reads raw scanner output. Scanner
acquisition and raw-output collection remain separate Human-approved steps.
Only a manually reviewed, redacted fixture committed under tests/fixtures may
be used as input here.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from repo_health_doctor.external_scanner import (  # noqa: E402
    assess_trivy_version,
    normalize_trivy_json_object,
    validate_external_scanner_result,
)


TRIVY_FIXTURE_DIR = ROOT / "tests" / "fixtures" / "real-scanners" / "trivy"
TRIVY_REDACTED_FIXTURE = TRIVY_FIXTURE_DIR / "licenses-redacted.real.json"
TRIVY_EXPECTED_EVIDENCE = TRIVY_FIXTURE_DIR / "expected-evidence.json"
TRIVY_VERSION_RECORD = TRIVY_FIXTURE_DIR / "trivy-version.txt"
SYNTHETIC_COMMIT = "0" * 40


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _trivy_expected_evidence() -> dict[str, object]:
    version_record = TRIVY_VERSION_RECORD.read_text(encoding="utf-8")
    version = assess_trivy_version(version_record, "")
    if not version.supported_for_live_scan or version.version == "unknown":
        raise ValueError("the recorded Trivy fixture version is not accepted")

    normalized = normalize_trivy_json_object(
        _load_json(TRIVY_REDACTED_FIXTURE),
        scanner_version=version.version,
        repo_commit=SYNTHETIC_COMMIT,
        dirty_state="clean",
    )
    validation = validate_external_scanner_result(normalized)
    if not validation.valid:
        raise ValueError("the redacted Trivy fixture does not produce valid evidence")

    findings = normalized.get("findings")
    if not isinstance(findings, list) or len(findings) != 1 or not isinstance(findings[0], Mapping):
        raise ValueError("the redacted Trivy fixture must produce exactly one finding")
    finding = findings[0]
    summary = normalized["summary"]
    mapping_result = normalized["mapping_result"]
    redaction_status = normalized["redaction_status"]
    execution_context = normalized["execution_context"]
    if not all(isinstance(item, Mapping) for item in (summary, mapping_result, redaction_status, execution_context)):
        raise ValueError("the normalized Trivy evidence has an unexpected shape")

    return {
        "license": {
            "expected_count": len(findings),
            "outcome": summary["outcome"],
            "primary_category": finding["primary_category"],
            "secondary_category": finding["secondary_category"],
            "scanner_rule_id": finding["scanner_rule_id"],
            "scanner_severity": finding["scanner_severity"],
            "normalized_severity": finding["normalized_severity"],
            "gate_effect": finding["gate_effect"],
            "redaction_validated": redaction_status["redaction_validated"],
            "raw_scanner_output_included": redaction_status["raw_scanner_output_included"],
            "raw_output_retained": execution_context["raw_output_retained"],
            "risk_lowering_allowed": mapping_result["risk_lowering_allowed"],
            "execution_authorized": normalized["execution_authorized"],
        }
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Regenerate expected evidence from a reviewed redacted real-scanner fixture.",
    )
    parser.add_argument("--scanner", choices=("trivy",), required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="fail if committed expected evidence is stale")
    action.add_argument("--write", action="store_true", help="replace only the committed expected-evidence file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.scanner != "trivy":
        return 2

    expected = _trivy_expected_evidence()
    rendered = json.dumps(expected, indent=2, sort_keys=True) + "\n"
    if args.check:
        current = json.dumps(_load_json(TRIVY_EXPECTED_EVIDENCE), indent=2, sort_keys=True) + "\n"
        if current != rendered:
            print("Trivy expected evidence is stale.", file=sys.stderr)
            return 1
        print("Trivy expected evidence is current.")
        return 0

    TRIVY_EXPECTED_EVIDENCE.write_text(rendered, encoding="utf-8")
    print("Updated the reviewed Trivy expected-evidence fixture.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
