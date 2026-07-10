"""Real external scanner suite inventory.

This module exposes the implemented real scanner adapters as a static
capability inventory. Importing it does not execute scanners, contact a
network, create caches, or read scanner reports.
"""

from __future__ import annotations

from typing import Mapping

from .adapters import (
    ExternalScannerAdapterCapability,
    default_gitleaks_adapter,
    default_osv_scanner_adapter,
    default_trivy_adapter,
)


REAL_SCANNER_ADAPTER_NAMES = ("gitleaks", "osv-scanner", "trivy")

REAL_SCANNER_SUITE_LIMITATIONS = (
    "real_scanner_execution_is_explicit_not_default_cli",
    "scanner_unavailable_is_fail_closed_not_pass",
    "no_findings_not_safety_proof",
    "raw_scanner_output_not_retained",
    "network_cache_and_privacy_limitations_apply",
)


def default_real_scanner_adapters() -> tuple[object, ...]:
    return (
        default_gitleaks_adapter(),
        default_osv_scanner_adapter(),
        default_trivy_adapter(),
    )


def real_scanner_capabilities() -> tuple[ExternalScannerAdapterCapability, ...]:
    return tuple(adapter.capability() for adapter in default_real_scanner_adapters())


def real_scanner_inventory() -> tuple[Mapping[str, object], ...]:
    return tuple(_inventory_item(capability) for capability in real_scanner_capabilities())


def _inventory_item(capability: ExternalScannerAdapterCapability) -> Mapping[str, object]:
    return {
        "scanner_name": capability.scanner_name,
        "scanner_category": capability.scanner_category,
        "supported_mode": capability.supported_mode,
        "allowed_input_paths": list(capability.allowed_input_paths),
        "requires_network": capability.requires_network,
        "executes_target_code": capability.executes_target_code,
        "docker_needed": capability.docker_needed,
        "raw_output_retention": capability.raw_output_retention,
        "expected_output_kind": capability.expected_output_kind,
        "default_cli_execution": False,
        "unavailable_result": "fail_closed_unknown_not_pass",
        "no_findings_result": "limited_evidence_not_safety_proof",
        "limitations": list(capability.limitations),
        "residual_risks": list(capability.residual_risks),
    }
