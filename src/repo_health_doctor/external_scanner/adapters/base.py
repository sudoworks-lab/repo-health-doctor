"""Base models for external scanner adapter foundations.

Adapters in this package describe static capabilities, parse caller-supplied
synthetic data, and normalize evidence. They do not execute scanners.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExternalScannerAdapterCapability:
    scanner_name: str
    scanner_category: str
    supported_mode: str
    allowed_input_paths: tuple[str, ...]
    requires_network: bool
    executes_target_code: bool
    docker_needed: bool
    raw_output_retention: bool
    expected_output_kind: str
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]


@dataclass(frozen=True)
class ExternalScannerCommandPlan:
    argv: tuple[str, ...]
    execution_authorized: bool
    scanner_executed: bool
    network_allowed: bool
    target_code_execution_allowed: bool
    docker_allowed: bool
    raw_output_retention: bool
    requires_human_approval: bool
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "execution_authorized": self.execution_authorized,
            "scanner_executed": self.scanner_executed,
            "network_allowed": self.network_allowed,
            "target_code_execution_allowed": self.target_code_execution_allowed,
            "docker_allowed": self.docker_allowed,
            "raw_output_retention": self.raw_output_retention,
            "requires_human_approval": self.requires_human_approval,
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
        }
