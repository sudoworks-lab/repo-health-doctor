"""Data models for evidence validation results."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceValidationResult:
    valid: bool
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    limitations: tuple[str, ...]
    residual_risks: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "limitations": list(self.limitations),
            "residual_risks": list(self.residual_risks),
        }
