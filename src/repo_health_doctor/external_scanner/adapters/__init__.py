"""External scanner adapter foundations.

These adapters normalize supplied evidence and build non-executing plans only.
They do not run scanners or authorize execution.
"""

from .base import ExternalScannerAdapterCapability, ExternalScannerCommandPlan
from .zizmor_adapter import (
    ZIZMOR_STYLE_SCANNER_NAME,
    ZIZMOR_STYLE_OUTPUT_KIND,
    ZizmorStyleAdapter,
    ZizmorStyleFinding,
    ZizmorStyleParsedOutput,
    default_zizmor_style_adapter,
)

__all__ = [
    "ExternalScannerAdapterCapability",
    "ExternalScannerCommandPlan",
    "ZIZMOR_STYLE_OUTPUT_KIND",
    "ZIZMOR_STYLE_SCANNER_NAME",
    "ZizmorStyleAdapter",
    "ZizmorStyleFinding",
    "ZizmorStyleParsedOutput",
    "default_zizmor_style_adapter",
]
