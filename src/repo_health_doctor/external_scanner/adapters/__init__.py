"""External scanner adapter foundations.

These adapters normalize supplied evidence and build non-executing plans only.
They do not run scanners or authorize execution.
"""

from .base import ExternalScannerAdapterCapability, ExternalScannerCommandPlan
from .gitleaks_adapter import (
    GITLEAKS_SCANNER_NAME,
    GitleaksAdapter,
    GitleaksCommandResult,
    GitleaksExitInterpretation,
    GitleaksRunResult,
    build_gitleaks_scan_argv,
    default_gitleaks_adapter,
    interpret_gitleaks_exit_code,
    normalize_gitleaks_json_array,
    run_gitleaks_scan,
)
from .osv_scanner_adapter import (
    OSV_SCANNER_NAME,
    OsvScannerAdapter,
    OsvScannerCommandResult,
    OsvScannerExitInterpretation,
    OsvScannerRunResult,
    build_osv_scan_argv,
    default_osv_scanner_adapter,
    interpret_osv_exit_code,
    normalize_osv_json_object,
    run_osv_scan,
)
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
    "GITLEAKS_SCANNER_NAME",
    "GitleaksAdapter",
    "GitleaksCommandResult",
    "GitleaksExitInterpretation",
    "GitleaksRunResult",
    "OSV_SCANNER_NAME",
    "OsvScannerAdapter",
    "OsvScannerCommandResult",
    "OsvScannerExitInterpretation",
    "OsvScannerRunResult",
    "ZIZMOR_STYLE_OUTPUT_KIND",
    "ZIZMOR_STYLE_SCANNER_NAME",
    "ZizmorStyleAdapter",
    "ZizmorStyleFinding",
    "ZizmorStyleParsedOutput",
    "build_gitleaks_scan_argv",
    "build_osv_scan_argv",
    "default_gitleaks_adapter",
    "default_osv_scanner_adapter",
    "default_zizmor_style_adapter",
    "interpret_gitleaks_exit_code",
    "interpret_osv_exit_code",
    "normalize_gitleaks_json_array",
    "normalize_osv_json_object",
    "run_osv_scan",
    "run_gitleaks_scan",
]
