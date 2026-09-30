"""Static analysis of MCP tool metadata."""

from .detector import Finding, Severity, ShadowingDetector, has_high_severity
from .pin import PinStore, PinViolation, diff_tools

__all__ = [
    "Finding",
    "Severity",
    "ShadowingDetector",
    "has_high_severity",
    "PinStore",
    "PinViolation",
    "diff_tools",
]
