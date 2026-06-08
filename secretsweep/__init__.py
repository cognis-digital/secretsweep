"""SECRETSWEEP - repo secret scanner + auto-rotator across providers.

Standard-library only. Zero install. Real detection + redaction logic.
"""
from .core import (
    Detector,
    Finding,
    DETECTORS,
    scan_text,
    scan_path,
    redact,
    rotation_plan,
    shannon_entropy,
)

TOOL_NAME = "secretsweep"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Detector",
    "Finding",
    "DETECTORS",
    "scan_text",
    "scan_path",
    "redact",
    "rotation_plan",
    "shannon_entropy",
]
