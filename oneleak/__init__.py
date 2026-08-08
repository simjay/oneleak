"""oneleak: a lightweight, pure-Python sensitive-data scanner and sanitizer."""

from oneleak import git
from oneleak.errors import ConfigError, OneleakError, ScanError
from oneleak.models import (
    Category,
    Finding,
    MappingEntry,
    PythonRule,
    Rule,
    SanitizedResult,
    ScanResult,
    Severity,
)
from oneleak.sanitizer import desanitize, sanitize
from oneleak.scanner import scan

__version__ = "0.1.0"

__all__ = [
    "Category",
    "ConfigError",
    "Finding",
    "MappingEntry",
    "OneleakError",
    "PythonRule",
    "Rule",
    "SanitizedResult",
    "ScanError",
    "ScanResult",
    "Severity",
    "desanitize",
    "git",
    "sanitize",
    "scan",
]
