"""oneleaks: a lightweight, pure-Python sensitive-data scanner and sanitizer."""

from oneleaks import git
from oneleaks.config import Config
from oneleaks.errors import ConfigError, OneleaksError, ScanError
from oneleaks.models import (
    Category,
    Finding,
    MappingEntry,
    PythonRule,
    Rule,
    RuleMatch,
    SanitizedResult,
    ScanResult,
    Severity,
)
from oneleaks.sanitizer import desanitize, sanitize
from oneleaks.scanner import scan

__version__ = "0.1.0"

__all__ = [
    "Category",
    "Config",
    "ConfigError",
    "Finding",
    "MappingEntry",
    "OneleaksError",
    "PythonRule",
    "Rule",
    "RuleMatch",
    "SanitizedResult",
    "ScanError",
    "ScanResult",
    "Severity",
    "desanitize",
    "git",
    "sanitize",
    "scan",
]
