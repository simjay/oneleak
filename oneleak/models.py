"""Core data models: Finding, ScanResult, SanitizedResult, Rule, and related types."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from re import Pattern


class Category(str, Enum):
    SECRET = "secret"
    PII = "pii"
    SENSITIVE = "sensitive"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER[Severity(severity)]


@dataclass(frozen=True)
class Finding:
    """A single scan result. Never carries the raw sensitive value."""

    rule_id: str
    category: str
    type: str
    severity: str

    start: int
    end: int

    path: str | None = None
    line: int | None = None
    column: int | None = None

    preview: str | None = None
    fingerprint: str | None = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return len(self.findings) == 0

    @property
    def risk(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)


@dataclass(frozen=True)
class MappingEntry:
    """Only ever produced when sanitize(..., reveal=True) is used. Carries a raw value."""

    value: str
    rule_id: str
    fingerprint: str | None = None


@dataclass
class SanitizedResult:
    text: str
    findings: list[Finding] = field(default_factory=list)
    mapping: dict[str, MappingEntry] | None = None


@dataclass(frozen=True)
class RuleMatch:
    """A raw candidate span found by a rule, before context/validation/priority resolution."""

    start: int
    end: int


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    type: str
    severity: str

    pattern: Pattern[str] | None = None
    keywords: tuple[str, ...] = ()

    validator: str | None = None

    # Higher wins when two rules match the same span. Provider-specific/structured
    # rules should rank above generic patterns, which rank above entropy-only rules.
    priority: int = 0


class PythonRule:
    """Base class for advanced, imperative detection logic.

    Subclasses must set id/category/type/severity as class attributes and
    implement detect(). Python rules are never auto-loaded from repository
    config — callers must pass instances explicitly to scan(rules=[...]).
    """

    id: str
    category: str
    type: str
    severity: str
    priority: int = 0

    def detect(self, text: str) -> Iterable[RuleMatch]:
        raise NotImplementedError
