"""`.oneleak.yaml` loading. Unknown top-level fields are a hard error."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from oneleak.errors import ConfigError
from oneleak.models import Severity

_KNOWN_TOP_LEVEL_KEYS = {
    "version",
    "exclude",
    "pii",
    "rule_paths",
    "allow",
    "disabled_rules",
    "severity_overrides",
}

_KNOWN_PII_KEYS = {"email", "phone", "ssn", "credit_card", "ipv4", "ipv6", "iban"}
_KNOWN_SEVERITIES = {s.value for s in Severity}


@dataclass
class Config:
    version: int = 1
    exclude: list[str] = field(default_factory=list)
    pii: dict[str, bool] = field(default_factory=dict)
    rule_paths: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)


def _validate_top_level(data: dict, source: str) -> None:
    unknown = set(data) - _KNOWN_TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"{source}: unknown config field(s): {', '.join(sorted(unknown))}")


def _validate_pii(pii: dict, source: str) -> None:
    unknown = set(pii) - _KNOWN_PII_KEYS
    if unknown:
        raise ConfigError(f"{source}: unknown pii detector(s): {', '.join(sorted(unknown))}")


def _validate_severity_overrides(overrides: dict, source: str) -> None:
    invalid = {v for v in overrides.values() if v not in _KNOWN_SEVERITIES}
    if invalid:
        raise ConfigError(
            f"{source}: unknown severity in severity_overrides: {', '.join(sorted(invalid))}"
        )


def parse_config(text: str, source: str = "<config>") -> Config:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a YAML mapping at the top level")
    _validate_top_level(data, source)

    pii = data.get("pii", {}) or {}
    _validate_pii(pii, source)

    severity_overrides = dict(data.get("severity_overrides", {}) or {})
    _validate_severity_overrides(severity_overrides, source)

    allow = data.get("allow", {}) or {}

    return Config(
        version=data.get("version", 1),
        exclude=list(data.get("exclude", []) or []),
        pii=dict(pii),
        rule_paths=list(data.get("rule_paths", []) or []),
        allow_paths=list(allow.get("paths", []) or []),
        disabled_rules=list(data.get("disabled_rules", []) or []),
        severity_overrides=severity_overrides,
    )


def load_config(path: str | Path) -> Config:
    path = Path(path)
    return parse_config(path.read_text(encoding="utf-8"), source=str(path))


DEFAULT_CONFIG_FILENAME = ".oneleak.yaml"


def discover_config(start: Path | None = None) -> Config | None:
    """Look for `.oneleak.yaml` in `start` (default: cwd). Used by the CLI only --
    the Python API never auto-loads config, to keep library calls side-effect-free.
    """
    base = start or Path.cwd()
    candidate = base / DEFAULT_CONFIG_FILENAME
    if candidate.is_file():
        return load_config(candidate)
    return None
