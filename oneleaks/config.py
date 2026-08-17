"""`.oneleaks.yaml` loading. Unknown top-level fields are a hard error."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

from oneleaks.errors import ConfigError, read_text_file, yaml_error_detail
from oneleaks.models import Severity
from oneleaks.pii_rules import known_types as known_pii_types

_KNOWN_TOP_LEVEL_KEYS = {
    "version",
    "exclude",
    "pii",
    "rule_paths",
    "allow",
    "disabled_rules",
    "severity_overrides",
}

_KNOWN_SEVERITIES = {s.value for s in Severity}

# The only schema this build understands. A config claiming a different one was
# written for a oneleaks that reads fields differently, so running it under
# these rules would apply settings the author never asked for. Baseline files
# are checked the same way, in baseline.py.
CONFIG_VERSION = 1


@dataclass
class Config:
    """Parsed `.oneleaks.yaml`, or construct one directly to pass to
    `scan(config=...)` without a YAML file. `allow_paths` here corresponds to
    the YAML's nested `allow: {paths: [...]}`, flattened for convenience.
    """

    version: int = 1
    exclude: list[str] = field(default_factory=list)
    pii: dict[str, bool] = field(default_factory=dict)
    rule_paths: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    root: Path | None = None
    """The folder this config file was read from.

    `exclude` and `allow.paths` are written relative to the config file, so a
    scan starting further down needs this to adjust them. `None` for a config
    built in code, whose patterns are then taken as relative to the scan root.
    """


def _validate_top_level(data: dict, source: str) -> None:
    unknown = set(data) - _KNOWN_TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"{source}: unknown config field(s): {', '.join(sorted(unknown))}")

    version = data.get("version", CONFIG_VERSION)
    if version != CONFIG_VERSION:
        raise ConfigError(
            f"{source}: unsupported config version {version!r} "
            f"(this build understands version {CONFIG_VERSION})"
        )


def _require_list_of_str(value, field_name: str, source: str) -> list:
    """Guards every list-shaped field before it's consumed. Without this, a
    field given as a bare string (a plausible typo: `exclude: "foo/**"`
    instead of `exclude: ["foo/**"]`) silently iterates character-by-character
    instead of raising, since `list("foo/**")` is valid Python and just
    produces the wrong list.
    """
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{source}: '{field_name}' must be a list of strings")
    return value


def _require_mapping(value, field_name: str, source: str) -> dict:
    """Guards every mapping-shaped field before it's consumed. Without this,
    a field given as a list (e.g. `pii: [email, phone]` instead of
    `pii: {email: true, phone: true}`) reaches `dict(...)` and raises a raw
    `ValueError` instead of a clean `ConfigError`.
    """
    if not isinstance(value, dict):
        raise ConfigError(f"{source}: '{field_name}' must be a mapping")
    return value


def _validate_pii(pii: dict, source: str) -> None:
    unknown = set(pii) - known_pii_types()
    if unknown:
        raise ConfigError(f"{source}: unknown pii detector(s): {', '.join(sorted(unknown))}")


def _validate_severity_overrides(overrides: dict, source: str) -> None:
    invalid = {v for v in overrides.values() if v not in _KNOWN_SEVERITIES}
    if invalid:
        raise ConfigError(
            f"{source}: unknown severity in severity_overrides: {', '.join(sorted(invalid))}"
        )


def parse_config(text: str, source: str = "<config>") -> Config:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: invalid YAML: {yaml_error_detail(exc)}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a YAML mapping at the top level")
    _validate_top_level(data, source)

    exclude = _require_list_of_str(data.get("exclude") or [], "exclude", source)
    rule_paths = _require_list_of_str(data.get("rule_paths") or [], "rule_paths", source)
    disabled_rules = _require_list_of_str(
        data.get("disabled_rules") or [], "disabled_rules", source
    )

    pii = _require_mapping(data.get("pii") or {}, "pii", source)
    _validate_pii(pii, source)

    severity_overrides = _require_mapping(
        data.get("severity_overrides") or {}, "severity_overrides", source
    )
    _validate_severity_overrides(severity_overrides, source)

    allow = _require_mapping(data.get("allow") or {}, "allow", source)
    allow_paths = _require_list_of_str(allow.get("paths") or [], "allow.paths", source)

    return Config(
        version=data.get("version", 1),
        exclude=list(exclude),
        pii=dict(pii),
        rule_paths=list(rule_paths),
        allow_paths=list(allow_paths),
        disabled_rules=list(disabled_rules),
        severity_overrides=dict(severity_overrides),
    )


def load_config(path: str | Path) -> Config:
    text = read_text_file(path, what="config file")
    cfg = parse_config(text, source=str(path))
    cfg.root = Path(path).resolve().parent
    return cfg


DEFAULT_CONFIG_FILENAME = ".oneleaks.yaml"


def discover_config(start: Path | None = None) -> Config | None:
    """Look for `.oneleaks.yaml` in `start` (default: cwd), then each parent
    directory up to the filesystem root. Used by the CLI and MCP server only.
    The Python API never auto-loads config, to keep library calls
    side-effect-free.

    Walking up matters because the config almost always sits at the project
    root while the scan is often launched from somewhere below it: a
    pre-commit hook, an editor integration, or just `cd src && oneleaks scan`.
    Checking only the starting directory made every one of those silently
    ignore the project's excludes, allow-paths and disabled rules.
    """
    base = (start or Path.cwd()).resolve()
    for directory in (base, *base.parents):
        candidate = directory / DEFAULT_CONFIG_FILENAME
        if candidate.is_file():
            return load_config(candidate)
    return None


# --- Adjusting path patterns when a scan starts in a subfolder ---

_GLOB_CHARS = ("*", "?", "[")


def _shorten_pattern(pattern: str, folders_below: tuple[str, ...]) -> str | None:
    """Trim the leading folders off a pattern so it matches from the scan root.

    A config in `project/` listing `src/vendor/**`, scanned from `project/src`,
    needs the pattern to become `vendor/**`. `folders_below` is the path from
    the config file down to the scan root, here `("src",)`.

    Returns None when the pattern can never match here, which is known as soon
    as a folder name disagrees. Trimming stops at the first `*`, since a `*` can
    stand for any number of folders.

    A pattern trimmed away entirely (`sub`, scanned from inside `sub`) named the
    scan root itself, so everything under it is covered and the result is `**`.
    Returning None there would silently drop the exclusion.
    """
    segments = pattern.split("/")
    for folder in folders_below:
        if not segments or any(ch in segments[0] for ch in _GLOB_CHARS):
            break
        if segments[0] != folder:
            return None
        segments = segments[1:]
    return "/".join(segments) if segments else "**"


def make_patterns_relative_to_scan_folder(cfg, base: Path):
    """Rewrite the config's file patterns so they match from `base`.

    Patterns in `.oneleaks.yaml` are relative to that file, but the scan may
    start below it (`cd src && oneleaks scan .`), and reported paths then start
    at `src`. Without this the two are anchored differently and never match.

    A no-op for a config built in code, or when the scan root is the config's
    own folder.
    """
    if cfg.root is None:
        return cfg
    try:
        folders_below = base.resolve().relative_to(cfg.root).parts
    except ValueError:
        return cfg  # scan root is outside the config's tree; leave as written
    if not folders_below:
        return cfg
    return replace(
        cfg,
        exclude=[p for p in (_shorten_pattern(x, folders_below) for x in cfg.exclude) if p],
        allow_paths=[p for p in (_shorten_pattern(x, folders_below) for x in cfg.allow_paths) if p],
    )
