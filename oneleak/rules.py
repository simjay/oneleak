"""Rule loading: built-in YAML rules, user YAML/JSON rules, and Python rule registration."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

import yaml

from oneleak.errors import ConfigError, read_text_file, yaml_error_detail
from oneleak.models import Category, PythonRule, Rule, Severity

_REQUIRED_FIELDS = ("id", "category", "type", "severity")

# Default priority tiers when a rule doesn't specify one explicitly.
# provider-specific/structured > generic pattern > entropy-only.
DEFAULT_PRIORITY_WITH_PATTERN = 80
DEFAULT_PRIORITY_WITH_KEYWORDS_ONLY = 60
GENERIC_ASSIGNMENT_PRIORITY = 50
ENTROPY_PRIORITY = 10


def _validate_entry(entry: dict, source: str) -> None:
    missing = [f for f in _REQUIRED_FIELDS if f not in entry]
    if missing:
        raise ConfigError(f"rule in {source} is missing required field(s): {', '.join(missing)}")
    if entry["category"] not in {c.value for c in Category}:
        raise ConfigError(f"rule '{entry['id']}' has unknown category: {entry['category']}")
    if entry["severity"] not in {s.value for s in Severity}:
        raise ConfigError(f"rule '{entry['id']}' has unknown severity: {entry['severity']}")
    if "pattern" not in entry and "keywords" not in entry:
        raise ConfigError(f"rule '{entry['id']}' needs at least a pattern or keywords")


def _compile_pattern(entry: dict) -> re.Pattern[str] | None:
    pattern = entry.get("pattern")
    if pattern is None:
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"rule '{entry['id']}' has invalid regex: {exc}") from exc


def build_rule(entry: dict, source: str = "<config>") -> Rule:
    _validate_entry(entry, source)
    pattern = _compile_pattern(entry)
    keywords = tuple(entry.get("keywords") or ())

    priority = entry.get("priority")
    if priority is None:
        priority = (
            DEFAULT_PRIORITY_WITH_PATTERN
            if pattern is not None
            else DEFAULT_PRIORITY_WITH_KEYWORDS_ONLY
        )

    return Rule(
        id=entry["id"],
        category=entry["category"],
        type=entry["type"],
        severity=entry["severity"],
        pattern=pattern,
        keywords=keywords,
        validator=entry.get("validator"),
        priority=priority,
    )


def parse_yaml_rules(text: str, source: str = "<yaml>") -> list[dict]:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: invalid YAML: {yaml_error_detail(exc)}") from exc
    if not isinstance(data, dict) or "rules" not in data:
        raise ConfigError(f"{source}: expected a top-level 'rules' list")
    return data["rules"]


def parse_json_rules(text: str, source: str = "<json>") -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{source}: invalid JSON: {exc.msg} (line {exc.lineno})") from exc
    if not isinstance(data, dict) or "rules" not in data:
        raise ConfigError(f"{source}: expected a top-level 'rules' list")
    return data["rules"]


class RuleRegistry:
    def __init__(self) -> None:
        self.rules: list[Rule] = []
        self.python_rules: list[PythonRule] = []
        self._ids: set[str] = set()

    def _register_id(self, rule_id: str) -> None:
        if rule_id in self._ids:
            raise ConfigError(f"duplicate rule id: {rule_id}")
        self._ids.add(rule_id)

    def add_rule(self, rule: Rule) -> None:
        self._register_id(rule.id)
        self.rules.append(rule)

    def add_python_rule(self, rule: PythonRule) -> None:
        self._register_id(rule.id)
        self.python_rules.append(rule)

    def load_entries(self, entries: list[dict], source: str = "<config>") -> None:
        for entry in entries:
            self.add_rule(build_rule(entry, source))

    def load_yaml_text(self, text: str, source: str = "<yaml>") -> None:
        self.load_entries(parse_yaml_rules(text, source), source)

    def load_yaml_file(self, path: str | Path) -> None:
        text = read_text_file(path, what="rule file")
        self.load_yaml_text(text, source=str(path))

    def load_json_file(self, path: str | Path) -> None:
        text = read_text_file(path, what="rule file")
        self.load_entries(parse_json_rules(text, str(path)), str(path))

    def load_builtin(self) -> None:
        for filename in ("secrets.yaml", "pii.yaml"):
            text = (
                resources.files("oneleak.builtin_rules")
                .joinpath(filename)
                .read_text(encoding="utf-8")
            )
            self.load_yaml_text(text, source=f"builtin:{filename}")

    def load_source(self, source) -> None:
        """Accepts a path (str/Path) to a .yaml/.yml/.json rule file, a Rule,
        or a PythonRule instance.
        """
        if isinstance(source, PythonRule):
            self.add_python_rule(source)
            return
        if isinstance(source, Rule):
            self.add_rule(source)
            return
        path = Path(source)
        if path.suffix in (".yaml", ".yml"):
            self.load_yaml_file(path)
        elif path.suffix == ".json":
            self.load_json_file(path)
        else:
            raise ConfigError(f"unsupported rule source: {source}")

    def load_sources(self, sources) -> None:
        for source in sources:
            self.load_source(source)
