"""PII's peer of secret_rules.py: owns builtin_rules/pii.yaml's loading and
the type -> rule_id map the `pii:` config toggle uses. Everything else
(matching engine, validators, overlap resolution) is shared, category-
agnostic machinery in detectors.py/rules.py/scanner.py, not duplicated here.

The rule-writing conventions themselves (severity philosophy, what counts as
sufficient evidence) live in pii.yaml's own header comment, next to the rules
they govern, not here.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

from oneleaks.rules import parse_yaml_rules

BUILTIN_FILENAME = "pii.yaml"


@lru_cache(maxsize=1)
def builtin_entries() -> tuple[dict, ...]:
    text = (
        resources.files("oneleaks.builtin_rules")
        .joinpath(BUILTIN_FILENAME)
        .read_text(encoding="utf-8")
    )
    return tuple(parse_yaml_rules(text, source=f"builtin:{BUILTIN_FILENAME}"))


@lru_cache(maxsize=1)
def known_types() -> frozenset[str]:
    """Every `type` a builtin PII rule declares. This is what `.oneleaks.yaml`'s
    `pii: {<type>: bool}` block validates against, derived from pii.yaml
    itself so a new builtin PII rule is automatically toggleable without a
    matching Python edit anywhere else.
    """
    return frozenset(entry["type"] for entry in builtin_entries())


@lru_cache(maxsize=1)
def type_to_rule_id() -> dict[str, str]:
    """`{type: rule_id}` for every builtin PII rule, same derivation as
    known_types(). Used to turn `pii: {<type>: false}` into the rule_id
    scan_text()'s `disabled_rules` actually understands.
    """
    return {entry["type"]: entry["id"] for entry in builtin_entries()}
