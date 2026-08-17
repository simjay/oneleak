"""Secrets' peer of pii_rules.py: owns builtin_rules/secrets.yaml's loading.
Everything else (matching engine, validators, overlap resolution) is shared,
category-agnostic machinery in detectors.py/rules.py/scanner.py, not
duplicated here.

Unlike pii_rules.py, there's no type -> rule_id map here: secrets have no
`secrets: {<type>: bool}` config toggle, deliberately. `disabled_rules:
[rule-id]` already disables any rule, secret or PII, uniformly, and a second
type-keyed toggle here would just be a hand-maintained duplicate of that
mechanism, not a distinct feature.

The rule-writing conventions themselves (precision, severity, naming
criteria) live in secrets.yaml's own header comment, next to the rules they
govern, not here.
"""

from __future__ import annotations

from functools import lru_cache

from oneleaks.rules import load_builtin_entries

BUILTIN_FILENAME = "secrets.yaml"


@lru_cache(maxsize=1)
def builtin_entries() -> tuple[dict, ...]:
    return load_builtin_entries(BUILTIN_FILENAME)
