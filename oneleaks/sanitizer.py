"""Typed-placeholder sanitization, referential consistency, mapping export, and reversal."""

from __future__ import annotations

import re

from oneleaks.models import Finding, MappingEntry, SanitizedResult
from oneleaks.scanner import (
    build_registry,
    resolve_config,
    resolve_text_input,
    scan_text_with_config,
)

_PLACEHOLDER_RE = re.compile(r"^<(?P<type>[A-Z0-9_]+)_(?P<idx>\d+)>$")


def _seed_counters(seed_mapping: dict[str, MappingEntry] | None) -> dict[str, int]:
    counters: dict[str, int] = {}
    if not seed_mapping:
        return counters
    for placeholder in seed_mapping:
        m = _PLACEHOLDER_RE.match(placeholder)
        if not m:
            continue
        type_key, idx = m.group("type"), int(m.group("idx"))
        counters[type_key] = max(counters.get(type_key, 0), idx)
    return counters


def sanitize_text(
    text: str,
    findings: list[Finding],
    *,
    reveal: bool = False,
    seed_mapping: dict[str, MappingEntry] | None = None,
) -> SanitizedResult:
    fingerprint_to_placeholder: dict[str, str] = {}
    if seed_mapping:
        for seed_placeholder, entry in seed_mapping.items():
            if entry.fingerprint:
                fingerprint_to_placeholder[entry.fingerprint] = seed_placeholder

    counters = _seed_counters(seed_mapping)
    mapping: dict[str, MappingEntry] = dict(seed_mapping) if seed_mapping else {}

    ordered = sorted(findings, key=lambda f: f.start)
    placeholder_for_finding: dict[int, str] = {}  # id(finding) -> placeholder

    for finding in ordered:
        fingerprint = finding.fingerprint or ""
        placeholder = fingerprint_to_placeholder.get(fingerprint) if fingerprint else None
        if placeholder is None:
            type_key = finding.type.upper()
            counters[type_key] = counters.get(type_key, 0) + 1
            placeholder = f"<{type_key}_{counters[type_key]}>"
            if fingerprint:
                fingerprint_to_placeholder[fingerprint] = placeholder
        placeholder_for_finding[id(finding)] = placeholder
        mapping[placeholder] = MappingEntry(
            value=text[finding.start : finding.end],
            rule_id=finding.rule_id,
            fingerprint=finding.fingerprint,
        )

    sanitized = text
    for finding in sorted(ordered, key=lambda f: f.start, reverse=True):
        placeholder = placeholder_for_finding[id(finding)]
        sanitized = sanitized[: finding.start] + placeholder + sanitized[finding.end :]

    return SanitizedResult(
        text=sanitized,
        findings=list(findings),
        mapping=mapping if reveal else None,
    )


def sanitize(
    content,
    *,
    rules=None,
    config=None,
    reveal: bool = False,
    seed_mapping: dict[str, MappingEntry] | None = None,
) -> SanitizedResult:
    """content: str, bytes, or a single file Path (not a directory)."""
    cfg = resolve_config(config)
    registry = build_registry(rules, cfg)
    text, path = resolve_text_input(content)
    assert text is not None  # skip_unreadable defaults to False: raises rather than returns None
    findings = scan_text_with_config(text, registry, cfg, path=path)
    return sanitize_text(text, findings, reveal=reveal, seed_mapping=seed_mapping)


def desanitize(text: str, mapping: dict[str, MappingEntry]) -> str:
    """Replace each placeholder found in `text` with its mapped raw value.
    Placeholders absent from `text`, and placeholder-shaped tokens absent
    from `mapping`, are left untouched rather than raising.
    """
    restored = text
    for placeholder, entry in mapping.items():
        restored = restored.replace(placeholder, entry.value)
    return restored
