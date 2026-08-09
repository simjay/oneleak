"""Candidate generation: regex rules, generic sensitive-assignment detection, entropy."""

from __future__ import annotations

import math
import re

from oneleak.models import Rule, RuleMatch

_CONTEXT_WINDOW = 60  # chars of look-back on the same line used for keyword gating


def _line_start(text: str, pos: int) -> int:
    idx = text.rfind("\n", 0, pos)
    return idx + 1


def _has_keyword_context(text: str, start: int, keywords: tuple[str, ...]) -> bool:
    if not keywords:
        return True
    window_start = max(_line_start(text, start), start - _CONTEXT_WINDOW)
    window = text[window_start:start].lower()
    return any(kw.lower() in window for kw in keywords)


def regex_candidates(text: str, rule: Rule) -> list[RuleMatch]:
    """Run a compiled-regex rule over text. If the pattern has a named group
    'value', the finding span is that group's span (e.g. connection-string
    credentials). Otherwise the whole match is used.
    """
    if rule.pattern is None:
        return []
    matches: list[RuleMatch] = []
    for m in rule.pattern.finditer(text):
        if not _has_keyword_context(text, m.start(), rule.keywords):
            continue
        if "value" in rule.pattern.groupindex:
            if m.group("value") is None:
                continue
            start, end = m.span("value")
        else:
            start, end = m.span()
        matches.append(RuleMatch(start=start, end=end))
    return matches


# --- Generic sensitive-assignment detection -------------------------------------------------

GENERIC_SECRET_KEYWORDS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "auth_token",
    "credential",
    "aws_secret_access_key",
    "secret_key",
    "token",
)

_PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change_me",
    "your-secret-here",
    "xxx",
    "xxxx",
    "true",
    "false",
    "null",
    "none",
    "todo",
    "fixme",
    "redacted",
    "password",
    "secret",
    "<password>",
    "<secret>",
    "example",
    "test",
    "read",
    "write",
}

_ASSIGNMENT_ALTERNATION = "|".join(re.escape(k) for k in GENERIC_SECRET_KEYWORDS)
_ASSIGNMENT_RE = re.compile(
    r"""
    \b(?P<key>__KEYWORDS__)\b
    \s*[:=]\s*
    (?:
        "(?P<dq>[^"\n]{1,256})"
      | '(?P<sq>[^'\n]{1,256})'
      | (?P<uq>[^\s,;]{1,256})
    )
    """.replace("__KEYWORDS__", _ASSIGNMENT_ALTERNATION),
    re.VERBOSE | re.IGNORECASE,
)


def generic_assignment_candidates(text: str, min_length: int = 4) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for m in _ASSIGNMENT_RE.finditer(text):
        value = m.group("dq") or m.group("sq") or m.group("uq")
        if value is None:
            continue
        if len(value) < min_length:
            continue
        if value.strip().lower() in _PLACEHOLDER_VALUES:
            continue
        group_name = (
            "dq" if m.group("dq") is not None else ("sq" if m.group("sq") is not None else "uq")
        )
        start, end = m.span(group_name)
        matches.append(RuleMatch(start=start, end=end))
    return matches


# --- Entropy detection -----------------------------------------------------------------------

_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_-]{20,100}={0,2}")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

DEFAULT_ENTROPY_THRESHOLD = 4.3
DEFAULT_MIN_LENGTH = 20


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def entropy_candidates(
    text: str,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list[RuleMatch]:
    """Only considers base64-alphabet candidates. Pure-hex runs (git hashes,
    checksums) and canonical UUID shapes are excluded via dedicated checks
    rather than relying on entropy to catch them, since entropy alone can't
    distinguish structured-but-random-looking data from a real secret. See
    docs/concepts.md for why a BPE-tokenizer-based scorer (as used by
    Betterleaks) was evaluated and not adopted: measured on oneleak's own
    candidate set it doesn't separate real secrets from the false-positive
    classes those two checks don't already handle.
    """
    matches: list[RuleMatch] = []
    for m in _BASE64_CANDIDATE_RE.finditer(text):
        candidate = m.group()
        if len(candidate) < min_length:
            continue
        if all(c in "0123456789abcdefABCDEF" for c in candidate):
            continue  # pure hex: hash/commit-id false-positive trap, skip in v0.1
        if _UUID_RE.match(candidate):
            continue
        if len(set(candidate)) <= 2:
            continue  # trivially repetitive
        if shannon_entropy(candidate) < threshold:
            continue
        matches.append(RuleMatch(start=m.start(), end=m.end()))
    return matches
