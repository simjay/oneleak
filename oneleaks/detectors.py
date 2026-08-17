"""Candidate generation: regex rules, generic sensitive-assignment detection, entropy."""

from __future__ import annotations

import math
import re

from oneleaks.models import Rule, RuleMatch

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
    # `http://user:pass@host` is how every proxy tutorial is written.
    "pass",
    "user",
    "username",
}

_KEYWORD_CHOICES = "|".join(re.escape(k) for k in GENERIC_SECRET_KEYWORDS)
_ASSIGNMENT_RE = re.compile(
    r"""
    \b(?P<key>__KEYWORDS__)\b
    \s*[:=]\s*
    (?:
        "(?P<dq>[^"\n]{1,256})"
      | '(?P<sq>[^'\n]{1,256})'
      | (?P<uq>[^\s,;]{1,256})
    )
    """.replace("__KEYWORDS__", _KEYWORD_CHOICES),
    re.VERBOSE | re.IGNORECASE,
)


# Characters that cannot occur in a credential but are everywhere in code.
# Without this, a type annotation, a call expression and a prose sentence all
# read as the credential itself.
_CHARACTERS_ONLY_FOUND_IN_CODE = set("()<>|")


def _looks_like_code(value: str) -> bool:
    """Whether an assigned value is program text rather than a literal secret."""
    stripped = value.strip()
    if any(ch.isspace() for ch in stripped):
        return True
    return any(ch in _CHARACTERS_ONLY_FOUND_IN_CODE for ch in stripped)


def generic_assignment_candidates(text: str, min_length: int = 4) -> list[RuleMatch]:
    """Candidates for `<credential keyword> <separator> <value>`.

    An unquoted value that is purely alphabetic is dropped: it is a type
    annotation or an identifier, and a real credential written without quotes
    carries digits or punctuation. Quoted values are exempt, so an all-letter
    passphrase in quotes still reports.
    """
    matches: list[RuleMatch] = []
    for m in _ASSIGNMENT_RE.finditer(text):
        value = m.group("dq") or m.group("sq") or m.group("uq")
        if value is None:
            continue
        if len(value) < min_length:
            continue
        if value.strip().lower() in _PLACEHOLDER_VALUES:
            continue
        if _looks_like_code(value):
            continue
        unquoted = m.group("uq") is not None
        if unquoted and value.isalpha():
            continue
        group_name = (
            "dq" if m.group("dq") is not None else ("sq" if m.group("sq") is not None else "uq")
        )
        start, end = m.span(group_name)
        matches.append(RuleMatch(start=start, end=end))
    return matches


# --- Placeholder credentials ------------------------------------------------------------------

# Words that only ever turn up in examples. The clearest case is AWS's own
# documentation key, AKIAIOSFODNN7EXAMPLE, which is copied into thousands of
# tutorials and config files.
#
# Only self-labelling markers. Heuristics like "a long run of one repeated
# character" look safe but are not forbidden in a real token, and suppressing a
# live credential is far worse than reporting a sample.
_PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "yourkey",
    "your_key",
    "your-key",
    "randomstring",
    "insert_",
)


def is_placeholder_credential(value: str) -> bool:
    """Whether a well-formed credential is labelling itself as a sample.

    Shape alone cannot tell a real key from the one in a vendor's quickstart,
    so a provider rule matches both. Applied to secret rules only: an email
    address in documentation is still an address the caller asked to redact.
    """
    lowered = value.strip().lower()
    if lowered in _PLACEHOLDER_VALUES:
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


# --- Entropy detection -----------------------------------------------------------------------

_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_-]{20,100}={0,2}")

# `/` is in the base64 alphabet, so a URL path reads as one long candidate.
# Those score inside the range real tokens occupy, so no threshold separates
# them and the shape has to: path segments are lowercase words, random base64
# segments are not.
#
# Lowercase-only is deliberate. Allowing mixed case suppresses roughly 1% of
# real base64 tokens; lowercase-only costs about 1 in 8000.
_LOWERCASE_WORD_RE = re.compile(r"^[a-z][a-z-]+$")


def _looks_like_a_web_link(candidate: str) -> bool:
    if candidate.count("/") < 2:
        return False
    return sum(1 for seg in candidate.split("/") if _LOWERCASE_WORD_RE.match(seg)) >= 2


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
    checksums) and anything shaped like a UUID are excluded by their own checks
    rather than relying on entropy, since entropy alone can't distinguish
    structured-but-random-looking data from a real secret. See
    docs/advanced/concepts.md for why token-efficiency scoring (BPE, as used by
    Betterleaks) isn't used here instead.
    """
    matches: list[RuleMatch] = []
    for m in _BASE64_CANDIDATE_RE.finditer(text):
        candidate = m.group()
        if len(candidate) < min_length:
            continue
        if all(c in "0123456789abcdefABCDEF" for c in candidate):
            continue  # pure hex: indistinguishable from a git hash/commit ID by entropy alone
        if _UUID_RE.match(candidate):
            continue
        if _looks_like_a_web_link(candidate):
            continue
        if len(set(candidate)) <= 2:
            continue  # trivially repetitive
        if shannon_entropy(candidate) < threshold:
            continue
        matches.append(RuleMatch(start=m.start(), end=m.end()))
    return matches
