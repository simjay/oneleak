"""Hypothesis property tests for the parts of oneleak with clean invariants:
Luhn/IBAN checksum construction, sanitization offset math, overlap
resolution, and config-schema validation.
"""

from __future__ import annotations

import itertools
import string

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from oneleak.config import _KNOWN_TOP_LEVEL_KEYS, parse_config
from oneleak.errors import ConfigError
from oneleak.models import Finding, Rule
from oneleak.sanitizer import sanitize_text
from oneleak.scanner import _Candidate, _resolve_overlaps
from oneleak.validators import iban, luhn

# --- Luhn -----------------------------------------------------------------------------------


def _luhn_check_digit(prefix_digits: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(prefix_digits)):
        d = int(ch)
        if (i + 1) % 2 == 1:  # +1: the check digit will occupy position 0
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - (total % 10)) % 10)


@given(st.text(alphabet=string.digits, min_size=11, max_size=18))
def test_constructed_luhn_numbers_always_validate(prefix):
    full = prefix + _luhn_check_digit(prefix)
    assert luhn(full)


@given(
    st.text(alphabet=string.digits, min_size=11, max_size=18),
    st.integers(min_value=1, max_value=9),
)
def test_wrong_check_digit_always_fails(prefix, delta):
    correct = int(_luhn_check_digit(prefix))
    wrong = (correct + delta) % 10
    full = prefix + str(wrong)
    assert not luhn(full)


# --- IBAN -----------------------------------------------------------------------------------


def _iban_check_digits(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    remainder = int(numeric) % 97
    return f"{98 - remainder:02d}"


@given(st.text(alphabet=string.digits, min_size=18, max_size=18))
def test_constructed_ibans_always_validate(bban):
    check_digits = _iban_check_digits("DE", bban)
    full = f"DE{check_digits}{bban}"
    assert iban(full)


@given(st.text(alphabet=string.digits, min_size=18, max_size=18), st.integers(0, 17))
def test_corrupted_iban_bban_usually_fails(bban, corrupt_index):
    check_digits = _iban_check_digits("DE", bban)
    corrupted_digit = str((int(bban[corrupt_index]) + 1) % 10)
    corrupted_bban = bban[:corrupt_index] + corrupted_digit + bban[corrupt_index + 1 :]
    full = f"DE{check_digits}{corrupted_bban}"
    assert not iban(full)


# --- Sanitization offsets --------------------------------------------------------------------

_SAFE_ALPHABET = string.ascii_letters + string.digits + " "


@st.composite
def _text_with_disjoint_spans(draw, max_spans=4):
    n_spans = draw(st.integers(min_value=0, max_value=max_spans))
    gaps = draw(
        st.lists(
            st.text(alphabet=_SAFE_ALPHABET, min_size=0, max_size=15),
            min_size=n_spans + 1,
            max_size=n_spans + 1,
        )
    )
    span_texts = draw(
        st.lists(
            st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=10),
            min_size=n_spans,
            max_size=n_spans,
        )
    )

    full_text = gaps[0]
    spans = []
    for gap, span_text in zip(gaps[1:], span_texts, strict=True):
        start = len(full_text)
        full_text += span_text
        spans.append((start, len(full_text)))
        full_text += gap

    return full_text, spans


@given(_text_with_disjoint_spans())
def test_sanitize_preserves_gaps_and_replaces_each_span_once(text_and_spans):
    text, spans = text_and_spans
    findings = [
        Finding(
            rule_id=f"rule{i}",
            category="secret",
            type=f"type{i}",  # unique type per finding: no referential-consistency reuse
            severity="low",
            start=start,
            end=end,
        )
        for i, (start, end) in enumerate(spans)
    ]

    result = sanitize_text(text, findings)

    expected = []
    cursor = 0
    for i, (start, end) in enumerate(spans):
        expected.append(text[cursor:start])
        expected.append(f"<TYPE{i}_1>")
        cursor = end
    expected.append(text[cursor:])

    assert result.text == "".join(expected)


# --- Overlap resolution -----------------------------------------------------------------------


@given(
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=50),  # start
            st.integers(min_value=1, max_value=20),  # length
            st.integers(min_value=0, max_value=100),  # priority
        ),
        min_size=0,
        max_size=8,
    )
)
def test_resolve_overlaps_is_non_overlapping_and_never_loses_to_a_weaker_candidate(specs):
    candidates = [
        _Candidate(
            rule=Rule(id=f"r{i}", category="secret", type="t", severity="low", priority=priority),
            start=start,
            end=start + length,
        )
        for i, (start, length, priority) in enumerate(specs)
    ]

    result = _resolve_overlaps(candidates)

    # 1. No two surviving candidates overlap.
    for a, b in itertools.combinations(result, 2):
        assert not (a.start < b.end and b.start < a.end)

    # 2. Every survivor actually came from the input.
    result_set = {id(c) for c in result}
    assert result_set <= {id(c) for c in candidates}

    # 3. Every candidate that did NOT survive lost to a surviving candidate
    #    that overlaps it and is at least as high priority -- overlap
    #    resolution should never let a weaker candidate win.
    for c in candidates:
        if id(c) in result_set:
            continue
        assert any(
            c.start < r.end and r.start < c.end and r.rule.priority >= c.rule.priority
            for r in result
        )


# --- Config parsing ---------------------------------------------------------------------------

_SAFE_KEY_TEXT = st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10)


@given(
    exclude=st.lists(_SAFE_KEY_TEXT, max_size=3),
    disabled_rules=st.lists(_SAFE_KEY_TEXT, max_size=3),
    pii_email=st.booleans(),
)
def test_valid_known_fields_never_raise(exclude, disabled_rules, pii_email):
    data = {
        "exclude": exclude,
        "disabled_rules": disabled_rules,
        "pii": {"email": pii_email},
    }
    parse_config(yaml.dump(data))  # must not raise


@given(_SAFE_KEY_TEXT.filter(lambda k: k not in _KNOWN_TOP_LEVEL_KEYS))
def test_unknown_top_level_key_always_raises(key):
    with pytest.raises(ConfigError):
        parse_config(yaml.dump({key: True}))
