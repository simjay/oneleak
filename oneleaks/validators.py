"""Built-in validators referenced by rules via `validator: <name>`."""

from __future__ import annotations

import base64
import ipaddress
import json

_IBAN_LENGTHS = {
    "AD": 24,
    "AE": 23,
    "AT": 20,
    "AZ": 28,
    "BA": 20,
    "BE": 16,
    "BG": 22,
    "BH": 22,
    "BR": 29,
    "BY": 28,
    "CH": 21,
    "CR": 22,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "DO": 28,
    "EE": 20,
    "EG": 29,
    "ES": 24,
    "FI": 18,
    "FO": 18,
    "FR": 27,
    "GB": 22,
    "GE": 22,
    "GI": 23,
    "GL": 18,
    "GR": 27,
    "GT": 28,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IL": 23,
    "IQ": 23,
    "IS": 26,
    "IT": 27,
    "JO": 30,
    "KW": 30,
    "KZ": 20,
    "LB": 28,
    "LC": 32,
    "LI": 21,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "LY": 25,
    "MC": 27,
    "MD": 24,
    "ME": 22,
    "MK": 19,
    "MR": 27,
    "MT": 31,
    "MU": 30,
    "NL": 18,
    "NO": 15,
    "PK": 24,
    "PL": 28,
    "PS": 29,
    "PT": 25,
    "QA": 29,
    "RO": 24,
    "RS": 22,
    "SA": 24,
    "SC": 31,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "SM": 27,
    "ST": 25,
    "SV": 28,
    "TL": 23,
    "TN": 24,
    "TR": 26,
    "UA": 29,
    "VA": 22,
    "VG": 24,
    "XK": 20,
}


def luhn(digits: str) -> bool:
    """Luhn checksum. `digits` must already be normalized to digits-only."""
    if not digits.isdigit() or len(digits) < 12:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Issuer Identification Number ranges as (brand, low prefix, high prefix,
# permitted lengths). The prefix is compared as an integer over the first
# len(str(low)) digits, so ("mastercard", 51, 55, ...) tests digits[:2].
#
# Luhn alone is not enough: it accepts roughly one in ten random digit runs, so
# timestamps and IDs pass it routinely. An issuer prefix at a brand-specific
# length is what separates a card from a number that merely checksums.
_CARD_ISSUERS: tuple[tuple[str, int, int, frozenset[int]], ...] = (
    ("visa", 4, 4, frozenset({13, 16, 19})),
    ("amex", 34, 34, frozenset({15})),
    ("amex", 37, 37, frozenset({15})),
    ("mastercard", 51, 55, frozenset({16})),
    ("mastercard-2", 2221, 2720, frozenset({16})),
    ("discover", 6011, 6011, frozenset({16, 19})),
    ("discover", 644, 649, frozenset({16, 19})),
    ("discover", 65, 65, frozenset({16, 19})),
    ("jcb", 3528, 3589, frozenset({16, 17, 18, 19})),
    ("diners", 300, 305, frozenset({14, 15, 16, 17, 18, 19})),
    ("diners", 36, 36, frozenset({14, 15, 16, 17, 18, 19})),
    ("diners", 38, 39, frozenset({14, 15, 16, 17, 18, 19})),
    ("unionpay", 62, 62, frozenset({16, 17, 18, 19})),
    ("maestro", 50, 50, frozenset({12, 13, 14, 15, 16, 17, 18, 19})),
    ("maestro", 56, 58, frozenset({12, 13, 14, 15, 16, 17, 18, 19})),
)


def credit_card(value: str) -> bool:
    """Luhn plus an issuer-prefix check. `value` must already be digits-only.

    Luhn alone flags Go module pseudo-versions (`v0.0.0-20190510104115-...`),
    ISO timestamps and similar digit runs, at `high` severity. Requiring a
    known issuer prefix at a length that issuer actually uses removes those
    without dropping any real card format.
    """
    if not luhn(value):
        return False
    length = len(value)
    for _brand, low, high, lengths in _CARD_ISSUERS:
        width = len(str(low))
        if length < width:
            continue
        if low <= int(value[:width]) <= high and length in lengths:
            return True
    return False


def iban(value: str) -> bool:
    """Format + country-length + Mod-97 checksum validation."""
    candidate = "".join(value.split()).upper()
    if len(candidate) < 4 or not candidate[:2].isalpha() or not candidate[2:4].isdigit():
        return False
    country = candidate[:2]
    expected_len = _IBAN_LENGTHS.get(country)
    if expected_len is not None and len(candidate) != expected_len:
        return False
    if not candidate[4:].isalnum():
        return False

    rearranged = candidate[4:] + candidate[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def ssn(value: str) -> bool:
    """Structural SSN validation only. Deliberately does NOT use pre-2011
    state-based area-number tables, which the SSA's June 2011 randomization
    made obsolete: that older approach rejects valid modern SSNs.
    """
    digits = value.replace("-", "").replace(" ", "")
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = digits[0:3], digits[3:5], digits[5:9]
    if area in ("000", "666") or area[0] == "9":
        return False
    if group == "00":
        return False
    return serial != "0000"


def ipv4(value: str) -> bool:
    """Parses as an IPv4 address. Available to custom rules that want every
    address; the built-in PII rule uses `public_ipv4` instead.
    """
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def ipv6(value: str) -> bool:
    """Parses as an IPv6 address. See `ipv4` on why the built-in rule differs."""
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


# Ranges set aside for documentation and examples, which `ipaddress` has no
# predicate for: RFC 5737 for v4, RFC 3849 for v6.
_DOC_RANGES = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _can_reach_the_internet(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address could identify a host on the public internet.

    An address that cannot leave the machine or the local network identifies
    nobody, so treating it as personal data is simply wrong. `127.0.0.1`,
    `0.0.0.0` and the RFC 1918 private ranges appear in the configs, tests and
    docs of essentially every repository: on three real projects these
    accounted for the majority of all IP findings, and every one was noise.
    """
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_link_local
    ):
        return False
    return not any(ip in network for network in _DOC_RANGES)


def public_ipv4(value: str) -> bool:
    try:
        return _can_reach_the_internet(ipaddress.IPv4Address(value))
    except ValueError:
        return False


def public_ipv6(value: str) -> bool:
    try:
        return _can_reach_the_internet(ipaddress.IPv6Address(value))
    except ValueError:
        return False


def aba_routing(value: str) -> bool:
    """US ABA bank routing number checksum: 3/7/1-weighted digit sum mod 10 == 0."""
    digits = value.replace("-", "").replace(" ", "")
    if len(digits) != 9 or not digits.isdigit():
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    total = sum(int(d) * w for d, w in zip(digits, weights, strict=True))
    return total % 10 == 0


def jwt(value: str) -> bool:
    """Structural anchor: three dot-separated base64url segments, header decodes to JSON
    containing 'alg'. Does not verify the signature.
    """
    parts = value.split(".")
    if len(parts) != 3 or not all(parts):
        return False
    header_b64 = parts[0]
    padded = header_b64 + "=" * (-len(header_b64) % 4)
    try:
        header_bytes = base64.urlsafe_b64decode(padded)
        header = json.loads(header_bytes)
    except (ValueError, TypeError):
        return False
    return isinstance(header, dict) and "alg" in header


VALIDATORS = {
    "luhn": luhn,
    "credit_card": credit_card,
    "iban": iban,
    "ssn": ssn,
    "ipv4": ipv4,
    "ipv6": ipv6,
    "public_ipv4": public_ipv4,
    "public_ipv6": public_ipv6,
    "jwt": jwt,
    "aba_routing": aba_routing,
}
