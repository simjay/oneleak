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


_SSN_RE_STRICT = None  # populated lazily to avoid import cost at module load


def ssn(value: str) -> bool:
    """Structural SSN validation only. Deliberately does NOT use pre-2011
    state-based area-number tables, which the SSA's June 2011 randomization
    made obsolete -- that older approach rejects valid modern SSNs.
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
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


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
    "iban": iban,
    "ssn": ssn,
    "ipv4": ipv4,
    "ipv6": ipv6,
    "jwt": jwt,
}
