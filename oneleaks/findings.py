"""Turning a match into a Finding that is safe to show or store.

Two jobs. Fingerprinting gives each found value a stable id, so the same secret
can be recognised across runs without keeping the value itself. Previews mask
the value for display. Neither ever lets a raw secret out.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets

from oneleaks.models import Finding

_SESSION_KEY: bytes | None = None
_FINGERPRINT_PREFIX = {"secret": "sec", "pii": "pii", "sensitive": "sen"}


def _fingerprint_key(explicit_key: bytes | None) -> bytes:
    if explicit_key is not None:
        return explicit_key
    env = os.environ.get("ONELEAKS_FINGERPRINT_KEY")
    if env:
        return env.encode("utf-8")
    global _SESSION_KEY
    if _SESSION_KEY is None:
        _SESSION_KEY = secrets.token_bytes(32)
    return _SESSION_KEY


def _compute_fingerprint(
    rule_id: str, category: str, normalized_value: str, key: bytes | None = None
) -> str:
    digest = hmac.new(
        _fingerprint_key(key),
        f"{rule_id}:{normalized_value}".encode(),
        hashlib.sha256,
    ).hexdigest()
    prefix = _FINGERPRINT_PREFIX.get(category, "fnd")
    return f"{prefix}_{digest[:16]}"


def _safe_preview(type_: str, value: str) -> str:
    if type_ in ("private_key", "pgp_private_key"):
        return "<PRIVATE_KEY>"
    if type_ == "email" and "@" in value:
        local, _, domain = value.partition("@")
        head = local[0] if local else ""
        return f"{head}***@{domain}"
    if type_ == "ssn":
        digits = re.sub(r"\D", "", value)
        if len(digits) == 9:
            return f"***-**-{digits[5:]}"
    if type_ == "credit_card":
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4:
            return f"{'*' * (len(digits) - 4)}{digits[-4:]}"
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:4]}****{value[-3:]}"


def finding_to_dict(f: Finding) -> dict:
    """JSON-serializable shape for a Finding. Shared by the CLI's --json
    output and the MCP server's tool results, so both surfaces stay in sync.
    """
    return {
        "rule_id": f.rule_id,
        "category": f.category,
        "type": f.type,
        "severity": f.severity,
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "start": f.start,
        "end": f.end,
        "preview": f.preview,
        "fingerprint": f.fingerprint,
        "commit": f.commit,
    }
