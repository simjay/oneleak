"""Baseline files: accept today's findings, fail the build only on new ones.

A baseline is a JSON snapshot of `(rule_id, path, fingerprint)` triples for
findings a team has already seen and decided not to block on yet. It's the
standard adoption path for turning a scanner on against an existing codebase
(`detect-secrets scan > .secrets.baseline` is the reference UX this mirrors).

Baselines only ever store fingerprints, never raw values, so they're safe to
commit. In fact they must be committed for the "whole team sees the same
accepted findings" workflow to work at all.

This is deliberately a CLI-only concept (see cli.py's `--baseline` /
`--update-baseline`), not a `Config` field: unlike `allow.paths`, a baselined
finding is still a real secret, just one already triaged. Routing it through
the shared `scan_text_with_config()` pipeline would silently stop
`sanitize()` from redacting it too, which would be a real regression. A
"known, accepted" secret must still never leak into sanitized output.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from oneleak.errors import ConfigError, read_text_file
from oneleak.models import Finding

BASELINE_VERSION = 1

_Key = tuple[str, str | None, str | None]


def require_stable_fingerprint_key() -> None:
    """Baselines match findings by fingerprint, and fingerprints are HMAC-keyed
    off a random key generated fresh per process unless `ONELEAK_FINGERPRINT_KEY`
    is set. Without a stable key, a baseline could never match anything written
    by a previous run, so it would silently fail to do its one job. Fail loudly
    up front instead.
    """
    if not os.environ.get("ONELEAK_FINGERPRINT_KEY"):
        raise ConfigError(
            "--baseline requires a stable fingerprint key: set the "
            "ONELEAK_FINGERPRINT_KEY environment variable (same value on every "
            "machine/CI run that reads or writes this baseline). See "
            "docs/configuration.md#baselines."
        )


def _key(rule_id: str, path: str | None, fingerprint: str | None) -> _Key:
    return (rule_id, path, fingerprint)


def load_baseline(path: str | Path) -> set[_Key]:
    text = read_text_file(path, what="baseline file")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid baseline file: {exc.msg} (line {exc.lineno})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ConfigError(f"{path}: expected a top-level 'findings' list")
    if data.get("version") != BASELINE_VERSION:
        raise ConfigError(
            f"{path}: unsupported baseline version {data.get('version')!r} "
            f"(expected {BASELINE_VERSION}); regenerate it with --update-baseline"
        )

    keys: set[_Key] = set()
    for entry in data["findings"]:
        try:
            keys.add(_key(entry["rule_id"], entry.get("path"), entry["fingerprint"]))
        except (KeyError, TypeError) as exc:
            raise ConfigError(
                f"{path}: malformed baseline entry (needs 'rule_id' and 'fingerprint')"
            ) from exc
    return keys


def write_baseline(path: str | Path, findings: list[Finding]) -> None:
    """Overwrites `path` with a fresh snapshot of `findings`. Not a merge: a
    finding no longer present (secret was removed from the code) simply drops
    out of the baseline on the next update, so accepted debt shrinks as it's
    paid down instead of accumulating forever.
    """
    payload = {
        "version": BASELINE_VERSION,
        "findings": [
            {"rule_id": f.rule_id, "path": f.path, "fingerprint": f.fingerprint} for f in findings
        ],
    }
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def filter_new(findings: list[Finding], baseline_keys: set[_Key]) -> list[Finding]:
    """Findings not already accounted for in the baseline."""
    return [f for f in findings if _key(f.rule_id, f.path, f.fingerprint) not in baseline_keys]
