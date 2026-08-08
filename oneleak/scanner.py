"""Scanning orchestration: candidate generation -> validation -> overlap resolution ->
safe findings. This is where scan(text | bytes | Path) is implemented.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass, replace
from pathlib import Path

from oneleak.detectors import (
    entropy_candidates,
    generic_assignment_candidates,
    regex_candidates,
)
from oneleak.errors import ScanError
from oneleak.models import Finding, Rule, ScanResult
from oneleak.rules import (
    ENTROPY_PRIORITY as _ENTROPY_PRIORITY,
)
from oneleak.rules import (
    GENERIC_ASSIGNMENT_PRIORITY as _GENERIC_PRIORITY,
)
from oneleak.rules import (
    RuleRegistry,
)
from oneleak.validators import VALIDATORS

DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_EXCLUDED_DIR_NAMES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
}

_INLINE_ALLOW_RE = re.compile(r"#\s*oneleak:\s*allow(?:\s+(?P<rule_id>[\w-]+))?", re.IGNORECASE)

_GENERIC_ASSIGNMENT_RULE = Rule(
    id="generic-secret",
    category="secret",
    type="generic_credential",
    severity="medium",
    priority=_GENERIC_PRIORITY,
)

_ENTROPY_RULE = Rule(
    id="high-entropy-string",
    category="secret",
    type="high_entropy_string",
    severity="medium",
    priority=_ENTROPY_PRIORITY,
)


@dataclass
class _Candidate:
    rule: Rule
    start: int
    end: int


def _offset_to_line_col(text: str, start: int) -> tuple[int, int]:
    line = text.count("\n", 0, start) + 1
    line_start = text.rfind("\n", 0, start) + 1
    return line, start - line_start + 1


def _line_span(text: str, start: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    return line_start, line_end


def _normalize_for_validator(validator_name: str, raw: str) -> str:
    if validator_name == "luhn":
        return re.sub(r"[ -]", "", raw)
    return raw


# --- Fingerprinting ---------------------------------------------------------------------------

_SESSION_KEY: bytes | None = None
_FINGERPRINT_PREFIX = {"secret": "sec", "pii": "pii", "sensitive": "sen"}


def _fingerprint_key(explicit_key: bytes | None) -> bytes:
    if explicit_key is not None:
        return explicit_key
    env = os.environ.get("ONELEAK_FINGERPRINT_KEY")
    if env:
        return env.encode("utf-8")
    global _SESSION_KEY
    if _SESSION_KEY is None:
        _SESSION_KEY = secrets.token_bytes(32)
    return _SESSION_KEY


def compute_fingerprint(
    rule_id: str, category: str, normalized_value: str, key: bytes | None = None
) -> str:
    digest = hmac.new(
        _fingerprint_key(key),
        f"{rule_id}:{normalized_value}".encode(),
        hashlib.sha256,
    ).hexdigest()
    prefix = _FINGERPRINT_PREFIX.get(category, "fnd")
    return f"{prefix}_{digest[:16]}"


# --- Safe preview -------------------------------------------------------------------------------


def safe_preview(type_: str, value: str) -> str:
    if type_ == "private_key":
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


# --- Candidate generation + overlap resolution -------------------------------------------------


def _generate_candidates(text: str, registry: RuleRegistry) -> list[_Candidate]:
    candidates: list[_Candidate] = []

    for rule in registry.rules:
        for match in regex_candidates(text, rule):
            raw = text[match.start : match.end]
            if rule.validator is not None:
                validator_fn = VALIDATORS.get(rule.validator)
                if validator_fn is None or not validator_fn(
                    _normalize_for_validator(rule.validator, raw)
                ):
                    continue
            candidates.append(_Candidate(rule=rule, start=match.start, end=match.end))

    for match in generic_assignment_candidates(text):
        candidates.append(
            _Candidate(rule=_GENERIC_ASSIGNMENT_RULE, start=match.start, end=match.end)
        )

    for match in entropy_candidates(text):
        candidates.append(_Candidate(rule=_ENTROPY_RULE, start=match.start, end=match.end))

    for py_rule in registry.python_rules:
        rule = Rule(
            id=py_rule.id,
            category=py_rule.category,
            type=py_rule.type,
            severity=py_rule.severity,
            priority=py_rule.priority,
        )
        for py_match in py_rule.detect(text):
            candidates.append(_Candidate(rule=rule, start=py_match.start, end=py_match.end))

    return candidates


def _resolve_overlaps(candidates: list[_Candidate]) -> list[_Candidate]:
    ordered = sorted(
        candidates,
        key=lambda c: (-c.rule.priority, -(c.end - c.start), c.start, c.rule.id),
    )
    accepted: list[_Candidate] = []
    for candidate in ordered:
        if any(candidate.start < a.end and a.start < candidate.end for a in accepted):
            continue
        accepted.append(candidate)
    accepted.sort(key=lambda c: c.start)
    return accepted


def _is_suppressed(text: str, candidate: _Candidate) -> bool:
    line_start, line_end = _line_span(text, candidate.start)
    m = _INLINE_ALLOW_RE.search(text, line_start, line_end)
    if not m:
        return False
    scoped_id = m.group("rule_id")
    return scoped_id is None or scoped_id == candidate.rule.id


def scan_text(
    text: str,
    registry: RuleRegistry,
    *,
    path: str | None = None,
    fingerprint_key: bytes | None = None,
    disabled_rules: frozenset[str] = frozenset(),
) -> list[Finding]:
    candidates = _generate_candidates(text, registry)
    candidates = [c for c in candidates if c.rule.id not in disabled_rules]
    # Suppress before resolving overlaps: a rule-scoped `# oneleak: allow <id>`
    # must only remove that one rule's candidate, leaving any other
    # (non-allow-listed, lower-priority) rule that matches the same span free
    # to win the overlap and still be reported. Suppressing after overlap
    # resolution would instead silently drop the whole span whenever the
    # *winning* candidate happened to be the suppressed one.
    candidates = [c for c in candidates if not _is_suppressed(text, c)]
    candidates = _resolve_overlaps(candidates)

    findings: list[Finding] = []
    for c in candidates:
        raw = text[c.start : c.end]
        line, col = _offset_to_line_col(text, c.start)
        fingerprint = compute_fingerprint(c.rule.id, c.rule.category, raw, key=fingerprint_key)
        findings.append(
            Finding(
                rule_id=c.rule.id,
                category=c.rule.category,
                type=c.rule.type,
                severity=c.rule.severity,
                start=c.start,
                end=c.end,
                path=path,
                line=line,
                column=col,
                preview=safe_preview(c.rule.type, raw),
                fingerprint=fingerprint,
            )
        )
    return findings


# --- Path / directory scanning -------------------------------------------------------------------


def _is_probably_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _matches_any(relative_posix: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(relative_posix, pattern) for pattern in patterns)


def _scan_file(
    path: Path,
    registry: RuleRegistry,
    *,
    base: Path,
    max_file_size: int,
    fingerprint_key: bytes | None,
    disabled_rules: frozenset[str],
) -> list[Finding]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ScanError(f"cannot stat {path}: {exc}") from exc
    if size > max_file_size:
        return []
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ScanError(f"cannot read {path}: {exc}") from exc
    if _is_probably_binary(data):
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []

    try:
        rel = path.relative_to(base).as_posix()
    except ValueError:
        rel = path.as_posix()
    return scan_text(
        text,
        registry,
        path=rel,
        fingerprint_key=fingerprint_key,
        disabled_rules=disabled_rules,
    )


def scan_path(
    target: Path,
    registry: RuleRegistry,
    *,
    exclude: tuple[str, ...] = (),
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    fingerprint_key: bytes | None = None,
    disabled_rules: frozenset[str] = frozenset(),
) -> list[Finding]:
    if not target.exists():
        raise ScanError(f"path does not exist: {target}")

    if target.is_file():
        base = target.parent
        return _scan_file(
            target,
            registry,
            base=base,
            max_file_size=max_file_size,
            fingerprint_key=fingerprint_key,
            disabled_rules=disabled_rules,
        )

    findings: list[Finding] = []
    base = target
    for root, dirnames, filenames in os.walk(target):
        root_path = Path(root)
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDED_DIR_NAMES]
        for filename in filenames:
            file_path = root_path / filename
            try:
                rel = file_path.relative_to(base).as_posix()
            except ValueError:
                rel = file_path.as_posix()
            if exclude and _matches_any(rel, exclude):
                continue
            findings.extend(
                _scan_file(
                    file_path,
                    registry,
                    base=base,
                    max_file_size=max_file_size,
                    fingerprint_key=fingerprint_key,
                    disabled_rules=disabled_rules,
                )
            )
    findings.sort(key=lambda f: (f.path or "", f.start))
    return findings


# --- Public entry point --------------------------------------------------------------------------


def resolve_text_input(content, *, skip_unreadable: bool = False) -> tuple[str | None, str | None]:
    """Resolve str/bytes/single-file-Path input to (text, path). Directories
    are not supported here -- use scan_path() directly for those.

    With skip_unreadable=True (used by scan(), to match directory-scan's
    "skip binary files safely" default), a binary/undecodable file yields
    (None, path) instead of raising. sanitize() uses skip_unreadable=False:
    asking to sanitize a specific unreadable file is a real user-facing error.
    """
    if isinstance(content, Path):
        if content.is_dir():
            raise ScanError("this operation does not support directory input; pass a file or text")
        data = content.read_bytes()
        if _is_probably_binary(data):
            if skip_unreadable:
                return None, str(content)
            raise ScanError(f"cannot process binary file: {content}")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            if skip_unreadable:
                return None, str(content)
            raise ScanError(f"cannot decode {content} as UTF-8") from exc
        return text, str(content)
    if isinstance(content, bytes):
        if _is_probably_binary(content):
            if skip_unreadable:
                return None, None
            raise ScanError("input looks binary, not text")
        try:
            return content.decode("utf-8"), None
        except UnicodeDecodeError as exc:
            if skip_unreadable:
                return None, None
            raise ScanError("input is not valid UTF-8") from exc
    if isinstance(content, str):
        return content, None
    raise ScanError(f"unsupported input type: {type(content).__name__}")


def build_registry(rules, cfg) -> RuleRegistry:
    registry = RuleRegistry()
    registry.load_builtin()
    for rule_path in cfg.rule_paths:
        registry.load_source(rule_path)
    if rules:
        registry.load_sources(rules)
    return registry


def resolve_config(config):
    from oneleak.config import Config, load_config

    if config is None:
        return Config()
    if isinstance(config, Config):
        return config
    return load_config(config)


def disabled_rule_ids(cfg) -> frozenset[str]:
    """Rule IDs disabled by config: explicit `disabled_rules` plus any PII
    detector turned off via `pii: {<type>: false}`. Shared by every scan
    entry point (scan(), oneleak.git's scan_changed()/scan_staged(), and
    sanitize()) so config behaves consistently everywhere, not just on
    whichever path got it first.
    """
    return frozenset(cfg.disabled_rules) | frozenset(_pii_disabled_rule_ids(cfg))


def apply_allow_paths(findings: list[Finding], cfg) -> list[Finding]:
    """Drop findings under `allow.paths`-matched paths."""
    if not cfg.allow_paths:
        return findings
    return [f for f in findings if not (f.path and _matches_any(f.path, tuple(cfg.allow_paths)))]


def apply_severity_overrides(findings: list[Finding], cfg) -> list[Finding]:
    """Apply `severity_overrides: {rule_id: severity}` from config."""
    if not cfg.severity_overrides:
        return findings
    return [
        replace(f, severity=cfg.severity_overrides[f.rule_id])
        if f.rule_id in cfg.severity_overrides
        else f
        for f in findings
    ]


def apply_config_filters(findings: list[Finding], cfg) -> list[Finding]:
    """The full set of post-scan, config-driven transforms: severity
    overrides, then allow-path filtering. Every entry point that produces
    findings from a Config should route through this -- see disabled_rule_ids()
    for why (this is the other half of the same consistency guarantee).
    """
    return apply_allow_paths(apply_severity_overrides(findings, cfg), cfg)


def scan_text_with_config(
    text: str,
    registry: RuleRegistry,
    cfg,
    *,
    path: str | None = None,
    fingerprint_key: bytes | None = None,
) -> list[Finding]:
    """scan_text() plus the full config pipeline (disabled rules going in,
    severity overrides and allow-paths coming out). The single code path
    scan(), oneleak.git, and sanitize() all share for single-text scanning.
    """
    findings = scan_text(
        text,
        registry,
        path=path,
        fingerprint_key=fingerprint_key,
        disabled_rules=disabled_rule_ids(cfg),
    )
    return apply_config_filters(findings, cfg)


def scan(content, *, rules=None, config=None) -> ScanResult:
    """content: str (raw text), bytes (utf-8 text), or Path (file or directory)."""
    cfg = resolve_config(config)
    registry = build_registry(rules, cfg)

    if isinstance(content, Path) and content.is_dir():
        findings = scan_path(
            content,
            registry,
            exclude=tuple(cfg.exclude),
            disabled_rules=disabled_rule_ids(cfg),
        )
        findings = apply_config_filters(findings, cfg)
    else:
        text, path = resolve_text_input(content, skip_unreadable=True)
        findings = [] if text is None else scan_text_with_config(text, registry, cfg, path=path)

    return ScanResult(findings=findings)


_PII_TYPE_TO_RULE_ID = {
    "email": "email",
    "phone": "phone",
    "ssn": "ssn",
    "credit_card": "credit-card",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "iban": "iban",
}


def _pii_disabled_rule_ids(cfg) -> list[str]:
    disabled = []
    for key, enabled in cfg.pii.items():
        if not enabled and key in _PII_TYPE_TO_RULE_ID:
            disabled.append(_PII_TYPE_TO_RULE_ID[key])
    return disabled
