"""Finding things: turning text into findings, and walking a folder to do it.

The pipeline is candidates -> validation -> overlap resolution -> findings, and
`scan(text | bytes | Path)` is the way in. What counts as a match lives in
detectors.py and the rule files; what gets skipped lives in skip_rules.py;
turning a match into something safe to show lives in findings.py.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from pathlib import Path

from oneleaks import pii_rules
from oneleaks.config import (
    Config,
    load_config,
    make_patterns_relative_to_scan_folder,
)
from oneleaks.detectors import (
    entropy_candidates,
    generic_assignment_candidates,
    is_placeholder_credential,
    regex_candidates,
)
from oneleaks.errors import ScanError
from oneleaks.findings import _compute_fingerprint, _safe_preview
from oneleaks.models import Finding, Rule, ScanResult
from oneleaks.reading import _decode_text, _matches_any, resolve_text_input
from oneleaks.rules import ENTROPY_PRIORITY as _ENTROPY_PRIORITY
from oneleaks.rules import GENERIC_ASSIGNMENT_PRIORITY as _GENERIC_PRIORITY
from oneleaks.rules import RuleRegistry
from oneleaks.skip_rules import (
    DEFAULT_EXCLUDED_DIR_NAMES,
    DEFAULT_MAX_FILE_SIZE,
    GUESSING_RULE_IDS,
    _public_certificate_ranges,
    _rules_to_skip_for_file,
)
from oneleaks.validators import VALIDATORS

_INLINE_ALLOW_RE = re.compile(r"#\s*oneleaks:\s*allow(?:\s+(?P<rule_id>[\w-]+))?", re.IGNORECASE)

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
    if validator_name in ("luhn", "credit_card"):
        return re.sub(r"[ -]", "", raw)
    return raw


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
            if rule.category == "secret" and is_placeholder_credential(raw):
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
    # Before overlap resolution, not after: a rule-scoped
    # `# oneleaks: allow <id>` must remove only that rule's candidate, leaving
    # any lower-priority rule on the same span free to win and still report.
    candidates = [c for c in candidates if not _is_suppressed(text, c)]
    if pem_spans := _public_certificate_ranges(text):
        candidates = [
            c
            for c in candidates
            if c.rule.id not in GUESSING_RULE_IDS
            or not any(start <= c.start and c.end <= end for start, end in pem_spans)
        ]
    candidates = _resolve_overlaps(candidates)

    findings: list[Finding] = []
    for c in candidates:
        raw = text[c.start : c.end]
        line, col = _offset_to_line_col(text, c.start)
        fingerprint = _compute_fingerprint(c.rule.id, c.rule.category, raw, key=fingerprint_key)
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
                preview=_safe_preview(c.rule.type, raw),
                fingerprint=fingerprint,
            )
        )
    return findings


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
    text = _decode_text(data)
    if text is None:
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
        disabled_rules=_rules_to_skip_for_file(rel, disabled_rules),
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


def build_registry(rules, cfg) -> RuleRegistry:
    registry = RuleRegistry()
    registry.load_builtin()
    for rule_path in cfg.rule_paths:
        registry.load_source(rule_path)
    if rules:
        registry.load_sources(rules)
    return registry


def resolve_config(config):
    if config is None:
        return Config()
    if isinstance(config, Config):
        return config
    return load_config(config)


def _disabled_rule_ids(cfg) -> frozenset[str]:
    """Rule IDs disabled by config: explicit `disabled_rules` plus any PII
    detector turned off via `pii: {<type>: false}`. Shared by every scan
    entry point (scan(), oneleaks.git's scan_changed()/scan_staged(), and
    sanitize()) so config behaves consistently everywhere, not just on
    whichever path got it first.
    """
    return frozenset(cfg.disabled_rules) | frozenset(_pii_disabled_rule_ids(cfg))


def _apply_allow_paths(findings: list[Finding], cfg) -> list[Finding]:
    """Drop findings under `allow.paths`-matched paths."""
    if not cfg.allow_paths:
        return findings
    return [f for f in findings if not (f.path and _matches_any(f.path, tuple(cfg.allow_paths)))]


def _apply_severity_overrides(findings: list[Finding], cfg) -> list[Finding]:
    """Apply `severity_overrides: {rule_id: severity}` from config."""
    if not cfg.severity_overrides:
        return findings
    return [
        replace(f, severity=cfg.severity_overrides[f.rule_id])
        if f.rule_id in cfg.severity_overrides
        else f
        for f in findings
    ]


def _apply_config_filters(findings: list[Finding], cfg) -> list[Finding]:
    """The full set of post-scan, config-driven transforms: severity
    overrides, then allow-path filtering. Every entry point that produces
    findings from a Config should route through this. See _disabled_rule_ids()
    for why (this is the other half of the same consistency guarantee).
    """
    return _apply_allow_paths(_apply_severity_overrides(findings, cfg), cfg)


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
    scan(), oneleaks.git, and sanitize() all share for single-text scanning.
    """
    findings = scan_text(
        text,
        registry,
        path=path,
        fingerprint_key=fingerprint_key,
        disabled_rules=_rules_to_skip_for_file(path, _disabled_rule_ids(cfg)),
    )
    return _apply_config_filters(findings, cfg)


def scan(content, *, rules=None, config=None) -> ScanResult:
    """content: str (raw text), bytes (utf-8 text), or Path (file or directory)."""
    cfg = resolve_config(config)
    registry = build_registry(rules, cfg)

    if isinstance(content, Path) and content.is_dir():
        cfg = make_patterns_relative_to_scan_folder(cfg, content)
        findings = scan_path(
            content,
            registry,
            exclude=tuple(cfg.exclude),
            disabled_rules=_disabled_rule_ids(cfg),
        )
        findings = _apply_config_filters(findings, cfg)
    else:
        # File and text targets report the path as given, so it is relative to
        # the working directory rather than a scan root. Git scans need no
        # equivalent: their paths are already repo-root-relative.
        cfg = make_patterns_relative_to_scan_folder(cfg, Path.cwd())
        text, path = resolve_text_input(content, skip_unreadable=True)
        findings = [] if text is None else scan_text_with_config(text, registry, cfg, path=path)

    return ScanResult(findings=findings)


def _pii_disabled_rule_ids(cfg) -> list[str]:
    type_to_rule_id = pii_rules.type_to_rule_id()
    disabled = []
    for key, enabled in cfg.pii.items():
        if not enabled and key in type_to_rule_id:
            disabled.append(type_to_rule_id[key])
    return disabled
