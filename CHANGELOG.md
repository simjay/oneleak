# Changelog

All notable changes to this project are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project tooling: `Makefile`, GitHub Actions CI, tag-triggered PyPI trusted-publish workflow, pre-commit dogfooding config, MkDocs + Material docs site.
- `severity_overrides` in `.oneleak.yaml` is now applied to findings (previously parsed but unused); values are validated against the known severity levels.
- **Git history scanning**: `oneleak.git.scan_history()` / `oneleak scan --history` scans commit history for secrets, including ones later removed from the working tree — something `scan()`/`scan_changed()`/`scan_staged()` cannot see, since they only look at current content. Defaults to the current branch's history capped at the most recent 5000 commits (`--since`/`--max-commits`/`--all-refs` to override); truncation is always reported, never silent. Detection runs per-commit, per-diff-hunk (only what each commit actually added, with each hunk's added lines joined into one block so multi-line formats like PEM keys still match correctly), not a full-file rescan at every commit. `Finding.commit` and `ScanResult.truncated` are new fields supporting this.
- **MCP server** (`oneleak[mcp]`, `oneleak-mcp` command): exposes `scan_text`, `scan_path`, `sanitize_text`, `desanitize_text` as MCP tools over stdio, for agent runtimes to call directly instead of shelling out to the CLI. Config auto-discovery matches CLI behavior. See `docs/mcp.md`.
- Provider rule test coverage for GitLab, Slack, Twilio, Datadog, Google, and PyPI (positive/negative/boundary cases).
- Hypothesis property tests (`tests/test_properties.py`): Luhn, IBAN, sanitization offsets, overlap resolution, and config-schema validation.
- `scripts/benchmark.py` / `make bench`: prints timing for 1KB/1MB text, a config-sized input, small/large synthetic repos, and `git.scan_changed()` — an observability script, not a CI gate.

### Fixed
- Several provider secret regexes (`openai-api-key`, `anthropic-api-key`, `stripe-secret-key`, `stripe-restricted-key`, `pypi-token`, plus the entropy-candidate regex) used unbounded quantifiers that could run away across trailing content with no separator. Bounded them to a realistic max length.
- Inline `# oneleak: allow <rule-id>` suppression ran *after* overlap resolution, so scoping suppression to one rule could accidentally suppress a different, non-allow-listed rule's finding for the same span. Suppression now runs before overlap resolution.
- `azure-storage-key`'s regex had an unsatisfiable trailing word-boundary and could never match anything.
- `aws-secret-access-key`'s bare 40-character charset match could shift across the `=` delimiter in `KEY=value`, capturing the wrong span. Now anchored on the key name + assignment operator.
- A YAML/JSON custom rule with `keywords:` (or other list fields) present but null crashed with an unhandled `TypeError` instead of a clean `ConfigError`.
- `oneleak.scan(bytes)` on non-UTF8 input raised unconditionally, unlike an equivalent binary file on disk (silently skipped) — the two input forms now behave consistently.
- `sanitize()` (like `git.scan_changed()`/`scan_staged()` before it) called the scanner directly and bypassed `.oneleak.yaml`'s `disabled_rules`/`allow.paths`/`severity_overrides`. All three entry points now share one code path (`scan_text_with_config()`), closing this class of bug for good rather than patching each call site.
- CLI: `oneleak scan <path> --changed`/`--staged` now errors instead of silently ignoring the path argument; `--changed`/`--staged` together is now a clean argparse error instead of `--changed` silently winning.
- The generic-assignment detector's bare `token` keyword false-positived on non-secret values like GitHub Actions' `permissions: { id-token: write }` — `read`/`write` added to the placeholder-value denylist.

### Removed
- Dropped several unused/never-wired fields found during a bug + simplification pass: `Rule.min_entropy`, `Rule.python_rule`, `Finding.confidence`, `RuleMatch.confidence`, `Config.sanitize`, `Rule.include_paths`/`exclude_paths`. All were parsed/declared but never consumed anywhere in the detection pipeline. `PythonRule.detect()` now only accepts `RuleMatch`, not a bare `(start, end)` tuple, removing a branch used by nothing in practice.
- Dropped the `oneleak[pii-ml]` optional-dependency group until there's an actual adapter behind it — it was pure packaging plumbing with no code path.

### Changed
- `.plan/` (internal PRD/spec/plan/roadmap docs) is no longer tracked in git — kept locally, `.gitignore`d going forward.

## [0.1.0] - 2026-08-08

### Added
- Initial implementation of the v0.1 scope: `oneleak.scan()` / `oneleak.sanitize()` / `oneleak.desanitize()` Python API and `oneleak` CLI.
- Detection engine: rule registry (built-in, YAML, JSON, and Python rules), regex matching with keyword-context gating, generic credential-assignment detection, Shannon-entropy detection, structural-anchor detection (PEM private keys, JWTs, connection-string credentials), and priority-based overlap resolution.
- ~20 built-in provider secret rules (AWS, GitHub, GitLab, OpenAI, Anthropic, Slack, Stripe, Twilio, Datadog, Google, Azure, PyPI, npm) and 7 PII detectors (email, phone, SSN, credit card, IPv4, IPv6, IBAN) with real validators (Luhn, IBAN Mod-97, SSN, `ipaddress`, JWT structure).
- Safe findings: type-specific masked previews, HMAC-SHA256 fingerprints.
- Sanitization: typed numbered placeholders, referential consistency, optional reversible mapping export (`reveal=True`, `seed_mapping`) and `desanitize()`.
- File and directory scanning with binary/size/exclude filtering; `.oneleak.yaml` config with strict unknown-field rejection.
- Inline suppression (`# oneleak: allow`), path/rule exclusions and allowlisting.
- Git integration: `scan_changed()` / `scan_staged()`.
- CLI: `scan` / `sanitize` / `desanitize` subcommands, stdin/stdout, `--json`, `--fail-on`, `--map`, exit codes.

### Known gaps (tracked in `.plan/v1-roadmap.md`)
- `pii_ml=True` is declared as an installable extra but not yet wired to a Presidio adapter.
- `severity_overrides` in config is parsed but not yet applied to findings.
- Rule-level `include_paths` / `exclude_paths` are parsed but not yet enforced.
- Full positive/negative/boundary test coverage across all built-in provider rules, Hypothesis property tests, and performance benchmarks are still outstanding.

[Unreleased]: https://github.com/simjay/oneleak/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/simjay/oneleak/releases/tag/v0.1.0
