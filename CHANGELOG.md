# Changelog

All notable changes to this project are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project tooling: `Makefile`, GitHub Actions CI, tag-triggered PyPI trusted-publish workflow, pre-commit dogfooding config, MkDocs + Material docs site.

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
