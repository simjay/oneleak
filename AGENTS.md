# AGENTS.md

Orientation for coding agents working in this repo. Humans: see [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/](docs/index.md) instead. This file is deliberately terse and command-oriented.

## What this is

`oneleak` is a pure-Python secret/PII scanner and sanitizer (`oneleak/`), a CLI (`oneleak scan`/`sanitize`/`desanitize`), and an MCP server (`oneleak-mcp`). No ML, no network calls, no external binary except `git` (used only by `oneleak/git.py`).

## Setup

```bash
uv sync --all-extras
```

Base runtime dependency is PyYAML only. `--all-extras` additionally pulls in `docs` (mkdocs) and `mcp` (MCP SDK) for local dev.

## Commands

```bash
make format   # ruff format + ruff check --fix (run this before committing)
make lint     # ruff check + ruff format --check + mypy (verify only, no mutation)
make test     # pytest with coverage
make ci       # lint + test + docs-build (exactly what GitHub Actions runs)
make bench    # scripts/benchmark.py (observability only, not a gate)
```

Run `make ci` before considering any change done. It must be clean.

## Repo layout

```text
oneleak/               the package
  scanner.py            orchestration: candidate generation -> overlap resolution -> findings
                         (read this file first, everything else feeds into it)
  detectors.py           regex / generic-assignment / entropy candidate generation, shared by
                          secrets and PII alike (category-agnostic, no branching on it)
  validators.py           luhn, iban, ssn, ipv4/ipv6, jwt, aba_routing structural checks
  rules.py                rule loading (built-in YAML, custom YAML/JSON, Python rules)
  secret_rules.py           owns builtin_rules/secrets.yaml's loading. Peer of pii_rules.py:
                            same job, one per category, everything below rule-loading is shared
  pii_rules.py               owns builtin_rules/pii.yaml's loading, plus the type -> rule_id
                              map the `pii:` config toggle uses (derived from pii.yaml, not
                              hand-maintained, so a new PII rule can't silently fail to toggle)
  sanitizer.py             typed placeholders, referential consistency, mapping/desanitize
  git.py                    scan_changed/staged/history (the one module that shells out)
  cli.py                     argparse CLI
  baseline.py                 baseline file read/write/filter (CLI-only, see cli.py --baseline)
  mcp_server.py                  MCP tools (scan_text, scan_path, sanitize_text, desanitize_text)
  config.py                       .oneleak.yaml loading, strict unknown-field rejection
  models.py                        Finding, ScanResult, Rule, etc.
  builtin_rules/*.yaml               declarative secret/PII rules
tests/                  one test file per oneleak/ module, plus test_properties.py (Hypothesis)
docs/                   published docs (mkdocs). docs/architecture.md explains the pipeline in detail
scripts/benchmark.py    perf timing, not a test
```

## Before changing detection logic, read `docs/architecture.md`

Two orderings in `scanner.py::scan_text()` are load-bearing, not arbitrary, and have each caused a real bug when gotten wrong before:

1. **Suppression runs before overlap resolution**, not after. Suppressing after resolution can make a narrowly rule-scoped `# oneleak: allow <rule-id>` silently suppress a *different* rule's finding for the same span (the higher-priority rule was suppressed, but the lower-priority rule that would have caught it independently was already discarded during overlap resolution).
2. **Structural-anchor rules (PEM/JWT/connection-string) outrank provider-specific and PII rules** (priority 110 vs. 90-100), because e.g. a connection-string password can look like an email's `local@domain` shape. This is also why secrets and PII can't be split into fully independent pipelines: `_resolve_overlaps()` needs both categories' candidates in one pool to resolve exactly this kind of cross-category collision. `secret_rules.py`/`pii_rules.py` own rule *loading* only; matching and overlap resolution stay shared, category-agnostic code in `detectors.py`/`scanner.py`.

Also load-bearing: **every entry point that produces findings from a `Config` must go through `scan_text_with_config()`**, not call `scan_text()` directly. Three different call sites (`scan()`, `git.py`, `sanitizer.py`) each independently reimplemented "apply `disabled_rules`/`allow.paths`/`severity_overrides`" at different points and each one shipped with a bug where it forgot part of it. Don't add a fourth.

## Conventions

- **Never store or log a raw sensitive value** outside of `SanitizedResult.mapping` (only populated when the caller explicitly passes `reveal=True`) and mapping files written via `--map` (always `0600`, always with a "don't commit this" warning). `Finding` never carries a raw value, only `preview` (masked) and `fingerprint` (HMAC, one-way).
- **Test fixtures use fake-but-realistic values only**, e.g. `"sk-proj-" + "a" * 20`, never a real or even expired/revoked credential. This is enforced by convention, not tooling. Don't break it.
- **New built-in rule -> three tests**: positive (realistic match detected), negative (adjacent non-match isn't), boundary (off-by-one length/prefix). See `tests/test_scanner.py::TestProviderRules` for the pattern.
- **Regex quantifiers on secret patterns must be bounded** (`{20,100}`, not `{20,}`). An unbounded quantifier let a match run away across trailing content with no separator. See the git history / CHANGELOG for the exact failure mode before "fixing" this differently.
- **Declarative YAML/JSON rules never execute code. Python rules are never auto-loaded** from repo config, only from explicit `rules=[...]` in caller code. This is a security boundary, not a style choice. Don't add a mechanism that auto-discovers Python rule files from a repo.
- **Simplicity over speculative flexibility.** This codebase has twice had a pass that found and removed fields/config options that were parsed but never consumed (`Rule.min_entropy`, `Config.sanitize`, etc.). Don't add a config knob or model field before something actually reads it.

## Verifying a change end-to-end

```bash
make ci
uv run pre-commit run --all-files   # dogfoods oneleak on its own staged diff
uv run python -c "import oneleak; r = oneleak.scan('OPENAI_API_KEY=sk-proj-' + 'a'*20); assert not r.safe"
```

## Docs

- [docs/architecture.md](docs/architecture.md): the detection pipeline and sanitization algorithm, stage by stage
- [docs/concepts.md](docs/concepts.md): the field knowledge behind the design, including why some competitor techniques were evaluated and not adopted
- [docs/rules.md](docs/rules.md): rule schema, priority tiers
- [CONTRIBUTING.md](CONTRIBUTING.md): human-oriented contribution guide
- [CHANGELOG.md](CHANGELOG.md): what changed and why, including past bugs and their fixes
