# oneleak — v1.0 Roadmap

**Status:** Draft
**Scope decision:** v1.0 = harden v0.1 into a trustworthy release, not new detection capabilities. Confirmed with the user: fill what v0.1 left incomplete (implementation gaps, test coverage, tooling, docs, packaging) rather than pull in the bigger deferred features from spec.md §33. Those stay explicitly post-v1.0 (see bottom of this doc).

---

## v1.0 checklist

### Fill implementation gaps
- [ ] Wire `pii_ml=True` to a real Presidio adapter. Currently `oneleak[pii-ml]` is only packaging plumbing in `pyproject.toml` — there is no code path in `oneleak/scanner.py` that consumes it yet.
- [ ] Apply `severity_overrides` from config. `oneleak/config.py`'s `Config.severity_overrides` is parsed and validated but never read by the scanner.
- [ ] Enforce rule-level `include_paths` / `exclude_paths`. `Rule.include_paths`/`exclude_paths` (models.py) are parsed from YAML/JSON (rules.py) but `scanner.py` never checks them against the file currently being scanned — only the config-level `exclude`/`allow.paths` work today. Found via `docs/rules.md`/`docs/configuration.md` authoring this session; documented as a known gap rather than silently claimed as working.
- [x] ~~`git.scan_changed()`/`scan_staged()` don't respect `.oneleak.yaml`'s `allow.paths` / `disabled_rules`~~ — **found and fixed this session** via dogfooding (`git.py`'s `_scan_files` called `scan_text()` directly instead of going through the same `disabled_rule_ids()`/`apply_allow_paths()` path as `scan()`; both now share those helpers, with a regression test in `tests/test_git.py`).

### Rule-tuning debt (found via dogfooding this session)
- [ ] The generic-assignment detector's bare `token` keyword over-matches structural config keys like GitHub Actions' `permissions: { id-token: write }` — a real value never follows `token:` there, it's a permission scope name. Consider requiring more specific keywords (`auth_token`, `access_token`, etc.) over bare `token`, or excluding common non-secret value tokens (`read`, `write`, `none`) for the generic-assignment rule specifically.
- [ ] Do a broader false-positive pass now that the repo itself is a real (if small) corpus: rerun `oneleak scan .` after any detector change and treat new findings as a signal, not just test-suite green.

### Test coverage (plan.md's stated bar: positive/negative/boundary per rule)
- [ ] Full coverage for all ~20 provider secret rules in `oneleak/builtin_rules/secrets.yaml` — currently only AWS, GitHub PAT, OpenAI, Anthropic, Stripe, and npm have explicit tests (`tests/test_scanner.py::TestProviderRules`). GitLab, Slack, Twilio, Datadog, Google, Azure, PyPI, and the AWS-secret/generic-format rules have none yet.
- [ ] Hypothesis property tests (plan.md Step 48, renumbered): Luhn, IBAN, sanitization offsets, overlap resolution, config parsing. `hypothesis` is already a dev dependency but unused so far.
- [ ] Performance benchmarks (plan.md Step 49): 1 KB text, 1 MB text, single config file, small repo, large repo, changed-file scan. Goal is confirming "cheap enough to invoke on every agent turn," not raw speed.

### Tooling & process (this session)
- [x] Makefile (`lint`, `format`, `format-check`, `typecheck`, `test`, `test-cov`, `build`, `publish`, `publish-test`, `docs-serve`, `docs-build`, `precommit-install`, `ci`, `all`)
- [x] CI (`.github/workflows/ci.yml`) — lint/format-check/typecheck/test/docs-build on push+PR
- [x] PyPI trusted publishing (`.github/workflows/publish.yml`, tag-triggered) — **needs an external one-time step**: register this repo + workflow + the `pypi` environment as a trusted publisher on the `oneleak` PyPI project's settings page before a real publish will succeed
- [x] Dogfooding: `.pre-commit-config.yaml` running ruff/mypy/`oneleak scan --staged --fail-on high` on the repo's own changes, `.oneleak.yaml` allowlisting `.plan/`, `docs/`, `tests/`, etc. for their intentional example content
- [x] `docs/` site (MkDocs + Material), builds clean under `mkdocs build --strict`; `.readthedocs.yaml` ready — connecting the repo on readthedocs.org itself is a separate external step

### Release hygiene (this session)
- [x] `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`
- [x] `pyproject.toml` metadata: classifiers, `project.urls`, keywords
- [ ] Before tagging `v1.0.0`: rerun plan.md's original "Release v0.1" checklist (`pip install oneleak` works with no external binaries/ML/network; `scan .`, `--changed`, `--staged`, `--json`, `sanitize -` all validated) and update `CHANGELOG.md`'s `[Unreleased]` section into a dated `[1.0.0]` entry

---

## Explicitly post-v1.0

From spec.md §33's Deferred list — unchanged, not pulled forward:

- Full git history scanning
- Persistent scan caching
- Multiprocessing
- Archive scanning, binary document scanning, OCR
- IDE plugins
- Remote rule registry
- Credential verification against providers, credential rotation
- `oneleak[pii-ml]` becoming a default/bundled capability (stays opt-in)

**MCP server** (spec.md §33's "fast-follow", plan.md Step 52): still not built. It was tracked as a near-term v0.1.x fast-follow, not a v1.0-hardening item, so it stays out of this checklist — but its priority should be re-evaluated once v1.0 ships, since "agent-friendly" is core to oneleak's positioning (PRD §8/§18) and the MCP server is the most direct way to deliver on that versus the general Python/CLI API already in place.
