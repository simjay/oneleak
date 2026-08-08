# oneleak — v1.0 Roadmap

**Status:** Draft
**Scope decision:** v1.0 = harden v0.1 into a trustworthy release, not new detection capabilities. Confirmed with the user: fill what v0.1 left incomplete (implementation gaps, test coverage, tooling, docs, packaging) rather than pull in the bigger deferred features from spec.md §33. Those stay explicitly post-v1.0 (see bottom of this doc).

**Priority order, per the user (this supersedes earlier "wire it up" framing below for dead/unused fields — see the revised Fill implementation gaps section):**
1. Remove all bugs.
2. Simplify the repo structure; remove over-engineering and excessive/unused logic.

---

## Priority 0: Confirmed bugs (found via `/code-review high` + manual dogfooding) — all fixed

Real, reproduced correctness bugs. All confirmed against the actual installed package, fixed, and covered by a regression test in the same session.

1. **[Fixed] Unbounded greedy quantifiers let a secret's match run away across trailing junk with zero separator.** `openai-api-key`, `anthropic-api-key`, `stripe-secret-key`, `stripe-restricted-key`, `pypi-token` (secrets.yaml) and the generic entropy-candidate regex (`detectors.py`) all used unbounded `{20,}`-style quantifiers. **Fix applied:** bounded each to a realistic max (e.g. `{20,100}`) **and dropped the trailing `\b`** on the five provider patterns — bounding alone was not enough and initially made things *worse*: a bounded quantifier followed by `\b` cannot backtrack to a valid match at all when the word-character run extends past the upper bound (every position in range is still mid-word), so `sk-proj-<20 chars><500 chars of junk, zero separator>` went from "over-matches, at least detected" to "matches nothing, total miss" — confirmed via `re.search()` before deciding on the fix. Dropping the trailing boundary and keeping only the bound means the match now truncates cleanly at the cap instead of failing outright. Residual, much narrower limitation (accepted, not fixed): two *short* adjacent secrets whose combined length still fits under the same cap (e.g. two 20-char toy keys back to back, total 47 chars, still under `{20,100}`) still merge into one finding — full separation would require per-provider exact-length modeling rather than a generous bound, which isn't worth the precision-vs-effort tradeoff for v1.0. Regression test: `tests/test_scanner.py::test_openai_key_bounded_not_defeated_by_trailing_junk`.
2. **[Fixed] Suppression was applied after overlap resolution**, so a narrowly-scoped `# oneleak: allow <rule-id>` could accidentally achieve full suppression — reproduced, `api_key = "AKIAABCDEFGHIJKLMNOP"  # oneleak: allow aws-access-key-id` returned zero findings instead of letting `generic-secret` still catch it. **Fix:** suppression now runs before overlap resolution in `scan_text()`. Regression test: `test_scoped_suppression_of_the_overlap_winner_lets_the_loser_surface`.
3. **[Fixed] `azure-storage-key`'s regex could never match anything** — `\b[A-Za-z0-9+/]{86}==\b`'s trailing `\b` was unsatisfiable after `=` (a non-word char). **Fix:** dropped the trailing `\b`. Regression test: `test_azure_storage_key`.
4. **[Fixed] `aws-secret-access-key`'s fixed `{40}` char class (includes `=`/`+`/`/`) could shift the match across the `=` in `KEY=value`**, capturing the wrong span. **Fix:** re-anchored on the key name + assignment operator with a named `value` group, same mechanism as `connection-string-credential`, instead of a bare charset scan. Regression test: `test_aws_secret_access_key_span_does_not_shift_across_delimiter`.
5. **[Fixed] `keywords:` present but null in a custom rule crashed with a raw `TypeError`** instead of `ConfigError`. **Fix:** `entry.get("keywords") or ()`. (`include_paths`/`exclude_paths` had the same bug but were removed entirely — see below.) Regression test: `test_null_keywords_does_not_crash`.
6. **[Fixed] `resolve_text_input()`'s `bytes` branch ignored `skip_unreadable`**, unlike its `Path` branch — `oneleak.scan(non_utf8_bytes)` raised where an equivalent binary file on disk was silently skipped. **Fix:** bytes branch now honors the flag (and gained the same binary-content pre-check the Path branch has). Regression tests: `TestBytesInput::test_non_utf8_bytes_skipped_not_raised`, `test_sanitize_bytes_still_raises`.
7. **[Fixed] `sanitize()` bypassed config filtering entirely** — same root cause as the `git.py` bug fixed earlier this session, just a third call site. **Fix:** root-caused properly instead of patched again — extracted `scan_text_with_config()` (disabled-rules in, severity-overrides + allow-paths out) and made `scan()`, `git.py`, and `sanitizer.py` all call it, so this class of bug can't reappear at a fourth call site. Regression test verified manually; covered indirectly by the severity_overrides/disabled_rules tests below.

### Lower-priority robustness/UX items — also fixed alongside the above
- **[Fixed]** `oneleak/git.py::_has_head()` now wraps `FileNotFoundError` into `ScanError("git executable not found")`, consistent with `_run_git()`.
- **[Fixed]** CLI: `oneleak scan <path> --changed`/`--staged` now errors clearly instead of silently ignoring `<path>`; `--changed`+`--staged` together is a clean argparse mutual-exclusion error. Regression test: `test_changed_with_paths_errors_instead_of_silently_ignoring_paths`.
- **Not fixed, accepted as-is:** the `email` regex can merge two emails with zero separator into one malformed match (e.g. `alice@example.combob@example.com`) — an inherent limitation of simple email regexes, not a design defect.

---

## v1.0 checklist

### Fill implementation gaps — revised toward removal, per priority 2 (simplify, don't complete speculative features)
- [x] **Removed `Rule.min_entropy`.** Was parsed from every YAML/JSON rule but never read anywhere — dead field, deleted rather than wired up.
- [x] **Removed `Rule.python_rule`.** Never populated or read anywhere — `PythonRule` instances are tracked separately via `RuleRegistry.python_rules`. Vestigial from an earlier design, deleted.
- [x] **Removed `Finding.confidence` and `RuleMatch.confidence`.** Never set by any code path; was serialized as a permanent `null` in CLI JSON output. Deleted.
- [x] **Removed the `sanitize:` block from `.oneleak.yaml`'s schema (`Config.sanitize`).** Was parsed but never consumed. `sanitize:` is now a rejected unknown top-level field (confirmed via `test_removed_sanitize_field_is_now_unknown`).
- [x] **Removed `Rule.include_paths`/`exclude_paths`.** Unused; top-level `exclude`/`allow.paths` config fields already cover path scoping in practice. Docs updated accordingly.
- [x] **Dropped the `oneleak[pii-ml]` extra** from `pyproject.toml` until there's a real adapter behind it. Re-add deliberately when that work happens.
- [x] **Applied `severity_overrides` from config.** Wired up via `apply_severity_overrides()` (part of the new `apply_config_filters()` pipeline all scan entry points share); values validated against known severities at config-parse time.
- [x] ~~`git.scan_changed()`/`scan_staged()` don't respect `.oneleak.yaml`'s `allow.paths` / `disabled_rules`~~ — found and fixed via dogfooding; then generalized (see Priority 0 item 7) once the same bug was found a third time in `sanitize()`.

### Other simplification candidates — done
- [x] `PythonRule.detect()` now only accepts `RuleMatch`, not a plain `(start, end)` tuple — dropped the `isinstance` branch in `scanner.py`. Also moved the per-`PythonRule` `Rule(...)` construction out of the inner match loop (was rebuilding an identical object per match).
- [x] Investigated `scanner.py::_FINGERPRINT_PREFIX.get(category, "fnd")`'s `"fnd"` fallback — **kept, not dead**: `PythonRule.category` is a free-form string never validated against `Category` (unlike declarative rules), so a custom rule with a non-standard category genuinely reaches this branch. Added a test (`test_python_rule_with_nonstandard_category`) confirming it's live, reachable code rather than removing it.

### Rule-tuning debt (found via dogfooding this session)
- [ ] The generic-assignment detector's bare `token` keyword over-matches structural config keys like GitHub Actions' `permissions: { id-token: write }` — a real value never follows `token:` there, it's a permission scope name. Consider requiring more specific keywords (`auth_token`, `access_token`, etc.) over bare `token`, or excluding common non-secret value tokens (`read`, `write`, `none`) for the generic-assignment rule specifically.
- [ ] Do a broader false-positive pass now that the repo itself is a real (if small) corpus: rerun `oneleak scan .` after any detector change and treat new findings as a signal, not just test-suite green.

### Test coverage (plan.md's stated bar: positive/negative/boundary per rule)
- [ ] Full coverage for all ~20 provider secret rules in `oneleak/builtin_rules/secrets.yaml` — currently AWS (both rules), GitHub PAT, OpenAI, Anthropic, Stripe, npm, and Azure have explicit tests (`tests/test_scanner.py::TestProviderRules`). GitLab, Slack, Twilio, Datadog, Google, and PyPI have none yet.
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
- `oneleak[pii-ml]` / a real Presidio adapter (the extra was dropped this session until this is actually implemented — see Priority 0/checklist above)

**MCP server** (spec.md §33's "fast-follow", plan.md Step 52): still not built. It was tracked as a near-term v0.1.x fast-follow, not a v1.0-hardening item, so it stays out of this checklist — but its priority should be re-evaluated once v1.0 ships, since "agent-friendly" is core to oneleak's positioning (PRD §8/§18) and the MCP server is the most direct way to deliver on that versus the general Python/CLI API already in place.
