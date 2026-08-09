# How Scanning & Sanitization Work

This page explains the actual mechanism behind `scan()` and `sanitize()`: the pipeline stages, why they're ordered the way they are, and the specific bugs that ordering was chosen to avoid. If you just want to *use* oneleak, see [Quickstart](quickstart.md). This page is for understanding or extending its internals.

## The detection pipeline

Every scan (text, a file, a directory, a git diff hunk) goes through the same sequence, implemented in `oneleak/scanner.py::scan_text()`:

```mermaid
flowchart TD
    A[Input text] --> B[Candidate generation]
    B --> C[Disabled-rule filtering]
    C --> D[Suppression<br/>#35; oneleak: allow]
    D --> E[Overlap resolution]
    E --> F[Finding construction<br/>preview + fingerprint]
    F --> G[Config filters<br/>severity_overrides, allow.paths]
    G --> H[Findings]
```

### 1. Candidate generation

`_generate_candidates()` collects raw matches from four independent sources, each producing a `RuleMatch(start, end)` span before anything is filtered or ranked:

- **Regex rules** (`detectors.py::regex_candidates()`): every built-in and custom declarative rule with a `pattern`. If the rule also has `keywords`, a match only counts if one of those keywords appears within ~60 characters before it on the same line (`_has_keyword_context()`). This is what lets a rule like `aws-secret-access-key` require both a specific 40-character shape *and* nearby context, instead of flagging every base64-looking string in a codebase.
- **Generic assignment detection** (`detectors.py::generic_assignment_candidates()`): a single regex over key names like `password`, `token`, `api_key`, matched against common assignment syntax (`key = "value"`, `key: value`, `KEY=value`). This is what catches secrets that don't match any specific provider's format.
- **Entropy detection** (`detectors.py::entropy_candidates()`): scans for base64-alphabet runs (20-100 characters) and computes Shannon entropy on each. Deliberately excludes pure-hex runs (git hashes and checksums are indistinguishable from real secrets by entropy alone) and known-shape false positives like UUIDs. This is the lowest-confidence, lowest-priority signal. See [Overlap resolution](#4-overlap-resolution) below.
- **Python rules**: any `PythonRule` instances passed via `rules=[...]`, called directly. Never auto-loaded from files. See [Custom Rules](rules.md).

Each regex match with a `validator` (`luhn`, `iban`, `ssn`, `ipv4`, `ipv6`, `jwt`) is checked immediately. A candidate that fails validation is dropped before it ever becomes a `_Candidate`, not filtered out later.

### 2. Disabled-rule filtering

Rules turned off via `.oneleak.yaml`'s `disabled_rules` or `pii: {<type>: false}` are removed next (`_disabled_rule_ids()`). This happens before suppression and overlap resolution so a disabled rule never competes for a span in the first place.

### 3. Suppression: *before* overlap resolution, deliberately

Inline `# oneleak: allow` (optionally scoped to a rule ID) is applied next. This ordering is load-bearing, not incidental: suppression used to run *after* overlap resolution, and that was a real bug. Consider:

```python
api_key = "AKIAABCDEFGHIJKLMNOP"  # oneleak: allow aws-access-key-id
```

Two rules match this span: `aws-access-key-id` (priority 100) and the generic-assignment rule (priority 50). [Overlap resolution](#4-overlap-resolution) keeps only the higher-priority one. If suppression ran *after* that resolution, scoping the `allow` comment to `aws-access-key-id` would discard the only surviving candidate for that span: the generic-assignment rule that would have caught it independently was already gone, discarded during overlap resolution before suppression got a say. The result: a narrowly-scoped suppression silently suppressed *everything* on that line, not just the one rule.

Running suppression first fixes this: the suppressed candidate is removed from the pool, then overlap resolution runs on what's left, so `generic-secret` is free to win the span and still get reported.

### 4. Overlap resolution

One value can match multiple rules: an OpenAI key is both `openai-api-key`-shaped *and* high-entropy. `_resolve_overlaps()` sorts all surviving candidates by `(priority descending, span length descending, start position, rule ID)` and greedily accepts non-overlapping candidates in that order, so the highest-priority rule always wins a contested span:

```text
structural anchor (PEM, JWT, connection-string): 110
provider-specific pattern (AWS, GitHub, OpenAI, ...):  90-100
keyword-anchored generic pattern (Datadog, Azure):      70
generic credential assignment:                          50
entropy-only:                                            10
```

Structural-anchor formats sit *above* provider-specific patterns because a connection-string password can incidentally look like an email address's `local@domain` shape. The more structurally-specific match should win regardless of span length.

### 5. Finding construction

Each surviving candidate becomes a `Finding`: line/column computed from the byte offset, a masked `preview` (`_safe_preview()`, type-specific, e.g. `a***@example.com` for email, `<PRIVATE_KEY>` for keys, never the raw value), and a `fingerprint` (see below). Raw sensitive values are never stored on a `Finding`.

### 6. Config filters

Finally, `_apply_config_filters()` applies `severity_overrides` (swap a finding's severity per `.oneleak.yaml`) and `allow.paths` (drop findings under an allowed path entirely). This step, along with disabled-rule filtering, is applied through one shared function, `scan_text_with_config()`, used identically by `scan()`, `git.scan_changed()`/`scan_staged()`/`scan_history()`, and `sanitize()`. That's deliberate: earlier, each of those entry points independently reimplemented "apply the config," and each one launched with a slightly different bug (`git.py` and later `sanitize()` both shipped without `allow.paths`/`disabled_rules` support at various points before this was consolidated). One shared function means that class of bug can't reappear at a fourth call site.

## Fingerprinting

A fingerprint identifies a value without storing it: `HMAC-SHA256(key, rule_id + ":" + normalized_value)`, truncated and prefixed by category (`sec_`, `pii_`, `sen_`, or `fnd_` for a custom Python rule's non-standard category). The key is, in order of preference: an explicit key passed by the caller, the `ONELEAK_FINGERPRINT_KEY` environment variable, or a random 32-byte key generated once per process and reused for that process's lifetime.

HMAC (not a plain hash) matters specifically for low-entropy values like SSNs. A plain `sha256(ssn)` is reversible by brute force (there are only ~10 billion possible SSNs, so an attacker can hash all of them once and build a lookup table). Mixing in a secret key defeats that, *provided the key itself never ends up alongside the fingerprints it produced*. See the warning in [Sanitization](sanitization.md#the-mapping-file-is-a-vault-not-a-log) about the equivalent risk for mapping files.

## Sanitization

`sanitize()` reuses `scan()`'s findings. It is not a second detection system. The algorithm, in `sanitizer.py::sanitize_text()`:

1. **Assign placeholders.** Findings are processed in text order. Each gets a placeholder `<TYPE_N>` where `TYPE` is the finding's `type` uppercased and `N` increments per type. Before assigning a new number, the finding's fingerprint is checked against fingerprints already seen in this call (or carried in via `seed_mapping`, for cross-call consistency). A repeated value reuses its existing placeholder instead of getting a new number. This is why `alice@example.com` mentioned three times in one document becomes `<EMAIL_1>` all three times, not `<EMAIL_1>`, `<EMAIL_2>`, `<EMAIL_3>`.
2. **Replace right-to-left.** Findings are sorted by start offset *descending* and replaced in that order. This is the only replacement order that's safe without re-computing offsets after every substitution: replacing a span earlier in the text would shift the character positions of every finding after it, invalidating their stored offsets. Replacing from the end backwards means each replacement only affects text *after* the point already processed.
3. **Build the mapping, conditionally.** If `reveal=True`, a `MappingEntry(value, rule_id, fingerprint)` is recorded per placeholder. If not, this step is skipped entirely and `result.mapping` stays `None`. This is the one deliberate exception to "never return raw values by default," and it's opt-in for a reason: see [Sanitization](sanitization.md) for what that mapping actually is (a reversible token vault, not an audit log) and how to handle it safely.

`desanitize()` is the inverse: a plain per-placeholder string replace, `text.replace(placeholder, entry.value)` for each mapping entry. Placeholders in the mapping that never appear in the given text, and placeholder-shaped tokens in the text that aren't in the mapping, are left untouched rather than raising, since sanitized text often passes through an LLM before coming back, and the model may not echo every placeholder verbatim.

## Git history scanning

`git.scan_history()` (see [CLI Reference](cli.md#git-history-scanning)) needs to find secrets that were committed and later removed, something scanning current content can never do. The naive approach (rescan every file's full content at every commit) is correctness-safe but wastefully redundant: a file touched 50 times gets rescanned in full 50 times.

Instead, `_commit_diff_hunks()` parses `git diff --unified=0`'s output per commit and extracts only the *added* lines, grouped by diff hunk. A hunk's added lines are joined into one text blob (preserving their relative newlines) before being run through the normal `scan_text_with_config()` pipeline, the same pipeline described above, just fed a diff hunk's content instead of a whole file.

The join-into-one-blob step is not an optimization detail. It's a correctness requirement. Scanning each added line independently, one `scan_text()` call per line, would break multi-line secret formats. A PEM private key's `-----BEGIN...-----` and `-----END...-----` markers can be many lines apart. If each line were scanned as an isolated string, the two markers would never appear in the same piece of text for the PEM regex to match across. Joining a hunk's added lines into one blob preserves that adjacency while still only scanning what the commit actually introduced.

Each finding's line number is then translated from "line within the hunk" back to "line within the file at that point in history" using the hunk's starting line (parsed from the `@@ -a,b +start,count @@` header), and stamped with the commit SHA that introduced it (`Finding.commit`).

## See also

- [Sanitization](sanitization.md): the reversible-mapping workflow and how to use it safely from an agent
- [Custom Rules](rules.md): the rule schema and priority tiers in more detail
- [CLI Reference](cli.md#git-history-scanning): `--history` flags and defaults
- `oneleak/scanner.py`, `oneleak/detectors.py`, `oneleak/sanitizer.py`, `oneleak/git.py`: the actual implementation. Every function named on this page lives in one of those four files
