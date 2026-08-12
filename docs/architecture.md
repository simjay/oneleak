# How Scanning & Sanitization Work

How `scan()` and `sanitize()` work inside: the pipeline stages, and why they run in this order.

Reading this is optional. To just *use* oneleaks, start with the [Quickstart](quickstart.md).

## Secrets and PII share one pipeline

oneleaks scans for both in a single pass. There is no separate PII engine.

What differs is not the machinery but the **evidence** each category can rely on.

| | Secrets | PII |
|---|---|---|
| Rules | 56 | 10 |
| Anchored on a literal prefix | 44 | 3 |
| Confirmed by a checksum | 1 | 7 |
| Typical severity | high, critical | low, medium |

The reason is that providers *want* their tokens found. AWS stamps `AKIA` on access keys and GitHub stamps `ghp_` on tokens, partly so scanners can spot a leak. A fixed prefix is strong evidence on its own.

Nobody stamps a prefix on a credit card number. PII has to be confirmed a different way, usually by a checksum such as Luhn or Mod-97, or by a complete structural shape like an IPv4 address.

Severity follows from that. A leaked AWS key is actionable immediately, so secret rules sit at high or critical. An email address in a log file is a privacy concern rather than an emergency, so most PII sits at low or medium.

!!! info "Where this lives in the code"

    `secret_rules.py` and `pii_rules.py` are peer modules, one per category. Each owns loading its own rule file, and nothing else.

    Everything downstream is category-agnostic. Matching, validation, and overlap resolution never branch on whether a rule is a secret or PII rule.

    They cannot be split further, because overlap resolution needs candidates from both categories in one pool. A connection-string password can look exactly like an email address.

## The detection pipeline

Every scan runs the same six stages, whether the input is text, a file, a directory, or a git diff hunk. The code is in `scanner.py::scan_text()`.

```mermaid
flowchart TD
    A[Input text] --> B[1 · Candidate generation]
    B --> C[2 · Disabled-rule filtering]
    C --> D[3 · Suppression<br/>#35; oneleaks: allow]
    D --> E[4 · Overlap resolution]
    E --> F[5 · Finding construction<br/>preview + fingerprint]
    F --> G[6 · Config filters<br/>severity_overrides, allow.paths]
    G --> H[Findings]
```

### 1. Candidate generation

Four detectors run independently over the input. Each returns raw `RuleMatch(start, end)` spans, before any filtering or ranking.

| Detector | What it matches | Source |
|---|---|---|
| **Regex rules** | Built-in and custom rules with a `pattern` | `regex_candidates()` |
| **Generic assignment** | `password = "..."`, `api_key: ...`, `TOKEN=...` | `generic_assignment_candidates()` |
| **Entropy** | Base64-alphabet runs of 20 to 100 chars, high Shannon entropy | `entropy_candidates()` |
| **Python rules** | Whatever your `PythonRule.detect()` returns | your code |

Two details worth knowing.

**Keywords narrow matches, they do not find them.** When a rule has `keywords`, a regex match only counts if one of those words appears within about 60 characters before it on the same line. This lets `aws-secret-access-key` demand both a 40-character shape and nearby context.

**Validators run immediately.** A match with a `validator` is checked on the spot, and failures are dropped here rather than filtered later. This is the stage where most PII is confirmed.

??? note "Why oneleaks does not use a keyword prefilter"

    Some scanners run a fast keyword search first, then run the slower regex only on text that passed. It is a performance optimization for large repositories.

    oneleaks does the opposite. Every regex always runs over the whole input, and `keywords` is checked afterwards against a window near a match that was already found.

    The tradeoff: oneleaks pays full regex cost regardless of keyword presence. In exchange the pipeline has no "did any keyword appear in this file" pass to keep correct.

### 2. Disabled-rule filtering

Rules switched off in `.oneleaks.yaml` are removed next, through `disabled_rules` or `pii: {<type>: false}`.

This runs early on purpose, so a disabled rule never competes for a span in stage 4.

### 3. Suppression

Inline `# oneleaks: allow` comments are applied here, optionally scoped to one rule ID.

!!! warning "This stage must run before overlap resolution"

    It used to run after, and that was a real bug. Take this line:

    ```python
    api_key = "AKIAABCDEFGHIJKLMNOP"  # oneleaks: allow aws-access-key-id
    ```

    Two rules match that span. `aws-access-key-id` has priority 100 and the generic-assignment rule has 50. Overlap resolution keeps only the winner.

    Suppressing after resolution meant the generic-assignment candidate was already gone. Removing the winner then left nothing, so a comment scoped to one rule silently suppressed the whole line.

    Suppressing first leaves the generic rule in the pool, free to win the span and still be reported.

### 4. Overlap resolution

One value often matches several rules. An OpenAI key is both `openai-api-key`-shaped and high-entropy.

`_resolve_overlaps()` sorts every surviving candidate by `(priority desc, span length desc, start, rule ID)`. It then walks that order and accepts any candidate not overlapping one already accepted. Highest priority wins a contested span.

| Tier | Priority | Examples |
|---|---|---|
| Structural anchor | 110 | PEM, JWT, connection string |
| Provider-specific | 90 to 100 | AWS, GitHub, OpenAI |
| Keyword-anchored generic | 70 | Datadog, Azure |
| Generic assignment | 50 | `password = ...` |
| Entropy only | 10 | high-entropy string |

Structural anchors outrank provider patterns for a concrete reason. A connection-string password can look like an email's `local@domain` shape. The more structurally specific match should win regardless of span length.

This is also the stage that requires secrets and PII to stay in one pool. Splitting them into separate pipelines would let both categories claim the same span.

### 5. Finding construction

Each surviving candidate becomes a `Finding` carrying line and column, a masked `preview`, and a `fingerprint`.

Previews are type-specific. Email becomes `a***@example.com`, and a private key becomes `<PRIVATE_KEY>`.

**A `Finding` never holds the raw value.**

### 6. Config filters

Finally `_apply_config_filters()` applies two things from `.oneleaks.yaml`:

- `severity_overrides` swaps a finding's severity
- `allow.paths` drops findings under matching paths entirely

??? note "Why every entry point shares one function"

    Config filtering runs through a single shared function, `scan_text_with_config()`. It is used identically by `scan()`, all three `git.scan_*()` functions, and `sanitize()`.

    Each of those once applied config itself, and each shipped with a different piece missing. Both `git.py` and `sanitize()` went out without `allow.paths` support at some point.

    One shared function means that class of bug cannot reappear at a fourth call site.

## Fingerprinting

A fingerprint identifies a value without storing it:

```text
HMAC-SHA256(key, rule_id + ":" + normalized_value)
```

The result is truncated and prefixed by category: `sec_`, `pii_`, `sen_`, or `fnd_` for a custom Python rule with a non-standard category.

The key is chosen in this order:

1. An explicit key passed by the caller
2. The `ONELEAKS_FINGERPRINT_KEY` environment variable
3. A random 32-byte key, generated once per process

!!! info "Why HMAC instead of a plain hash"

    It matters most for PII, because PII values are often low-entropy.

    There are only about 10 billion possible SSNs. That makes `sha256(ssn)` reversible: an attacker hashes all of them once and builds a lookup table.

    A secret key defeats that, as long as the key never travels alongside the fingerprints it produced. The same risk applies to [mapping files](sanitization.md#the-mapping-file-is-a-vault-not-a-log).

## Sanitization

`sanitize()` reuses `scan()`'s findings. It is not a second detection system.

**1. Assign placeholders.** Each finding gets `<TYPE_N>`, where `TYPE` is its type uppercased and `N` counts up per type.

Before assigning a new number, oneleaks checks the finding's fingerprint against ones already seen. A repeated value reuses its placeholder.

That is why `alice@example.com` appearing three times becomes `<EMAIL_1>` all three times, not `<EMAIL_1>`, `<EMAIL_2>`, `<EMAIL_3>`. Passing `seed_mapping` extends this across separate calls.

**2. Replace right to left.** Findings are replaced in descending order of start offset.

This is the only order that is safe without recomputing offsets after every substitution. Replacing an earlier span shifts the position of everything after it. Working backwards means each replacement only touches text already processed.

**3. Build the mapping, only if asked.** With `reveal=True`, each placeholder records a `MappingEntry(value, rule_id, fingerprint)`. Otherwise this step is skipped and `result.mapping` stays `None`.

This is the one deliberate exception to "never return raw values by default". See [Sanitization](sanitization.md) for handling that mapping safely.

### Reversing it

`desanitize()` is a plain string replace, one per mapping entry.

Unmatched placeholders are left alone rather than raising, in both directions. Sanitized text often passes through an LLM before coming back, and the model may not echo every placeholder verbatim.

## Git history scanning

`git.scan_history()` finds secrets that were committed and later removed. Scanning current content can never do that.

Rescanning every file at every commit would work, but it is wasteful. A file touched 50 times would be read 50 times in full.

Instead `_commit_diff_hunks()` parses `git diff --unified=0` per commit and keeps only the added lines, grouped by hunk. Each hunk's added lines are joined into one blob and run through the normal pipeline.

!!! important "Joining a hunk into one blob is correctness, not optimization"

    Scanning added lines one at a time would break multi-line formats.

    A PEM private key's `-----BEGIN-----` and `-----END-----` markers sit many lines apart. Scanned as isolated strings, the two markers never appear in the same text, so the regex can never match across them.

    Joining preserves that adjacency while still only scanning what the commit actually introduced.

Line numbers are then translated from hunk-relative back to file-relative using the hunk header, and stamped with the commit SHA that introduced them (`Finding.commit`).

## See also

- [Concepts](concepts.md) for the reasoning behind these choices
- [Sanitization](sanitization.md) for the reversible-mapping workflow
- [Custom Rules](rules.md) for the rule schema and priority tiers
- [CLI Reference](cli.md#git-history-scanning) for `--history` flags

Every function named on this page lives in `scanner.py`, `detectors.py`, `sanitizer.py`, or `git.py`.
