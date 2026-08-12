# Concepts

The reasoning behind oneleaks's design.

[How Scanning & Sanitization Work](architecture.md) covers *what* the pipeline does. This page covers *why* it does it that way, so choices that look arbitrary have a reason attached.

---

# Part 1 · Finding things

## The layered approach

Almost every scanner in this space breaks "is this string sensitive?" into layers:

| Layer | Question | Cost |
|---|---|---|
| Pattern | Is this shaped like something interesting? | cheap, syntactic |
| Context | Does anything nearby corroborate it? | keywords, structure |
| Verification | Can I independently confirm it is valid? | math or network |

Why not one big regex? Because each layer alone fails in its own way:

- **Pattern only** misses unknown formats. It also cannot tell `password = "hello123"` from `password = "REDACTED"`.
- **Context only**, meaning just the word "password", floods you with false positives.
- **Entropy only** flags UUIDs, hashes, base64 images, and minified JS.

oneleaks's [detection pipeline](architecture.md#the-detection-pipeline) is this idea, formalized.

## Secrets and PII need different evidence

This is the most important distinction on the page, and it drives most of what follows.

Both categories run through one pipeline. What differs is what counts as proof.

| | Secrets | PII |
|---|---|---|
| Built-in rules | 56 | 10 |
| Anchored on a literal prefix | 44 | 3 |
| Confirmed by a checksum | 1 | 7 |
| Typical severity | high, critical | low, medium |

**Secrets announce themselves.** Providers deliberately stamp identifiable prefixes on their tokens so scanners can find leaks. AWS uses `AKIA`, GitHub uses `ghp_`, Stripe uses `sk_live_`. A fixed prefix plus a fixed length is strong evidence by itself, which is why 44 of 56 secret rules need nothing more.

**PII has no vendor.** Nobody stamps a prefix on a credit card number or an SSN. So PII leans on the other two kinds of proof:

- **Checksums.** Luhn for cards, Mod-97 for IBANs, the 3/7/1 weighting for routing numbers.
- **Complete structural shapes.** An IPv4 address is fully specified, so the shape *is* the proof.

That difference explains a rule that would otherwise look inconsistent. A bare 32-character hex string is not enough to flag as a Datadog key, so that rule is keyword-gated. A bare 9-digit number is not enough to flag as a routing number either, so that one is keyword-gated *and* checksum-validated.

**Severity follows the same split.** A leaked AWS key is actionable the moment it lands, so secret rules sit at high or critical. An email address in a log is a privacy issue rather than an emergency, so most PII sits at low or medium.

The deliberate exceptions are SSN and credit card at high, and IMEI at medium. Those specific values enable direct fraud on their own.

## Pattern matching

The simplest layer, and the primary tool for secrets. Providers bake an identifiable prefix into their tokens on purpose.

```text
AWS access key    →  AKIA[0-9A-Z]{16}
GitHub PAT        →  ghp_[A-Za-z0-9]{36}
OpenAI key        →  sk-proj-...
Stripe secret key →  sk_live_...
```

High precision, but zero recall on anything outside your pattern library: internal tools, new providers, one-off tokens.

It is also the layer with the most reinvent-the-wheel risk. Hundreds of vetted patterns already exist in projects like gitleaks' rule file. Writing your own means rediscovering every edge case others already hit. That is why oneleaks lets you [add your own patterns](rules.md) rather than fork.

!!! danger "ReDoS: the regex trap"

    A badly written regex with nested quantifiers like `(a+)+b` can take exponential time on crafted input. That is Regular Expression Denial of Service.

    It matters here because a scanner runs regexes over arbitrary repository content, which is attacker-influenced in some workflows such as scanning PR content.

    Prefer patterns adapted from well-exercised sources over hand-written ones.

## Entropy

The catch-all for secrets that match no known pattern.

Random data from a CSPRNG looks statistically different from human-written text. Shannon entropy measures how surprising each character is, on average.

```text
entropy(s) = -Σ p(c) · log2(p(c))   for each character c in s
```

`aaaaaaaa` scores low. `kX9$mQ2!vR` scores high.

In practice: extract token-like candidates, compute entropy over each, flag the ones above a threshold.

**Why it produces false positives.** Entropy sees only one string's local character distribution. It has no idea what is normal in real code.

A UUID like `f47ac10b-58cc-4372-a567-0e02b2c3d479` scores as high-entropy but is almost never a secret. The same goes for commit hashes, package checksums, and minified identifiers.

This is the single biggest false-positive source in entropy-based scanners, which is why oneleaks excludes pure-hex runs and UUID shapes by exact check *before* computing entropy at all. That is cheaper and more precise than tuning one threshold to handle every false-positive class.

## Validators

The primary tool for PII. A regex candidate gets checked against a mathematical rule, which drops coincidental matches.

| Validator | Applies to | How it works |
|---|---|---|
| `luhn` | Credit cards, IMEI | Check digit from a doubling and summing rule |
| `iban` | Bank accounts | Mod-97 checksum over a rearranged number |
| `aba_routing` | US routing numbers | 3/7/1-weighted digit sum, mod 10 |
| `ssn` | US SSNs | Structurally invalid ranges rejected |
| `ipv4`, `ipv6` | IP addresses | Standard library `ipaddress` parsing |
| `jwt` | JWTs | Header decodes to JSON containing `alg` |

The general pattern: **regex narrows candidates, a validator confirms them.** That is why a rule carries both a `pattern` and an optional `validator`.

Checksums are not free precision. A random 16-digit number still passes Luhn about one time in ten. That is far better than no check, and cheap, but it is not proof.

??? note "The SSN validation bug worth knowing about"

    SSNs were once validated against a table mapping area numbers to states.

    The SSA's 2011 randomization removed that mapping. Validators still using the old table now **reject real, valid, post-2011 SSNs**.

    It is a common bug in copy-pasted SSN validators, worth recognizing outside this project too. oneleaks checks only the permanently-invalid ranges: area `000`, `666`, `900-999`, group `00`, serial `0000`.

## Structural anchors

Some formats identify themselves, independent of entropy or checksums:

- **PEM keys** start with `-----BEGIN ... KEY-----` and end with a matching `-----END-----`.
- **JWTs** are three dot-separated base64url segments whose first segment decodes to JSON containing `alg`.

When a format has an anchor this strong, match the anchor first and treat entropy as corroboration.

That is more precise, and it avoids double-counting. A JWT segment is also high-entropy, so without anchor priority you would get two findings for one secret.

## Overlap resolution

One secret can match several rules. An OpenAI key matches both `openai-api-key` and the generic high-entropy rule.

Without resolution you would emit two findings, and worse, two different placeholders, for one secret.

The fix is a priority order, most specific wins:

```text
structural anchor > provider-specific > keyword-anchored generic
                  > generic assignment > entropy-only
```

When two spans overlap, keep only the highest-priority finding.

This is also why secrets and PII cannot be split into separate pipelines. A connection-string password can look exactly like an email address, so both categories have to compete in one pool.

## Precision and recall

```text
precision = true positives / (true positives + false positives)
recall    = true positives / (true positives + false negatives)
```

Precision answers "when I flag something, how often am I right?" Recall answers "of all real secrets, how many did I catch?"

The two trade off. Tuning for recall flags more non-secrets. Tuning for precision misses more real ones.

Secret detection leans toward recall, because a missed credential is far worse than a false positive someone dismisses.

---

# Part 2 · Handling what you find

## Fingerprinting

You often need to say "this is the same secret I saw before", for baselines or for consistent placeholders, without keeping the value.

The standard technique is a **keyed hash (HMAC)**, not a plain hash.

A plain hash of a low-entropy value is reversible by brute force. An attacker hashes every possible input once and builds a lookup table.

This matters most for PII, precisely because PII values are low-entropy. There are only about 10 billion possible SSNs. A secret key defeats the attack, provided the key stays separate from anything shipping the fingerprints.

## Redaction vs tokenization

Two different things get called "sanitization":

| | Redaction | Tokenization |
|---|---|---|
| Direction | One-way | Reversible |
| Output | `***`, `[REDACTED]` | A token plus a separate mapping |
| Recovery | Impossible from output alone | Authorized lookup through the vault |

Tokenization is the idea payment processors use. A card number becomes a token, and the real number lives only in a compliant vault. LLM gateways do the same, redacting PII before the prompt and reinserting real values into the output.

oneleaks's `sanitize(reveal=True)` plus `desanitize()` is tokenization. **The mapping file is the vault.**

That is why it is never written by default, gets `0600` permissions, and prints a warning when written. A leaked mapping file is exactly as bad as a leaked secret.

---

# Part 3 · Living with false positives

Every real scanner accumulates known false positives, such as test fixtures and example keys in docs. Three mechanisms, increasing in scope:

**Inline suppression.** A comment next to the line (`# oneleaks: allow`), for one-off known-safe values.

**Allowlist.** Config that exempts a path or rule entirely, for things that are structurally always safe like a fixtures directory. `allow.paths` treats matching content as genuinely not sensitive, which is why it applies to `sanitize()` too. Nothing there needs redacting.

**Baseline.** A snapshot of current findings, stored by fingerprint, that future scans diff against. New findings fail, and existing ones are tracked as accepted debt. It is the standard way to adopt a scanner on a codebase that already has findings.

!!! important "A baselined finding is still a real secret"

    Unlike an allowlist, a baseline says "already triaged", not "not sensitive".

    So it deliberately suppresses `scan()`'s *reporting* but **not** `sanitize()`'s redaction. A known secret must never leak into sanitized output.

See [Inline suppression](rules.md#inline-suppression) and [Baselines](configuration.md#baselines).

---

# Part 4 · Extending it safely

## Declarative rules vs plugins

Two ways scanners let you extend detection:

| | Declarative | Plugin, imperative |
|---|---|---|
| A rule is | Data: pattern, keywords, severity | Code: arbitrary logic |
| Examples | gitleaks TOML, oneleaks YAML/JSON | detect-secrets plugins, `PythonRule` |
| Power | Limited to the schema | Unlimited |
| Safe to auto-load? | **Yes** | **Never** |

Auto-loading code from repository config is a remote-code-execution vector. Anyone able to add a file could run code in your CI.

oneleaks supports both with an explicit boundary. YAML and JSON can never execute code. Python rules require opt-in registration in your own code, never auto-discovery.

---

# Part 5 · Roads not taken

## Token efficiency (BPE)

In 2026 [Betterleaks](https://github.com/betterleaks/betterleaks), a gitleaks successor from the same author, replaced Shannon entropy with **token efficiency**, measured using a BPE tokenizer.

**The theory.** A BPE tokenizer learns to merge frequently co-occurring byte sequences into single tokens.

Structured-but-random-looking data tokenizes *efficiently*, because the tokenizer saw those shapes constantly in training. A genuine CSPRNG secret is a novel byte sequence, so it tokenizes *inefficiently*. Low token efficiency then acts as a proxy for true randomness.

**What we measured.** Tested as a candidate `oneleaks[bpe]` extra using `tiktoken`'s `cl100k_base`, against the false-positive classes oneleaks actually sees:

| Input | chars/token |
|---|---|
| Fresh CSPRNG secrets | 1.33 to 1.60 |
| npm/yarn lockfile hash | 1.41 |
| base64-encoded English | 1.38 |
| base64-encoded JSON | 1.40 |

Real secrets and false positives land in the same band. The signal does not separate them.

**Why the idea is sound but does not help here.** oneleaks already strips the classes token efficiency is best at catching, pure-hex and UUIDs, using cheap exact checks before entropy runs.

Betterleaks' framing is "one general signal instead of hand-written carve-outs". Adding it on top of carve-outs that already handle that class leaves it nothing to do.

**Not adopted.** A `tiktoken` dependency, and losing "PyYAML is the only required dependency", is not worth a filter that measurably does not discriminate in this pipeline.

??? note "On Betterleaks' published benchmark"

    Betterleaks reports 98.6% versus 70.4% recall on the CredData dataset.

    That reflects its own evaluation setup rather than an independent replication. It evidently measures a broader false-positive distribution than the one remaining after oneleaks's existing checks.

## Live credential verification

TruffleHog calls the provider's API to check whether a candidate credential is *currently valid*.

That kills a whole class of false positives, such as expired and example keys, which no amount of pattern or entropy analysis can catch. Validity is a fact about the provider's live state, not the string's shape.

**Why oneleaks does not do it:**

- It needs per-provider integration code tracking auth quirks, rate limits, and endpoint churn across hundreds of APIs, indefinitely. That is a sustained maintenance burden a small library is not positioned to carry.
- The scanner stops being deterministic and offline. A `verified: false` result might just mean the network call failed.

The README says "no network calls **required**" deliberately, not "never". An opt-in mode would not break that promise. Maintenance cost is the real reason.

---

# Part 6 · Fitting into a workflow

## Git scanning modes

| Mode | Reads | Catches |
|---|---|---|
| **Changed** | Working tree, files differing from HEAD | What is on disk right now |
| **Staged** | Git's index | What `git add` queued, which can differ from disk |
| **History** | Every commit's diff | Secrets committed and later removed |

Staged and changed genuinely differ. Edit a file after staging it and the two disagree, so scanning staged content reads the index rather than the file.

History matters because a secret committed and later "removed" stays recoverable until history is rewritten. That is why it is a separate, heavier feature.

## MCP

A protocol from Anthropic that lets an LLM agent call external tools in a standardized way, over stdio or HTTP. It is effectively a plugin API for agents.

An MCP server exposes callable tools, and any compatible agent can use them without per-agent integration code.

For oneleaks that is the natural way to plug `scan` and `sanitize` into an arbitrary agent runtime: expose them once instead of writing glue for every framework.

---

## Glossary

| Term | Definition |
|---|---|
| Shannon entropy | Statistical measure of how random a string's characters are |
| Token efficiency | BPE-compression-based entropy alternative, evaluated and not adopted |
| ReDoS | Regex Denial of Service, where a pathological regex takes exponential time |
| Luhn | Checksum validating credit card numbers and IMEIs |
| Mod-97 | Checksum validating IBANs |
| HMAC | Keyed hash resisting the brute-force reversal plain hashing allows |
| Fingerprint | One-way identifier recognizing a repeated value without storing it |
| Redaction | One-way replacement, where the original cannot be recovered |
| Tokenization | Reversible replacement, where a separate vault recovers the original |
| Precision | Of things flagged, what fraction are real |
| Recall | Of real things, what fraction got flagged |
| Allowlist | Config exemption treating content as genuinely not sensitive |
| Baseline | Snapshot of accepted findings, failing only on new ones |
| Structural anchor | A fixed marker like `-----BEGIN KEY-----` used to detect a format directly |
| Declarative rule | A rule expressed as data, not code, safe to load from untrusted config |
| MCP | Model Context Protocol, a standard way for agents to call external tools |
