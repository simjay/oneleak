# Concepts

[How Scanning & Sanitization Work](architecture.md) explains *what* happens when you run a scan.
This page explains *why* it was built that way, so the choices that look odd
have a reason attached.

---

# Part 1 · Deciding whether something is sensitive

## Three kinds of evidence

Almost every scanner answers "is this string sensitive?" using three kinds of
evidence, in increasing order of cost:

| Layer | The question it answers | What it costs |
|---|---|---|
| Pattern | Does this look like a key? | Cheap. A regex match. |
| Context | Does anything nearby back that up? | A quick look at the same line. |
| Verification | Can I confirm it independently? | A checksum, or a network call. |

Why not one big pattern? Because each kind of evidence fails on its own:

- **Pattern alone** misses formats it has never seen. It also cannot tell
  `password = "hello123"` from `password = "REDACTED"`.
- **Context alone**, meaning just spotting the word "password", floods you with
  false positives.
- **Entropy alone** flags UUIDs, checksums, base64-encoded images, and minified
  JavaScript.

oneleaks uses all three. [How Scanning & Sanitization Work](architecture.md#the-detection-pipeline)
walks through the order they run in.

## Secrets and PII need different evidence

This is the most important idea on the page, and most of what follows comes
from it.

Both go through the same scan. What differs is what counts as proof.

| | Secrets | PII |
|---|---|---|
| Built-in rules | 65 | 10 |
| Anchored on a literal prefix | 53 | 3 |
| Confirmed by a checksum | 1 | 7 |
| Usual severity | high, critical | low, medium |

**Secrets announce themselves.** Companies deliberately stamp a recognisable
prefix on their keys, precisely so scanners can spot a leak. AWS uses `AKIA`,
GitHub uses `ghp_`, Stripe uses `sk_live_`. A fixed prefix plus a fixed length
is strong evidence on its own, which is why most secret rules need nothing
else.

**PII has no company behind it.** Nobody stamps a prefix on a card
number. So those rules lean on the other two kinds of evidence:

- **Checksums.** Card numbers, bank accounts and routing numbers each carry a check
  digit worked out from the rest of the number. If the checksum does not come out
  right, the number is not real.
- **Complete shapes.** An IP address is fully described by its shape, so the
  shape *is* the proof.

That explains a pair of rules that would otherwise look inconsistent. A bare
32-character string of hex is not enough to call a Datadog key, so that rule
also needs the word "datadog" nearby. A bare 9-digit number is not enough to
call a bank routing number either, so that rule needs a nearby word **and** a
correct checksum.

**Severity splits the same way.** A leaked AWS key can be used the moment it
lands, so secret rules sit at high or critical. An email address in a log file
is a privacy problem rather than an emergency, so most PII rules sit
at low or medium.

The deliberate exceptions are SSNs and card numbers at
high, and IMEIs at medium. Those can be used for fraud directly.

## Pattern matching

The simplest kind of evidence, and the main one for secrets.

```text
AWS access key    →  AKIA[0-9A-Z]{16}
GitHub token      →  ghp_[A-Za-z0-9]{36}
OpenAI key        →  sk-proj-...
Stripe key        →  sk_live_...
```

High precision, and zero recall on anything outside the pattern list: internal
tools, new providers, one-off tokens.

It is also the layer with the most reinvent-the-wheel risk. Hundreds of vetted
patterns already exist in projects like gitleaks. Writing your own
means rediscovering every trap someone else already hit. That is why oneleaks
lets you [add your own patterns](../guides/rules.md) rather than fork it.

!!! danger "ReDoS: the regex trap"

    A badly written regex, one with a repeat inside a repeat like `(a+)+b`, can
    take exponential time on crafted input. That is a regular-expression denial
    of service, or ReDoS.

    It matters here because a scanner runs patterns over whatever is in a
    repository, and in some setups that content comes from strangers, such as
    scanning an incoming pull request.

    Prefer patterns adapted from well-used sources over ones you invent.

## Entropy

The catch-all for secrets that fit no known shape.

Text from a proper random generator looks statistically different from text a
person wrote. **Shannon entropy** measures how surprising each character is, on
average.

`aaaaaaaa` scores low. `kX9$mQ2!vR` scores high.

In practice: extract token-like candidates, compute entropy over each, and flag
the ones above a threshold.

**Why it gets things wrong.** The score only sees one string's own characters.
It has no idea what is normal in real code.

A UUID like `f47ac10b-58cc-4372-a567-0e02b2c3d479` scores high but is almost
never a secret. The same goes for commit hashes, package checksums, and URLs.

This is the single biggest source of false positives in entropy-based scanners.
oneleaks therefore excludes pure-hex runs, UUIDs and URL paths by exact check
*before* computing entropy at all. That is cheaper and more
accurate than trying to tune one threshold to handle every case.

## Validators

The main tool for PII. A candidate found by pattern then has to pass a
checksum, which throws out coincidental matches.

| Validator | Used for | How it works |
|---|---|---|
| Luhn | Card numbers, IMEIs | A check digit worked out by doubling and adding |
| Mod-97 | International bank accounts | A remainder check over the rearranged number |
| ABA | US routing numbers | A weighted sum of the digits, checked against 10 |
| SSN | SSNs | Ranges that can never be issued are rejected |
| IP address | IPv4 and IPv6 | Must parse, and must be an address that can reach the internet |
| JWT | Web tokens | The first part must decode to data containing `alg` |

The general shape is: **a pattern narrows it down, a validator confirms it.** That is
why a rule can carry both a `pattern` and a `validator`.

Checksums are not free accuracy. A random 16-digit number still passes the card
check about one time in ten. Much better than nothing, and cheap, but not
proof. That is why card numbers also have to start with a real issuer's prefix.

??? note "An SSN checking bug worth knowing about"

    SSNs used to be checkable against a table mapping
    the first three digits to a US state.

    In 2011 the issuing agency switched to random assignment and that table
    stopped meaning anything. Checkers still using it now **reject real,
    valid numbers issued since 2011**.

    It is a common bug in copy-pasted code, worth recognising outside this
    project. oneleaks only rejects the ranges that can never be issued at all:
    first three digits `000`, `666` or `900-999`, middle `00`, last four
    `0000`.

## Structural anchors

Some formats say what they are, without needing entropy or a checksum:

- **Private keys** start with `-----BEGIN ... KEY-----` and end with a matching
  `-----END-----`.
- **JWTs** are three dot-separated parts, where the first decodes to JSON
  containing `alg`.

When a format announces itself this clearly, match the anchor first and treat
entropy as corroboration.

That is more precise, and it stops one secret being counted twice. A JWT segment
is also high-entropy, so without anchor priority the same secret would be
reported by two rules.

## Overlap resolution

One secret can match several rules. An OpenAI key matches both the OpenAI rule
and the generic high-entropy rule.

Without a tie-breaker you would get two findings, and worse, two different
placeholders, for one secret.

The tie-breaker is an order, most specific first:

```text
structural anchor  >  provider-specific  >  keyword-anchored generic
                  >  generic assignment  >  entropy-only
```

Where two findings cover the same text, only the highest one is kept.

This is also why secrets and PII cannot be scanned separately. A
password inside a database address can look exactly like an email address, so
both kinds have to compete in one pool.

## Precision and recall

Every scanner sits between two kinds of mistake:

- A **false positive** is flagging something that was not a secret.
- A **false negative** is missing something that was.

**Precision** is how often a thing you flagged was real. **Recall** is how much
of the real stuff you caught. Push hard on one and the other gets worse.

For secrets, oneleaks leans towards recall, because a missed credential is far
worse than a false positive somebody dismisses.

For PII it leans the other way, because an email address in a contributor list
is not an emergency and there are a great many of them.

---

# Part 2 · What to do with what you find

## Fingerprinting

You often need to say "this is the same secret I saw last time", for a
[baseline](../getting-started/configuration.md#baselines) or for consistent
placeholders, without keeping the value itself.

The standard technique is a **keyed hash (HMAC)**, not a plain hash.

A plain hash of a low-entropy value is reversible by brute force: an attacker
hashes every possible input once and builds a lookup table.

That matters most for PII, precisely because PII values are low-entropy. There are only about ten billion possible SSNs. Mixing in a secret key defeats the attack, as long as the key is kept
apart from anything the fingerprints are shipped in.

## Redaction versus tokenization

Two different things both get called "sanitizing":

| | Redaction | Tokenization |
|---|---|---|
| Reversible? | No | Yes |
| What you get | `***`, `[REDACTED]` | A placeholder, plus a separate mapping |
| Getting the original back | Impossible from the output | Only through the vault |

Tokenization is what payment companies do. A card number becomes a placeholder, and
the real number lives only in a secured vault. Services that sit in front
of language models do the same, taking PII out before the prompt and
putting it back in the answer.

`sanitize(reveal=True)` plus `desanitize()` is tokenization. **The mapping file is
the vault.**

That is why it is never written unless you ask, why it is written so only you
can read it, and why writing it prints a warning. A leaked mapping file is
exactly as bad as a leaked secret.

---

# Part 3 · When it gets things wrong

Every real scanner accumulates known false positives: test fixtures, example
keys in documentation. There are three ways to handle them, from narrowest to
broadest.

**A comment on the line.** `# oneleaks: allow` next to one known-safe value.

**A config exemption.** `allow.paths` marks a whole path as genuinely not
sensitive, for something like a folder of test fixtures. Because it means "not
sensitive", it applies to `sanitize()` too. There is nothing there to redact.

**A baseline.** A snapshot of what a scan finds today, stored by fingerprint,
that later scans compare against. New findings fail the build; existing ones
are recorded as known. It is the standard way to start using a scanner on a
codebase that already has findings.

!!! important "A baselined finding is still a real secret"

    Unlike an exemption, a baseline says "already looked at", not "not
    sensitive".

    So it deliberately stops `scan()` **reporting** it, but does not stop
    `sanitize()` **redacting it**. A known secret must never reach sanitized
    output.

See [comments on a line](../guides/rules.md#inline-suppression) and
[baselines](../getting-started/configuration.md#baselines).

---

# Part 4 · Adding your own rules safely

There are two ways scanners let you add detection:

| | Written as data | Written as code |
|---|---|---|
| A rule is | A pattern, some words, a severity | Any logic you like |
| Examples | gitleaks TOML, oneleaks YAML and JSON | detect-secrets plugins, `PythonRule` |
| What it can do | Only what the format allows | Anything |
| Safe to load automatically? | **Yes** | **Never** |

Auto-loading code from repository config is a remote-code-execution vector:
anyone able to add a file could run code in your CI.

oneleaks supports both, with a hard line between them. YAML and JSON rules can
never run code. Python rules have to be handed to `scan()` from your own
program; they are never picked up from a config file.

---

# Part 5 · Things we tried and did not keep

## Token efficiency (BPE)

In 2026 [Betterleaks](https://github.com/betterleaks/betterleaks), a successor
to gitleaks from the same author, replaced Shannon entropy with a measure
called **token efficiency**, from a BPE tokenizer.

**The idea.** A BPE tokenizer learns to merge byte sequences that occur together
often. Structured-but-random-looking data tokenizes *efficiently*, because the
tokenizer saw shapes like it constantly in training. A genuinely random secret
is a novel byte sequence, so it tokenizes *inefficiently*. Low token efficiency
then stands in for true randomness.

**What we measured.** Tried as an optional extra using `tiktoken`, against the
false-positive classes oneleaks actually sees:

| Input | Chars per token |
|---|---|
| Freshly generated secrets | 1.33 to 1.60 |
| npm/yarn lockfile hash | 1.41 |
| base64-encoded English | 1.38 |
| base64-encoded JSON | 1.40 |

Real secrets and false positives land in the same band. The measure does not tell
them apart.

**Why a sound idea does not help here.** oneleaks already removes the exact
classes this is best at catching, pure-hex runs and UUIDs, with cheap exact
checks before entropy runs.

The pitch is "one general signal instead of hand-written carve-outs". Layered on
top of carve-outs that already handle that class, there is nothing left for it
to do.

**Not adopted.** An extra dependency, and giving up "PyYAML is the only thing
you need", is not worth a filter that measurably does not separate the two.

??? note "About their published benchmark"

    Betterleaks reports catching 98.6% against gitleaks' 70.4% on a public test
    set.

    That is their own measurement rather than an independent one, and it
    evidently measures a broader false-positive distribution than the one left
    over after oneleaks' existing checks.

## Live credential verification

TruffleHog calls the provider's API to check whether a candidate credential is
*currently valid*.

That kills a whole class of false positives, such as expired and example keys,
which no amount of pattern or entropy analysis can catch. Validity is a fact
about the provider's live state, not about the string's shape.

**Why oneleaks does not do it:**

- It needs per-provider integration code tracking auth quirks, rate limits and
  endpoint churn across hundreds of APIs, indefinitely. That is a sustained
  maintenance burden a small library is not positioned to carry.
- The scanner stops being deterministic and offline. A `verified: false` result
  might just mean the network call failed.

The README says "no network calls **required**" deliberately, not "never". An
opt-in mode would not break that promise. Maintenance cost is the real reason.

---

# Part 6 · Where it fits in your work

## Git scanning modes

| Mode | Reads | Catches |
|---|---|---|
| **Changed** | Files on disk that differ from the last commit | What is there right now |
| **Staged** | Git's index | What `git add` queued, which can differ from disk |
| **History** | Every commit | Secrets committed and later deleted |

Staged and changed genuinely differ. Edit a file after staging it and the two
disagree, so scanning staged content reads the index rather than the file.

History matters because a secret that was committed and later "removed" can
still be recovered until the history itself is rewritten. That is why it is a
separate, slower option.

## MCP

A protocol from Anthropic that lets an LLM agent call external tools in a
standard way, over stdio or HTTP. It is effectively a plugin API for agents.

An MCP server exposes callable tools, and any compatible agent can use them
without per-agent integration code.

For oneleaks that is the natural way to plug `scan` and `sanitize` into any
agent runtime: expose them once, instead of writing glue for every framework.

---

## Glossary

| Term | Definition |
|---|---|
| Shannon entropy | A measure of how random a string's characters are |
| Luhn | Checksum validating credit card numbers and IMEIs |
| Mod-97 | Checksum validating IBANs |
| HMAC | Keyed hash, resisting the brute-force reversal plain hashing allows |
| Fingerprint | One-way identifier recognising a repeated value without storing it |
| Redaction | One-way replacement; the original cannot be recovered |
| Tokenization | Reversible replacement; a separate vault recovers the original |
| Allowlist | Config exemption treating content as genuinely not sensitive |
| Baseline | A snapshot of accepted findings, so only new ones fail |
| JWT | JSON Web Token: three dot-separated base64url segments |
| MCP | Model Context Protocol, a standard way for agents to call external tools |
| ReDoS | Regex denial of service, where a pathological regex takes exponential time |
| Precision | Of things flagged, what fraction are real |
| Recall | Of real things, what fraction got flagged |
