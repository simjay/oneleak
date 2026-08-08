# oneleak — Implementation Plan

## Goal

Build `oneleak` v0.1 as a lightweight, pure-Python sensitive-data scanner and sanitizer supporting:

* Secrets
* PII
* Custom YAML/JSON rules
* Custom Python rules
* File and directory scanning
* Git changed/staged scanning
* CLI and JSON output
* Agent-friendly sanitization

Keep the public API centered around:

```python
oneleak.scan(...)
oneleak.sanitize(...)
```

---

# Phase 1 — Project Foundation

## Step 1. Create package structure

Create:

```text
oneleak/
├── __init__.py
├── scanner.py
├── models.py
├── rules.py
├── detectors.py
├── validators.py
├── sanitizer.py
├── config.py
├── git.py
├── cli.py
└── builtin_rules/
```

Also create:

```text
tests/
pyproject.toml
README.md
LICENSE
```

Set:

```text
Python >= 3.11
```

Initial dependencies:

```text
PyYAML
```

Build backend: Hatchling. Recommended dev workflow tool: `uv` (lockfile, venv management) — neither is a runtime dependency.

Development dependencies:

```text
pytest
ruff
mypy
hypothesis
```

---

## Step 2. Define core models

Implement:

```python
Finding
ScanResult
SanitizedResult
Rule
```

Define:

```text
Category:
- secret
- pii
- sensitive

Severity:
- low
- medium
- high
- critical
```

`Finding` must contain source offsets:

```text
start
end
```

and must not store the raw sensitive value.

Add unit tests for all models.

---

# Phase 2 — Basic Detection Engine

## Step 3. Build the rule registry

Implement a `RuleRegistry` that:

* Loads built-in rules
* Loads YAML rules
* Loads JSON rules
* Accepts Python rule objects
* Detects duplicate rule IDs
* Compiles regexes once

Flow:

```text
built-in rules
      +
user config
      +
Python rules
      ↓
RuleRegistry
```

Add tests for:

* Valid rules
* Invalid regex
* Duplicate IDs
* Missing required fields
* Unknown config fields

---

## Step 4. Implement regex rule execution

Implement the first detection path:

```text
text
 ↓
regex rule
 ↓
candidate
 ↓
Finding
```

Support:

```text
pattern
category
type
severity
keywords
```

Start with a few fake/internal test rules.

Do not add the full provider library yet.

Verify:

```python
result = oneleak.scan("...")
```

works end-to-end.

---

## Step 5. Implement overlap resolution

Multiple rules may detect the same value.

Implement deduplication using:

```text
rule specificity
match range
rule priority
```

Default priority:

```text
provider-specific
>
structured credential
>
generic pattern
>
entropy
```

Add tests where the same token matches multiple rules.

---

# Phase 3 — Secrets Engine

## Step 6. Add provider-specific secret rules

Create:

```text
oneleak/builtin_rules/secrets.yaml
```

Start with high-value providers:

```text
AWS
GitHub
GitLab
OpenAI
Anthropic
Slack
Stripe
Twilio
Datadog
Google
Azure
PyPI
npm
```

For each rule add:

* Positive test
* Negative test
* Boundary test

Do not use real credentials.

Source starting regexes from a vetted, ReDoS-tested pattern database (e.g. `secrets-patterns-db`) rather than writing every provider pattern from scratch. Normalize each imported pattern into oneleak's own rule schema and re-verify it against oneleak's own fixtures — do not trust an imported pattern's claimed accuracy without a local positive/negative/boundary test.

---

## Step 7. Add generic sensitive-assignment detection

Detect assignments like:

```text
password = "foo"
api_key: foo
TOKEN=foo
"client_secret": "foo"
```

Initial sensitive keywords:

```text
password
passwd
secret
api_key
apikey
access_token
refresh_token
client_secret
private_key
auth_token
credential
```

Support common assignment styles:

```text
=
:
JSON-style
.env-style
```

Favor precision over aggressive matching.

---

## Step 8. Add entropy detection

Implement Shannon entropy.

Flow:

```text
extract token candidates
      ↓
minimum length
      ↓
calculate entropy
      ↓
threshold
      ↓
Finding
```

Do not calculate entropy over arbitrary substrings.

Start thresholds from commonly cited defaults (roughly 4.5 bits/char for base64-alphabet candidates, roughly 3.0 bits/char for hex-alphabet candidates) and tune against oneleak's fixture corpus. Entropy must always be combined with candidate gating (length, character set) and, where available, a contextual keyword — never emit a finding from entropy alone. This is a known weak point of classic Shannon entropy (2026's Betterleaks scanner replaced it with corpus-normalized scoring specifically to cut false positives on base64/UUIDs/hashes/minified code); revisiting the scoring approach is a reasonable post-v0.1 improvement, not a v0.1 requirement.

Add negative tests for:

```text
UUIDs
hashes
package checksums
base64-encoded binary blobs
minified JS/CSS identifiers
repeated characters
ordinary identifiers
```

---

## Step 9. Add special secret formats

Implement dedicated detection for:

```text
PEM private keys
RSA private keys
EC private keys
OpenSSH private keys
JWTs
connection strings
credentials in URLs
```

These formats have structural anchors (PEM `-----BEGIN ... KEY-----`/`-----END ... KEY-----` markers; JWT's three dot-separated base64url segments with a decodable header). Match the anchor first and treat entropy as corroboration only — do not let the generic entropy rule in Step 8 independently fire on the same span, which would cause false positives and duplicate findings that Step 5's overlap resolution would otherwise have to paper over.

For connection strings, prefer matching only the credential portion when possible.

Example:

```text
postgres://user:password@host/db
```

Sanitization should eventually preserve:

```text
postgres://user:<PASSWORD_1>@host/db
```

---

# Phase 4 — Lightweight PII

## Step 10. Implement email detection

Add:

```text
candidate regex
+
basic validation
```

Tests should include:

* Normal emails
* Subdomains
* Invalid domains
* Common false positives

---

## Step 11. Implement phone detection

Support common structured phone formats.

Examples:

```text
617-555-1234
(617) 555-1234
+1 617 555 1234
```

Avoid matching arbitrary long digit strings.

Keep this conservative for v0.1.

---

## Step 12. Implement SSN detection

Detect US SSNs.

Validate ranges and reject invalid values such as:

```text
000-xx-xxxx
666-xx-xxxx
9xx-xx-xxxx
xxx-00-xxxx
xxx-xx-0000
```

Do not add area-number validation beyond this. Since the SSA's June 2011 randomization, area numbers are no longer assigned by state in a fixed, predictable range, so older "highest assigned area number per state" tables (sometimes copied from outdated SSN-validator code) will reject valid post-2011 SSNs and must not be used.

---

## Step 13. Implement credit card detection

Implement:

```text
candidate extraction
 ↓
normalization
 ↓
length validation
 ↓
Luhn checksum
```

Only emit a finding when Luhn validation succeeds.

---

## Step 14. Implement IP detection

Use:

```python
ipaddress.ip_address(...)
```

Support:

```text
IPv4
IPv6
```

Make IP scanning configurable because not every user considers IP addresses sensitive.

---

## Step 15. Implement IBAN detection

Implement:

```text
candidate extraction
 ↓
normalization
 ↓
country/length validation
 ↓
Mod-97
```

Add positive and negative test vectors.

---

# Phase 5 — Safe Findings

## Step 16. Implement preview generation

Create type-specific safe previews.

Examples:

```text
alice@example.com
→ a***@example.com

123-45-6789
→ ***-**-6789

sk-proj-abcdefxyz
→ sk-proj-****xyz
```

Private keys:

```text
<PRIVATE_KEY>
```

Never show meaningful private-key content.

---

## Step 17. Implement fingerprints

Implement HMAC-SHA256-based fingerprints.

Use:

```text
rule ID
+
normalized sensitive value
```

as the fingerprint input.

For the initial implementation:

* Generate a session key by default
* Allow callers/config to provide a stable key later

Do not directly hash low-entropy PII.

The stable key must never be written into the baseline file or committed to version control alongside it — a leaked key makes every fingerprint in the baseline reversible by brute force (this is the entire reason to use HMAC over plain hashing). Document this explicitly wherever baseline usage is documented, and default the stable-key location to somewhere outside the repo (e.g. an env var), not a project file.

---

# Phase 6 — Sanitization

## Step 18. Implement typed sanitization

Implement:

```python
oneleak.sanitize(text)
```

Default replacements:

```text
<EMAIL_1>
<PHONE_1>
<SSN_1>
<OPENAI_API_KEY_1>
<PASSWORD_1>
```

Use the same findings produced by `scan()`.

Do not implement a second detection system.

---

## Step 19. Add referential consistency

Within one sanitization operation:

```text
alice@example.com
→ <EMAIL_1>

alice@example.com
→ <EMAIL_1>
```

while:

```text
bob@example.com
→ <EMAIL_2>
```

Maintain:

```text
fingerprint → placeholder
```

for the sanitization session.

---

## Step 20. Add mapping export and desanitize

Extend sanitization with an explicit, opt-in reveal path:

```python
result = oneleak.sanitize(content, reveal=True)

result.mapping
# {"<EMAIL_1>": MappingEntry(value="alice@example.com", rule_id="email", fingerprint="sec_...")}

restored = oneleak.desanitize(result.text, result.mapping)
```

Add:

```text
MappingEntry (value, rule_id, fingerprint)
SanitizedResult.mapping: dict[placeholder, MappingEntry] | None
```

`mapping` stays `None` unless `reveal=True` is passed. This is the one deliberate, explicit exception to "no raw values by default."

`desanitize(text, mapping)` replaces each placeholder token found in `text` with its mapped value. Leave unmapped/missing placeholders untouched rather than raising.

Support `seed_mapping` so a caller can continue placeholder numbering and reuse placeholders for repeated values across multiple sequential `sanitize()` calls in one session:

```python
r2 = oneleak.sanitize(text2, reveal=True, seed_mapping=r1.mapping)
```

CLI:

```bash
oneleak sanitize file.txt --map mapping.json
oneleak desanitize sanitized.txt --map mapping.json
```

`--map <path>` is required to write a mapping file — never written by default. Write it with restrictive permissions (`0600` where supported) and print a stderr warning that it contains raw sensitive values and must not be committed.

Add tests for:

* `reveal=True` populates mapping; default call leaves it `None`
* Round-trip: `desanitize(sanitize(x, reveal=True).text, mapping) == x` for text fully covered by findings
* Missing placeholders in text, and unmapped placeholder-shaped tokens, are left untouched
* `seed_mapping` reuses placeholders for repeated values across two `sanitize()` calls
* Mapping file permissions and stderr warning

---

## Step 21. Handle replacement offsets safely

Replacement algorithm:

```text
resolve overlaps
 ↓
sort findings by start descending
 ↓
replace right-to-left
```

Add tests for:

* Multiple findings
* Adjacent findings
* Overlapping findings
* Unicode
* Multiline values
* Repeated values

---

# Phase 7 — Input Handling

## Step 22. Support text and bytes

Support:

```python
oneleak.scan("text")
oneleak.scan(b"bytes")
```

Strings always mean content.

Do not automatically interpret strings as paths.

---

## Step 23. Support files

Use:

```python
Path("config.yaml")
```

for file input.

Implement:

```text
path validation
binary check
size limit
decode
scan
```

Default:

```text
UTF-8
10 MB max file size
```

Skip unsupported binary files safely.

---

## Step 24. Support directories

Implement recursive scanning.

Default exclusions:

```text
.git/
node_modules/
.venv/
venv/
__pycache__/
dist/
build/
```

Return aggregate findings in one `ScanResult`.

---

## Step 25. Add `.env` awareness

Parse common forms:

```text
KEY=value
KEY="value"
KEY='value'
export KEY=value
```

Use key names as context for secret detection.

---

## Step 26. Add structured config awareness

Initial formats:

```text
JSON
YAML
TOML
```

Use parsed structure to identify relationships such as:

```text
database.password → hello123
```

Do not reserialize config during sanitization.

Continue using offsets into the original text.

If source mapping becomes too complex, use structured parsing only as supplemental context in v0.1.

---

# Phase 8 — Configuration and Custom Rules

## Step 27. Implement `.oneleak.yaml`

Support:

```yaml
version: 1

exclude:
  - ".git/**"

pii:
  email: true
  phone: true

rule_paths:
  - ".oneleak/rules/"
```

Config should support:

* Detector enable/disable
* Exclusions
* Severity overrides
* Custom rule files
* Sanitization settings
* Allowlists

Reject unknown fields.

---

## Step 28. Add YAML/JSON rule files

Support:

```yaml
rules:
  - id: company-api-key
    category: secret
    type: company_api_key
    severity: high
    pattern: '\bCOMPANY_[A-Za-z0-9]{32}\b'
```

Support:

```text
pattern
keywords
entropy
validator
severity
category
include paths
exclude paths
```

---

## Step 29. Add built-in validators

Initial validators:

```text
luhn
iban
ipv4
ipv6
jwt
```

Declarative rules can reference validators by name.

Example:

```yaml
validator: luhn
```

Never allow arbitrary code execution from YAML/JSON.

---

## Step 30. Add Python rule API

Implement a small extension interface:

```python
class PythonRule:
    def detect(self, text):
        ...
```

Support explicit registration:

```python
oneleak.scan(
    text,
    rules=[MyRule()],
)
```

Do not automatically load Python modules from repository config.

---

# Phase 9 — False Positive Management

## Step 31. Add path exclusions

Support config-level exclusions:

```yaml
exclude:
  - "tests/fixtures/**"
```

---

## Step 32. Add rule allowlisting

Allow rules to be disabled globally or by path.

---

## Step 33. Add inline suppression

Support:

```python
TOKEN = "fake-secret"  # oneleak: allow
```

Optional rule-specific syntax:

```python
TOKEN = "fake-secret"  # oneleak: allow generic-secret
```

---

## Step 34. Add baselines

Baseline file stores:

```text
rule_id
path
fingerprint
```

Never raw values.

Example:

```json
{
  "version": 1,
  "findings": [
    {
      "rule_id": "generic-secret",
      "path": "tests/example.py",
      "fingerprint": "sec_..."
    }
  ]
}
```

---

# Phase 10 — Git Integration

## Step 35. Implement changed-file scanning

Add:

```python
oneleak.git.scan_changed()
```

Initial implementation:

```text
git changed/untracked files
        ↓
scan entire files
```

Do not optimize to changed hunks yet.

---

## Step 36. Implement staged scanning

Add:

```python
oneleak.git.scan_staged()
```

Important:

Scan staged content, not the current working-tree version.

---

## Step 37. Defer Git-history scanning

Full Git-history scanning is desirable for Gitleaks parity but can follow v0.1.

Do not delay the first release for it.

---

# Phase 11 — CLI

## Step 38. Implement CLI entry point

Commands:

```bash
oneleak scan
oneleak sanitize
```

Examples:

```bash
oneleak scan .
oneleak scan --changed
oneleak scan --staged
oneleak sanitize file.txt
```

Use `argparse`.

---

## Step 39. Add stdin/stdout

Support:

```bash
cat file | oneleak scan -
```

and:

```bash
kubectl logs pod | oneleak sanitize -
```

Sanitized content goes to stdout.

Diagnostics go to stderr.

---

## Step 40. Add JSON output

Support:

```bash
oneleak scan . --json
```

JSON must contain only safe finding information.

---

## Step 41. Implement exit codes

Use:

```text
0 = clean
1 = findings detected
2 = execution/configuration error
```

Add:

```bash
--fail-on high
```

for severity thresholds.

---

# Phase 12 — Agent-Focused Usability

## Step 42. Validate agent scan workflow

Ensure this works cleanly:

```bash
oneleak scan --changed --json
```

An agent should be able to determine:

```text
safe?
highest risk?
which file?
which line?
which rule?
```

without parsing human prose.

---

## Step 43. Validate agent sanitization workflow

Ensure:

```bash
some-tool | oneleak sanitize -
```

works as a clean filter.

Python equivalent:

```python
safe = oneleak.sanitize(tool_output)

agent.add_context(safe.text)
```

This should be a primary integration test.

Also validate the reveal/rehydrate round trip end to end, since it's the mechanism agents use to act on a real secret without ever putting it in LLM context:

```python
safe = oneleak.sanitize(tool_output, reveal=True)

agent.add_context(safe.text)          # LLM only ever sees placeholders
...
real = oneleak.desanitize(agent_decision_text, safe.mapping)  # rehydrate right before use
```

---

## Step 44. Ensure findings are agent-safe

Audit every output path:

```text
Python repr
JSON
CLI text
logs
errors
debug output
baseline
```

Confirm none expose raw sensitive values by default.

---

# Phase 13 — Optional ML PII

## Step 45. Add optional extra

Define:

```text
oneleak[pii-ml]
```

with Presidio dependencies.

Do not import them during normal package startup.

---

## Step 46. Implement PII backend adapter

Expose optional usage such as:

```python
oneleak.scan(
    text,
    pii_ml=True,
)
```

Convert ML results into standard `Finding` objects.

Core scanning behavior must remain unchanged when the optional extra is not installed.

---

# Phase 14 — Quality and Release

## Step 47. Expand rule test coverage

Every built-in secret rule must include:

```text
positive tests
negative tests
boundary tests
```

Add false-positive regressions as real issues are found.

---

## Step 48. Add property tests

Use Hypothesis for:

```text
Luhn
IBAN
sanitization offsets
overlap handling
config parsing
```

---

## Step 49. Add performance benchmarks

Benchmark at least:

```text
1 KB text
1 MB text
single config file
small repository
large repository
changed-file scan
```

The goal is not extreme optimization yet.

The goal is ensuring oneleak is cheap enough to invoke repeatedly in agent workflows.

---

## Step 50. Dogfood oneleak

Add oneleak to its own:

```text
pre-commit
CI
```

Use the project itself to identify usability and false-positive issues.

---

## Step 51. Release v0.1

Before release confirm:

```text
pip install oneleak
```

works without:

```text
external binaries
ML models
network access
system dependencies
```

Validate these core workflows:

```bash
oneleak scan .
oneleak scan --changed
oneleak scan --staged
oneleak scan . --json
some-command | oneleak sanitize -
```

And:

```python
import oneleak

oneleak.scan(text)
oneleak.sanitize(text)
```

---

# Phase 15 — Fast Follow (v0.1.x)

## Step 52. Ship a minimal MCP server

Expose `scan`/`sanitize` over stdio via a thin MCP server. No new detection logic — it wraps the existing Python API.

This is the most direct path to oneleak's "agent-friendly" positioning (Section 8/PRD), and it should ship shortly after v0.1, not be treated as equal priority to longer-tail deferred items such as OCR or archive scanning. Competing tooling for "redact tool output before it reaches an LLM" already exists (LLM-gateway redaction layers, MCP guardrail wrappers), so this is a real gap to close quickly rather than a nice-to-have.

Scope for the first version:

```text
scan(content) → findings
sanitize(content) → sanitized text
```

Defer richer MCP features (resources, prompts, streaming) until real usage surfaces a need.

---

# Recommended Build Order

For actual implementation, follow this sequence:

```text
1. Models
2. Rule registry
3. Regex detection
4. ScanResult
5. Provider secrets
6. Generic credential detection
7. Entropy
8. PII validators
9. Safe previews/fingerprints
10. Sanitization
11. File/directory scanning
12. Config
13. Custom YAML/JSON rules
14. Python rules
15. Allowlists/suppression
16. Git changed/staged
17. CLI/stdin/JSON
18. Optional ML PII
19. Performance/testing
20. v0.1 release
21. MCP server (fast follow)
```

The first major milestone should be reached as soon as this works:

```python
import oneleak

result = oneleak.scan("""
OPENAI_API_KEY=...
email=alice@example.com
""")

safe = oneleak.sanitize("""
OPENAI_API_KEY=...
email=alice@example.com
""")
```

Everything else should build outward from that core.

