# oneleak — Technical Specification

**Status:** Draft
**Target:** v0.1
**Language:** Python 3.11+
**Distribution:** PyPI
**Primary interfaces:** Python API + CLI

## 1. Architecture

oneleak uses one deterministic detection engine for scanning and sanitization.

```text
Input
  │
  ▼
Scanner
  │
  ├── Built-in rules
  ├── Custom YAML/JSON rules
  ├── Custom Python rules
  ├── Entropy detection
  └── Validators
  │
  ▼
Findings
  │
  ├── ScanResult
  └── Sanitizer
```

Core scanning must not require:

* External binaries
* Network access
* ML models
* Presidio/spaCy

Optional ML-based PII detection is isolated behind an extra dependency.

---

## 2. Package Structure

Keep the package simple initially:

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
    ├── secrets.yaml
    └── pii.yaml
```

Do not create provider-specific modules unless the rule library becomes large enough to justify it.

---

## 3. Public API

The primary API should remain minimal:

```python
import oneleak

result = oneleak.scan(content)

sanitized = oneleak.sanitize(content)
```

Reversing sanitization uses an explicitly requested mapping:

```python
result = oneleak.sanitize(content, reveal=True)

restored = oneleak.desanitize(result.text, result.mapping)
```

Filesystem input uses `Path` explicitly:

```python
from pathlib import Path

oneleak.scan(Path("config.yaml"))
oneleak.scan(Path("."))
```

Git operations:

```python
oneleak.git.scan_changed()
oneleak.git.scan_staged()
```

Custom rules:

```python
oneleak.scan(
    content,
    rules=["company-rules.yaml"],
)
```

or:

```python
oneleak.scan(
    content,
    rules=[MyCustomRule()],
)
```

---

## 4. Core Models

### Finding

```python
@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    type: str
    severity: str

    start: int
    end: int

    path: str | None = None
    line: int | None = None
    column: int | None = None

    confidence: float | None = None

    preview: str | None = None
    fingerprint: str | None = None
```

`start` and `end` refer to offsets in the original input.

Raw sensitive values must not be stored in findings by default.

### ScanResult

```python
@dataclass
class ScanResult:
    findings: list[Finding]

    @property
    def safe(self) -> bool: ...

    @property
    def risk(self) -> str | None: ...
```

Usage:

```python
result = oneleak.scan(text)

if not result.safe:
    for finding in result.findings:
        ...
```

### SanitizedResult

```python
@dataclass
class SanitizedResult:
    text: str
    findings: list[Finding]
    mapping: dict[str, "MappingEntry"] | None = None
```

`mapping` stays `None` unless `sanitize(..., reveal=True)` is passed. See Section 12.

### MappingEntry

```python
@dataclass(frozen=True)
class MappingEntry:
    value: str
    rule_id: str
    fingerprint: str | None = None
```

`value` is the raw sensitive value. `MappingEntry` only ever exists inside a `reveal=True` mapping — never inside a `Finding`.

Usage:

```python
result = oneleak.sanitize(text)

print(result.text)
```

---

## 5. Detection Pipeline

Each input passes through:

```text
Candidate generation
        ↓
Context evaluation
        ↓
Validation
        ↓
Finding generation
        ↓
Overlap resolution
        ↓
Allowlist/suppression
        ↓
Final findings
```

Candidate generation includes:

* Provider-specific regex
* Generic credential assignments
* PII patterns
* High-entropy tokens
* Private-key blocks
* Connection strings

---

## 6. Rule Model

Built-in and user-defined declarative rules compile into the same internal rule structure.

```python
@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    type: str
    severity: str

    pattern: Pattern[str] | None = None
    keywords: tuple[str, ...] = ()

    min_entropy: float | None = None
    validator: str | None = None

    include_paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
```

A rule may combine multiple signals.

Example:

```yaml
- id: company-api-key
  category: secret
  type: company_api_key
  severity: high

  pattern: '\bCOMPANY_[A-Za-z0-9]{32}\b'

  keywords:
    - api_key
    - token
```

---

## 7. Rule Loading

Rules come from:

```text
Built-in rules
      +
YAML/JSON rules
      +
Explicit Python rules
      ↓
Rule Registry
```

Rule IDs must be unique.

Duplicate IDs should raise a configuration error unless explicit override support is added later.

Declarative rule files must never execute arbitrary Python.

---

## 8. Python Rules

Advanced rules use a small Python interface.

Example:

```python
from oneleak import PythonRule


class EmployeeIdRule(PythonRule):
    id = "employee-id"
    category = "pii"
    type = "employee_id"
    severity = "medium"

    def detect(self, text):
        ...
```

Python rules must be explicitly registered.

For example:

```python
oneleak.scan(
    text,
    rules=[EmployeeIdRule()],
)
```

A repository configuration file must not automatically import Python code.

---

## 9. Secret Detection

The secret engine should combine four main techniques.

### Provider patterns

Examples:

* AWS
* GitHub
* GitLab
* OpenAI
* Anthropic
* Slack
* Stripe
* Twilio
* Datadog
* Google
* Azure
* PyPI
* npm

These should primarily live in declarative built-in rules.

Rather than hand-writing every provider regex from scratch, source starting patterns from vetted, ReDoS-tested pattern databases such as `secrets-patterns-db`, then normalize them into oneleak's own rule schema and add oneleak-specific negative/boundary tests.

### Sensitive assignments

Detect values assigned to keys such as:

```text
password
secret
api_key
apikey
access_token
refresh_token
client_secret
private_key
credential
```

Examples:

```python
password = "hello123"
```

```yaml
database:
  password: hello123
```

### Entropy

Extract candidate token-like strings first, then calculate Shannon entropy.

Do not calculate entropy over every substring.

Example criteria:

```text
minimum length
+
allowed character set
+
entropy threshold
+
optional contextual keyword
```

Starting thresholds should follow commonly cited defaults (e.g. roughly 4.5 bits/char for base64-alphabet tokens, roughly 3.0 bits/char for hex-alphabet tokens), then be tuned empirically against oneleak's own fixture corpus. Entropy must never be the sole basis for a finding: classic Shannon entropy is known to over-flag base64 blobs, UUIDs, hashes, package checksums, and minified code, which is precisely why newer scanners (e.g. Betterleaks, 2026) replaced raw entropy with corpus-normalized "token efficiency" scoring to cut false positives. For v0.1, control this with strict candidate gating (length, charset) plus a contextual keyword or structural anchor wherever one is available; evaluating a token-efficiency-style scorer as an entropy replacement is a reasonable post-v0.1 improvement, not a v0.1 blocker.

### Special formats

Dedicated detection for:

* Private keys
* JWTs
* Credentials embedded in URLs
* Connection strings

These formats have structural anchors — PEM `-----BEGIN ... KEY-----`/`-----END ... KEY-----` markers, JWT's three dot-separated base64url segments with a recognizable header. Structural-anchor matching must gate and take priority over generic entropy scanning for these formats: anchor first, then treat entropy/validation as corroboration. This avoids both false positives (entropy alone on a high-entropy blob) and double-detection (the same value matching both a special-format rule and the generic entropy rule).

---

## 10. PII Detection

Core PII detection is lightweight and deterministic.

Initial detectors:

```text
Email
Phone
US SSN
Credit card
IPv4
IPv6
IBAN
```

Each detector should validate candidates where possible.

### Credit card

```text
regex candidate
    ↓
normalize
    ↓
length validation
    ↓
Luhn checksum
```

### SSN

Reject invalid or reserved ranges: area 000/666/900–999, group 00, serial 0000. Do not add state-based area-number validation — the SSA's 2011 randomization removed the fixed per-state area ranges that older SSN validators rely on, so that approach now rejects valid SSNs.

### IP

Use Python's `ipaddress` module.

### IBAN

Validate format and Mod-97 checksum.

Phone detection should intentionally favor precision over aggressively matching arbitrary digit sequences.

---

## 11. Optional ML PII

Optional installation:

```bash
pip install oneleak[pii-ml]
```

This may provide a Presidio-backed adapter.

Example:

```python
oneleak.scan(
    text,
    pii_ml=True,
)
```

If the optional dependency is unavailable, raise a clear error:

```text
Install ML PII support with:
pip install oneleak[pii-ml]
```

The optional backend should return normal `Finding` objects.

---

## 12. Sanitization

Sanitization always uses scanner findings.

```text
scan
 ↓
findings
 ↓
replacement
 ↓
sanitized text
```

Example:

```text
alice@example.com
```

becomes:

```text
<EMAIL_1>
```

Repeated values within one sanitization operation must receive the same placeholder.

```text
alice@example.com → <EMAIL_1>
bob@example.com   → <EMAIL_2>
alice@example.com → <EMAIL_1>
```

Secrets use typed placeholders:

```text
<OPENAI_API_KEY_1>
<AWS_ACCESS_KEY_1>
<PASSWORD_1>
```

### Mapping Export and Reversal

`sanitize(content, reveal=True)` populates `SanitizedResult.mapping`: `dict[placeholder, MappingEntry]`. Without `reveal=True`, `mapping` stays `None` — sanitize() remains safe-by-default; `reveal=True` is the one deliberate, explicit exception.

```python
result = oneleak.sanitize(content, reveal=True)

result.mapping
# {
#   "<EMAIL_1>": MappingEntry(value="alice@example.com", rule_id="email", fingerprint="sec_..."),
#   "<OPENAI_API_KEY_1>": MappingEntry(value="sk-proj-...", rule_id="openai-api-key", fingerprint="sec_..."),
# }
```

`oneleak.desanitize(text, mapping)` reverses sanitization: it replaces each placeholder token found in `text` with its mapped `value`. Placeholders present in `mapping` but absent from `text`, and tokens in `text` that look like placeholders but are absent from `mapping`, are both left untouched rather than raising — sanitized text may pass through an agent that doesn't echo back every placeholder verbatim.

`sanitize(..., reveal=True, seed_mapping=previous.mapping)` continues placeholder numbering and reuses placeholders for repeated values across multiple sequential `sanitize()` calls (e.g. an agent scanning several tool outputs in one session, where the same email should keep resolving to `<EMAIL_1>` across calls). Without `seed_mapping`, referential consistency is scoped to a single `sanitize()` call, as above.

**Mapping file (CLI):**

```json
{
  "version": 1,
  "mapping": {
    "<EMAIL_1>": {"value": "alice@example.com", "rule_id": "email", "fingerprint": "sec_..."}
  }
}
```

A mapping file contains raw sensitive values by design. It is written only when explicitly requested (`--map <path>`), never by default; see Section 21 and Section 29.

---

## 13. Sanitization Algorithm

Findings contain source offsets.

Replacement should happen from right to left:

```text
1. Detect findings
2. Resolve overlaps
3. Assign placeholders
4. Sort findings by offset descending
5. Replace spans
6. Return sanitized content
```

This prevents replacements from invalidating subsequent offsets.

---

## 14. Overlapping Findings

A single value may match multiple rules.

Example:

```text
OpenAI API key
+
generic high-entropy token
```

Only one finding should normally be returned.

Priority:

```text
provider-specific
    >
structured credential
    >
generic pattern
    >
entropy-only
```

The more specific rule wins.

---

## 15. Safe Preview

Findings should include masked previews rather than raw values.

Examples:

```text
sk-proj-abcdefxyz
→ sk-proj-****xyz

alice@example.com
→ a***@example.com

123-45-6789
→ ***-**-6789
```

Private-key findings should expose no key material.

---

## 16. Fingerprints

A fingerprint allows the same sensitive value to be recognized without returning it.

Use HMAC-SHA256 where persistent identity is needed.

Conceptually:

```text
HMAC(key, rule_id + normalized_value)
```

This avoids directly hashing low-entropy PII such as SSNs.

For simple in-process sanitization, fingerprints may use a temporary session key.

Persistent baselines require a stable project-specific fingerprint key.

This is stronger than the plain SHA-1 hashing some prior art uses (e.g. `hash(secret + filepath + plugin)`), because HMAC resists dictionary/rainbow-table attacks on low-entropy values. That benefit only holds if the HMAC key itself is kept out of the baseline file and out of version control — document this as a hard requirement, not a suggestion, since a committed key makes every fingerprint in the baseline reversible by brute force.

---

## 17. File Scanning

File flow:

```text
Path
 ↓
exclusion check
 ↓
binary check
 ↓
size check
 ↓
decode
 ↓
scan text
```

Defaults:

* UTF-8
* Skip binary files
* Skip files larger than a configurable limit
* Do not inspect archives or binary documents in v0.1

Recommended default size limit:

```text
10 MB
```

---

## 18. Directory Scanning

Recursive directory scanning should support default exclusions such as:

```text
.git/
node_modules/
.venv/
venv/
__pycache__/
dist/
build/
```

Users can override exclusions.

Use normalized relative paths and glob matching.

---

## 19. Structured Configuration Awareness

Initial structured formats:

```text
.env
JSON
YAML
TOML
```

The goal is to improve context detection.

Example:

```yaml
database:
  password: hello
```

should expose:

```text
key = database.password
value = hello
```

to the detection engine.

Sanitization must still modify the original text rather than reserialize parsed configuration.

This preserves:

* Formatting
* Comments
* Ordering
* Whitespace

---

## 20. Git Integration

Git support can use the installed `git` command through `subprocess`.

The Python package itself remains pure Python.

Core Git APIs:

```python
oneleak.git.scan_changed()
oneleak.git.scan_staged()
```

`scan_changed()` initially scans whole changed files.

Optimization to changed hunks may be added later.

`scan_staged()` should scan the staged version rather than the working-tree version.

Git-history scanning can follow after v0.1.

---

## 21. CLI

Primary commands:

```bash
oneleak scan .
oneleak scan config.yaml
oneleak scan --changed
oneleak scan --staged
oneleak scan - --json

oneleak sanitize file.txt
oneleak sanitize -
oneleak sanitize file.txt --map mapping.json

oneleak desanitize sanitized.txt --map mapping.json
```

`--map <path>` is required to write a mapping file — never written by default. The file is written with restrictive permissions (`0600` where supported), and the CLI prints a stderr warning that it contains raw sensitive values and must not be committed. `oneleak desanitize` reverses sanitization using a previously exported mapping file; see Section 12.

Use `argparse` initially.

No heavy CLI framework is required.

---

## 22. CLI Exit Codes

```text
0 = no blocking findings
1 = sensitive data detected
2 = execution or configuration error
```

Support severity threshold:

```bash
oneleak scan . --fail-on high
```

This lets low-severity findings remain informational.

---

## 23. JSON Output

Example:

```json
{
  "safe": false,
  "risk": "critical",
  "findings": [
    {
      "rule_id": "openai-api-key",
      "category": "secret",
      "type": "openai_api_key",
      "severity": "critical",
      "path": "config.py",
      "line": 12,
      "preview": "sk-proj-****xyz",
      "fingerprint": "sec_f83..."
    }
  ]
}
```

JSON output must never include raw sensitive values by default.

---

## 24. stdin/stdout

stdin support is first-class.

```bash
kubectl logs my-pod | oneleak scan -
```

Sanitization:

```bash
kubectl logs my-pod | oneleak sanitize -
```

Sanitized content goes to stdout.

Diagnostics go to stderr.

This enables safe agent tool pipelines.

---

## 25. Configuration

Default configuration:

```text
.oneleak.yaml
```

Example:

```yaml
version: 1

exclude:
  - ".git/**"
  - "node_modules/**"

pii:
  email: true
  phone: true
  ssn: true

rule_paths:
  - ".oneleak/rules/"

allow:
  paths:
    - "tests/fixtures/**"

sanitize:
  mode: typed
```

Unknown fields should cause a configuration error rather than being silently ignored.

---

## 26. Allowlisting and Suppression

Initial support:

* Path exclusions
* Rule exclusions
* Fingerprint allowlists
* Inline suppression
* Baselines

Example:

```python
TEST_TOKEN = "fake-secret"  # oneleak: allow
```

Rule-specific suppression may also be supported:

```python
TEST_TOKEN = "fake-secret"  # oneleak: allow generic-secret
```

---

## 27. Baselines

Baseline files should contain metadata and fingerprints only.

Example:

```json
{
  "version": 1,
  "findings": [
    {
      "rule_id": "generic-secret",
      "path": "tests/example.py",
      "fingerprint": "sec_abcd..."
    }
  ]
}
```

Never store raw sensitive values.

---

## 28. Performance

Primary optimization goals:

* Regexes compiled once
* Files read once
* Fast single-text scanning
* Early path/binary/size filtering
* Entropy only on candidate strings
* Efficient changed-file scanning

Persistent caching and multiprocessing are not required in v0.1.

The core target is that agents can invoke oneleak repeatedly without significant workflow overhead.

---

## 29. Security Requirements

oneleak handles sensitive data, so the scanner itself must be conservative.

Requirements:

* No raw sensitive values in logs
* No network access in the core engine
* No telemetry by default
* No automatic Python execution from repository config
* No plaintext sensitive values in baselines
* No raw sensitive values in JSON output by default
* Errors should not dump source content
* `SanitizedResult.mapping` and exported mapping files contain raw sensitive values by design, and only ever exist behind explicit opt-in (`reveal=True` / `--map`) — never produced by default. Mapping files must be written with restrictive permissions and a stderr warning that they must not be committed.

---

## 30. Dependencies

Keep runtime dependencies minimal.

Recommended:

```text
Python >= 3.11

PyYAML
```

Use the standard library for most functionality:

```text
re
json
pathlib
hashlib
hmac
ipaddress
subprocess
argparse
tomllib
```

Optional:

```text
oneleak[pii-ml]
    presidio-analyzer
    presidio-anonymizer
```

Build backend: Hatchling, the current default for new pure-Python `pyproject.toml` packages. Recommended dev workflow tool: `uv`, for lockfile and virtualenv management. Neither is a runtime dependency.

Development dependencies:

```text
pytest
hypothesis
ruff
mypy
```

---

## 31. Testing

Core test areas:

```text
Secrets
PII
Entropy
Validators
Rules
Config
Sanitization
Overlap resolution
Git
CLI
False positives
```

Every built-in rule should have:

* Positive fixtures
* Negative fixtures
* Boundary cases

Never use real live credentials in tests.

False-positive regressions should become permanent test cases.

---

## 32. v0.1 Scope

Implement:

**Core**

* Scanner
* Findings
* Rule registry
* Sanitizer
* Config

**Secrets**

* Provider rules
* Generic credential assignments
* Entropy
* Private keys
* JWTs
* Connection strings

**PII**

* Email
* Phone
* SSN
* Credit card
* IP
* IBAN

**Rules**

* YAML
* JSON
* Python extension API
* Built-in validators

**Inputs**

* Text
* File
* Directory
* stdin

**Git**

* Changed files
* Staged files

**Outputs**

* Python API
* Human CLI
* JSON
* Safe previews
* Fingerprints

**Sanitization**

* Typed placeholders
* Referential consistency
* Mapping export (`reveal=True`, `--map`)
* Desanitize / reversal

---

## 33. Deferred

Not required for v0.1:

* Full Git history scanning
* Persistent scan caching
* Multiprocessing
* Archive scanning
* Binary document scanning
* OCR
* IDE plugins
* Remote rule registry
* Credential verification against providers
* Credential rotation

### Fast-follow (target v0.1.x, not indefinitely deferred)

* **MCP server** — a thin server exposing `scan`/`sanitize` over stdio, reusing the existing Python API with no new detection logic. Unlike the items above, this isn't low-priority housekeeping: it's the most direct path to oneleak's stated "agent-friendly" positioning, and competing redaction-for-LLM-context tooling (MCP guardrail wrappers, LLM-gateway redaction layers) already exists. Ship it as soon as the core `scan`/`sanitize` API is stable, rather than treating it as equivalent priority to OCR or archive scanning.
* Agent framework integrations (LangChain/etc. adapters) can follow the MCP server once its interface is validated.
* ML PII in base package

---

## 34. Core Technical Principle

oneleak should keep complexity behind a stable interface:

```python
oneleak.scan(...)
oneleak.sanitize(...)
```

Internally, the scanner can continue gaining better rules, validation, PII coverage, Git support, and agent integrations without changing how applications consume it.

The central architecture is:

```text
Rules + deterministic signals
            ↓
       Detection Engine
            ↓
         Findings
        /        \
      scan      sanitize
```

That should remain the foundation of oneleak.

