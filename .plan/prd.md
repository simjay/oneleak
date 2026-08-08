# oneleak — Product Requirements Document

**Status:** Draft
**Product:** oneleak
**Category:** Sensitive data detection and sanitization

## 1. Overview

**oneleak** is a lightweight, pure-Python library and CLI for detecting and sanitizing sensitive information.

It provides one scanning engine for:

* Secrets and credentials
* PII
* Custom sensitive information

It is designed for traditional developer workflows such as pre-commit and CI, but also for agents that need to repeatedly scan files, tool output, logs, configuration, and generated code.

Core detection is deterministic and requires no external binary, network service, or ML model.

---

## 2. Product Goals

oneleak should:

* Install with a simple `pip install oneleak`
* Require no external executable
* Detect both secrets and PII in one scan
* Provide lightweight PII detection by default
* Support sanitization, not only detection
* Be easy to embed directly in Python
* Be inexpensive enough for agents to invoke frequently
* Support user-defined YAML, JSON, and Python rules
* Provide predictable structured output for agents and CI

Primary API:

```python
import oneleak

result = oneleak.scan(content)

safe = oneleak.sanitize(content)
```

---

## 3. Core Use Cases

### Developer scanning

```bash
oneleak scan .
```

Use oneleak in:

* Local development
* Pre-commit hooks
* CI
* Repository scanning

### Agent output scanning

After an agent edits code:

```python
result = oneleak.git.scan_changed()
```

The agent can detect and remediate leaked secrets or PII before continuing.

### Agent input sanitization

Before tool output enters LLM context:

```python
output = run_tool()

safe = oneleak.sanitize(output)

agent.add_context(safe.text)
```

This allows oneleak to act as a sensitive-data boundary between tools and agents.

### Embedded Python usage

Applications should be able to scan arbitrary content directly:

```python
oneleak.scan(api_response)
oneleak.scan(log_output)
oneleak.scan(config)
```

---

## 4. Secret Detection

oneleak will implement its own pure-Python secret detection engine.

It should support:

* Provider-specific API keys
* Access tokens
* Passwords
* Private keys
* Connection strings
* JWTs
* Cloud credentials
* Generic credentials
* High-entropy secrets

Detection should combine deterministic signals such as:

```text
patterns
+
keywords/context
+
entropy
+
validation
```

Example:

```python
password = "hello123"
```

The value may not have high entropy, but the key name `password` provides strong context.

Entropy is one signal among several, never a standalone detector. Classic Shannon entropy is known to over-flag base64 blobs, UUIDs, hashes, and minified code; it must always be gated by candidate shape (length, character set) and, where possible, corroborated by context or a structural anchor.

---

## 5. PII Detection

The base package should provide lightweight PII detection without ML dependencies.

Initial support should include:

* Email addresses
* Phone numbers
* US SSNs
* Credit card numbers
* IP addresses
* IBANs

Detection should use validation where possible.

For example:

```text
credit-card candidate
        ↓
pattern match
        ↓
Luhn checksum
        ↓
finding
```

The base installation should not depend on Presidio, spaCy, or ML models.

---

## 6. Optional ML PII

More advanced PII detection may be available through:

```bash
pip install oneleak[pii-ml]
```

This may use Presidio or another NER-based backend for detecting entities such as:

* Person names
* Locations
* Addresses
* Organizations

This functionality must remain optional and must not affect the lightweight core package.

---

## 7. Sanitization

Sanitization is a first-class feature.

```python
oneleak.sanitize(content)
```

Example:

```text
Before:

Email alice@example.com using key sk-proj-xxxx.
Contact alice@example.com again.
```

After:

```text
Email <EMAIL_1> using key <OPENAI_API_KEY_1>.
Contact <EMAIL_1> again.
```

Requirements:

* Preserve useful semantic meaning
* Repeated values use the same placeholder
* Secrets and PII use typed placeholders
* Raw sensitive values are not returned in findings by default

### Mapping export and reversal

Sanitization can optionally export a mapping of placeholder to original value:

```python
result = oneleak.sanitize(content, reveal=True)

result.mapping
# {
#   "<EMAIL_1>": "alice@example.com",
#   "<OPENAI_API_KEY_1>": "sk-proj-xxxx",
# }
```

This mapping can be used to reverse sanitization later:

```python
restored = oneleak.desanitize(result.text, result.mapping)
```

This enables an agent to work entirely on sanitized text, and rehydrate real values only at the point of actually performing an action (for example, an API call), so the LLM itself never sees the raw value.

Mapping export is never enabled by default — see Section 16's Safe by Default principle. It is the one deliberate, explicit exception to "no raw values returned," and callers must opt in.

---

## 8. Agent-Friendly Design

oneleak itself remains deterministic.

Agent optimization comes from its interface.

Agents should be able to:

```text
scan arbitrary text
scan changed files
sanitize tool output
consume JSON findings
use exit codes
run repeatedly with low overhead
```

A typical workflow:

```text
Agent edits files
      ↓
oneleak scan --changed
      ↓
finding?
  │        │
 no       yes
  │        │
continue   remediate
```

For tool input:

```text
Tool output
     ↓
oneleak sanitize
     ↓
LLM context
```

Several products (LLM-gateway redaction layers, MCP-guardrail wrappers) already solve "redact tool output before it reaches an LLM." A minimal MCP server that exposes `scan`/`sanitize` over stdio is the most direct way to plug oneleak into agent runtimes such as Claude Code without per-project glue code. This should not be treated as a someday feature — see the fast-follow note in the tech spec's deferred list.

---

## 9. Safe Findings

Scan results should never expose complete sensitive values by default.

Example:

```json
{
  "rule": "openai-api-key",
  "category": "secret",
  "severity": "critical",
  "path": "config.py",
  "line": 12,
  "preview": "sk-proj-****xyz",
  "fingerprint": "sec_f83..."
}
```

Findings should include:

* Rule
* Category
* Type
* Severity
* Path
* Line/column
* Safe preview
* Fingerprint
* Optional confidence

---

## 10. Custom Rules

Users should be able to extend oneleak without modifying the library.

Three rule sources are supported:

```text
Built-in rules
YAML / JSON rules
Python rules
```

Example YAML:

```yaml
rules:
  - id: company-api-key
    category: secret
    severity: high
    pattern: '\bCOMPANY_[A-Za-z0-9]{32}\b'
    keywords:
      - token
      - api_key
```

Declarative rules should support:

* Regex
* Keywords/context
* Entropy thresholds
* Severity
* Category
* Path restrictions
* Allowlists
* Built-in validators

---

## 11. Python Rules

Advanced users should be able to implement custom detection logic in Python.

Example use cases:

* Proprietary checksum
* Internal employee ID format
* Company-specific credential structure

Python rules must use the same finding model as built-in rules.

Declarative YAML/JSON files must never execute arbitrary Python.

Executable Python rules require explicit registration or activation.

---

## 12. Git Support

oneleak should support:

```bash
oneleak scan .
oneleak scan --changed
oneleak scan --staged
```

Python equivalents:

```python
oneleak.git.scan_changed()
oneleak.git.scan_staged()
```

Git-history scanning should also be supported over time to reach the capabilities expected from tools such as Gitleaks.

---

## 13. CLI

Primary commands:

```bash
oneleak scan .
oneleak scan config.yaml
oneleak scan --changed
oneleak scan --json

oneleak sanitize file.txt
some-command | oneleak sanitize -
```

Exit codes:

```text
0 = clean
1 = sensitive information detected
2 = scanner/configuration error
```

stdin/stdout support is important for agent and automation workflows.

---

## 14. Configuration

Example:

```yaml
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
```

Configuration should support:

* Enabled detectors
* Exclusions
* Allowlists
* Severity overrides
* Custom rules
* Sanitization options

The configuration format should remain simple.

---

## 15. False Positive Management

oneleak must support practical suppression mechanisms:

* Path exclusions
* Rule exclusions
* Allowlists
* Inline suppression
* Baselines

This is especially important for agents, which should not repeatedly attempt to fix known test data or intentional examples.

---

## 16. Product Principles

### Pure Python

No required external binary.

### Lightweight by default

No ML dependencies in the base package.

### One scanner

Secrets, PII, and custom sensitive information use the same engine.

### Deterministic core

No LLM calls or network dependency.

### Safe by default

The scanner itself should not leak the sensitive information it detects. The one explicit, opt-in exception is sanitization's mapping export (Section 7), which exists specifically to let a caller reverse sanitization later; it is never produced unless requested.

### Agent-friendly

Fast invocation, JSON output, stdin support, Git-change scanning, and sanitization.

### Extensible

Simple rules in YAML/JSON, advanced rules in Python.

### Simple interface

The majority of users should only need:

```python
oneleak.scan(...)
oneleak.sanitize(...)
```

---

## 17. v0.1 Scope

The first release should include:

**Secrets**

* Common provider API keys
* Generic credentials
* Sensitive assignments
* Entropy detection
* Private keys
* Connection strings
* JWTs

**PII**

* Email
* Phone
* SSN
* Credit card + Luhn
* IPv4/IPv6
* IBAN

**Rules**

* Built-in rules
* YAML
* JSON
* Python extensions

**Scanning**

* Text
* Files
* Directories
* stdin
* Changed/staged Git files

**Sanitization**

* Typed placeholders
* Referential consistency
* Safe previews

**Integration**

* Python API
* CLI
* JSON output
* CI exit codes
* Pre-commit support

**Optional**

* `oneleak[pii-ml]`

---

## 18. Positioning

oneleak should not be positioned simply as:

> Gitleaks rewritten in Python.

The intended positioning is:

> **oneleak is a lightweight, pure-Python sensitive-data scanner and sanitizer built for modern developer and agent workflows.**

Its core differentiation is the combination of:

```text
Secrets
+
PII
+
Custom rules
+
Sanitization
+
Pure Python embedding
+
Agent-friendly workflows
```

in one deterministic package.

As of 2026, no existing tool combines all of these. detect-secrets (Yelp) is pure Python with a plugin architecture but has no PII detection and no sanitize/redact output. gitleaks and ggshield have mature rule/allowlist ecosystems but are not pure Python and do not address PII. trufflehog differentiates on live credential verification against provider APIs — a deliberate non-goal for oneleak, since verification requires network calls and conflicts with the "deterministic core, no network dependency" principle in Section 16. oneleak should not attempt to match trufflehog on verification or noseyparker on bulk-repository scanning throughput; its performance target is "cheap enough to invoke on every agent turn," not "fastest full-history scan."

Two ecosystem practices are worth adopting rather than reinventing:

* Provider regex patterns can start from vetted, ReDoS-tested sources such as `secrets-patterns-db`, normalized into oneleak's own rule schema, rather than hand-written from scratch.
* gitleaks' allowlist/baseline UX (path, regex, and rule-scoped allowlists plus a baseline file) is a good model for Section 15's false-positive management.


