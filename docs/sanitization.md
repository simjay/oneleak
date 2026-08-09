# Sanitization

`oneleak.sanitize()` reuses `scan()`'s findings. There is no second detection system to keep in sync.

## Typed, numbered placeholders

```python
result = oneleak.sanitize("Email alice@example.com using key sk-proj-xxxx. Contact alice@example.com again.")
print(result.text)
```

```text
Email <EMAIL_1> using key <OPENAI_API_KEY_1>. Contact <EMAIL_1> again.
```

Repeated values reuse the same placeholder *within one call* (referential consistency). Distinct values of the same type get distinct numbers (`<EMAIL_1>`, `<EMAIL_2>`, ...).

## Reversible sanitization

By default `sanitize()` stays safe: no raw values are retrievable from the result. Pass `reveal=True` to opt into a mapping:

```python
result = oneleak.sanitize(text, reveal=True)

result.mapping
# {"<EMAIL_1>": MappingEntry(value="alice@example.com", rule_id="email", fingerprint="pii_..."), ...}

restored = oneleak.desanitize(result.text, result.mapping)
assert restored == text
```

`result.mapping` stays `None` unless you explicitly ask for it. This is the one deliberate exception to "no raw values by default," and it exists specifically to support the agent pattern below.

### Why reversibility matters for agents

An agent can work entirely on sanitized text (the LLM itself never sees a real secret) and rehydrate the real value only at the point of actually performing an action:

```python
safe = oneleak.sanitize(tool_output, reveal=True)
agent.add_context(safe.text)          # LLM only ever sees placeholders
...
real = oneleak.desanitize(agent_decision_text, safe.mapping)  # rehydrate right before use
```

### Continuing numbering across multiple calls

For an agent making many tool calls in one session, `seed_mapping` keeps placeholder numbering and reuse consistent across calls, not just within one:

```python
r1 = oneleak.sanitize(tool_output_1, reveal=True)
r2 = oneleak.sanitize(tool_output_2, reveal=True, seed_mapping=r1.mapping)
# a value repeated between tool_output_1 and tool_output_2 reuses the same placeholder
```

## The mapping file is a vault, not a log

If you export a mapping to disk (`oneleak sanitize --map mapping.json` on the CLI), treat it exactly as sensitively as the original content: it's tokenization (reversible), not redaction (one-way). The CLI writes it with `0600` permissions and a stderr warning. **Never commit it**.

## Algorithm notes

- Findings are replaced right-to-left (by descending start offset) so earlier replacements don't invalidate later offsets.
- Overlapping findings are resolved *before* replacement. See [how rule priority resolves overlaps](architecture.md#4-overlap-resolution) in How Scanning & Sanitization Work.
- `desanitize()` does a plain per-placeholder string replace. Placeholders missing from the input, or placeholder-shaped tokens missing from the mapping, are left untouched rather than raising.
