# Sanitization

`sanitize()` reuses `scan()`'s findings. There's no second detection system to keep in sync.

## Typed, numbered placeholders

```python
result = oneleaks.sanitize(
    "Email alice@example.com using key sk-proj-xxxx. Contact alice@example.com again."
)
print(result.text)
```

```text
Email <EMAIL_1> using key <OPENAI_API_KEY_1>. Contact <EMAIL_1> again.
```

Two things are happening:

- **Repeated values reuse one placeholder.** Both mentions of `alice@example.com` become `<EMAIL_1>`, so the text still reads coherently.
- **Distinct values get distinct numbers.** A second address would be `<EMAIL_2>`.

## Reversible sanitization

By default nothing raw survives in the result. Pass `reveal=True` to opt into a mapping:

```python
result = oneleaks.sanitize(text, reveal=True)

result.mapping
# {"<EMAIL_1>": MappingEntry(value="alice@example.com", rule_id="email", ...)}

restored = oneleaks.desanitize(result.text, result.mapping)
assert restored == text
```

`result.mapping` stays `None` unless you ask for it. This is the one deliberate exception to "no raw values by default," and it exists for the agent pattern below.

### Why reversibility matters for agents

An agent can work entirely on sanitized text — the model never sees a real secret — and rehydrate only at the moment of acting:

```python
safe = oneleaks.sanitize(tool_output, reveal=True)
agent.add_context(safe.text)                                  # model sees placeholders only
...
real = oneleaks.desanitize(agent_decision_text, safe.mapping)  # rehydrate right before use
```

### Consistency across multiple calls

For an agent making many tool calls in one session, `seed_mapping` carries numbering and reuse across calls:

```python
r1 = oneleaks.sanitize(tool_output_1, reveal=True)
r2 = oneleaks.sanitize(tool_output_2, reveal=True, seed_mapping=r1.mapping)
```

A value appearing in both outputs now reuses the same placeholder.

## The mapping file is a vault, not a log

!!! danger "Treat an exported mapping exactly like the original secrets"

    Writing a mapping to disk with `oneleaks sanitize --map mapping.json` produces **tokenization**, not redaction. It is reversible by design.

    A leaked mapping file is as bad as a leaked secret, because it undoes the whole protection.

    The CLI writes it with `0600` permissions and a stderr warning. **Never commit it.**

## Algorithm notes

- Replacements run **right to left**, by descending start offset, so earlier replacements don't invalidate later offsets.
- Overlapping findings are resolved *before* replacement. See [overlap resolution](architecture.md#4-overlap-resolution).
- `desanitize()` is a plain per-placeholder string replace. Placeholders missing from the input, or placeholder-shaped tokens missing from the mapping, are left alone rather than raising — sanitized text often round-trips through a model that won't echo every placeholder verbatim.
