# CLI Reference

```bash
oneleaks --version   # print the installed version and exit
oneleaks --help      # top-level usage (each subcommand also takes --help)
```

## `oneleaks scan`

```bash
oneleaks scan .
oneleaks scan config.yaml
oneleaks scan --changed
oneleaks scan --staged
oneleaks scan --history
oneleaks scan - --json          # read text from stdin
oneleaks scan . --fail-on high
oneleaks scan . --config path/to/.oneleaks.yaml
oneleaks scan . --baseline .oneleaks-baseline.json --update-baseline   # accept today's findings
oneleaks scan . --baseline .oneleaks-baseline.json                     # only report new ones
```

| Flag | Description |
|---|---|
| `paths` (positional) | Files, directories, or `-` for stdin. Defaults to `.` if omitted. Multiple paths may be given. Mutually exclusive with `--changed`/`--staged`/`--history`. |
| `--changed` | Scan git working-tree changes + untracked files instead of `paths`. |
| `--staged` | Scan git staged (index) content instead of `paths`. |
| `--history` | Scan git commit history for secrets, including ones later removed from the working tree. See [Git History Scanning](#git-history-scanning) below. |
| `--since DATE` | With `--history`: only commits after this date (passed straight to `git log --since=`). |
| `--max-commits N` | With `--history`: cap on commits scanned, most recent first. Default `5000`. `0` = unlimited. |
| `--all-refs` | With `--history`: scan all branches/tags, not just the current branch's history. |
| `--json` | Emit machine-readable JSON instead of human-readable lines. |
| `--fail-on {low,medium,high,critical}` | Only findings at or above this severity affect the exit code. Lower-severity findings still print/appear in output. |
| `--config PATH` | Path to a `.oneleaks.yaml` config file. If omitted, `.oneleaks.yaml` in the current directory is auto-discovered. |
| `--baseline PATH` | Only report findings not already recorded in this baseline file. Requires `ONELEAKS_FINGERPRINT_KEY` to be set. See [Baselines](../getting-started/configuration.md#baselines). |
| `--update-baseline` | With `--baseline`: overwrite it with this run's findings instead of filtering against it. |

### Git history scanning

`scan .`, `--changed`, and `--staged` only see *current* content.

A secret that was committed and later deleted stays recoverable from history until someone rewrites it. `--history` is what finds those.

```bash
oneleaks scan --history                     # current branch, most recent 5000 commits
oneleaks scan --history --since "2025-01-01"
oneleaks scan --history --max-commits 0     # no cap
oneleaks scan --history --all-refs          # every branch and tag, not just HEAD
```

History findings carry a `commit` field naming the commit that introduced the secret. Human output shows it as `path:line@abcd1234`.

**Defaults are conservative on purpose.** Current branch only, capped at 5000 commits, so a first run on a large repo doesn't turn into a surprise multi-hour scan. When the cap truncates a scan, you get a stderr warning rather than a silent partial result.

**Only added lines are scanned**, per commit diff, not whole files at every commit. A file touched 50 times isn't read 50 times over.

Multi-line formats like PEM keys still match correctly, because each hunk's added lines are joined into one block before scanning. See [why that join matters](../advanced/architecture.md#git-history-scanning).

### Exit codes

```text
0 = clean (no blocking findings)
1 = sensitive data detected
2 = execution/configuration error
```

### JSON output shape

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
      "column": 16,
      "start": 15,
      "end": 59,
      "preview": "sk-p****789",
      "fingerprint": "sec_595787508b210c47",
      "commit": null
    }
  ]
}
```

`commit` is only set for `--history` findings. It's `null` otherwise.

## `oneleaks sanitize`

```bash
oneleaks sanitize file.txt
some-command | oneleaks sanitize -
oneleaks sanitize file.txt --map mapping.json
```

Sanitized content is written to stdout, and diagnostics go to stderr, so this composes safely in pipelines.

| Flag | Description |
|---|---|
| `path` (positional) | File to sanitize, or `-` for stdin. |
| `--map PATH` | Write a placeholder → raw-value mapping file, enabling later reversal with `oneleaks desanitize`. **Never written unless you pass this flag.** |
| `--config PATH` | Path to a `.oneleaks.yaml` config file. |

!!! danger "The mapping file contains raw values by design"

    It's written with `0600` permissions and a stderr warning. Treat it exactly as sensitively as the original content, and don't commit it.

## `oneleaks desanitize`

```bash
oneleaks desanitize sanitized.txt --map mapping.json
```

Reverses a prior `sanitize --map` run, replacing each placeholder with its mapped value.

Mismatches are tolerated in both directions rather than raising: placeholders missing from the input, and placeholder-shaped tokens missing from the mapping, are left untouched.

| Flag | Description |
|---|---|
| `path` (positional) | Sanitized file to restore, or `-` for stdin. |
| `--map PATH` (required) | Mapping file written by a prior `sanitize --map`. |


## Triaging a noisy first run

A first scan of an established repository reports everything at once. Narrow it rather than turning rules off:

```bash
oneleaks scan . --category secret     # credentials only
oneleaks scan . --severity high       # high and critical only
oneleaks scan . --category secret --severity high
```

`--category` and `--severity` drop findings outright, so the output, `--json` and the exit code all agree. `--fail-on` is different: it leaves the output alone and only decides the exit code.

`email` is on by default and is usually the biggest source of noise, because
contributor lists and commit messages are full of addresses that were published
on purpose. It stays on because a tool that ships with PII detection
switched off is not a PII scanner. It is `low` severity, so
`--severity medium` clears it, and `--category secret` is the usual answer.

For findings you have reviewed and accepted, use a [baseline](../getting-started/configuration.md#baselines) rather than disabling the rule.
