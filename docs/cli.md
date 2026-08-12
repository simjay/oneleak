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
| `--baseline PATH` | Only report findings not already recorded in this baseline file. Requires `ONELEAKS_FINGERPRINT_KEY` to be set. See [Baselines](configuration.md#baselines). |
| `--update-baseline` | With `--baseline`: overwrite it with this run's findings instead of filtering against it. |

### Git history scanning

`oneleaks scan .`, `--changed`, and `--staged` only see *current* content. A secret committed and later removed is still fully recoverable from git history unless it's been rewritten, and `--history` is what catches that:

```bash
oneleaks scan --history                     # current branch, most recent 5000 commits
oneleaks scan --history --since "2025-01-01"
oneleaks scan --history --max-commits 0     # no cap
oneleaks scan --history --all-refs          # every branch and tag, not just HEAD
```

Findings from `--history` include a `commit` field (the commit that introduced the secret), shown as `path:line@abcd1234` in human output and `"commit"` in JSON. Defaulting to current-branch history capped at 5000 commits (rather than `--all-refs` with no cap) avoids a surprise multi-hour run on a large repo's first scan. If the cap truncates the scan, a warning is printed to stderr rather than failing silently.

Detection works on each commit's diff (only what that commit actually added), not the whole file at every commit, so a file changed 50 times isn't rescanned in full 50 times. Multi-line formats (like a PEM private key) are still detected correctly because each diff hunk's added lines are joined into one block before scanning, not scanned line by line.

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

The mapping file is written with `0600` permissions and a stderr warning, because it contains raw sensitive values by design. Treat it exactly as sensitively as the original content. Don't commit it.

## `oneleaks desanitize`

```bash
oneleaks desanitize sanitized.txt --map mapping.json
```

Reverses a prior `sanitize --map` output: replaces each placeholder found in the input with its mapped raw value. Placeholders in the mapping that don't appear in the input, and placeholder-shaped tokens in the input that aren't in the mapping, are left untouched rather than raising.

| Flag | Description |
|---|---|
| `path` (positional) | Sanitized file to restore, or `-` for stdin. |
| `--map PATH` (required) | Mapping file written by a prior `sanitize --map`. |
