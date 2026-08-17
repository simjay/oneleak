# API Reference

The public surface is intentionally small. Everything below is importable directly from `oneleaks` (e.g. `oneleaks.Config`, `oneleaks.RuleMatch`), except the `git` functions, which live under `oneleaks.git`:

```python
import oneleaks

oneleaks.scan(...)
oneleaks.sanitize(...)
oneleaks.desanitize(...)
oneleaks.git.scan_changed(...)
oneleaks.git.scan_staged(...)
oneleaks.git.scan_history(...)
```

## Scanning and sanitizing

::: oneleaks.scanner.scan

::: oneleaks.sanitizer.sanitize

::: oneleaks.sanitizer.desanitize

## Git

::: oneleaks.git.scan_changed

::: oneleaks.git.scan_staged

::: oneleaks.git.scan_history

## Configuration

`Config` mirrors `.oneleaks.yaml` for callers who want to build one directly instead of loading a file. See [Configuration](../getting-started/configuration.md) for the YAML shape and field descriptions.

::: oneleaks.config.Config

## Models

::: oneleaks.models.Finding

::: oneleaks.models.ScanResult

::: oneleaks.models.SanitizedResult

::: oneleaks.models.MappingEntry

::: oneleaks.models.Rule

::: oneleaks.models.RuleMatch

::: oneleaks.models.PythonRule

::: oneleaks.models.Category

::: oneleaks.models.Severity

## Errors

Every error oneleaks raises deliberately is an `OneleaksError`. Catch that if you don't need to distinguish the subclass, or catch the specific one for finer-grained handling.

::: oneleaks.errors.OneleaksError

::: oneleaks.errors.ConfigError

::: oneleaks.errors.ScanError
