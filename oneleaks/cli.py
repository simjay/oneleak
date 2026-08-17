"""Command-line interface: `oneleaks scan`, `oneleaks sanitize`, `oneleaks desanitize`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from oneleaks import __version__, git
from oneleaks import sarif as sarif_output
from oneleaks.baseline import (
    filter_new,
    load_baseline,
    require_stable_fingerprint_key,
    write_baseline,
)
from oneleaks.config import discover_config
from oneleaks.errors import ConfigError, OneleaksError, read_text_file
from oneleaks.findings import finding_to_dict
from oneleaks.models import Category, Finding, MappingEntry, Severity, severity_rank
from oneleaks.sanitizer import desanitize, sanitize
from oneleaks.scanner import scan

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _print_findings_human(findings: list[Finding]) -> None:
    if not findings:
        print("No findings.")
        return
    for f in findings:
        location = f.path or "<text>"
        if f.line is not None:
            location = f"{location}:{f.line}"
        if f.commit:
            location = f"{location}@{f.commit[:8]}"
        print(f"[{f.severity}] {f.rule_id} ({f.type}) at {location} -- {f.preview}")


def _print_summary(findings: list[Finding]) -> None:
    """One line telling you how much of what you are looking at is serious."""
    if not findings:
        return
    counts = Counter(f.severity for f in findings)
    parts = [
        f"{counts[name]} {name}"
        for name in ("critical", "high", "medium", "low")
        if counts.get(name)
    ]
    noun = "finding" if len(findings) == 1 else "findings"
    print(f"\n{len(findings)} {noun}: {', '.join(parts)}")


def _apply_filters(findings: list[Finding], categories: list[str] | None, severity: str | None):
    """Narrow the reported set. Unlike `--fail-on`, which only moves the exit
    code, these drop findings outright, so output, JSON and the exit code all
    agree on what was reported.
    """
    if categories:
        wanted = set(categories)
        findings = [f for f in findings if f.category in wanted]
    if severity is not None:
        threshold = severity_rank(severity)
        findings = [f for f in findings if severity_rank(f.severity) >= threshold]
    return findings


def _findings_that_fail_the_run(findings: list[Finding], fail_on: str | None) -> list[Finding]:
    if fail_on is None:
        return findings
    threshold = severity_rank(fail_on)
    return [f for f in findings if severity_rank(f.severity) >= threshold]


def _read_stdin_text() -> str:
    data = sys.stdin.buffer.read()
    return data.decode("utf-8")


def cmd_scan(args: argparse.Namespace) -> int:
    if (args.changed or args.staged or args.history) and args.paths:
        flag = "--changed" if args.changed else "--staged" if args.staged else "--history"
        print(
            f"error: {flag} scans git content, not the given path(s); drop one or the other",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if args.update_baseline and not args.baseline:
        print("error: --update-baseline requires --baseline", file=sys.stderr)
        return EXIT_ERROR

    config = args.config or discover_config()

    findings: list[Finding] = []
    truncated = False
    if args.changed:
        findings = git.scan_changed(config=config).findings
    elif args.staged:
        findings = git.scan_staged(config=config).findings
    elif args.history:
        result = git.scan_history(
            config=config,
            since=args.since,
            max_commits=args.max_commits,
            all_refs=args.all_refs,
        )
        findings = result.findings
        truncated = result.truncated
    else:
        targets = args.paths or ["."]
        for target in targets:
            if target == "-":
                text = _read_stdin_text()
                findings.extend(scan(text, config=config).findings)
            else:
                findings.extend(scan(Path(target), config=config).findings)

    if args.baseline:
        require_stable_fingerprint_key()
        if args.update_baseline:
            write_baseline(args.baseline, findings)
        findings = filter_new(findings, load_baseline(args.baseline))

    findings = _apply_filters(findings, args.category, args.severity)

    if truncated:
        print(
            f"warning: history scan stopped at --max-commits {args.max_commits}; "
            "raise it or pass --max-commits 0 for unlimited",
            file=sys.stderr,
        )

    blocking = _findings_that_fail_the_run(findings, args.fail_on)

    if args.json:
        risk = max((f.severity for f in blocking), key=severity_rank) if blocking else None
        payload = {
            "safe": len(blocking) == 0,
            "risk": risk,
            "findings": [finding_to_dict(f) for f in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_findings_human(findings)
        _print_summary(findings)

    if args.sarif:
        Path(args.sarif).write_text(sarif_output.dumps(findings, version=__version__))

    return EXIT_FINDINGS if blocking else EXIT_CLEAN


def _write_mapping_file(path: str, mapping: dict[str, MappingEntry]) -> None:
    payload = {
        "version": 1,
        "mapping": {
            placeholder: {"value": e.value, "rule_id": e.rule_id, "fingerprint": e.fingerprint}
            for placeholder, e in mapping.items()
        },
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"warning: {path} contains raw sensitive values -- do not commit it", file=sys.stderr)


def _load_mapping_file(path: str) -> dict[str, MappingEntry]:
    text = read_text_file(path, what="mapping file")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid mapping file: {exc.msg} (line {exc.lineno})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("mapping"), dict):
        raise ConfigError(f"{path}: expected a top-level 'mapping' object")

    mapping = {}
    for placeholder, entry in data["mapping"].items():
        try:
            mapping[placeholder] = MappingEntry(
                value=entry["value"],
                rule_id=entry["rule_id"],
                fingerprint=entry.get("fingerprint"),
            )
        except (KeyError, TypeError) as exc:
            raise ConfigError(
                f"{path}: mapping entry '{placeholder}' is missing or has a malformed "
                f"'value'/'rule_id'"
            ) from exc
    return mapping


def cmd_sanitize(args: argparse.Namespace) -> int:
    config = args.config or discover_config()
    content = "-" if args.path == "-" else Path(args.path)
    text = _read_stdin_text() if content == "-" else content

    result = sanitize(text, config=config, reveal=bool(args.map))
    sys.stdout.write(result.text)
    if not result.text.endswith("\n"):
        sys.stdout.write("\n")

    if args.map:
        _write_mapping_file(args.map, result.mapping or {})

    return EXIT_CLEAN


def cmd_desanitize(args: argparse.Namespace) -> int:
    mapping = _load_mapping_file(args.map)
    text = _read_stdin_text() if args.path == "-" else Path(args.path).read_text(encoding="utf-8")
    restored = desanitize(text, mapping)
    sys.stdout.write(restored)
    if not restored.endswith("\n"):
        sys.stdout.write("\n")
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oneleaks",
        description=(
            "Scan for and redact secrets and PII. Scans text, files, directories, "
            "or git content (working tree, index, or commit history); redacts with "
            "typed placeholders that can optionally be reversed."
        ),
    )
    parser.add_argument("--version", action="version", version=f"oneleaks {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Scan text/files/directories for sensitive data")
    scan_p.add_argument("paths", nargs="*", help="Files, directories, or '-' for stdin")
    git_group = scan_p.add_mutually_exclusive_group()
    git_group.add_argument(
        "--changed",
        action="store_true",
        help=("Scan the files you have changed but not committed yet"),
    )
    git_group.add_argument(
        "--staged", action="store_true", help=("Scan the files you have staged with git add")
    )
    git_group.add_argument(
        "--history",
        action="store_true",
        help=("Scan git commit history (see --since/--max-commits)"),
    )
    scan_p.add_argument(
        "--since",
        default=None,
        help="With --history: only commits after this date (git --since format)",
    )
    scan_p.add_argument(
        "--max-commits",
        type=int,
        default=5000,
        help=(
            "With --history: how many commits to look at, newest first (0 means all, default 5000)"
        ),
    )
    scan_p.add_argument(
        "--all-refs",
        action="store_true",
        help="With --history: scan all branches/tags, not just HEAD",
    )
    scan_p.add_argument(
        "--category",
        action="append",
        choices=[c.value for c in Category],
        help="Only report this kind of finding. Can be given more than once. "
        "This hides the others completely, so the exit code matches what you see",
    )
    scan_p.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        help="Only report findings this severe or worse. This hides the others "
        "completely, unlike --fail-on which still prints them",
    )
    scan_p.add_argument(
        "--json", action="store_true", help=("Print the results as JSON instead of plain text")
    )
    scan_p.add_argument(
        "--sarif",
        metavar="PATH",
        help="Also write a SARIF 2.1.0 report here, for GitHub code scanning",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help="Still print everything, but only fail the run on findings this severe or worse",
    )
    scan_p.add_argument("--config", default=None, help="Path to .oneleaks.yaml")
    scan_p.add_argument(
        "--baseline",
        default=None,
        help="Path to a list of findings you have already reviewed; only new ones are reported",
    )
    scan_p.add_argument(
        "--update-baseline",
        action="store_true",
        help="With --baseline: replace that file with everything found in this run",
    )
    scan_p.set_defaults(func=cmd_scan)

    sanitize_p = subparsers.add_parser(
        "sanitize", help="Redact secrets/PII, writing the result to stdout"
    )
    sanitize_p.add_argument("path", help="File to sanitize, or '-' for stdin")
    sanitize_p.add_argument(
        "--map",
        default=None,
        help=("Save a file that maps each placeholder back to the original value"),
    )
    sanitize_p.add_argument("--config", default=None, help="Path to .oneleaks.yaml")
    sanitize_p.set_defaults(func=cmd_sanitize)

    desanitize_p = subparsers.add_parser(
        "desanitize", help="Restore values redacted by `oneleaks sanitize --map`"
    )
    desanitize_p.add_argument("path", help="Sanitized file to restore, or '-' for stdin")
    desanitize_p.add_argument(
        "--map", required=True, help="Mapping file written by `sanitize --map`"
    )
    desanitize_p.set_defaults(func=cmd_desanitize)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OneleaksError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # CLI top-level guard, never dump content
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
