"""Command-line interface: `oneleak scan`, `oneleak sanitize`, `oneleak desanitize`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from oneleak import git
from oneleak.config import discover_config
from oneleak.errors import OneleakError
from oneleak.models import Finding, MappingEntry, Severity, severity_rank
from oneleak.sanitizer import desanitize, sanitize
from oneleak.scanner import finding_to_dict, scan

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


def _blocking(findings: list[Finding], fail_on: str | None) -> list[Finding]:
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

    if truncated:
        print(
            f"warning: history scan stopped at --max-commits {args.max_commits}; "
            "raise it or pass --max-commits 0 for unlimited",
            file=sys.stderr,
        )

    blocking = _blocking(findings, args.fail_on)

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
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        placeholder: MappingEntry(
            value=entry["value"], rule_id=entry["rule_id"], fingerprint=entry.get("fingerprint")
        )
        for placeholder, entry in data.get("mapping", {}).items()
    }


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
    parser = argparse.ArgumentParser(prog="oneleak")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Scan text/files/directories for sensitive data")
    scan_p.add_argument("paths", nargs="*", help="Files, directories, or '-' for stdin")
    git_group = scan_p.add_mutually_exclusive_group()
    git_group.add_argument("--changed", action="store_true", help="Scan git working-tree changes")
    git_group.add_argument("--staged", action="store_true", help="Scan git staged (index) content")
    git_group.add_argument(
        "--history", action="store_true", help="Scan git commit history (see --since/--max-commits)"
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
        help="With --history: commit cap, most recent first (0 = unlimited, default 5000)",
    )
    scan_p.add_argument(
        "--all-refs",
        action="store_true",
        help="With --history: scan all branches/tags, not just HEAD",
    )
    scan_p.add_argument("--json", action="store_true", help="Emit JSON output")
    scan_p.add_argument("--fail-on", choices=[s.value for s in Severity], default=None)
    scan_p.add_argument("--config", default=None, help="Path to .oneleak.yaml")
    scan_p.set_defaults(func=cmd_scan)

    sanitize_p = subparsers.add_parser("sanitize", help="Redact sensitive data")
    sanitize_p.add_argument("path", help="File to sanitize, or '-' for stdin")
    sanitize_p.add_argument("--map", default=None, help="Write a placeholder->value mapping file")
    sanitize_p.add_argument("--config", default=None, help="Path to .oneleak.yaml")
    sanitize_p.set_defaults(func=cmd_sanitize)

    desanitize_p = subparsers.add_parser(
        "desanitize", help="Reverse sanitize() using a mapping file"
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
    except OneleakError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # CLI top-level guard, never dump content
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
