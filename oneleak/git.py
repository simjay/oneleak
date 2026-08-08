"""Git integration: scan_changed() (working tree) and scan_staged() (index content).

Uses the installed `git` binary via subprocess; the Python package itself stays
pure Python (this is the one module that shells out).
"""

from __future__ import annotations

import subprocess

from oneleak.errors import ScanError
from oneleak.models import ScanResult
from oneleak.scanner import (
    _is_probably_binary,
    build_registry,
    resolve_config,
    scan_text_with_config,
)


def _run_git(args: list[str], cwd: str | None = None) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:
        raise ScanError("git executable not found") from exc
    except subprocess.CalledProcessError as exc:
        raise ScanError(f"git {' '.join(args)} failed: {exc.stderr.strip()}") from exc
    return result.stdout


def _has_head(cwd: str | None = None) -> bool:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "-q", "HEAD"],
            cwd=cwd,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScanError("git executable not found") from exc
    return result.returncode == 0


def _changed_files(cwd: str | None = None) -> list[str]:
    if _has_head(cwd):
        diff_out = _run_git(["diff", "--name-only", "--diff-filter=ACMR", "HEAD"], cwd=cwd)
    else:
        # No commits yet: there's no HEAD to diff against, so fall back to
        # staged-vs-empty-tree plus working-tree-vs-index.
        staged = _run_git(["diff", "--name-only", "--diff-filter=ACMR", "--cached"], cwd=cwd)
        unstaged = _run_git(["diff", "--name-only", "--diff-filter=ACMR"], cwd=cwd)
        diff_out = staged + "\n" + unstaged
    untracked_out = _run_git(["ls-files", "--others", "--exclude-standard"], cwd=cwd)
    files = {line for line in diff_out.splitlines() if line}
    files |= {line for line in untracked_out.splitlines() if line}
    return sorted(files)


def _staged_files(cwd: str | None = None) -> list[str]:
    out = _run_git(["diff", "--name-only", "--cached", "--diff-filter=ACMR"], cwd=cwd)
    return sorted(line for line in out.splitlines() if line)


def _read_working_tree_file(path: str, cwd: str | None = None) -> bytes | None:
    from pathlib import Path

    full = (Path(cwd) if cwd else Path.cwd()) / path
    try:
        return full.read_bytes()
    except OSError:
        return None


def _read_staged_blob(path: str, cwd: str | None = None) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "show", f":{path}"], cwd=cwd, capture_output=True, check=True
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return result.stdout


def _decode(data: bytes) -> str | None:
    if _is_probably_binary(data):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _scan_files(
    paths: list[str],
    reader,
    *,
    cwd: str | None,
    rules,
    config,
) -> ScanResult:
    cfg = resolve_config(config)
    registry = build_registry(rules, cfg)
    findings = []
    for path in paths:
        data = reader(path, cwd)
        if data is None:
            continue
        text = _decode(data)
        if text is None:
            continue
        findings.extend(scan_text_with_config(text, registry, cfg, path=path))
    return ScanResult(findings=findings)


def scan_changed(*, cwd: str | None = None, rules=None, config=None) -> ScanResult:
    """Scans the current working-tree content of files that differ from HEAD,
    plus untracked files. Whole-file scanning, not hunk-limited (see plan.md).
    """
    return _scan_files(
        _changed_files(cwd), _read_working_tree_file, cwd=cwd, rules=rules, config=config
    )


def scan_staged(*, cwd: str | None = None, rules=None, config=None) -> ScanResult:
    """Scans the staged (index) version of files, not the working-tree version --
    these can differ if a file was edited again after `git add`.
    """
    return _scan_files(_staged_files(cwd), _read_staged_blob, cwd=cwd, rules=rules, config=config)
