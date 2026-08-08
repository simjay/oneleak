"""Git integration: scan_changed() (working tree) and scan_staged() (index content).

Uses the installed `git` binary via subprocess; the Python package itself stays
pure Python (this is the one module that shells out).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, replace

from oneleak.errors import ScanError
from oneleak.models import ScanResult
from oneleak.scanner import (
    _is_probably_binary,
    build_registry,
    resolve_config,
    scan_text_with_config,
)

# The well-known SHA1 of git's empty tree object -- used as the "parent" of a
# root commit (which has no real parent to diff against).
_EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<newstart>\d+)(?:,\d+)? @@")


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


# --- History scanning ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CommitHunk:
    path: str
    start_line: int
    blob: str


def _commit_list(
    cwd: str | None,
    *,
    since: str | None,
    max_commits: int,
    all_refs: bool,
) -> tuple[list[tuple[str, str]], bool]:
    """Returns [(sha, parent_sha), ...] oldest-first, and whether the list was
    truncated. Capping keeps the *most recent* max_commits commits (the ones
    most likely to matter), not the oldest.
    """
    args = ["log", "--format=%H,%P"]
    if all_refs:
        args.insert(1, "--all")
    if since:
        args.append(f"--since={since}")
    lines = [line for line in _run_git(args, cwd=cwd).splitlines() if line]

    truncated = bool(max_commits) and len(lines) > max_commits
    if max_commits:
        lines = lines[:max_commits]  # git log is newest-first; keep the newest N
    lines.reverse()  # then process oldest-first, so `commit` means "introduced in"

    commits = []
    for line in lines:
        sha, _, parents = line.partition(",")
        parent = parents.split()[0] if parents.strip() else _EMPTY_TREE_SHA
        commits.append((sha, parent))
    return commits, truncated


def _commit_diff_hunks(sha: str, parent: str, cwd: str | None) -> list[_CommitHunk]:
    """Parses `git diff --unified=0` output into one blob per hunk, made of
    only the *added* lines (joined with newlines, so multi-line formats like
    a PEM private key stay adjacent for the detection pipeline to match --
    scanning line-by-line would split BEGIN/END markers into disconnected
    strings the PEM regex could never join). Only additions are collected;
    removed lines are ignored. Renamed/deleted files and binary diffs
    contribute nothing (a deletion-only hunk has no `+` lines to collect).
    """
    diff_text = _run_git(["diff", "--unified=0", "--no-color", parent, sha], cwd=cwd)

    hunks: list[_CommitHunk] = []
    current_path: str | None = None
    binary = False
    added_lines: list[str] = []
    hunk_start: int | None = None

    def flush() -> None:
        if current_path is not None and hunk_start is not None and added_lines:
            hunks.append(_CommitHunk(current_path, hunk_start, "\n".join(added_lines)))

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush()
            added_lines, hunk_start, binary, current_path = [], None, False, None
        elif line.startswith("Binary files "):
            binary = True
        elif line.startswith("+++ "):
            flush()
            added_lines, hunk_start = [], None
            target = line[4:]
            if target == "/dev/null":
                current_path = None
            else:
                current_path = target.removeprefix("b/")
        elif line.startswith("@@"):
            flush()
            added_lines = []
            m = _HUNK_HEADER_RE.match(line)
            hunk_start = int(m.group("newstart")) if m else None
        elif binary:
            continue
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])
    flush()
    return hunks


def scan_history(
    *,
    cwd: str | None = None,
    rules=None,
    config=None,
    since: str | None = None,
    max_commits: int = 5000,
    all_refs: bool = False,
) -> ScanResult:
    """Scans commit history for secrets, including ones later removed from
    the working tree -- what `oneleak scan .` / scan_changed() / scan_staged()
    cannot see, since they only look at current content.

    Defaults to the current branch's history (not --all), capped at the most
    recent 5000 commits; both are overridable. `since` is passed straight to
    `git log --since=`. `Finding.commit` records which commit introduced it;
    `ScanResult.truncated` is True if `max_commits` cut the scan short.
    """
    cfg = resolve_config(config)
    registry = build_registry(rules, cfg)

    commits, truncated = _commit_list(cwd, since=since, max_commits=max_commits, all_refs=all_refs)

    findings = []
    for sha, parent in commits:
        for hunk in _commit_diff_hunks(sha, parent, cwd):
            for finding in scan_text_with_config(hunk.blob, registry, cfg, path=hunk.path):
                line = (finding.line or 1) + hunk.start_line - 1
                findings.append(replace(finding, line=line, commit=sha))

    return ScanResult(findings=findings, truncated=truncated)
