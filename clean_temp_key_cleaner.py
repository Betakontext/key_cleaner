#!/usr/bin/env python3
"""Safely remove only known Key Cleaner temporary mirror directories.

This tool checks immediate children only. It is deliberately conservative: it cannot
reliably determine whether another Key Cleaner job is still running. Stop all such
jobs before deleting any directories.

Deletion is not secure erasure. It removes matching temporary mirrors and value files
inside them; it does not remove values stored elsewhere or overwrite disk blocks.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Iterable, NamedTuple

# Exact directory names created by supported cleaner releases; do not broaden these.
NAME_RE = re.compile(
    r"^(?:key-cleaner-work\.[A-Za-z0-9]{8}|"
    r"key-cleaner-publish\.[A-Za-z0-9]{8}|"
    r"key_cleaner_[A-Za-z0-9_-]+)$"
)


class Candidate(NamedTuple):
    """A directory selected after lstat, with its identity retained for rechecking."""
    path: Path
    device: int
    inode: int


def _is_link_or_junction(path: Path, st: os.stat_result) -> bool:
    """Return true for symlinks and Windows reparse points (including junctions)."""
    if stat.S_ISLNK(st.st_mode):
        return True
    attributes = getattr(st, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse and attributes & reparse)


def _owned_by_current_user(st: os.stat_result) -> bool:
    """On POSIX, reject directories not owned by this user; Windows has no uid field."""
    getuid = getattr(os, "getuid", None)
    return getuid is None or st.st_uid == getuid()


def _same_directory(path: Path, candidate: Candidate) -> bool:
    """Recheck name, type and lstat identity immediately before removal."""
    try:
        st = path.lstat()
    except OSError:
        return False
    return (
        NAME_RE.fullmatch(path.name) is not None
        and stat.S_ISDIR(st.st_mode)
        and not _is_link_or_junction(path, st)
        and _owned_by_current_user(st)
        and (st.st_dev, st.st_ino) == (candidate.device, candidate.inode)
    )


def scan_base(base: Path) -> tuple[list[Candidate], list[str]]:
    """Scan just *base*'s direct children, returning safe candidates and diagnostics."""
    found: list[Candidate] = []
    errors: list[str] = []
    try:
        with os.scandir(base) as entries:
            for entry in entries:
                if NAME_RE.fullmatch(entry.name) is None:
                    continue
                path = Path(entry.path)
                try:
                    st = path.lstat()
                    if _is_link_or_junction(path, st):
                        errors.append(f"Skipped link or junction: {path}")
                    elif not stat.S_ISDIR(st.st_mode):
                        errors.append(f"Skipped non-directory match: {path}")
                    elif not _owned_by_current_user(st):
                        errors.append(f"Skipped directory owned by another user: {path}")
                    else:
                        found.append(Candidate(path, st.st_dev, st.st_ino))
                except OSError as exc:
                    errors.append(f"Cannot inspect {path}: {exc}")
    except OSError as exc:
        errors.append(f"Cannot scan base {base}: {exc}")
    return found, errors


def _remove_readonly(func, path, exc_info) -> None:
    """rmtree callback: chmod and retry only an owned, non-link regular file on POSIX."""
    exc = exc_info[1]
    if not isinstance(exc, PermissionError):
        raise exc
    try:
        st = os.lstat(path)
        getuid = getattr(os, "getuid", None)
        if (getuid is None or st.st_uid != getuid() or not stat.S_ISREG(st.st_mode)
                or stat.S_ISLNK(st.st_mode)):
            raise exc
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        func(path)
    except OSError as retry_error:
        raise retry_error


def remove_candidate(candidate: Candidate) -> tuple[bool, str | None]:
    """Delete one revalidated candidate without following the candidate itself as a link."""
    if not _same_directory(candidate.path, candidate):
        return False, f"Safety recheck failed; not removed: {candidate.path}"
    try:
        shutil.rmtree(candidate.path, onerror=_remove_readonly)
        return True, None
    except OSError as exc:
        return False, f"Cannot remove {candidate.path}: {exc}"


def _default_bases() -> list[Path]:
    """Return de-duplicated default roots, without resolving symlinks."""
    return _dedupe([Path(tempfile.gettempdir()), Path.home()])


def _dedupe(paths: Iterable[Path]) -> list[Path]:
    """Deduplicate bases lexically, preserving the first occurrence."""
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = os.path.normcase(os.path.abspath(os.fspath(path)))
        if key not in seen:
            seen.add(key)
            result.append(Path(path))
    return result


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base", action="append", default=[], metavar="PATH",
                        help="Scan this base instead of defaults; repeatable. Immediate children only.")
    parser.add_argument("--list", action="store_true", help="List matches; do not delete.")
    parser.add_argument("-f", "--force", action="store_true",
                        help="Bypass only the DELETE confirmation, never safety checks.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the cleaner and return a process-style status code (testable with argv)."""
    args = build_parser().parse_args(argv)
    bases = _dedupe([Path(x).expanduser() for x in args.base]) if args.base else _default_bases()
    candidates: list[Candidate] = []
    problems: list[str] = []
    for base in bases:
        if not base.exists():
            print(f"Warning: base does not exist; skipped: {base}", file=sys.stderr)
            continue
        if not base.is_dir():
            problems.append(f"Base is not a directory: {base}")
            continue
        found, errors = scan_base(base)
        candidates.extend(found)
        problems.extend(errors)
    for candidate in candidates:
        print(candidate.path)
    for problem in problems:
        print(f"Warning: {problem}", file=sys.stderr)
    # Skips are warnings; only inaccessible/path errors make the run unsuccessful.
    fatal_problems = [x for x in problems if x.startswith(("Cannot inspect", "Cannot scan base", "Base is not"))]
    print(f"Matches: {len(candidates)}")
    if args.list:
        print("List mode: no directories were deleted.")
        return 1 if fatal_problems else 0
    if not candidates:
        print("Nothing deleted.")
        return 1 if fatal_problems else 0
    if not args.force:
        print("WARNING: Stop all running Key Cleaner jobs first. Active jobs cannot be detected reliably.")
        try:
            answer = input("Type DELETE to remove the listed directories: ")
        except (EOFError, KeyboardInterrupt):
            answer = ""
            print()
        if answer != "DELETE":
            print("Cancelled. Nothing deleted.")
            return 1 if fatal_problems else 0
    removed = 0
    deletion_problems: list[str] = []
    for candidate in candidates:
        ok, error = remove_candidate(candidate)
        if ok:
            removed += 1
            print(f"Removed: {candidate.path}")
        else:
            deletion_problems.append(error or "Unknown deletion error")
            print(f"Warning: {deletion_problems[-1]}", file=sys.stderr)
    print(f"Totals: matched={len(candidates)} removed={removed} errors={len(fatal_problems) + len(deletion_problems)}")
    return 1 if fatal_problems or deletion_problems else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
