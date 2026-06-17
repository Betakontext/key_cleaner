#!/usr/bin/env python3
"""
Key cleaner: One-click local tool to scan and (if needed) purge leaked secrets from a Git repository history.
:::::::::::::::::::::::::::::
Dry-run scan (no changes):

    ./key_cleaner.py --target https://github.com/your/repo.git --exact-key 'your_new_key_here' --scan-commit-messages --verify-only

Full run (will only rewrite if hits were found; add --confirm to skip prompt):

    ./key_cleaner.py --target https://github.com/your/repo.git --exact-key 'your_new_key_here' --purge-path .env --scan-commit-messages --confirm
:::::::::::::::::::::::::::::

What this tool does:
- Scans the entire Git history (all refs) for:
  - Exact secret values you provide via --exact-key (repeatable flag).
  - Optional heuristic patterns (enabled by default) such as 'sk-' prefixes and common env var names.
  - Optional commit message scan (via --scan-commit-messages).
- If NOTHING is found:
  - Prints a clear "not found" summary and exits without modifying anything.
- If SOMETHING is found:
  - Rewrites history using git-filter-repo to:
    - Remove specific paths across history (e.g., .env, images with embedded keys).
    - Strip any blobs that contain the exact secret values provided.
  - Prompts for confirmation (unless --confirm) before force-pushing rewritten branches (and optionally tags).
  - Verifies cleanup by cloning fresh and scanning again.
  - Prints step-by-step guidance to realign your local working folder (without touching untracked/ignored files).

Important notes:
- History rewrite is destructive to commit SHAs. Coordinate with collaborators.
- PR refs and forks are not rewritten by your push; they must be closed/rebased separately.
- The tool is strictly local and uses the Git CLI; it does not upload your data anywhere.

Prerequisites:
- git >= 2.30
- git-filter-repo installed (pipx install git-filter-repo or pip install git-filter-repo)
- Python 3.10+

Typical usage:
  # Scan only (non-destructive), including commit messages:
  python key_cleaner.py --target https://github.com/org/repo.git --exact-key 'sk_ABC...' --scan-commit-messages --verify-only

  # Full run: scan -> (if hits) rewrite -> confirm -> force-push -> verify
  python key_cleaner.py --target https://github.com/org/repo.git --exact-key 'sk_ABC...' --purge-path .env --confirm

  # Local repo path (preserves .venv, __pycache__, .env in your original folder):
  python key_cleaner.py --target /path/to/local/repo --exact-key 'sk_ABC...' --purge-path .env --confirm

Expected outcomes:

    # No matches: “[result] No secrets found.” and immediate exit. No rewrite/push.

    # Matches:
    -   Shows sample hits.
    -   Prints a plan and asks for confirmation (unless --confirm).
    -   Rewrites history (paths, blob strip by exact key), force-pushes, and verifies from a fresh clone.
    -   Prints “[verify-ok] No matches found …” on success, or lists residual matches with next-step hints.

"""

from __future__ import annotations
import argparse
import os
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Set

try:
    from pydantic import BaseModel, Field, validator
except ImportError:
    print("Missing dependency 'pydantic'. Install via: pip install pydantic")
    sys.exit(1)


# ---------------------------
# Configuration models
# ---------------------------

class CleanerConfig(BaseModel):
    """
    Validated runtime configuration for the cleaner.
    """
    target: str = Field(..., description="Remote URL (https/ssh) or local repo path")
    exact_keys: List[str] = Field(default_factory=list, description="Exact secret strings to search & purge (e.g., full 'sk_...' value)")
    purge_paths: List[str] = Field(default_factory=lambda: [".env"], description="Repository paths to remove across history")
    enable_heuristics: bool = Field(default=True, description="Search heuristic patterns like 'sk-' or env var names")
    push_tags: bool = Field(default=False, description="Also force-push tags after rewrite (off by default)")
    confirm: bool = Field(default=False, description="Proceed without interactive confirmation prompts")
    retries: int = Field(default=2, ge=0, le=5, description="Retries for networked git operations")
    timeout_sec: int = Field(default=600, ge=60, le=7200, description="Timeout for long-running steps (seconds)")
    verify_only: bool = Field(default=False, description="Only scan/verify; do not rewrite or push")
    keep_temp: bool = Field(default=False, description="Keep temporary working directories for inspection")
    scan_commit_messages: bool = Field(default=False, description="Also grep commit messages for exact keys/patterns")

    @validator("target")
    def _strip_target(cls, v: str) -> str:
        return v.strip()


@dataclass
class WorkDirs:
    """
    Ephemeral working directories:
    - rewrite_dir: used for cloning and rewriting history
    - verify_dir: used for fresh clone to verify results
    - logs_dir: reserved for future log files if needed
    """
    base: Path
    rewrite_dir: Path
    verify_dir: Path
    logs_dir: Path

    @staticmethod
    def create() -> "WorkDirs":
        base = Path(tempfile.gettempdir()) / f"key_cleaner_{uuid.uuid4().hex[:8]}"
        rewrite = base / "rewrite"
        verify = base / "verify"
        logs = base / "logs"
        for p in (rewrite, verify, logs):
            p.mkdir(parents=True, exist_ok=True)
        return WorkDirs(base=base, rewrite_dir=rewrite, verify_dir=verify, logs_dir=logs)


# ---------------------------
# Utility functions
# ---------------------------

def run(cmd: str, cwd: Optional[Path] = None, timeout: Optional[int] = None, check: bool = True) -> subprocess.CompletedProcess:
    """
    Run a shell command with:
    - echo of the command (so the user sees what runs),
    - captured stdout/stderr,
    - optional error raising when check=True.

    Expected output:
    - Prints the command prefixed with '$ '.
    - Prints stdout (normal output) and stderr (progress/warnings).
    - Raises RuntimeError on non-zero exit if check=True.
    """
    print(f"$ {cmd}")
    start = time.time()
    cp = subprocess.run(cmd, cwd=str(cwd) if cwd else None, shell=True,
                        capture_output=True, text=True, timeout=timeout)
    dur = time.time() - start
    if cp.stdout:
        print(cp.stdout.rstrip())
    if cp.stderr:
        # Many git commands write progress to stderr; we still show it
        print(cp.stderr.rstrip(), file=sys.stderr)
    if check and cp.returncode != 0:
        raise RuntimeError(f"Command failed ({cp.returncode}) after {dur:.1f}s: {cmd}\n{cp.stderr}")
    return cp


def is_git_repo(path: Path) -> bool:
    """
    Return True if the given path is inside a Git work tree.
    """
    try:
        run("git rev-parse --is-inside-work-tree", cwd=path, timeout=15)
        return True
    except Exception:
        return False


def has_git_filter_repo() -> bool:
    """
    Return True if git-filter-repo is available on PATH.
    """
    try:
        run("git filter-repo -h", timeout=15)
        return True
    except Exception:
        return False


def guess_origin_url(repo_dir: Path) -> Optional[str]:
    """
    Try to get the 'origin' remote URL of a local repo. Returns None if not set.
    """
    cp = run("git remote get-url origin", cwd=repo_dir, timeout=15, check=False)
    return cp.stdout.strip() if cp.returncode == 0 else None


# ---------------------------
# Scanning primitives
# ---------------------------

# Heuristic search patterns (regex) that often indicate API secrets.
HEURISTIC_PATTERNS = [
    r"sk-[A-Za-z0-9]{10,}",  # e.g., OpenAI-like prefix; adjust to your environment
    r"POLLINATIONS_SECRET",
    r"POLLINATIONS_API_KEY",
    r"API_KEY\s*=",
    r"SECRET\s*=",
]

def grep_history(repo_dir: Path, pattern: str, timeout: int) -> Tuple[int, List[str]]:
    """
    Search file contents across ALL refs (full history).
    We iterate all commits (git rev-list --all) and run git grep against each tree.

    Returns:
      (count, lines) where 'lines' contains up to thousands of 'ref:file:line:content' matches,
      depending on repo size.

    Expected behavior:
      - If matches exist: count > 0, lines non-empty (each line shows commit/tree context).
      - If no matches: count == 0, lines == [].
    """
    q = shlex.quote(pattern)  # safe quoting
    cmd = f"bash -lc \"git rev-list --all | xargs -I{{}} sh -c 'git grep -n -I -a --all-match {q} {{}}'\""
    try:
        cp = run(cmd, cwd=repo_dir, timeout=timeout, check=False)
        lines = [l for l in cp.stdout.splitlines() if l.strip()]
        return (len(lines), lines)
    except Exception as e:
        print(f"[warn] grep_history failed for pattern {pattern}: {e}")
        return (0, [])


def grep_commit_messages(repo_dir: Path, pattern: str, timeout: int) -> Tuple[int, List[str]]:
    """
    Search commit messages across ALL refs for a given pattern (regex or exact string).

    Returns:
      (count, lines) where lines are formatted as: '<short_sha> <date> <subject>'.

    Expected behavior:
      - If matches exist: count > 0, lines list with commit summaries.
      - If no matches: count == 0, lines == [].
    """
    q = shlex.quote(pattern)
    cmd = f"git log --all --grep={q} --pretty=format:'%h %ad %s' --date=iso"
    cp = run(cmd, cwd=repo_dir, timeout=timeout, check=False)
    lines = [l for l in cp.stdout.splitlines() if l.strip()]
    return (len(lines), lines)


def find_bad_blobs_by_exact_keys(repo_dir: Path, keys: List[str], timeout: int) -> Set[str]:
    """
    Identify blob object IDs that contain any of the provided exact key values.
    This is path-agnostic: it will find occurrences even inside renamed/moved files or binaries.

    Returns:
      A set of 40-hex blob IDs.

    Expected behavior:
      - If keys are provided and present in blobs: returns a non-empty set.
      - If no exact matches: returns an empty set.
    """
    blob_ids: Set[str] = set()
    if not keys:
        return blob_ids
    # Build a pipeline that cat-file each object and checks for any exact key via grep -F (fixed strings).
    key_greps = " || ".join([f"grep -F -q {shlex.quote(k)}" for k in keys])
    cmd = (
        "bash -lc \""
        "git rev-list --objects --all | cut -d' ' -f1 | "
        "while read oid; do "
        "  git cat-file -p \"$oid\" 2>/dev/null | ( " + key_greps + " ) && echo \"$oid\" || true; "
        "done | sort -u\""
    )
    cp = run(cmd, cwd=repo_dir, timeout=timeout, check=False)
    for line in cp.stdout.splitlines():
        if re.fullmatch(r"[0-9a-f]{40}", line.strip()):
            blob_ids.add(line.strip())
    return blob_ids


# ---------------------------
# Core flow helpers
# ---------------------------

def clone_fresh(target: str, into_dir: Path, retries: int, timeout: int) -> Path:
    """
    Clone a remote URL or a local repo (using file://) into into_dir/repo.
    Retries transient failures.

    Expected behavior:
      - On success: returns the path to the cloned repo dir.
      - On failure after retries: raises RuntimeError.
    """
    repo_dir = into_dir / "repo"
    # If target is a local git repo, clone via file:// to ensure a clean copy.
    if Path(target).exists() and is_git_repo(Path(target)):
        url = f"file://{Path(target).resolve()}"
    else:
        url = target
    last_err: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            run(f"git clone {shlex.quote(url)} {shlex.quote(str(repo_dir))}", timeout=timeout)
            return repo_dir
        except Exception as e:
            last_err = e
            print(f"[retry] clone failed (attempt {attempt+1}/{retries+1}): {e}")
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Clone failed after retries: {last_err}")


def fetch_all(repo_dir: Path, timeout: int) -> None:
    """
    Fetch all branches and tags (and prune deleted refs).
    """
    run("git fetch --all --prune --tags", cwd=repo_dir, timeout=timeout)


def remove_paths_with_filter_repo(repo_dir: Path, paths: List[str], timeout: int) -> None:
    """
    Remove specified paths from history using git-filter-repo with --invert-paths.
    This keeps everything except the listed paths.

    Expected behavior:
      - If paths are provided: history gets rewritten with those paths dropped.
      - If paths list is empty: no-op.
    """
    if not paths:
        return
    args = " ".join([f"--path {shlex.quote(p)}" for p in paths])
    run(f"git filter-repo {args} --invert-paths --force", cwd=repo_dir, timeout=timeout)


def strip_blobs_with_ids(repo_dir: Path, blob_ids: Set[str], timeout: int) -> None:
    """
    Strip any blobs by ID using git-filter-repo --strip-blobs-with-ids.

    Expected behavior:
      - If blob_ids is non-empty: writes IDs to a temp file and runs filter-repo.
      - If empty: no-op.
    """
    if not blob_ids:
        return
    tmpfile = repo_dir / "bad_blobs.txt"
    tmpfile.write_text("\n".join(sorted(blob_ids)) + "\n", encoding="utf-8")
    run(f"git filter-repo --strip-blobs-with-ids {shlex.quote(str(tmpfile))} --force", cwd=repo_dir, timeout=timeout)


def readd_origin_if_missing(repo_dir: Path, original_url: Optional[str]) -> None:
    """
    git-filter-repo removes the 'origin' remote by design.
    This function re-adds origin if it's missing, using the provided original_url.
    """
    cp = run("git remote -v", cwd=repo_dir, check=False)
    if "origin" in cp.stdout:
        return
    if original_url:
        run(f"git remote add origin {shlex.quote(original_url)}", cwd=repo_dir)
        run("git remote -v", cwd=repo_dir)
    else:
        print("[warn] No origin URL available to re-add; set it manually later (git remote add origin <url>).")


def list_local_branches(repo_dir: Path) -> List[str]:
    """
    Return a list of local branch names under refs/heads.
    """
    cp = run("git for-each-ref --format='%(refname:short)' refs/heads/", cwd=repo_dir, check=False)
    return [l.strip().strip("'") for l in cp.stdout.splitlines() if l.strip()]


def push_all(repo_dir: Path, push_tags: bool, timeout: int) -> None:
    """
    Force-push all local branches to 'origin'.
    Optionally force-push all tags.

    Expected behavior:
      - Useful after rewrite to update the remote with the sanitized history.
      - Authentication errors are printed; user should configure HTTPS PAT or SSH.
    """
    # Try pushing main first to surface auth/repo permission issues early.
    run("git push --force origin main", cwd=repo_dir, timeout=timeout, check=False)
    for b in list_local_branches(repo_dir):
        run(f"git push --force origin {shlex.quote(b)}", cwd=repo_dir, timeout=timeout, check=False)
    if push_tags:
        run("git push --force --tags", cwd=repo_dir, timeout=timeout, check=False)


def verify_clean(repo_url: str, tmpdir: Path, patterns: List[str], scan_commit_messages: bool, timeout: int
                 ) -> Dict[str, Dict[str, List[str]]]:
    """
    Fresh-clone the remote (no checkout) and run the same scans to validate that:
      - File contents no longer contain the searched secrets/patterns.
      - (Optional) Commit messages no longer contain them.

    Returns:
      {
        "files": { pattern: [lines...] },
        "messages": { pattern: [lines...] }  # only when scan_commit_messages=True
      }
    """
    verify_repo = tmpdir / "repo-scan"
    run(f"git clone --no-checkout {shlex.quote(repo_url)} {shlex.quote(str(verify_repo))}", timeout=timeout)
    fetch_all(verify_repo, timeout)
    out: Dict[str, Dict[str, List[str]]] = {"files": {}, "messages": {}}
    for pat in patterns:
        _, lines = grep_history(verify_repo, pat, timeout)
        out["files"][pat] = lines
        if scan_commit_messages:
            _, mlines = grep_commit_messages(verify_repo, pat, timeout)
            out["messages"][pat] = mlines
    return out


def yes_no(prompt: str, default_no: bool = True) -> bool:
    """
    Prompt the user for a yes/no answer.

    Returns:
      True for yes, False otherwise. Default is 'No' when user just presses Enter.
    """
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    try:
        resp = input(prompt + suffix).strip().lower()
    except EOFError:
        return False
    if not resp:
        return not default_no
    return resp in ("y", "yes")


# ---------------------------
# Main program
# ---------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Scan and (if needed) purge secrets from Git repo history using git-filter-repo")
    parser.add_argument("--target", required=True, help="Remote URL (https/ssh) or local repo path")
    parser.add_argument("--exact-key", action="append", default=[], help="Exact secret value to find and purge (repeatable)")
    parser.add_argument("--purge-path", action="append", default=[], help="File path to remove across history (repeatable). Default: .env")
    parser.add_argument("--no-heuristics", action="store_true", help="Disable heuristic scanning (regex patterns)")
    parser.add_argument("--scan-commit-messages", action="store_true", help="Also search commit messages for patterns/keys")
    parser.add_argument("--push-tags", action="store_true", help="Also force-push tags (off by default)")
    parser.add_argument("--confirm", action="store_true", help="Proceed without interactive confirmation prompts")
    parser.add_argument("--verify-only", action="store_true", help="Only scan/verify; do not rewrite or push")
    parser.add_argument("--keep-temp", action="store_true", help="Keep temporary working directories after finish")
    args = parser.parse_args()

    # Build validated config object
    cfg = CleanerConfig(
        target=args.target,
        exact_keys=args.exact_key or [],
        purge_paths=args.purge_path if args.purge_path else [".env"],
        enable_heuristics=not args.no_heuristics,
        push_tags=args.push_tags,
        confirm=args.confirm,
        verify_only=args.verify_only,
        keep_temp=args.keep_temp,
        scan_commit_messages=args.scan_commit_messages,
    )

    # Prepare working directories
    work = WorkDirs.create()
    print(f"[info] Working directory: {work.base}")

    # Determine the origin remote URL:
    # - If target is a local repo path, read its origin to re-add it after filter-repo.
    # - If target is a remote URL, use it directly.
    original_origin = None
    local_target = None
    if Path(cfg.target).exists():
        local_target = Path(cfg.target).resolve()
        if not is_git_repo(local_target):
            print(f"[error] Target path is not a Git repo: {local_target}")
            sys.exit(2)
        original_origin = guess_origin_url(local_target)
    else:
        original_origin = cfg.target

    # Fresh clone into rewrite area (safe working copy)
    try:
        rewrite_repo = clone_fresh(cfg.target, work.rewrite_dir, retries=cfg.retries, timeout=cfg.timeout_sec)
        fetch_all(rewrite_repo, cfg.timeout_sec)
    except Exception as e:
        print(f"[error] Clone/fetch failed: {e}")
        if not cfg.keep_temp:
            try:
                import shutil
                shutil.rmtree(work.base, ignore_errors=True)
            except Exception:
                pass
        sys.exit(2)

    # Build list of search patterns:
    # - Exact keys (provided via --exact-key)
    # - Heuristic regex patterns (if enabled)
    patterns: List[str] = []
    patterns.extend(cfg.exact_keys)
    if cfg.enable_heuristics:
        patterns.extend(HEURISTIC_PATTERNS)

    # 1) INITIAL SCAN (non-destructive)
    print("\n[step] Scanning full history for potential leaks (files)...")
    initial_file_hits: Dict[str, List[str]] = {}
    for pat in patterns:
        count, lines = grep_history(rewrite_repo, pat, cfg.timeout_sec)
        if count > 0:
            print(f"[hit] files: pattern '{pat}': {count} matches (showing up to 20)")
            initial_file_hits[pat] = lines[:20]  # preview first 20 lines
            for l in initial_file_hits[pat]:
                print("  " + l)
        else:
            print(f"[ok] files: pattern '{pat}': none")

    initial_msg_hits: Dict[str, List[str]] = {}
    if cfg.scan_commit_messages:
        print("\n[step] Scanning commit messages for potential leaks...")
        for pat in patterns:
            mcount, mlines = grep_commit_messages(rewrite_repo, pat, cfg.timeout_sec)
            if mcount > 0:
                print(f"[hit] messages: pattern '{pat}': {mcount} matches (showing up to 20)")
                initial_msg_hits[pat] = mlines[:20]
                for l in initial_msg_hits[pat]:
                    print("  " + l)
            else:
                print(f"[ok] messages: pattern '{pat}': none")

    # EARLY EXIT when nothing is found:
    # If no file hits AND no message hits (or message scan not requested), we stop here.
    no_file_hits = all(len(v) == 0 for v in initial_file_hits.values()) if initial_file_hits else True
    no_msg_hits = all(len(v) == 0 for v in initial_msg_hits.values()) if initial_msg_hits else True
    if (no_file_hits and (not cfg.scan_commit_messages or no_msg_hits)):
        # Nothing found anywhere: print summary and exit without any rewrite/push.
        searched = patterns if patterns else ["<no patterns>"]
        print("\n[result] No secrets found.")
        print("Searched patterns:")
        for p in searched:
            print(f"  - {p}")
        print("No rewrite or push has been performed.")
        # Cleanup temp dirs (unless kept), then exit 0.
        if not cfg.keep_temp:
            import shutil
            shutil.rmtree(work.base, ignore_errors=True)
        sys.exit(0)

    # If --verify-only is set, we do not rewrite/push, we just report findings.
    if cfg.verify_only:
        print("\n[result] Verification-only run finished (hits were found; no rewrite performed).")
        if not cfg.keep_temp:
            import shutil
            shutil.rmtree(work.base, ignore_errors=True)
        sys.exit(0)

    # 2) PLAN REWRITE (destructive unless you abort)
    print("\n[plan] Detected matches. Proposed actions:")
    print(f"- Remove paths across history: {', '.join(cfg.purge_paths) if cfg.purge_paths else '(none)'}")
    if cfg.exact_keys:
        print(f"- Strip blobs containing exact keys ({len(cfg.exact_keys)} provided)")
    else:
        print("- No exact keys provided; will rely on path removals and heuristics only")
    print(f"- Force-push rewritten branches to origin")
    print(f"- Push tags: {'yes' if cfg.push_tags else 'no'}")

    if not cfg.confirm:
        if not yes_no("Proceed with destructive history rewrite?", default_no=True):
            print("Aborted by user. No changes were pushed.")
            if not cfg.keep_temp:
                import shutil
                shutil.rmtree(work.base, ignore_errors=True)
            sys.exit(0)

    # 3) REWRITE STEPS
    # 3a) Path-based removals (.env, images, etc.)
    print("\n[step] Rewriting history (path removals with git-filter-repo)...")
    try:
        remove_paths_with_filter_repo(rewrite_repo, cfg.purge_paths, cfg.timeout_sec)
    except Exception as e:
        print(f"[warn] Path-based rewrite failed or may not be necessary: {e}")

    # After filter-repo, origin is usually removed; re-add it.
    readd_origin_if_missing(rewrite_repo, original_origin)

    # 3b) Blob stripping by exact key matches (path-agnostic)
    if cfg.exact_keys:
        print("\n[step] Locating blobs that contain provided exact keys...")
        bad_blobs = find_bad_blobs_by_exact_keys(rewrite_repo, cfg.exact_keys, cfg.timeout_sec)
        print(f"[info] Found {len(bad_blobs)} blob(s) containing exact keys.")
        if bad_blobs:
            print("[step] Stripping those blobs from history...")
            strip_blobs_with_ids(rewrite_repo, bad_blobs, cfg.timeout_sec)
            # Re-add origin again just in case filter-repo dropped it.
            readd_origin_if_missing(rewrite_repo, original_origin)
        else:
            print("[info] No blobs matched exact keys after path removals.")

    # 4) PUSH REWRITTEN HISTORY
    print("\n[step] Pushing rewritten history to remote (force)...")
    if not original_origin:
        print("[error] No origin remote URL known. Configure it manually and push (git remote add origin <url>).")
        sys.exit(3)
    try:
        push_all(rewrite_repo, cfg.push_tags, timeout=cfg.timeout_sec)
    except Exception as e:
        print(f"[error] Push failed: {e}")
        sys.exit(4)

    # 5) VERIFY FROM FRESH CLONE
    print("\n[step] Verifying cleanup from a fresh clone...")
    verification = verify_clean(original_origin, work.verify_dir, patterns, cfg.scan_commit_messages, cfg.timeout_sec)

    file_hits_remaining = {p: ls for p, ls in verification["files"].items() if ls}
    msg_hits_remaining = {p: ls for p, ls in verification["messages"].items() if ls} if cfg.scan_commit_messages else {}

    if not file_hits_remaining and (not cfg.scan_commit_messages or not msg_hits_remaining):
        print("[verify-ok] No matches found in files or commit messages after rewrite.")
    else:
        # If anything remains, print a concise summary (show up to 10 lines per pattern).
        if file_hits_remaining:
            print("[verify] Remaining FILE matches:")
            for pat, lines in file_hits_remaining.items():
                print(f"  - {pat}: {len(lines)} hits (showing up to 10)")
                for l in lines[:10]:
                    print("    " + l)
        if msg_hits_remaining:
            print("[verify] Remaining COMMIT MESSAGE matches:")
            for pat, lines in msg_hits_remaining.items():
                print(f"  - {pat}: {len(lines)} hits (showing up to 10)")
                for l in lines[:10]:
                    print("    " + l)
        print("\n[action] Some patterns still matched after rewrite. Consider:")
        print("- Adding more purge paths if files remain (e.g., renamed assets).")
        print("- Supplying the full exact secret via --exact-key to catch embedded blobs.")
        print("- For commit messages: consider rewriting with 'git filter-repo --replace-text' to redact messages.")

    # 6) LOCAL WORKING FOLDER GUIDANCE (non-destructive for untracked/ignored files)
    if local_target:
        print("\n[hint] To refresh your original working folder while preserving .venv, __pycache__, .env, etc.:")
        print(textwrap.dedent(f"""
        cd {shlex.quote(str(local_target))}
        git fetch --all --prune --tags
        git checkout main
        git reset --hard origin/main
        # Optionally realign other branches:
        # git checkout <branch> && git reset --hard origin/<branch>
        """).strip())

    print(f"\n[done] Finished. Temp workdir: {work.base}")
    if not cfg.keep_temp:
        try:
            import shutil
            shutil.rmtree(work.base, ignore_errors=True)
            print("[info] Temp workdir removed.")
        except Exception:
            print(f"[warn] Could not remove temp dir: {work.base}")


if __name__ == "__main__":
    main()
