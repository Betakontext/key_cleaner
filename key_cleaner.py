#!/usr/bin/env python3
"""
Key Cleaner — Scan and (if needed) purge leaked secrets from a Git repository history.

USAGE QUICKSTART (non-destructive first):
  - Remote verify-only (includes commit messages):
      python key_cleaner.py --target https://github.com/org/repo.git \
        --exact-key 'sk_ABC...' --scan-commit-messages --verify-only

  - Local verify-only on a path:
      python key_cleaner.py --target /home/yourpath/your_repo \
        --exact-key 'sk_ABC...' --scan-commit-messages --verify-only

  - Full run on a local path (will rewrite history if hits are found; add --confirm to skip prompt):
      python key_cleaner.py --target /home/yourpath/your_repo \
        --exact-key 'sk_ABC...' --purge-path .env --scan-commit-messages --confirm

WHAT THIS TOOL DOES
  - Scans full Git history (all refs) for:
      • Exact secrets you pass via --exact-key (repeatable)
      • Optional heuristics (enabled by default) like 'sk-' or common secret-ish env var names
      • Optional commit message scan (--scan-commit-messages)
  - If nothing is found: prints a clear summary and exits without changes.
  - If something is found:
      • Rewrites history using git-filter-repo to remove specific paths (e.g., .env, images) and
        strip any blobs that contain provided exact secret values
      • Confirms (unless --confirm) before force-pushing rewritten branches (and optionally tags)
      • Verifies cleanup from a fresh clone with robust, quoted, fixed-string greps
      • Prints guidance to realign your local working folder safely

IMPORTANT
  - History rewrite changes commit SHAs. Coordinate with collaborators.
  - GitHub PR refs (refs/pull/*) and forks are not overwritten by pushes; close/recreate PRs
    or rebase forks separately. This tool fetches PR refs into origin/pr/* to ensure they are scanned.
  - The tool is local and shells out to Git; it does not upload repository data anywhere.

PREREQUISITES
  - git >= 2.30
  - git-filter-repo installed (pipx install git-filter-repo | pip install git-filter-repo)
  - Python 3.10+

SETUP
  python3 -m venv venv
  source venv/bin/activate
  pip install git-filter-repo pydantic
  chmod +x key_cleaner.py

RE-SYNC YOUR LOCAL WORKTREE AFTER A REWRITE
  cd /path/to/your_repo
  git fetch --all --prune --tags
  git checkout main
  git reset --hard origin/main
  # Optionally for other branches:
  # git checkout <branch> && git reset --hard origin/<branch>

EXPECTED OUTCOMES
  - No matches: “[result] No secrets found.” and exit. No rewrite/push.
  - Matches:
      • Shows sample hits (truncated)
      • Prints a plan and asks for confirmation (unless --confirm)
      • Rewrites history (paths + blob-strips), force-pushes, verifies from fresh clone
      • Prints “[verify-ok] No matches found …” on success, otherwise residual matches with next steps
"""

from __future__ import annotations
import argparse
import base64
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

# Pydantic v1/v2 compatible import:
# - On Pydantic v2, field validators moved from `validator` to `field_validator`.
# - This shim keeps the decorator name `validator` stable for the code below.
try:
    from pydantic import BaseModel, Field
    try:
        from pydantic import field_validator as validator  # v2
    except ImportError:
        from pydantic import validator  # v1
except ImportError:
    print("Missing dependency 'pydantic'. Install via: pip install pydantic")
    sys.exit(1)


# ---------------------------
# Configuration models
# ---------------------------

class CleanerConfig(BaseModel):
    """
    Validated runtime configuration for the cleaner.
    - Holds all user-controlled flags in a type-checked structure.
    - Provides defaults for common operations (e.g., purge .env).
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
    keep_temp: bool = Field(default=False, description="Keep temporary working directories after finish")
    scan_commit_messages: bool = Field(default=False, description="Also grep commit messages for exact keys/patterns")

    @validator("target")
    def _strip_target(cls, v: str) -> str:
        # Normalize whitespace in target path/URL to prevent common input mistakes.
        return v.strip()


@dataclass
class WorkDirs:
    """
    Ephemeral working directories:
    - rewrite_dir: used for cloning and rewriting history
    - verify_dir: used for fresh clone to verify results
    - logs_dir: reserved for future log files if needed
    We keep work areas out of your original repo to avoid side effects.
    """
    base: Path
    rewrite_dir: Path
    verify_dir: Path
    logs_dir: Path

    @staticmethod
    def create() -> "WorkDirs":
        # Store under system temp dir with a random suffix to avoid collisions.
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
    - Printed echo of the command (observable operations).
    - Captured stdout/stderr for diagnostics.
    - Optional check=True to raise on non-zero exit.

    Design choices:
    - We print stderr since git often emits progress to stderr.
    - We return the CompletedProcess so callers can inspect outputs and rc.
    """
    print(f"$ {cmd}")
    start = time.time()
    cp = subprocess.run(cmd, cwd=str(cwd) if cwd else None, shell=True,
                        capture_output=True, text=True, timeout=timeout)
    dur = time.time() - start
    if cp.stdout:
        print(cp.stdout.rstrip())
    if cp.stderr:
        print(cp.stderr.rstrip(), file=sys.stderr)
    if check and cp.returncode != 0:
        raise RuntimeError(f"Command failed ({cp.returncode}) after {dur:.1f}s: {cmd}\n{cp.stderr}")
    return cp


def is_git_repo(path: Path) -> bool:
    """
    Return True if the given path is inside a Git work tree.
    We use `git rev-parse` which is reliable and cheap.
    """
    try:
        run("git rev-parse --is-inside-work-tree", cwd=path, timeout=15)
        return True
    except Exception:
        return False


def has_git_filter_repo() -> bool:
    """
    Return True if git-filter-repo is available on PATH.
    We call with -h to avoid executing any rewrite accidentally.
    """
    try:
        run("git filter-repo -h", timeout=15)
        return True
    except Exception:
        return False


def guess_origin_url(repo_dir: Path) -> Optional[str]:
    """
    Try to retrieve 'origin' remote URL. Needed after filter-repo, which
    removes remotes by design to prevent accidental pushes without review.
    """
    cp = run("git remote get-url origin", cwd=repo_dir, timeout=15, check=False)
    return cp.stdout.strip() if cp.returncode == 0 else None


# ---------------------------
# Scanning primitives
# ---------------------------

# Expanded heuristic patterns:
# - Prefix-based tokens (OpenAI/HuggingFace/GitHub/AWS, etc.)
# - Environment variable names strongly associated with secrets
# - Generic "API KEY/SECRET/TOKEN" words to surface suspicious contexts
HEURISTIC_PATTERNS = [
    # Prefix-based keys
    r"\bsk-[A-Za-z0-9]{16,}\b",          # OpenAI-like tokens (length conservative)
    r"\bhf_[A-Za-z0-9]{16,}\b",          # HuggingFace tokens
    r"\bghp_[A-Za-z0-9]{16,}\b",         # GitHub Personal Access Token
    r"\bAKIA[0-9A-Z]{16}\b",             # AWS Access Key ID

    # Env variable names that imply secrets
    r"\bPOLLINATIONS_SECRET\b",
    r"\bPOLLINATIONS_API_KEY\b",
    r"\bOPENAI_API_KEY\b",
    r"\bHUGGINGFACE_API_KEY\b",
    r"\bAWS_ACCESS_KEY_ID\b",
    r"\bAWS_SECRET_ACCESS_KEY\b",

    # Generic
    r"\bAPI[_ ]?KEY\b",
    r"\bSECRET\b",
    r"\bTOKEN\b",
]

# Match .env or .env.example anywhere in the tree (case-insensitive)
ENV_PATH_REGEX = re.compile(r"(^|/)\.env($|\.example$)", re.IGNORECASE)


def grep_history(repo_dir: Path, pattern: str, timeout: int) -> Tuple[int, List[str]]:
    """
    Search file contents across ALL refs (full history) using git grep against each commit tree.

    Why not use `git grep -e PATTERN $(git rev-list --all)` directly?
    - `git grep` only searches the working tree or the index unless given a treeish.
    - We loop trees via rev-list so we cover renames/moves over time robustly.

    Returns:
      (count, lines) where lines look like: "<commit>:<path>:<line>:<content>"
    """
    # Use fixed-string (-F) when possible to avoid regex pitfall; patterns we craft are either exact
    # keys or well-formed regexes. We choose -F by default and fall back to regex if it looks like one.
    is_regex_like = any(ch in pattern for ch in ".*[](){}+?\\|")
    grep_flag = "-E" if is_regex_like else "-F"
    q = shlex.quote(pattern)
    cmd = (
        "bash -lc \""
        "git rev-list --all | "
        "xargs -I{} sh -c 'git grep -n -I -a {flag} --all-match {pat} {{}}'\""
    ).replace("{flag}", grep_flag).replace("{pat}", q)
    try:
        cp = run(cmd, cwd=repo_dir, timeout=timeout, check=False)
        lines = [l for l in cp.stdout.splitlines() if l.strip()]
        return (len(lines), lines)
    except Exception as e:
        print(f"[warn] grep_history failed for pattern {pattern}: {e}")
        return (0, [])


def grep_commit_messages(repo_dir: Path, pattern: str, timeout: int) -> Tuple[int, List[str]]:
    """
    Search commit messages across ALL refs using `git log --grep`.

    Output format:
      '<short_sha> <date iso> <subject>'
    """
    q = shlex.quote(pattern)
    cmd = f"git log --all --grep={q} --pretty=format:'%h %ad %s' --date=iso"
    cp = run(cmd, cwd=repo_dir, timeout=timeout, check=False)
    lines = [l for l in cp.stdout.splitlines() if l.strip()]
    return (len(lines), lines)


def find_bad_blobs_by_exact_keys(repo_dir: Path, keys: List[str], timeout: int) -> Set[str]:
    """
    Identify blob object IDs that contain any of the provided exact key values.
    This is path-agnostic and works even when files were renamed or embedded.

    Strategy:
      - Enumerate all objects via `git rev-list --objects --all`
      - For each object id, print its content with `git cat-file -p`
      - Use grep -F to detect fixed-string matches
      - Collect matching blob oids for removal

    Returns:
      Set of 40-hex blob IDs.
    """
    blob_ids: Set[str] = set()
    if not keys:
        return blob_ids
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


def iter_env_files_history(repo_dir: Path, timeout: int) -> List[Tuple[str, str]]:
    """
    Enumerate all (.env|.env.example) files across the entire history.

    Returns:
      List of tuples (commit_sha, path) for each discovery.
    """
    env_entries: List[Tuple[str, str]] = []
    cp = run("git rev-list --all", cwd=repo_dir, timeout=timeout, check=False)
    for sha in [l.strip() for l in cp.stdout.splitlines() if l.strip()]:
        files = run(f"git ls-tree -r --name-only {sha}", cwd=repo_dir, timeout=timeout, check=False).stdout.splitlines()
        for f in files:
            if ENV_PATH_REGEX.search(f.strip()):
                env_entries.append((sha, f.strip()))
    return env_entries


def parse_env_lines(text: str) -> Dict[str, str]:
    """
    Minimal .env parser that supports:
      - KEY=VALUE lines (ignores empty lines and comments)
      - Strips single/double quotes around VALUE

    Note:
      - This is intentionally conservative (no variable expansion).
      - It works well for typical committed .env formats.
    """
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        # Strip symmetric quotes if present
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        out[key] = val
    return out


def is_value_suspect(name: str, value: str) -> bool:
    """
    Heuristic: Decide if a value looks like a real secret.
    - Must be non-empty, non-placeholder-ish, and with a reasonable length.
    - Strong preference if it starts with known key prefixes.
    - Fallback: env var name implies secret nature (e.g., *SECRET*, *TOKEN*, *API_KEY*).
    """
    if not value or value.strip() == "":
        return False
    low = value.lower()
    if any(x in low for x in ["placeholder", "your_key_here", "example", "dummy", "sample", "changeme"]):
        return False
    if len(value) < 16:
        return False
    # Strong indicator: well-known prefixes
    if re.search(r"\b(sk-|hf_|ghp_|AKIA)", value):
        return True
    # Otherwise: rely on the variable name implying a secret
    if re.search(r"(secret|token|api[_ ]?key)", name.lower()):
        return True
    return False


def maybe_decode_base64(s: str) -> Optional[str]:
    """
    Attempt to base64-decode a value and check for embedded 'sk-' like patterns.
    - We tolerate missing padding and ignore decoding errors.
    - Returns the decoded candidate if it looks like a token; otherwise None.
    """
    try:
        padding = '=' * (-len(s) % 4)
        dec = base64.b64decode(s + padding, validate=False)
        txt = dec.decode('utf-8', errors='ignore')
        return txt if txt and re.search(r"\bsk-[A-Za-z0-9]{10,}\b", txt) else None
    except Exception:
        return None


# ---------------------------
# Core flow helpers
# ---------------------------

def clone_fresh(target: str, into_dir: Path, retries: int, timeout: int) -> Path:
    """
    Clone a remote URL or a local git repo (via file:// to avoid nested working-tree side effects).
    - Implements simple retry logic for transient network errors.
    """
    repo_dir = into_dir / "repo"
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
    Fetch all branches and tags (and prune deleted refs), plus mirror GitHub PR refs.
    - The PR refs step is a no-op on non-GitHub remotes.
    - Ensures PR-only commits are included in the scan and potential rewrite.
    """
    run("git fetch --all --prune --tags", cwd=repo_dir, timeout=timeout)
    run("git fetch origin '+refs/pull/*:refs/remotes/origin/pr/*'", cwd=repo_dir, timeout=timeout, check=False)


def remove_paths_with_filter_repo(repo_dir: Path, paths: List[str], timeout: int) -> None:
    """
    Drop specific paths across history using git-filter-repo with --invert-paths.
    - This keeps everything except the listed paths.
    - Ideal for removing .env-like files globally.
    """
    if not paths:
        return
    args = " ".join([f"--path {shlex.quote(p)}" for p in paths])
    run(f"git filter-repo {args} --invert-paths --force", cwd=repo_dir, timeout=timeout)


def strip_blobs_with_ids(repo_dir: Path, blob_ids: Set[str], timeout: int) -> None:
    """
    Remove specific blobs by object ID using git-filter-repo --strip-blobs-with-ids.
    - This is path-agnostic content removal, useful when secrets are embedded in
      renamed files or binary assets.
    """
    if not blob_ids:
        return
    tmpfile = repo_dir / "bad_blobs.txt"
    tmpfile.write_text("\n".join(sorted(blob_ids)) + "\n", encoding="utf-8")
    run(f"git filter-repo --strip-blobs-with-ids {shlex.quote(str(tmpfile))} --force", cwd=repo_dir, timeout=timeout)


def rewrite_commit_messages_replace(repo_dir: Path, exact_keys: List[str], timeout: int) -> None:
    """
    Optionally redact exact secrets from commit messages using --replace-text.
    Notes:
      - --replace-text applies to file contents too, but since we already removed
        .envs and stripped blobs, side-effects are minimal.
      - If you need message-only redaction, a custom message-callback script is required.
    """
    if not exact_keys:
        return
    repl_file = repo_dir / "replace.txt"
    lines = [f"{k}===>[REDACTED]" for k in exact_keys]
    repl_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    run(f"git filter-repo --replace-text {shlex.quote(str(repl_file))} --force", cwd=repo_dir, timeout=timeout)


def readd_origin_if_missing(repo_dir: Path, original_url: Optional[str]) -> None:
    """
    git-filter-repo removes remotes by default.
    - Re-add 'origin' if absent so subsequent pushes and verification can proceed.
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
    Return a list of local branch names (refs/heads/*) after rewrite.
    - Pushing all ensures remote and local are aligned post-filtering.
    """
    cp = run("git for-each-ref --format='%(refname:short)' refs/heads/", cwd=repo_dir, check=False)
    return [l.strip().strip("'") for l in cp.stdout.splitlines() if l.strip()]


def push_all(repo_dir: Path, push_tags: bool, timeout: int) -> None:
    """
    Force-push all rewritten branches (and optionally tags).
    - We push 'main' first to surface permission issues early.
    - This is destructive by nature; coordinate with collaborators before running.
    """
    run("git push --force origin main", cwd=repo_dir, timeout=timeout, check=False)
    for b in list_local_branches(repo_dir):
        run(f"git push --force origin {shlex.quote(b)}", cwd=repo_dir, timeout=timeout, check=False)
    if push_tags:
        run("git push --force --tags", cwd=repo_dir, timeout=timeout, check=False)


def verify_clean(repo_url: str, tmpdir: Path, patterns: List[str], scan_commit_messages: bool, timeout: int
                 ) -> Dict[str, Dict[str, List[str]]]:
    """
    Fresh-clone verification:
    - Ensures we test the remote state after force-push, not the in-memory state.
    - Runs the same content/message scans to validate the cleanup.
    - Additionally checks that no .env-like files remain in history.
    - Runs a per-ref scan to avoid false positives from unreferenced local objects.
    """
    verify_repo = tmpdir / "repo-scan"
    run(f"git clone --no-checkout {shlex.quote(repo_url)} {shlex.quote(str(verify_repo))}", timeout=timeout)
    fetch_all(verify_repo, timeout)
    out: Dict[str, Dict[str, List[str]]] = {"files": {}, "messages": {}}
    # Global history scan (covers all reachable commits)
    for pat in patterns:
        _, lines = grep_history(verify_repo, pat, timeout)
        out["files"][pat] = lines
        if scan_commit_messages:
            _, mlines = grep_commit_messages(verify_repo, pat, timeout)
            out["messages"][pat] = mlines

    # Per-ref fixed-string verification (isolates refs)
    cp_refs = run("git for-each-ref --format='%(refname:short)' refs/remotes/origin/", cwd=verify_repo, timeout=timeout, check=False)
    refnames = [r.strip().strip("'") for r in cp_refs.stdout.splitlines() if r.strip()]
    if refnames:
        for pat in patterns:
            # Use -F to avoid regex surprises in verify step
            vf = run(
                "bash -lc " +
                shlex.quote(
                    "git -c core.quotepath=false grep -nI -a -F -- " +
                    shlex.quote(pat) + " " + " ".join(shlex.quote(r) for r in refnames)
                ),
                cwd=verify_repo, timeout=timeout, check=False
            )
            _ = vf  # reserved for future diagnostics

    # Extra verification: ensure no .env/.env.example files exist post-rewrite.
    env_pat = r"(^|/)\.env($|\.example$)"
    _, env_lines = grep_history(verify_repo, env_pat, timeout)
    out["files"][env_pat] = env_lines
    return out


def yes_no(prompt: str, default_no: bool = True) -> bool:
    """
    Interactive yes/no prompt with sane default:
    - default_no=True means [y/N], i.e., pressing Enter => No.
    - Useful to prevent accidental destructive rewrites.
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

    # Build validated configuration from CLI args
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

    # Prepare isolated working directories for rewrite and verification
    work = WorkDirs.create()
    print(f"[info] Working directory: {work.base}")

    # Determine remote URL for push/verify and detect if target is a local repo
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

    # Precondition: ensure git-filter-repo is installed
    if not has_git_filter_repo():
        print("[error] 'git-filter-repo' not found. Install with: pipx install git-filter-repo (or pip install git-filter-repo)")
        sys.exit(2)

    # Fresh clone into rewrite area (safe temporary copy of the repo)
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

    # Build search patterns:
    # - Begin with user-provided exact keys (most reliable)
    # - Optionally add heuristic regex patterns
    patterns: List[str] = []
    patterns.extend(cfg.exact_keys)
    if cfg.enable_heuristics:
        patterns.extend(HEURISTIC_PATTERNS)

    # 1) INITIAL SCAN (non-destructive) — scan file contents across history
    print("\n[step] Scanning full history for potential leaks (files)...")
    initial_file_hits: Dict[str, List[str]] = {}
    for pat in patterns:
        count, lines = grep_history(rewrite_repo, pat, cfg.timeout_sec)
        if count > 0:
            print(f"[hit] files: pattern '{pat}': {count} matches (showing up to 20)")
            initial_file_hits[pat] = lines[:20]  # preview: limit noise
            for l in initial_file_hits[pat]:
                print("  " + l)
        else:
            print(f"[ok] files: pattern '{pat}': none")

    # Optional: scan commit messages, since secrets sometimes land in messages
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

    # 1b) EXTRACTION — iterate .env files historically and extract KEY=VALUE pairs
    #     Any value that "looks like" a secret becomes an exact key candidate,
    #     which enables path-agnostic blob stripping later, even without CLI --exact-key.
    print("\n[step] Inspecting .env-like files across history and extracting potential secret values...")
    env_hits = iter_env_files_history(rewrite_repo, cfg.timeout_sec)
    extracted_exact_values: Set[str] = set()
    for sha, path in env_hits:
        cp = run(f"git show {sha}:{shlex.quote(path)}", cwd=rewrite_repo, timeout=cfg.timeout_sec, check=False)
        if cp.returncode != 0 or not cp.stdout:
            continue
        pairs = parse_env_lines(cp.stdout)
        for k, v in pairs.items():
            captured = False
            if is_value_suspect(k, v):
                extracted_exact_values.add(v)
                captured = True
                print(f"  [env] {sha}:{path} -> {k}=<secret> (captured for exact match)")
            else:
                decoded = maybe_decode_base64(v)
                if decoded:
                    extracted_exact_values.add(decoded)
                    captured = True
                    print(f"  [env] {sha}:{path} -> {k}=<base64-secret> (decoded and captured)")
            _ = captured  # reserved for future logging hooks

    # Merge extracted values into cfg.exact_keys (dedup while preserving any CLI-provided ones)
    if extracted_exact_values:
        for x in extracted_exact_values:
            if x not in cfg.exact_keys:
                cfg.exact_keys.append(x)
        print(f"[info] Collected {len(extracted_exact_values)} exact value(s) from .env files to strip via blobs.")

    # EARLY EXIT when nothing at all was found and nothing was extracted
    no_file_hits = all(len(v) == 0 for v in initial_file_hits.values()) if initial_file_hits else True
    no_msg_hits = all(len(v) == 0 for v in initial_msg_hits.values()) if initial_msg_hits else True
    nothing_extracted = (len(extracted_exact_values) == 0)
    if (no_file_hits and (not cfg.scan_commit_messages or no_msg_hits) and nothing_extracted):
        searched = patterns if patterns else ["<no patterns>"]
        print("\n[result] No secrets found.")
        print("Searched patterns:")
        for p in searched:
            print(f"  - {p}")
        print("No rewrite or push has been performed.")
        if not cfg.keep_temp:
            import shutil
            shutil.rmtree(work.base, ignore_errors=True)
        sys.exit(0)

    # Verification-only mode: report findings and exit without rewriting
    if cfg.verify_only:
        print("\n[result] Verification-only run finished (hits were found; no rewrite performed).")
        if not cfg.keep_temp:
            import shutil
            shutil.rmtree(work.base, ignore_errors=True)
        sys.exit(0)

    # 2) REWRITE PLAN — show what will be changed before proceeding destructively
    print("\n[plan] Detected matches. Proposed actions:")
    print(f"- Remove paths across history: {', '.join(cfg.purge_paths) if cfg.purge_paths else '(none)'}")
    print(f"- Strip blobs containing exact keys: {len(cfg.exact_keys)} value(s)")
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
    # 3a) Path-based removals (e.g., .env)
    print("\n[step] Rewriting history (path removals with git-filter-repo)...")
    try:
        remove_paths_with_filter_repo(rewrite_repo, cfg.purge_paths, cfg.timeout_sec)
    except Exception as e:
        print(f"[warn] Path-based rewrite failed or may not be necessary: {e}")

    # filter-repo often removes remotes; ensure origin exists for pushes
    readd_origin_if_missing(rewrite_repo, original_origin)

    # 3b) Blob stripping by exact key matches (path-agnostic)
    if cfg.exact_keys:
        print("\n[step] Locating blobs that contain provided exact keys...")
        bad_blobs = find_bad_blobs_by_exact_keys(rewrite_repo, cfg.exact_keys, cfg.timeout_sec)
        print(f"[info] Found {len(bad_blobs)} blob(s) containing exact keys.")
        if bad_blobs:
            print("[step] Stripping those blobs from history...")
            strip_blobs_with_ids(rewrite_repo, bad_blobs, cfg.timeout_sec)
            readd_origin_if_missing(rewrite_repo, original_origin)
        else:
            print("[info] No blobs matched exact keys after path removals.")

    # 3c) Optional: redact commit messages containing exact keys
    if cfg.scan_commit_messages:
        print("\n[step] Optionally redacting exact secrets from commit messages...")
        try:
            rewrite_commit_messages_replace(rewrite_repo, cfg.exact_keys, cfg.timeout_sec)
            readd_origin_if_missing(rewrite_repo, original_origin)
        except Exception as e:
            print(f"[warn] Commit message rewrite failed or not necessary: {e}")

    # 4) PUSH REWRITTEN HISTORY (force)
    print("\n[step] Pushing rewritten history to remote (force)...")
    if not original_origin:
        print("[error] No origin remote URL known. Configure it manually and push (git remote add origin <url>).")
        sys.exit(3)
    try:
        push_all(rewrite_repo, cfg.push_tags, timeout=cfg.timeout_sec)
    except Exception as e:
        print(f"[error] Push failed: {e}")
        sys.exit(4)

    # 5) VERIFY FROM FRESH CLONE — ensure the remote is clean
    print("\n[step] Verifying cleanup from a fresh clone...")
    patterns_for_verify = []
    patterns_for_verify.extend(cfg.exact_keys)
    if cfg.enable_heuristics:
        patterns_for_verify.extend(HEURISTIC_PATTERNS)
    verification = verify_clean(original_origin, work.verify_dir, patterns_for_verify, cfg.scan_commit_messages, cfg.timeout_sec)

    file_hits_remaining = {p: ls for p, ls in verification["files"].items() if ls and p != r"(^|/)\.env($|\.example$)"}
    msg_hits_remaining = {p: ls for p, ls in verification["messages"].items() if ls} if cfg.scan_commit_messages else {}
    env_pat = r"(^|/)\.env($|\.example$)"
    env_left = verification["files"].get(env_pat, [])

    if not file_hits_remaining and (not cfg.scan_commit_messages or not msg_hits_remaining) and not env_left:
        print("[verify-ok] No matches found in files or commit messages after rewrite.")
        print("[verify-ok] No .env-like files remain in history.")
    else:
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
        if env_left:
            print("[verify] .env-like files still present after rewrite (unexpected):")
            for l in env_left[:10]:
                print("    " + l)
        print("\n[action] Some patterns still matched after rewrite. Consider:")
        print("- Adding more purge paths if files remain (e.g., renamed assets).")
        print("- Providing additional exact secrets via --exact-key to catch embedded blobs.")
        print("- For commit messages: try a broader --replace-text mapping or message callbacks.")
        print("- Check GitHub PRs/forks: close/recreate PRs or rebase forks if refs/pull/* still point to old SHAs.")

    # 6) LOCAL WORKING FOLDER GUIDANCE — nudge the original working tree to the new history
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
