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
"""

from __future__ import annotations
import argparse
import base64
import os
import platform
import re
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
    target: str = Field(..., description="Remote URL (https/ssh) or local repo path")
    exact_keys: List[str] = Field(default_factory=list, description="Exact secret strings to search & purge")
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
        return v.strip()

@dataclass
class WorkDirs:
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
# Cross-platform subprocess helpers
# ---------------------------

def runx(args: List[str], cwd: Optional[Path] = None, timeout: Optional[int] = None, check: bool = True) -> subprocess.CompletedProcess:
    print("$ " + " ".join(args))
    start = time.time()
    cp = subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout)
    dur = time.time() - start
    if cp.stdout:
        print(cp.stdout.rstrip())
    if cp.stderr:
        print(cp.stderr.rstrip(), file=sys.stderr)
    if check and cp.returncode != 0:
        raise RuntimeError(f"Command failed ({cp.returncode}) after {dur:.1f}s: {' '.join(args)}\n{cp.stderr}")
    return cp

def is_git_repo(path: Path) -> bool:
    try:
        cp = runx(["git", "rev-parse", "--is-inside-work-tree"], cwd=path, timeout=15, check=False)
        return cp.returncode == 0 and "true" in (cp.stdout or "").lower()
    except Exception:
        return False

def has_git_filter_repo() -> bool:
    try:
        cp = runx(["git", "filter-repo", "-h"], timeout=15, check=False)
        return cp.returncode == 0
    except Exception:
        return False

def guess_origin_url(repo_dir: Path) -> Optional[str]:
    cp = runx(["git", "remote", "get-url", "origin"], cwd=repo_dir, timeout=15, check=False)
    return cp.stdout.strip() if cp.returncode == 0 else None

# ---------------------------
# Heuristics and parsers
# ---------------------------

HEURISTIC_PATTERNS = [
    r"\bsk-[A-Za-z0-9]{16,}\b",
    r"\bhf_[A-Za-z0-9]{16,}\b",
    r"\bghp_[A-Za-z0-9]{16,}\b",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bPOLLINATIONS_SECRET\b",
    r"\bPOLLINATIONS_API_KEY\b",
    r"\bOPENAI_API_KEY\b",
    r"\bHUGGINGFACE_API_KEY\b",
    r"\bAWS_ACCESS_KEY_ID\b",
    r"\bAWS_SECRET_ACCESS_KEY\b",
    r"\bAPI[_ ]?KEY\b",
    r"\bSECRET\b",
    r"\bTOKEN\b",
]

ENV_PATH_REGEX = re.compile(r"(^|/)\.env($|\.example$)", re.IGNORECASE)

def parse_env_lines(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        out[key] = val
    return out

def is_value_suspect(name: str, value: str) -> bool:
    if not value or value.strip() == "":
        return False
    low = value.lower()
    if any(x in low for x in ["placeholder", "your_key_here", "example", "dummy", "sample", "changeme"]):
        return False
    if len(value) < 16:
        return False
    if re.search(r"\b(sk-|hf_|ghp_|AKIA)", value):
        return True
    if re.search(r"(secret|token|api[_ ]?key)", name.lower()):
        return True
    return False

def maybe_decode_base64(s: str) -> Optional[str]:
    try:
        padding = '=' * (-len(s) % 4)
        dec = base64.b64decode(s + padding, validate=False)
        txt = dec.decode('utf-8', errors='ignore')
        return txt if txt and re.search(r"\bsk-[A-Za-z0-9]{10,}\b", txt) else None
    except Exception:
        return None

# ---------------------------
# Scan filters (new)
# ---------------------------

SKIP_DIRS = {
    ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "build", "dist", "node_modules"
}

# Set to None to include all; otherwise only these suffixes will be scanned
INCLUDE_SUFFIXES: Optional[Set[str]] = {
    ".py", ".env", ".txt", ".json", ".yml", ".yaml", ".ini", ".cfg", ".toml", ".md", ".csv"
}

def should_skip_path(p: str) -> bool:
    parts = p.strip().split("/")
    return any(part in SKIP_DIRS for part in parts)

def has_included_suffix(p: str) -> bool:
    if INCLUDE_SUFFIXES is None:
        return True
    return any(p.lower().endswith(suf) for suf in INCLUDE_SUFFIXES)

# ---------------------------
# Cross-platform scanning primitives
# ---------------------------

def rev_list_all(repo_dir: Path, timeout: int) -> List[str]:
    cp = runx(["git", "rev-list", "--all"], cwd=repo_dir, timeout=timeout, check=False)
    return [l.strip() for l in cp.stdout.splitlines() if l.strip()]

def ls_tree_names(repo_dir: Path, sha: str, timeout: int) -> List[str]:
    cp = runx(["git", "ls-tree", "-r", "--name-only", sha], cwd=repo_dir, timeout=timeout, check=False)
    files = [l.strip() for l in cp.stdout.splitlines() if l.strip()]
    # Early filtering: skip dirs and limit suffixes
    return [f for f in files if not should_skip_path(f) and has_included_suffix(f)]

def show_file_at(repo_dir: Path, sha: str, path: str, timeout: int) -> str:
    cp = runx(["git", "show", f"{sha}:{path}"], cwd=repo_dir, timeout=timeout, check=False)
    return cp.stdout if cp.returncode == 0 else ""

def grep_history_py(repo_dir: Path, pattern: str, timeout: int) -> Tuple[int, List[str]]:
    is_regex = any(ch in pattern for ch in ".*[](){}+?\\|^$")
    rx = re.compile(pattern) if is_regex else None
    hits: List[str] = []
    for sha in rev_list_all(repo_dir, timeout):
        for p in ls_tree_names(repo_dir, sha, timeout):
            text = show_file_at(repo_dir, sha, p, timeout)
            if not text:
                continue
            for idx, line in enumerate(text.splitlines(), 1):
                if (rx and rx.search(line)) or ((not rx) and (pattern in line)):
                    hits.append(f"{sha}:{p}:{idx}:{line[:200]}")
    return (len(hits), hits)

def grep_commit_messages_py(repo_dir: Path, pattern: str, timeout: int) -> Tuple[int, List[str]]:
    is_regex = any(ch in pattern for ch in ".*[](){}+?\\|^$")
    rx = re.compile(pattern) if is_regex else None
    cp = runx(["git", "log", "--all", "--pretty=format:%h %ad %s", "--date=iso"], cwd=repo_dir, timeout=timeout, check=False)
    out: List[str] = []
    for l in cp.stdout.splitlines():
        if (rx and rx.search(l)) or ((not rx) and (pattern in l)):
            out.append(l)
    return (len(out), out)

def find_bad_blobs_by_exact_keys_py(repo_dir: Path, keys: List[str], timeout: int) -> Set[str]:
    bad: Set[str] = set()
    if not keys:
        return bad
    cp = runx(["git", "rev-list", "--objects", "--all"], cwd=repo_dir, timeout=timeout, check=False)
    oids = [l.split()[0] for l in cp.stdout.splitlines() if l.strip()]
    for oid in oids:
        cp2 = runx(["git", "cat-file", "-p", oid], cwd=repo_dir, timeout=timeout, check=False)
        content = cp2.stdout
        if not content:
            continue
        if any(k in content for k in keys):
            bad.add(oid)
    return bad

def iter_env_files_history(repo_dir: Path, timeout: int) -> List[Tuple[str, str]]:
    env_entries: List[Tuple[str, str]] = []
    for sha in rev_list_all(repo_dir, timeout):
        files = ls_tree_names(repo_dir, sha, timeout)
        for f in files:
            if ENV_PATH_REGEX.search(f.strip()):
                env_entries.append((sha, f.strip()))
    return env_entries

# ---------------------------
# Core flow helpers
# ---------------------------

def to_file_url(p: Path) -> str:
    ps = p.resolve()
    if platform.system().lower().startswith("win"):
        posix_path = ps.as_posix()
        return f"file:///{posix_path.lstrip('/')}"
    else:
        return f"file://{ps.as_posix()}"

def clone_fresh(target: str, into_dir: Path, retries: int, timeout: int) -> Path:
    """
    Clone a remote URL or a local git repo. For local repos, prefer cloning from
    the raw path (no file://) because Git handles it natively cross-platform.
    """
    repo_dir = into_dir / "repo"
    last_err: Optional[Exception] = None

    if Path(target).exists() and is_git_repo(Path(target)):
        url = str(Path(target).resolve())  # raw path for local clone
    else:
        url = target

    # Guard against malformed Windows file URLs with backslashes
    if url.startswith("file://") and "\\" in url:
        raise ValueError(f"Invalid file URL on Windows (use forward slashes): {url}")

    repo_dir.parent.mkdir(parents=True, exist_ok=True)

    for attempt in range(retries + 1):
        try:
            print(f"[debug] clone_fresh target={target!r} resolved_url={url!r} into={str(repo_dir)!r}")
            runx(["git", "clone", url, str(repo_dir)], timeout=timeout)
            return repo_dir
        except Exception as e:
            last_err = e
            print(f"[retry] clone failed (attempt {attempt+1}/{retries+1}): {e}")
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Clone failed after retries: {last_err}")

def fetch_all(repo_dir: Path, timeout: int) -> None:
    runx(["git", "fetch", "--all", "--prune", "--tags"], cwd=repo_dir, timeout=timeout)
    runx(["git", "fetch", "origin", "+refs/pull/*:refs/remotes/origin/pr/*"], cwd=repo_dir, timeout=timeout, check=False)

def remove_paths_with_filter_repo(repo_dir: Path, paths: List[str], timeout: int) -> None:
    if not paths:
        return
    args: List[str] = ["git", "filter-repo"]
    for p in paths:
        args.extend(["--path", p])
    args.extend(["--invert-paths", "--force"])
    runx(args, cwd=repo_dir, timeout=timeout)

def strip_blobs_with_ids(repo_dir: Path, blob_ids: Set[str], timeout: int) -> None:
    if not blob_ids:
        return
    tmpfile = repo_dir / "bad_blobs.txt"
    tmpfile.write_text("\n".join(sorted(blob_ids)) + "\n", encoding="utf-8")
    runx(["git", "filter-repo", "--strip-blobs-with-ids", str(tmpfile), "--force"], cwd=repo_dir, timeout=timeout)

def rewrite_commit_messages_replace(repo_dir: Path, exact_keys: List[str], timeout: int) -> None:
    if not exact_keys:
        return
    repl_file = repo_dir / "replace.txt"
    lines = [f"{k}===>[REDACTED]" for k in exact_keys]
    repl_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    runx(["git", "filter-repo", "--replace-text", str(repl_file), "--force"], cwd=repo_dir, timeout=timeout)

def readd_origin_if_missing(repo_dir: Path, original_url: Optional[str]) -> None:
    cp = runx(["git", "remote", "-v"], cwd=repo_dir, check=False)
    if "origin" in cp.stdout:
        return
    if original_url:
        runx(["git", "remote", "add", "origin", original_url], cwd=repo_dir)
        runx(["git", "remote", "-v"], cwd=repo_dir)
    else:
        print("[warn] No origin URL available to re-add; set it manually later (git remote add origin <url>).")

def list_local_branches(repo_dir: Path) -> List[str]:
    cp = runx(["git", "for-each-ref", "--format=%(refname:short)", "refs/heads/"], cwd=repo_dir, check=False)
    return [l.strip() for l in cp.stdout.splitlines() if l.strip()]

def push_all(repo_dir: Path, push_tags: bool, timeout: int) -> None:
    runx(["git", "push", "--force", "origin", "main"], cwd=repo_dir, timeout=timeout, check=False)
    for b in list_local_branches(repo_dir):
        runx(["git", "push", "--force", "origin", b], cwd=repo_dir, timeout=timeout, check=False)
    if push_tags:
        runx(["git", "push", "--force", "--tags"], cwd=repo_dir, timeout=timeout, check=False)

def verify_clean(repo_url: str, tmpdir: Path, patterns: List[str], scan_commit_messages: bool, timeout: int
                 ) -> Dict[str, Dict[str, List[str]]]:
    verify_repo = tmpdir / "repo-scan"
    runx(["git", "clone", "--no-checkout", repo_url, str(verify_repo)], timeout=timeout)
    fetch_all(verify_repo, timeout)

    out: Dict[str, Dict[str, List[str]]] = {"files": {}, "messages": {}}

    for pat in patterns:
        _, lines = grep_history_py(verify_repo, pat, timeout)
        out["files"][pat] = lines
        if scan_commit_messages:
            _, mlines = grep_commit_messages_py(verify_repo, pat, timeout)
            out["messages"][pat] = mlines

    env_pat = r"(^|/)\.env($|\.example$)"
    _, env_lines = grep_history_py(verify_repo, env_pat, timeout)
    out["files"][env_pat] = env_lines
    return out

def yes_no(prompt: str, default_no: bool = True) -> bool:
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

    work = WorkDirs.create()
    print(f"[info] Working directory: {work.base}")

    original_origin = None
    local_target = None
    if Path(cfg.target).exists():
        local_target = Path(cfg.target).resolve()
        if not is_git_repo(local_target):
            print(f"[error] Target path is not a Git repo: {local_target}")
            sys.exit(2)
        original_origin = guess_origin_url(local_target) or str(local_target)
    else:
        original_origin = cfg.target

    if not has_git_filter_repo():
        print("[error] 'git-filter-repo' not found. Install with: pipx install git-filter-repo (or pip install git-filter-repo)")
        sys.exit(2)

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

    # Build search patterns
    patterns: List[str] = []
    patterns.extend(cfg.exact_keys)
    if cfg.enable_heuristics:
        patterns.extend(HEURISTIC_PATTERNS)

    # 1) INITIAL SCAN — files (against rewrite_repo only; never touch local working tree)
    print("\n[step] Scanning full history for potential leaks (files)...")
    initial_file_hits: Dict[str, List[str]] = {}
    for pat in patterns:
        count, lines = grep_history_py(rewrite_repo, pat, cfg.timeout_sec)
        if count > 0:
            print(f"[hit] files: pattern '{pat}': {count} matches (showing up to 20)")
            initial_file_hits[pat] = lines[:20]
            for l in initial_file_hits[pat]:
                print("  " + l)
        else:
            print(f"[ok] files: pattern '{pat}': none")

    # 1a) commit messages (optional)
    initial_msg_hits: Dict[str, List[str]] = {}
    if cfg.scan_commit_messages:
        print("\n[step] Scanning commit messages for potential leaks...")
        for pat in patterns:
            mcount, mlines = grep_commit_messages_py(rewrite_repo, pat, cfg.timeout_sec)
            if mcount > 0:
                print(f"[hit] messages: pattern '{pat}': {mcount} matches (showing up to 20)")
                initial_msg_hits[pat] = mlines[:20]
                for l in initial_msg_hits[pat]:
                    print("  " + l)
            else:
                print(f"[ok] messages: pattern '{pat}': none")

    # 1b) extract .env secrets historically
    print("\n[step] Inspecting .env-like files across history and extracting potential secret values...")
    env_hits = iter_env_files_history(rewrite_repo, cfg.timeout_sec)
    extracted_exact_values: Set[str] = set()
    for sha, path in env_hits:
        cp = runx(["git", "show", f"{sha}:{path}"], cwd=rewrite_repo, timeout=cfg.timeout_sec, check=False)
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
            _ = captured

    if extracted_exact_values:
        for x in extracted_exact_values:
            if x not in cfg.exact_keys:
                cfg.exact_keys.append(x)
        print(f"[info] Collected {len(extracted_exact_values)} exact value(s) from .env files to strip via blobs.")

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

    if cfg.verify_only:
        print("\n[result] Verification-only run finished (hits were found; no rewrite performed).")
        if not cfg.keep_temp:
            import shutil
            shutil.rmtree(work.base, ignore_errors=True)
        sys.exit(0)

    # 2) REWRITE PLAN
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
    print("\n[step] Rewriting history (path removals with git-filter-repo)...")
    try:
        remove_paths_with_filter_repo(rewrite_repo, cfg.purge_paths, cfg.timeout_sec)
    except Exception as e:
        print(f"[warn] Path-based rewrite failed or may not be necessary: {e}")

    readd_origin_if_missing(rewrite_repo, original_origin)

    if cfg.exact_keys:
        print("\n[step] Locating blobs that contain provided exact keys...")
        bad_blobs = find_bad_blobs_by_exact_keys_py(rewrite_repo, cfg.exact_keys, cfg.timeout_sec)
        print(f"[info] Found {len(bad_blobs)} blob(s) containing exact keys.")
        if bad_blobs:
            print("[step] Stripping those blobs from history...")
            strip_blobs_with_ids(rewrite_repo, bad_blobs, cfg.timeout_sec)
            readd_origin_if_missing(rewrite_repo, original_origin)
        else:
            print("[info] No blobs matched exact keys after path removals.")

    if cfg.scan_commit_messages:
        print("\n[step] Optionally redacting exact secrets from commit messages...")
        try:
            rewrite_commit_messages_replace(rewrite_repo, cfg.exact_keys, cfg.timeout_sec)
            readd_origin_if_missing(rewrite_repo, original_origin)
        except Exception as e:
            print(f"[warn] Commit message rewrite failed or not necessary: {e}")

    print("\n[step] Pushing rewritten history to remote (force)...")
    if not original_origin:
        print("[error] No origin remote URL known. Configure it manually and push (git remote add origin <url>).")
        sys.exit(3)
    try:
        push_all(rewrite_repo, cfg.push_tags, timeout=cfg.timeout_sec)
    except Exception as e:
        print(f"[error] Push failed: {e}")
        sys.exit(4)

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

    if local_target:
        print("\n[hint] To refresh your original working folder while preserving .venv, __pycache__, .env, etc.:")
        print(textwrap.dedent(f"""
        cd {str(local_target)}
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
