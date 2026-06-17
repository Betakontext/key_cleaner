## Key cleaner

#### One-click local tool to scan and (if needed) purge leaked secrets from a Git repository history.
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
