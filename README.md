## Key cleaner

#### Command-line tool to scan and (if needed) purge leaked secrets from a Git repository history.
:::::::::::::::::::::::::::::

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

PREREQUISITES

  - git >= 2.30
  - git-filter-repo installed (pipx install git-filter-repo | pip install git-filter-repo)
  - Python 3.10+

SETUP

Ubuntu BASH

    python3 -m venv venv
    source venv/bin/activate
    pip install git-filter-repo pydantic
    chmod +x key_cleaner.py

Windows PS

    py -3 -m venv venv
    .\venv\Scripts\Activate.ps1
    pip install git-filter-repo pydantic
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    

USAGE QUICKSTART (non-destructive first):

VERIFY RUN (no changes):

Local verify-only on a path:
  
      python key_cleaner.py --target /home/yourpath/your_repo 
        --exact-key 'sk_ABC...' --scan-commit-messages --verify-only

Windows PS 

    python .\key_cleaner_win.py ` --target "C:\Users\yourpath\your_repo" ` 
    --exact-key "sk_ABC..." ` --no-heuristics ` --scan-commit-messages ` --verify-only

Remote verify-only (includes commit messages):

      python key_cleaner.py --target https://github.com/org/repo.git 
        --exact-key 'sk_ABC...' --scan-commit-messages --verify-only

FULL RUN (changes git commit history):


Full run on a local path (will rewrite history if hits are found; add --confirm to skip prompt):
  
      python key_cleaner.py --target /home/yourpath/your_repo 
        --exact-key 'sk_ABC...' --purge-path .env --scan-commit-messages --confirm

Full run on a remote path (will rewrite history if hits are found; add --confirm to skip prompt):

      python key_cleaner.py --target https://github.com/org/repo.git 
        --exact-key 'sk_ABC...' --purge-path .env --scan-commit-messages --confirm
        
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

CLEANUP (optional, f.e. if key_cleaner.py got aborted and left temporary files in TEMP folder)

If you abborted key_cleaner runs you can clean the leftovers from /temp via clean_temp_key_cleaner.py.
It detects automaticly the right Temp-Verzeichnis (TEMP/TMP/TMPDIR).

Safe mode: -- list first, then delete: with -f.

Windows PowerShell/cmd:
 
    	python clean_temp_key_cleaner.py --list
    	python clean_temp_key_cleaner.py -f

    	python clean_temp_key_cleaner.py --base "C:\Temp" -f # your path to \Temp, if it is not in the standart System structure

Ubuntu/Linux:

    	python3 clean_temp_key_cleaner.py --list
    	python3 clean_temp_key_cleaner.py -f
    	python3 clean_temp_key_cleaner.py --base /tmp -f # your path to \Temp, if it is not in the standart System structure
    
Make executable: 
	
	chmod +x clean_temp_key_cleaner.py und dann ./clean_temp_key_cleaner.py -f




IMPORTANT

  - History rewrite changes commit SHAs. Coordinate with collaborators.
  - GitHub PR refs (refs/pull/*) and forks are not overwritten by pushes; close/recreate PRs
    or rebase forks separately. This tool fetches PR refs into origin/pr/* to ensure they are scanned.
  - The tool is local and shells out to Git; it does not upload repository data anywhere.

