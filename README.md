### Key Cleaner Interactive

Key Cleaner provides an interactive, safety-oriented workflow for finding selected literal values in Git history and, only after explicit confirmation, rewriting and publishing cleaned history.

It is intended for sensitive values that were committed by mistake. Rewriting history changes commit IDs; coordinate a pause on pushes with everyone who uses the repository.

### Project files and setup

The project uses these files:

- `key_cleaner.py` — core scanning, filtering, verification, and safeguards.
- `key_cleaner_interactive.py` — interactive local/URL workflow.

From the tool project directory, reuse the existing virtual environment directly. Do not resolve its path with `realpath`.

```bash
.venv/bin/python key_cleaner_interactive.py
```

If setup is new, create the environment and install the required tool:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install git-filter-repo
```

### Prepare `values.txt`

Create a UTF-8 `values.txt` with exactly one literal, case-sensitive value per line.

- Do not add blank lines, comments, or quotes.
- Prefer storing this file outside the repository being scanned.
- Treat the file itself as sensitive; delete it only after it is no longer needed.

Example:

```text
example-secret-token
AKIAEXAMPLEVALUE
```

### Start an interactive run

Provide either a local repository path or a GitHub URL when prompted.

- For a local repository with an `origin`, the origin is used for the authoritative remote snapshot.
- Local-only work is not published.
- Enter the path to `values.txt`; after the directory-input patch described below, a directory containing `values.txt` is also accepted.
- Hints are advisory only and are not automatically removed.

The dry-run prompt is a safety gate: enter `Y` to proceed. Entering `N` or pressing Enter cancels. A dry run does not change the original repository and does not push, but it does create diagnostic mirrors.

### Review and publication

If exact matches are found on the remote, the interface asks whether to rewrite and publish. The default is `N`; answer `Y` only after reviewing the result and coordinating the rewrite.

With `Y`, the tool rewrites an isolated mirror, verifies it, and publishes branches and tags through its core safeguards. Commit IDs will change. Pause pushes and tell collaborators when they must re-clone or reset their local history.

Do not assume that every remote reference is clean after a head/tag publication. GitHub pull-request refs can retain matches separately from cleaned branches and tags. Investigate residual references before deciding whether any diagnostic or PR-related reference should be removed; there is no blanket assertion that the remote is clean.

### Fresh-clone verification

The interface can request a fresh clone for verification.

- Press Enter to use the suggested path.
- Supply a new, nonexisting full path to choose another location.
- Enter `-` to skip the fresh clone.

Scan the fresh clone and use that scan result for review. Do not push an old clone, and do not copy an old `.git` directory into the fresh clone.

### Before cleanup

Complete these prerequisites before removing temporary work:

- Review the publication outcome and all prompts.
- Scan a fresh clone when applicable.
- Save or otherwise preserve any local-only changes.
- Investigate residual refs, including PR-related refs and diagnostic evidence.

Retained directories named `/tmp/key-cleaner-work.*` are not removed automatically. Their original history may still contain sensitive data. Keep them for investigation until the review is complete.

### Safe cleanup of one retained work directory

Use the exact directory printed by the tool, not the illustrative value below. Replace `/tmp/key-cleaner-work.ABC12345` with the actual printed path.

Inspect it first:

```bash
cleanup=/tmp/key-cleaner-work.ABC12345
printf 'Selected cleanup directory: %s\n' "$cleanup"
ls -ld -- "$cleanup"
du -sh -- "$cleanup"
```

Run this selection prompt **alone** (not pasted together with deletion logic):

```bash
read -r -p 'Type the full directory path to delete: ' selected
```

Then run the following Bash block only if the selected path is exactly the reviewed cleanup directory. It requires a direct child of `/tmp` whose basename matches `key-cleaner-work.*`, rejects symlinks, and otherwise cancels.

```bash
cleanup=$selected
if [ "$cleanup" = "/tmp/key-cleaner-work.ABC12345" ] \
  && [ "$(dirname -- "$cleanup")" = /tmp ] \
  && [[ "$(basename -- "$cleanup")" == key-cleaner-work.* ]] \
  && [ ! -L "$cleanup" ] \
  && [ -d "$cleanup" ]; then
  LC_ALL=C rm -rI -- "$cleanup"
else
  printf '%s\n' 'Cleanup cancelled: selection did not pass the safety checks.'
fi
```

At the `rm -rI` prompt, confirm with English `y` only after rechecking the target. Additional read-only questions are normal. Do not use `sudo`; wait for the prompt rather than bypassing it.

Verify full absence, including the absence of a symlink at that path:

```bash
if [ ! -e "$cleanup" ] && [ ! -L "$cleanup" ]; then
  printf '%s\n' 'Cleanup verified: path is absent.'
else
  printf '%s\n' 'Cleanup not verified: path still exists or is a symlink.'
fi
```

Never delete the project directory, `.venv`, or the fresh clone through this cleanup procedure. Review an old clone separately. Ordinary deletion is not secure erase and does not remove backups or SSD-resident data.

### Appendix: optional directory-input patch

The following instructions describe a patch that may be applied to the existing interactive script; they do not claim that it is already applied. In `run_interactive`, replace the existing input and initial `Path` construction with this logic. Keep subsequent `scan_ns` and `read_keys` processing unchanged.

```python
key_file_text = ask("Path to values.txt or its directory: ", input_fn).strip()
key_file = Path(key_file_text).expanduser()
if key_file.is_dir():
    key_file = key_file / "values.txt"
if not key_file.is_file():
    raise core.Failure("The selected values file is unavailable.")
```

Use English-only comments if comments are added to this code. The failure message is deliberately generic and safe.
