### Key Cleaner

Scan local or remote Git repositories for exact values. Optionally create a separate cleaned mirror.

**Scan-only by default. No automatic pushes.**

### Requirements

- Python 3.10+ recommended
- Git
- `git-filter-repo` only for rewriting

### Scan a local repository

```bash
python3 key_cleaner.py \
  --target /path/to/repository \
  --exact-key 'VALUE_TO_FIND' \
  --scan-commit-messages \
  --no-heuristics \
  --verify-only
```

Checks reachable historical files, the Git index, and regular working files, including untracked and ignored files. Local scans do not fetch remote updates.

### Scan a remote repository

```bash
python3 key_cleaner.py \
  --target https://github.com/organization/repository.git \
  --exact-key 'VALUE_TO_FIND' \
  --scan-commit-messages \
  --no-heuristics \
  --verify-only
```

Scans a temporary mirror of refs published by the server. Private repositories require configured Git authentication.

### Read search values from a file

Use a UTF-8 file with one value per line, without quotes, comments, or blank lines. Store it outside the scanned repository.

```bash
python3 key_cleaner.py \
  --target /path/to/repository \
  --key-file /secure/path/search-values.txt \
  --scan-commit-messages \
  --no-heuristics \
  --verify-only
```

`--exact-key` and `--key-file` are repeatable. Exact values are case-sensitive literal UTF-8 byte sequences, not regex patterns.

### Windows PowerShell

Use the same script:

```powershell
py -3 .\key_cleaner.py `
  --target "C:\Projects\repository" `
  --key-file "C:\Secure\search-values.txt" `
  --scan-commit-messages `
  --no-heuristics `
  --verify-only
```

### Create a cleaned mirror

Install the optional dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install git-filter-repo
```

Create a cleaned copy from a local repository:

```bash
python key_cleaner.py \
  --target /path/to/local/repository \
  --key-file /secure/path/search-values.txt \
  --scan-commit-messages \
  --no-heuristics \
  --rewrite \
  --output /outside/source/cleaned.git \
  --confirm
```

The output directory must not exist and should be outside the source repository.

Exact values are replaced with `[REMOVED]`. The generated mirror is checked again. The original repository, working files, and remote remain unchanged. Uncommitted changes are not included.

### Remove historical paths

```bash
python key_cleaner.py \
  --target /path/to/local/repository \
  --rewrite \
  --output /outside/source/cleaned.git \
  --purge-path .env \
  --purge-path config/old-credentials.json \
  --no-heuristics \
  --confirm
```

Paths are repository-relative. Specify previous filenames separately when needed. No paths are removed by default.

### Results and exit codes

```text
HIT exact#1 history blob <object-id> path=b'.env.example'
Summary: exact_hits=1 heuristic_hints=0
```

Historical hits are counted per object and search value, not per occurrence or commit. `b'...'` is byte-string notation, not part of the filename.

| Code | Meaning |
|---|---|
| `0` | No scan findings, or isolated rewrite verified |
| `1` | Scan found exact matches or heuristic hints |
| `2` | Error or invalid invocation; not a clean result |

Check immediately after execution:

```bash
echo $?
```

PowerShell:

```powershell
$LASTEXITCODE
```

### Important limitations

- No unreachable objects, reflog-only history, hidden remote refs, external LFS data, or submodule contents.
- Symlinks, nonregular working files, and recognized nested repositories are skipped.
- Archives are not unpacked; encoded values are not automatically decoded.
- Shallow repositories and detected partial clones are rejected.
- Large files and Git objects require corresponding memory.
- Cleaning a mirror does not clean GitHub, forks, PR refs, or other clones.
- Rewriting changes history and may invalidate signatures.

**Rotate or revoke exposed credentials separately. History cleanup does not make exposed values private again.**

### Help

```bash
python3 key_cleaner.py --help
```
_________________
MIT Licence
Contact: https://dev.betakontext.de
