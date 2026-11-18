#!/usr/bin/env python3
"""Interactive, conservative front end for the adjacent key_cleaner.py scanner.

With command-line arguments this file deliberately delegates unchanged to key_cleaner.py.
Run it without arguments for the guided workflow.  The wrapper never displays values from
values.txt and retains its private working directory for manual review.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

TIMEOUT = 600


def load_core():
    """Load the authoritative scanner from the same directory, without changing it."""
    path = Path(__file__).resolve().with_name("key_cleaner.py")
    if not path.is_file():
        raise RuntimeError("key_cleaner.py must be placed beside key_cleaner_interactive.py")
    spec = importlib.util.spec_from_file_location("key_cleaner_adjacent", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("key_cleaner.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    needed = ("cmd", "repo", "read_keys", "scan", "rewrite", "publish", "Failure", "noleak", "HINT")
    if any(not hasattr(module, name) for name in needed):
        raise RuntimeError("adjacent key_cleaner.py has an unsupported API")
    return module


def ns(key_file=None, output=None):
    return argparse.Namespace(exact_key=[], key_file=[] if key_file is None else [str(key_file)],
        heuristics=True, scan_commit_messages=True, timeout=TIMEOUT, purge_path=[],
        confirm=False, output=None if output is None else str(output))


def ask(prompt, input_fn=input):
    return input_fn(prompt)


def yes(prompt, input_fn=input, default=False):
    value = ask(prompt, input_fn).strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


def safe_error(core, keys, message):
    """Do not expose entered paths, URLs, or supplied values in diagnostics."""
    try:
        message = core.noleak(keys, message)
    except Exception:
        message = "operation could not be completed"
    print("ERROR: " + str(message).replace("\n", " "), file=sys.stderr)


def local_repo(core, value):
    p = Path(value).expanduser()
    if not p.exists():
        return None
    # repo() validates git structure and rejects shallow/partial repositories.
    core.repo(p.resolve(), TIMEOUT)
    return p.resolve()


def valid_remote(core, value):
    """Return a validated clone target.  Reject option-like targets before Git sees them."""
    value = value.strip()
    if not value or value.startswith("-"):
        raise core.Failure("invalid repository target")
    p = Path(value).expanduser()
    if p.exists():
        core.repo(p.resolve(), TIMEOUT)
        return str(p.resolve())
    if value.startswith("file://"):
        u = urlparse(value)
        if u.netloc not in ("", "localhost"):
            raise core.Failure("invalid repository target")
        fp = Path(unquote(u.path))
        if not fp.exists():
            raise core.Failure("invalid repository target")
        core.repo(fp.resolve(), TIMEOUT)
        return value
    # Network targets are intentionally limited to GitHub HTTPS or SSH spellings.
    if re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", value):
        return value
    if re.fullmatch(r"(?:ssh://)?git@github\.com(?::|/)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", value):
        return value
    raise core.Failure("invalid repository target")


def origin_of(core, repo_path):
    result = core.cmd(["git", "-C", str(repo_path), "remote", "get-url", "origin"], timeout=TIMEOUT)
    origin = result.stdout.decode("utf8", "surrogateescape").strip()
    if not origin or origin.startswith("-"):
        raise core.Failure("repository has no usable origin")
    return valid_remote(core, origin)


def clone(core, target, destination, mirror=False, interactive=True):
    """Clone through core.cmd so GIT_NO_LAZY_FETCH protections are consistently applied."""
    if str(target).startswith("-"):
        raise core.Failure("invalid repository target")
    command = ["git", "clone"]
    if mirror:
        command += ["--mirror", "--no-local"]
    command += ["--", str(target), str(destination)]
    # ``interactive`` documents that this is a user-initiated clone.  core.cmd remains the
    # single command runner and supplies its hardened Git environment.
    core.cmd(command, timeout=TIMEOUT)

def install_hint_regex(core):
    """Broaden advisory hints only; exact values are the sole removal candidates."""
    old = core.HINT
    # Keep the scanner's existing flags for its established pattern.  New identifier matching
    # uses scoped case-insensitivity, so prefixes are not made case-insensitive accidentally.
    identifiers = (rb"\b(?i:POLLINATIONS_SECRET|POLLINATIONS_API_KEY|OPENAI_API_KEY|"
                   rb"HUGGINGFACE_API_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|FTPS_PASS|"
                   rb"SECRET|TOKEN|API[ _-]?KEY|API|KEY)\b")
    prefixes = (rb"(?:\bsk-[A-Za-z0-9_-]{8,}\b|\bhf_[A-Za-z0-9_-]{8,}\b|"
                rb"\bghp_[A-Za-z0-9]{8,}\b|\bAKIA[0-9A-Z]{12,}\b)")
    # The adjacent scanner uses a leading global (?i).  Move that behaviour into a
    # scoped group before appending case-sensitive prefix forms.
    old_pattern = old.pattern
    old_flags = old.flags
    if old_pattern.startswith(b"(?i)"):
        old_pattern = b"(?i:" + old_pattern[4:] + b")"
        old_flags &= ~re.IGNORECASE
    core.HINT = re.compile(b"(?:" + old_pattern + b"|" + identifiers + b"|" + prefixes + b")", old_flags)
    return old

def output(core, keys, message):
    """Route any user-facing text that contains a path through the scanner redactor."""
    print(core.noleak(keys, message))


def artifact_path(core, keys, path):
    output(core, keys, "Retained working artifact: " + str(path))


def default_clone_path(local, target):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if local is not None:
        return local.parent / (local.name + "-clean-" + stamp)
    name = target.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") or "repository"
    return Path.home() / (name + "-clean-" + stamp)


def offer_fresh_clone(core, keys, target, local, work, scan_ns, input_fn):
    """Offer a separately retained normal clone and make its scan result actionable."""
    default = default_clone_path(local, target)
    answer = ask(core.noleak(keys, "Create a fresh normal clone path [" + str(default) +
                                  "] (blank to use default; '-' to skip): "), input_fn).strip()
    fresh = None if answer == "-" else Path(answer).expanduser() if answer else default
    if fresh is None:
        return 0
    if os.path.lexists(fresh):
        raise core.Failure("fresh clone destination already exists")
    clone(core, target, fresh, mirror=False, interactive=True)
    _, froot, _ = core.repo(fresh, TIMEOUT)
    remaining, _ = core.scan(fresh, froot, keys, scan_ns, True)
    output(core, keys, "Fresh normal clone scanned: " + str(fresh))
    if remaining:
        print("WARNING: exact matches remain in the fresh normal clone.")
        return 1
    print("Fresh normal clone is clean of supplied exact values.")
    return 0


def run_interactive(core, input_fn=input):
    """Guided scan, optional remote rewrite, and independent post-publication verification."""
    keys = []
    old_hint = None
    work = None
    try:
        entered = ask("Repository path (local or GitHub URL): ", input_fn).strip()
        if not entered:
            print("Cancelled."); return 0
        key_file_text = ask("values.txt path: ", input_fn).strip()
        if not key_file_text:
            print("Cancelled."); return 0
        if not yes("Start dry run (read-only scans; no source/index changes or pushes) Y/N [N]: ", input_fn, False):
            print("Cancelled: no scans, clones, rewrites, or publication were performed.")
            return 0
        # Do not inspect a repository or key file until the user explicitly starts the dry run.
        local = local_repo(core, entered)
        target = origin_of(core, local) if local is not None else valid_remote(core, entered)
        # Expand before read_keys: it validates readability and rejects empty lines/values.
        # Accept either a values file or a directory containing values.txt.
        key_file = Path(key_file_text).expanduser()
        if key_file.is_dir():
            key_file = key_file / "values.txt"
        if not key_file.is_file():
            raise core.Failure(
                "Values file not found. Enter a file or a directory containing values.txt."
            )
        scan_ns = ns(key_file)
        keys = core.read_keys(scan_ns)
        if not keys:
            raise core.Failure("values file contains no values")

        old_hint = install_hint_regex(core)
        exact = hints = 0
        print("Dry run creates retained local snapshots but never changes the source, index, or remote.")
        if local is not None:
            print("Scanning local history, index, and working tree (read-only)...")
            _, root, bare = core.repo(local, TIMEOUT)
            exact, hints = core.scan(local, root, keys, scan_ns, not bare)
        work = Path(tempfile.mkdtemp(prefix="key-cleaner-work."))
        os.chmod(work, 0o700)
        # Announce allocation before clone, so clone failures still leave a reviewable location.
        artifact_path(core, keys, work)
        source = work / "source.git"
        clone(core, target, source, mirror=True, interactive=True)
        _, _, _ = core.repo(source, TIMEOUT)
        print("Scanning authoritative remote mirror (read-only; no remote changes)...")
        remote_exact, remote_hints = core.scan(source, None, keys, scan_ns, False)
        exact += remote_exact; hints += remote_hints
        if hints:
            print("Advisory heuristic hints were found. They are not proof and are never removed without exact values from values.txt.")

        if remote_exact <= 0:
            if exact:
                print("Exact matches were local-only; authoritative remote is clean, so no rewrite will be offered.")
            else:
                print("No exact values found in the authoritative remote; no rewrite was performed.")
            return offer_fresh_clone(core, keys, target, local, work, scan_ns, input_fn)

        print("Exact matches exist in the authoritative remote mirror. No remote changes occurred during the scan.")
        warning = ("Confirm remote rewrite and publication Y/N [N]. This changes commit IDs and remote heads/tags "
                   "at the origin target only; the local repository is untouched and PR/provider refs are not published: ")
        if not yes(warning, input_fn, False):
            print("Rewrite cancelled; no publication was performed.")
            return 0
        cleaned = work / "cleaned.git"
        rewrite_ns = ns(key_file, cleaned); rewrite_ns.confirm = True
        gd, _, _ = core.repo(source, TIMEOUT)
        core.rewrite(source, None, gd, keys, rewrite_ns)
        _, _, _ = core.repo(cleaned, TIMEOUT)
        remaining, _ = core.scan(cleaned, None, keys, scan_ns, False)
        if remaining:
            raise core.Failure("cleaned mirror verification failed")
        publish_ns = ns(); publish_ns.confirm = True
        core.publish(source, cleaned, target, publish_ns)
        print("Publication completed. Re-cloning remote for verification...")
        verified = work / "remote-verify.git"
        clone(core, target, verified, mirror=True, interactive=True)
        core.repo(verified, TIMEOUT)
        residual, _ = core.scan(verified, None, keys, scan_ns, False)
        if residual:
            print("WARNING: residual exact matches were found in remote refs; inspect provider-managed refs before relying on removal.")
        else:
            print("Remote verification found no supplied exact values.")
        fresh_status = offer_fresh_clone(core, keys, target, local, work, scan_ns, input_fn)
        return 1 if residual else fresh_status
    except (EOFError, KeyboardInterrupt):
        print("Cancelled."); return 0
    except core.Failure as exc:
        # Show controlled core errors with search values redacted.
        safe_error(core, keys, str(exc))
        return 2
    except Exception as exc:
        # Reveal the exception type without exposing sensitive details.
        safe_error(
            core,
            keys,
            f"Unexpected {type(exc).__name__}; operation stopped",
        )
        return 2

    finally:
        if old_hint is not None:
            core.HINT = old_hint
        if work is not None:
            output(core, keys, "Retained working directory: " + str(work) + "; it is never deleted automatically. Remove it manually when safe.")
        else:
            print("No retained working directory was created; no directory is deleted automatically.")

def main():
    if len(sys.argv) > 1:
        return load_core().main()
    try:
        return run_interactive(load_core())
    except (EOFError, KeyboardInterrupt):
        print("Cancelled."); return 0
    except RuntimeError as exc:
        print("ERROR: " + str(exc), file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(main())
