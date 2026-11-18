#!/usr/bin/env python3
"""Standalone, dependency-free Git secret scanner with an optional isolated rewrite.

Scanning reads complete raw bytes into memory for each reachable object and regular working
file.  It never fetches, pushes, or changes a local source.  It intentionally does not cover
reflogs, unreachable objects, LFS payloads, hidden/unadvertised remote refs, or submodules.
Annotated-tag signatures can be stripped by git-filter-repo during a rewrite.
"""
import argparse, importlib.util, json, os, re, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

OID_RE = re.compile(rb"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
HINT_RE = re.compile(rb"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*[A-Za-z0-9_./+=:@-]{4,512}")
MARKER = b"[REMOVED]"
class Failure(Exception): pass

def command(argv, cwd=None, inp=None, timeout=120, allowed=(0,)):
    env = os.environ.copy(); env["GIT_NO_LAZY_FETCH"] = "1"
    try:
        p = subprocess.run(argv, cwd=cwd, input=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Failure("command execution failed") from e
    if p.returncode not in allowed:
        raise Failure("git operation failed")
    return p

def git(repo, args, **kw): return command(["git", "-C", str(repo), *args], **kw)
def redactor(keys):
    # Replace raw UTF-8, decoded text, and common escaped/repr variants before every output.
    variants = set()
    for key in keys:
        variants.add(key.decode("utf-8", "surrogateescape")); variants.add(repr(key))
        variants.add(key.decode("utf-8", "backslashreplace")); variants.add(key.hex())
    def clean(value):
        text = str(value)
        for x in sorted(variants, key=len, reverse=True):
            if x: text = text.replace(x, "[REDACTED]")
        return text
    return clean

def read_keys(ns):
    values = list(ns.exact_key)
    try:
        for fn in ns.key_file:
            with open(fn, "rb") as f:
                for line in f:
                    values.append(line.rstrip(b"\r\n").decode("utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise Failure("cannot read key file") from e
    keys = []
    for v in values:
        b = v.encode("utf-8")
        if not b: raise Failure("empty exact key is not allowed")
        if b not in keys: keys.append(b)
    return keys

def repo_info(target, timeout):
    gd = git(target, ["rev-parse", "--absolute-git-dir"], timeout=timeout).stdout.decode("utf-8", "surrogateescape").strip()
    bare = git(target, ["rev-parse", "--is-bare-repository"], timeout=timeout).stdout.strip() == b"true"
    shallow = git(target, ["rev-parse", "--is-shallow-repository"], timeout=timeout).stdout.strip()
    if shallow == b"true": raise Failure("refusing incomplete shallow repository")
    # rc=1 means no matching partial-clone configuration, and is acceptable.
    p = git(target, ["config", "--get-regexp", r"^(extensions\.partialClone|remote\..*\.promisor|core\.partialCloneFilter)$"], timeout=timeout, allowed=(0,1))
    if p.returncode == 0 and p.stdout.strip(): raise Failure("refusing partial-clone repository")
    root = None if bare else Path(git(target, ["rev-parse", "--show-toplevel"], timeout=timeout).stdout.decode("utf-8", "surrogateescape").strip()).resolve()
    return Path(gd).resolve(), root, bare

def object_map(repo, timeout):
    raw = git(repo, ["rev-list", "--objects", "--all", "--no-object-names"], timeout=timeout).stdout
    ids=[]; seen=set()
    for line in raw.splitlines():
        if not OID_RE.fullmatch(line): raise Failure("unexpected object enumeration")
        if line not in seen: seen.add(line); ids.append(line)
    # A separate representative path map keeps enumeration strict while preserving useful labels.
    paths={}
    raw = git(repo, ["rev-list", "--objects", "--all"], timeout=timeout).stdout
    for line in raw.splitlines():
        oid, sep, path = line.partition(b" ")
        if not OID_RE.fullmatch(oid): raise Failure("unexpected object/path enumeration")
        if sep and oid not in paths: paths[oid] = repr(path)
    return ids, paths

def types_for(repo, ids, timeout):
    if not ids: return []
    p = git(repo, ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], inp=b"\n".join(ids)+b"\n", timeout=timeout)
    lines=p.stdout.splitlines()
    if len(lines) != len(ids): raise Failure("incomplete object type response")
    result=[]
    for asked, line in zip(ids, lines):
        parts=line.split()
        if len(parts) != 3 or parts[0] != asked or not OID_RE.fullmatch(parts[0]) or parts[1] not in (b"blob",b"tree",b"commit",b"tag") or not parts[2].isdigit():
            raise Failure("invalid object type response")
        result.append((asked, parts[1].decode()))
    return result

def matched(data, keys, heuristics): return [i+1 for i,k in enumerate(keys) if k in data], bool(heuristics and HINT_RE.search(data))
def scan_history(repo, keys, ns, emit):
    ids, paths = object_map(repo, ns.timeout); hits=hints=0; counts={}
    for oid, typ in types_for(repo, ids, ns.timeout):
        counts[typ]=counts.get(typ,0)+1
        if typ == "blob": data=git(repo,["cat-file","blob",oid.decode()],timeout=ns.timeout).stdout
        elif typ in ("commit","tag"):
            if not ns.scan_commit_messages: continue
            raw=git(repo,["cat-file",typ,oid.decode()],timeout=ns.timeout).stdout
            data=raw.partition(b"\n\n")[2]  # full commit body / annotated-tag message
        else: continue
        exact,hint=matched(data,keys,not ns.no_heuristics)
        loc="history %s %s" % (typ,oid.decode())
        if typ == "blob" and oid in paths: loc += " path=" + paths[oid]
        for n in exact: emit("HIT exact#%d %s"%(n,loc)); hits+=1
        if hint: emit("HINT "+loc); hints+=1
    emit("History objects: "+(", ".join("%s=%d"%x for x in sorted(counts.items())) if counts else "none"))
    return hits,hints

def scan_index(repo, keys, ns, emit):
    hits=hints=0
    raw=git(repo,["ls-files","--stage","-z"],timeout=ns.timeout).stdout
    for rec in raw.split(b"\0"):
        meta, sep, path=rec.partition(b"\t"); fields=meta.split()
        if not sep or len(fields)!=3 or not OID_RE.fullmatch(fields[1]) or fields[0] == b"160000": continue
        # all conflict stages are deliberately inspected; zero ids cannot be blobs.
        if set(fields[1]) == {48}: continue
        data=git(repo,["cat-file","blob",fields[1].decode()],timeout=ns.timeout).stdout
        exact,hint=matched(data,keys,not ns.no_heuristics); loc="index stage=%s path=%r"%(fields[2].decode(),path)
        for n in exact: emit("HIT exact#%d %s"%(n,loc));hits+=1
        if hint: emit("HINT "+loc);hints+=1
    return hits,hints

def scan_worktree(root, keys, ns, emit):
    hits=hints=skipped=0
    def badwalk(e): raise Failure("working tree walk failed") from e
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=badwalk):
        keep=[]
        for d in dirs:
            p=Path(base,d)
            try: is_nested=(p / ".git").exists()
            except OSError as e: raise Failure("working tree walk failed") from e
            if d == ".git" or is_nested: skipped+=1
            else: keep.append(d)
        dirs[:] = keep
        for name in files:
            p=Path(base,name)
            try: st=p.lstat()
            except OSError as e: raise Failure("working tree stat failed") from e
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode): skipped+=1; continue
            try:
                with open(p,"rb") as f: data=f.read()
            except OSError as e: raise Failure("working tree read failed") from e
            exact,hint=matched(data,keys,not ns.no_heuristics)
            # Binary-safe pathname label; content is never printed.
            loc="working path=%r" % (os.fsencode(p.relative_to(root)),)
            for n in exact: emit("HIT exact#%d %s"%(n,loc));hits+=1
            if hint: emit("HINT "+loc);hints+=1
    emit("Working entries skipped (symlink, nonregular, .git, nested repo): %d"%skipped)
    return hits,hints

def scan(repo, root, keys, ns, worktree):
    clean=redactor(keys); emit=lambda s: print(clean(s))
    h,q=scan_history(repo,keys,ns,emit)
    if worktree and root is not None:
        a,b=scan_index(repo,keys,ns,emit);h+=a;q+=b
        a,b=scan_worktree(root,keys,ns,emit);h+=a;q+=b
    emit("Summary: exact_hits=%d heuristic_hints=%d"%(h,q)); return h,q

def validate_purge(p):
    if not p or p.startswith("/") or ".." in Path(p).parts or any(c in p for c in "*?[]") or "\\" in p:
        raise Failure("invalid purge path")

def clone_mirror(source, out, timeout):
    command(["git","clone","--mirror","--no-local",source,str(out)],timeout=timeout)
def rewrite(source, source_root, source_git, keys, ns):
    if not keys and not ns.purge_path: raise Failure("rewrite needs a key or purge path")
    if not ns.confirm: raise Failure("rewrite requires --confirm")
    for x in ns.purge_path: validate_purge(x)
    if any(k in MARKER for k in keys): raise Failure("key occurs in replacement marker")
    out=Path(ns.output).expanduser().resolve()
    if out.exists(): raise Failure("rewrite output must not exist")
    if source_root and (out == source_root or source_root in out.parents or out == source_git or source_git in out.parents): raise Failure("rewrite output may not be inside source repository")
    with tempfile.TemporaryDirectory(prefix="key-cleaner-", dir=None) as td:
        os.chmod(td,0o700); secretfile=Path(td,"keys.json")
        secretfile.write_text(json.dumps([k.hex() for k in keys]),encoding="ascii"); os.chmod(secretfile,0o600)
        clone_mirror(source,out,ns.timeout)
        try:
            loader="import json; KEYS=[bytes.fromhex(x) for x in json.load(open(%r))]" % str(secretfile)
            blob=loader+"\nfor k in KEYS: blob.data=blob.data.replace(k,b'[REMOVED]')"
            msg=loader+"\nfor k in KEYS: message=message.replace(k,b'[REMOVED]')\nreturn message"
            if importlib.util.find_spec("git_filter_repo"):
                cmd=[sys.executable,"-m","git_filter_repo"]
            elif shutil.which("git-filter-repo"): cmd=["git-filter-repo"]
            else: raise Failure("git-filter-repo is required for rewrite")
            cmd += ["--force","--blob-callback",blob]
            if ns.scan_commit_messages: cmd += ["--message-callback",msg]
            for p in ns.purge_path: cmd += ["--path",p,"--invert-paths"]
            command(cmd,cwd=out,timeout=ns.timeout)
            h,_=scan(out,None,keys,ns,False)
            if h: raise Failure("post-rewrite verification found residual exact values")
            if ns.purge_path:
                commits = git(out,["rev-list","--all"],timeout=ns.timeout).stdout.splitlines()
                names=[]
                for commit in commits:
                    if not OID_RE.fullmatch(commit): raise Failure("invalid rewrite commit enumeration")
                    names.extend(git(out,["ls-tree","-r","--name-only",commit.decode()],timeout=ns.timeout).stdout.splitlines())
                for p in ns.purge_path:
                    b=p.encode()
                    if any(n==b or n.startswith(b+b"/") for n in names): raise Failure("post-rewrite purge verification failed")
        except Exception:
            # Retain output for forensic inspection, but never claim successful rewrite.
            raise
    print("Isolated rewritten mirror created and verified")

def main():
    p=argparse.ArgumentParser(description="Scan Git raw bytes for exact values; scan-only is default.")
    p.add_argument("--target",required=True,help="local repository or remote URL")
    p.add_argument("--exact-key",action="append",default=[]);p.add_argument("--key-file",action="append",default=[])
    mode=p.add_mutually_exclusive_group();mode.add_argument("--verify-only",action="store_true");mode.add_argument("--rewrite",action="store_true")
    p.add_argument("--output");p.add_argument("--confirm",action="store_true");p.add_argument("--purge-path",action="append",default=[])
    p.add_argument("--scan-commit-messages",action="store_true");p.add_argument("--no-heuristics",action="store_true");p.add_argument("--timeout",type=int,default=120)
    ns=p.parse_args()
    if ns.timeout<=0:p.error("--timeout must be positive")
    if (ns.output or ns.confirm or ns.purge_path) and not ns.rewrite:p.error("--output, --confirm, and --purge-path require --rewrite")
    if ns.rewrite and not ns.output:p.error("--output is required with --rewrite")
    try:
        keys=read_keys(ns); local=Path(ns.target).expanduser()
        if local.exists():
            local=local.resolve(); gd,root,bare=repo_info(local,ns.timeout)
            if ns.rewrite: rewrite(str(local),root,gd,keys,ns); return 0
            h,q=scan(local,root,keys,ns,not bare); return 1 if h or q else 0
        # Remote scans acquire only currently advertised refs, into a temporary isolated mirror.
        with tempfile.TemporaryDirectory(prefix="key-cleaner-") as td:
            mirror=Path(td,"mirror"); clone_mirror(ns.target,mirror,ns.timeout); gd,root,bare=repo_info(mirror,ns.timeout)
            if ns.rewrite: raise Failure("remote rewrite requires a local source")
            h,q=scan(mirror,None,keys,ns,False); return 1 if h or q else 0
    except Failure as e:
        # Deliberately generic: stderr must not expose target URLs, paths, keys, or command output.
        print("ERROR: "+redactor(locals().get("keys",[]))(e),file=sys.stderr); return 2
if __name__ == "__main__": sys.exit(main())
