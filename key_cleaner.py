#!/usr/bin/env python3
"""Audit exact byte values in Git and create a separately rewritten bare mirror.
The scanner deliberately does not print matching bytes.  It scans reachable objects, index
stages, and regular files in a non-bare work tree.  It does not scan reflogs, unreachable
objects, LFS payloads, submodules, or remote PR databases.
"""
import argparse, base64, hashlib, importlib.util, json, os, re, shutil, stat, subprocess, sys, tempfile
from collections import defaultdict
from pathlib import Path

MARKER=b"[REMOVED]"; OID=re.compile(rb"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
HINT=re.compile(rb"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*[^\s]{4,512}")
class Failure(Exception): pass

def cmd(a, cwd=None, inp=None, ok=(0,), timeout=180, interactive=False):
    env = os.environ.copy()
    env.update({
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "1" if interactive else "0",
    })
    try:
        p = subprocess.run(
            a, cwd=cwd, input=inp,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Failure("operation could not be completed") from e
    if p.returncode not in ok:
        raise Failure("git operation failed")
    return p

def git(r,*a,**kw): return cmd(["git","-C",str(r),*a],**kw)
def printable(b): return repr(bytes(b))
def refs(r, prefixes=None):
    """Return every ordinary ref by default, preserving non-ASCII names losslessly."""
    raw=git(r,"for-each-ref","--format=%(refname)%00%(objectname)").stdout; out={}
    for rec in raw.splitlines():
        x=rec.split(b"\0")
        if len(x)==2 and OID.fullmatch(x[1]) and (prefixes is None or any(x[0].startswith(q) for q in prefixes)):
            out[x[0].decode("utf8","surrogateescape")]=x[1].decode("ascii")
        else: raise Failure("local ref listing failed")
    return out
def all_refs(r):
    raw=git(r,"for-each-ref","--format=%(refname)%00%(objectname)").stdout; return [tuple(z.split(b"\0")) for z in raw.splitlines() if b"\0" in z]
def repo(r, timeout):
    gd=Path(git(r,"rev-parse","--absolute-git-dir",timeout=timeout).stdout.decode("utf8","surrogateescape").strip()).resolve()
    bare=git(r,"rev-parse","--is-bare-repository",timeout=timeout).stdout.strip()==b"true"
    if git(r,"rev-parse","--is-shallow-repository",timeout=timeout).stdout.strip()==b"true": raise Failure("refusing shallow repository")
    q=git(r,"config","--get-regexp",r"^(extensions\.partialclone|remote\..*\.promisor|core\.partialclonefilter)$",ok=(0,1),timeout=timeout)
    if q.returncode==0 and q.stdout.strip(): raise Failure("refusing partial clone")
    root=None if bare else Path(git(r,"rev-parse","--show-toplevel",timeout=timeout).stdout.decode("utf8","surrogateescape").strip()).resolve()
    return gd,root,bare
def read_keys(n):
    vals=[x.encode() for x in n.exact_key]
    try:
      for f in n.key_file:
       with open(f,"rb") as h: vals += [z.rstrip(b"\r\n") for z in h]
    except OSError as e: raise Failure("cannot read key file") from e
    ans=[]
    for x in vals:
      if not x: raise Failure("empty exact key is not allowed")
      if x not in ans: ans.append(x)
    return ans
def noleak(keys, text):
    # Only output controlled labels; this is a second defense for exception text.
    s=str(text)
    for k in keys:
      # repr's interior can appear in diagnostics even when the byte value cannot decode.
      escaped=repr(k)[2:-1]
      for q in (k.decode("utf8","surrogateescape"),k.hex(),repr(k),escaped):
       if q: s=s.replace(q,"[REDACTED]")
    return s
def occurrences(data, keys):
    # Regex lookahead gives every start, including overlaps, consistently for all scopes.
    rx=re.compile(b"(?="+b"|".join(re.escape(k) for k in sorted(keys,key=len,reverse=True))+b")") if keys else None
    out=defaultdict(list)
    if rx:
      for m in rx.finditer(data):
       pos=m.start()
       for i,k in enumerate(keys,1):
        if data.startswith(k,pos): out[i].append(pos)
    return out
def linecol(data, off): return (data.count(b"\n",0,off)+1, off-(data.rfind(b"\n",0,off)+1)+1)
def emit_occ(emit, scope, keynum, data, off, extra=""):
    ln,col=linecol(data,off); emit(f"HIT exact#{keynum} {scope}{extra} byte={off} line={ln} column={col}")
def object_ids(r, timeout):
    # rev-list covers commits/tags/trees; direct refs may name a blob, so explicitly add ref OIDs.
    raw=git(r,"rev-list","--objects","--all","--no-object-names",timeout=timeout).stdout
    ids={z for z in raw.splitlines() if OID.fullmatch(z)}
    ids.update(o for _,o in all_refs(r) if OID.fullmatch(o))
    return sorted(ids)
def batch_types(r, ids, timeout):
    if not ids:return []
    x=git(r,"cat-file","--batch-check=%(objectname) %(objecttype)",inp=b"\n".join(ids)+b"\n",timeout=timeout).stdout.splitlines()
    if len(x) != len(ids): raise Failure("object enumeration failed")
    out=[]
    for expected,z in zip(ids,x):
      q=z.split()
      if len(q)!=2 or q[0] != expected or not OID.fullmatch(q[0]) or q[1] not in (b"blob",b"commit",b"tree",b"tag"): raise Failure("object enumeration failed")
      out.append((q[0],q[1]))
    return out
def tree_paths(r, timeout):
    """Map every commit-tree pathname, not just one representative rev-list pathname."""
    mp=defaultdict(list)
    commits=git(r,"rev-list","--all",timeout=timeout).stdout.splitlines()
    for c in commits:
      raw=git(r,"ls-tree","-rz","--full-tree",c.decode(),timeout=timeout).stdout
      for z in raw.split(b"\0"):
       meta,sep,path=z.partition(b"\t"); f=meta.split()
       if sep and len(f)>=3 and f[1]==b"blob": mp[f[2]].append((c,path))
    return mp
def scan_history(r, keys, n, emit):
    paths=tree_paths(r,n.timeout); blobs={}; hist=0; objectonly=0; messages=0; hints=0; types=defaultdict(int)
    for oid,typ in batch_types(r,object_ids(r,n.timeout),n.timeout):
      types[typ.decode()]+=1
      if typ==b"blob":
       data=git(r,"cat-file","blob",oid.decode(),timeout=n.timeout).stdout; hit=occurrences(data,keys)
       if hit: blobs[oid]=hit
       if n.heuristics and HINT.search(data): hints+=1; emit("HINT blob="+oid.decode())
       for kn,oset in hit.items():
        if oid in paths:
         for c,p in paths[oid]:
          for off in oset: emit_occ(emit,"history",kn,data,off,f" commit={c.decode()} path={printable(p)} blob={oid.decode()}"); hist+=1
        else:
         for off in oset: emit_occ(emit,"object-only",kn,data,off,f" blob={oid.decode()}"); objectonly+=1
      elif typ in (b"commit",b"tag") and n.scan_commit_messages:
       raw=git(r,"cat-file",typ.decode(),oid.decode(),timeout=n.timeout).stdout; data=raw.partition(b"\n\n")[2]
       for kn,oset in occurrences(data,keys).items():
        for off in oset: emit_occ(emit,typ.decode()+"-message",kn,data,off,f" object={oid.decode()}"); messages+=1
       if n.heuristics and HINT.search(data): hints+=1; emit("HINT "+typ.decode()+"-message="+oid.decode())
    emit("History counts: unique_matching_blobs=%d unique_blob_occurrences=%d historical_occurrences=%d object_only_occurrences=%d message_occurrences=%d" % (len(blobs),sum(sum(len(v) for v in x.values()) for x in blobs.values()),hist,objectonly,messages))
    emit("History objects: "+", ".join(f"{k}={v}" for k,v in sorted(types.items())))
    return hist+objectonly+messages,hints
def scan_index(r,keys,n,emit):
    total=hints=0; raw=git(r,"ls-files","--stage","-z",timeout=n.timeout).stdout
    for z in raw.split(b"\0"):
      m,sep,p=z.partition(b"\t"); f=m.split()
      if not sep or len(f)!=3 or f[0]==b"160000" or not OID.fullmatch(f[1]) or f[1]==b"0"*len(f[1]):continue
      d=git(r,"cat-file","blob",f[1].decode(),timeout=n.timeout).stdout
      for kn,oset in occurrences(d,keys).items():
       for off in oset: emit_occ(emit,"index",kn,d,off,f" stage={f[2].decode()} path={printable(p)}"); total+=1
      if n.heuristics and HINT.search(d):hints+=1;emit("HINT index stage="+f[2].decode()+" path="+printable(p))
    emit("Index occurrences: %d"%total);return total,hints
def scan_work(root,keys,n,emit):
    total=hints=skip=0
    for base,dirs,files in os.walk(root,topdown=True,followlinks=False, onerror=lambda e: (_ for _ in ()).throw(Failure("working tree walk failed"))):
      keep=[]
      for d in dirs:
       p=Path(base,d)
       try: nested=(p/".git").exists() # detects .git file as well as directory
       except OSError as e: raise Failure("working tree walk failed") from e
       if d==".git" or p.is_symlink() or nested:skip+=1
       else:keep.append(d)
      dirs[:]=keep
      for name in files:
       if name == ".git": skip+=1; continue  # linked-worktree gitdir pointer
       p=Path(base,name)
       try:
        st=p.lstat()
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):skip+=1;continue
        flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0); fd=os.open(p,flags)
        with os.fdopen(fd,"rb") as f:d=f.read()
       except OSError as e: raise Failure("working tree read failed") from e
       for kn,oset in occurrences(d,keys).items():
        for off in oset:emit_occ(emit,"working",kn,d,off," path="+printable(os.fsencode(p.relative_to(root))));total+=1
       if n.heuristics and HINT.search(d):hints+=1;emit("HINT working path="+printable(os.fsencode(p.relative_to(root))))
    emit("Working occurrences: %d; skipped entries: %d"%(total,skip));return total,hints
def scan(r,root,keys,n,work=True):
    def e(s):print(noleak(keys,s))
    a,h=scan_history(r,keys,n,e)
    if work and root:
      b,q=scan_index(r,keys,n,e);c,z=scan_work(root,keys,n,e);a+=b+c;h+=q+z
    e("Summary: exact_occurrences=%d heuristic_hints=%d"%(a,h)); return a,h
def manifest_path(out):return Path(out,"key-cleaner-manifest.json")
def sha_mapping(d):return hashlib.sha256(json.dumps(d,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def validate_purge(p):
 if not p or p.startswith("/") or ".." in Path(p).parts or "\\" in p or any(x in p for x in "*?["):raise Failure("invalid purge path")
def rewrite(source,root,gd,keys,n):
 if not keys and not n.purge_path:raise Failure("rewrite needs keys or paths")
 if not n.confirm:raise Failure("rewrite requires --confirm")
 if any(k in MARKER for k in keys):raise Failure("key matches replacement marker")
 for p in n.purge_path:validate_purge(p)
 out=Path(n.output).expanduser().resolve()
 if out.exists():raise Failure("rewrite output must not exist")
 if out==gd or gd in out.parents or (root and (out==root or root in out.parents)):raise Failure("output cannot be inside source repository")
 original=refs(source)
 if not original:raise Failure("refusing repository without refs")
 with tempfile.TemporaryDirectory(prefix="key-cleaner-") as td:
  sf=Path(td,"keys.hex");sf.write_text("\n".join(k.hex() for k in keys));os.chmod(sf,0o600)
  cmd(["git","clone","--mirror","--no-local",str(source),str(out)],timeout=n.timeout)
  exe=[sys.executable,"-m","git_filter_repo"] if importlib.util.find_spec("git_filter_repo") else (["git-filter-repo"] if shutil.which("git-filter-repo") else None)
  if not exe:raise Failure("git-filter-repo is required for rewrite")
  pre="import re\nK=[bytes.fromhex(x.strip()) for x in open(%r) if x.strip()]\nR=re.compile(b'|'.join(re.escape(x) for x in sorted(K,key=len,reverse=True))) if K else None\n"%str(sf)
  blob=pre+"blob.data=R.sub(b'[REMOVED]',blob.data) if R else blob.data"
  msg=pre+"return R.sub(b'[REMOVED]',message) if R else message"
  a=exe+["--force","--prune-empty","never","--prune-degenerate","never","--blob-callback",blob]
  if n.scan_commit_messages:a += ["--message-callback",msg]
  for p in n.purge_path:a += ["--path",p,"--invert-paths"]
  cmd(a,cwd=out,timeout=n.timeout)
  got=refs(out)
  if set(got)!=set(original):raise Failure("rewrite lost or added a ref")
  # Scan exact bytes after rewrite. Purge verification uses NUL-safe ls-tree paths.
  hits,_=scan(out,None,keys,n,False)
  if hits:raise Failure("post-rewrite verification found exact value")
  for c in git(out,"rev-list","--all",timeout=n.timeout).stdout.splitlines():
   names=git(out,"ls-tree","-rz","--full-tree",c.decode(),timeout=n.timeout).stdout
   for z in names.split(b"\0"):
    _,_,p=z.partition(b"\t")
    for q in n.purge_path:
     b=q.encode();
     if p==b or p.startswith(b+b"/"):raise Failure("post-rewrite purge verification failed")
  m={"schema":2,"verified_complete":True,"original_refs":original,"resulting_refs":got,"cleaned_ref_mapping_sha256":sha_mapping(got)}
  manifest_path(out).write_text(json.dumps(m,indent=2,sort_keys=True)+"\n")
 print("Isolated rewritten bare mirror created and verified; no publication was performed")
def validate_ref_map(d):
 if not isinstance(d,dict) or not d: raise Failure("manifest ref map is invalid")
 for ref,oid in d.items():
  if not isinstance(ref,str) or not isinstance(oid,str) or not OID.fullmatch(oid.encode("ascii","ignore")): raise Failure("manifest ref map is invalid")
  cmd(["git","check-ref-format",ref])
def remote_refs(url,timeout):
 # Allow authentication for the pre-publication remote check.
 p=cmd(["git","ls-remote","--refs",url],timeout=timeout,interactive=True); d={}
 for z in p.stdout.splitlines():
  a=z.split(b"\t")
  if len(a)!=2 or not OID.fullmatch(a[0]) or not a[1].startswith(b"refs/"): raise Failure("remote ref listing failed")
  d[a[1].decode("utf8","surrogateescape")]=a[0].decode("ascii")
 return d
def publish(source,out,url,n):
 if n.exact_key or n.key_file:raise Failure("publish requires no keys")
 try:
  sgd,sroot,sbare=repo(source,n.timeout); ogd,oroot,obare=repo(out,n.timeout)
 except Failure: raise
 if not sbare or not obare: raise Failure("publication requires bare source and output mirrors")
 try:m=json.loads(manifest_path(out).read_text(encoding="utf8"))
 except (OSError,UnicodeError,json.JSONDecodeError) as e:raise Failure("valid manifest required") from e
 before=m.get("original_refs"); result=m.get("resulting_refs")
 if m.get("schema") != 2 or m.get("verified_complete") is not True: raise Failure("manifest is not a complete verified rewrite")
 validate_ref_map(before); validate_ref_map(result)
 if set(before) != set(result) or refs(source)!=before or refs(out)!=result or sha_mapping(result)!=m.get("cleaned_ref_mapping_sha256"):
  raise Failure("manifest or refs no longer match reviewed state")
 if remote_refs(url,n.timeout)!=before:raise Failure("remote refs differ from authoritative snapshot")
 opts=["--atomic"]
 specs=[]
 for ref,oid in sorted(before.items()):
  if ref.startswith(("refs/heads/","refs/tags/")):
   opts.append("--force-with-lease=%s:%s"%(ref,oid)); specs.append(ref+":"+ref)
 if not specs: raise Failure("no heads or tags available for publication")
 # Push explicit refs only; preserve leases and allow authentication.
 cmd(
     ["git", "-C", str(out), "push", "--no-mirror", *opts, url, *specs],
     timeout=n.timeout,
     interactive=True,
 )
 print("Published reviewed heads and tags only")
def main():
 p=argparse.ArgumentParser(description="Exact Git byte scanner; output never includes matching content.")
 p.add_argument("--target",help="local source repository (required except --publish)");p.add_argument("--exact-key",action="append",default=[]);p.add_argument("--key-file",action="append",default=[])
 p.add_argument("--scan-commit-messages",action="store_true",help="also inspect commit/tag bodies")
 p.add_argument("--no-heuristics",dest="heuristics",action="store_false",help="disable separate non-exact hints");p.set_defaults(heuristics=True)
 mode=p.add_mutually_exclusive_group();mode.add_argument("--rewrite",action="store_true");mode.add_argument("--verify-only",action="store_true");mode.add_argument("--publish",metavar="URL")
 p.add_argument("--output",help="new bare mirror for --rewrite");p.add_argument("--source",help="authoritative original bare snapshot for --publish");p.add_argument("--confirm",action="store_true");p.add_argument("--purge-path",action="append",default=[]);p.add_argument("--timeout",type=int,default=180)
 n=p.parse_args()
 if n.timeout<=0:p.error("timeout must be positive")
 if n.publish:
  if not(n.output and n.source and n.confirm):p.error("--publish needs --source, --output, and --confirm; use a fresh mirror snapshot of that URL")
  if n.target or n.purge_path:p.error("--publish is exclusive of --target and rewrite options")
 else:
  if not n.target:p.error("--target required")
  if (n.output or n.confirm or n.purge_path) and not n.rewrite:p.error("rewrite options require --rewrite")
  if n.rewrite and not n.output:p.error("--rewrite requires --output")
  if n.verify_only and n.source:p.error("--source is only for --publish")
 try:
  keys=read_keys(n)
  if n.publish: publish(Path(n.source).resolve(),Path(n.output).resolve(),n.publish,n);return 0
  target=Path(n.target).expanduser()
  if target.exists():
   gd,root,bare=repo(target.resolve(),n.timeout)
   if n.rewrite:rewrite(target.resolve(),root,gd,keys,n);return 0
   h,q=scan(target.resolve(),root,keys,n,not bare);return 1 if h or q else 0
  if n.rewrite:raise Failure("remote rewrite requires local snapshot")
  with tempfile.TemporaryDirectory(prefix="key-cleaner-") as td:
   mirror=Path(td,"mirror");cmd(["git","clone","--mirror","--no-local",n.target,str(mirror)],timeout=n.timeout);gd,root,b=repo(mirror,n.timeout);h,q=scan(mirror,None,keys,n,False);return 1 if h or q else 0
 except Failure as e:print("ERROR: "+noleak(locals().get("keys",[]),e),file=sys.stderr);return 2
 except (OSError,UnicodeError,json.JSONDecodeError):
  print("ERROR: operation could not be completed",file=sys.stderr);return 2
if __name__=="__main__":sys.exit(main())
