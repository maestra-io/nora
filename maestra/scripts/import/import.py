# /// script
# requires-python = ">=3.11"
# dependencies = ["requests", "twine"]
# ///
"""Push the artifacts listed by enumerate.py from artifactory.mindbox.ru into nora.

    ART_TOKEN=... NORA_TOKEN=nra_... uv run maestra/scripts/import/import.py \
        --manifest manifest.json --state state.jsonl [--dry-run] [--packages A,B] [--limit-packages 3]

ART_TOKEN: Artifactory read token (GET/HEAD only). NORA_TOKEN: a nora `write` token
(`POST /api/tokens` with the htpasswd admin) or a GitHub Actions OIDC JWT.

Idempotent and resumable: every finished artifact is appended to --state (JSON lines) and skipped
on the next run; nora's own 409 on an existing version counts as done (= `--skip-duplicate`).
Each artifact is verified against the source digest before it is pushed (NuGet: Artifactory
sha256; npm: dist.integrity sha512, else shasum; PyPI: the index sha256). Packages run in
parallel (--workers), the versions of one package run in version order.

Not preserved, because nora's APIs take no such input: NuGet `published` and the npm `time`
map are the import time (nora regenerates them). Preserved: bytes, NuGet listed flag (unlisted
versions are unlisted after the push), npm version documents incl. `deprecated`, all npm dist-tags.
"""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

from common import ART, NORA, Limiter, art_session, env

art = art_session()
pub = requests.Session()
nora = requests.Session()
art_lim, nora_lim = Limiter(8), Limiter(8)
lock = threading.Lock()
stats = Counter()
nbytes = Counter()


class Failed(Exception):
    pass


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(fmt, pkg, ver, status, size=0, secs=0.0, detail=""):
    with lock:
        stats[(fmt, status)] += 1
        if status in ("pushed", "verified"):
            nbytes[fmt] += size
        print(f"{now()} {fmt} {pkg} {ver} {status} {size}B {secs:.2f}s {detail}".rstrip(), flush=True)


def call(sess, limiter, method, url, tries=8, **kw):
    """HTTP with retries on transport errors, 429 and 5xx; returns the response for any other status."""
    for i in range(tries):
        limiter.wait()
        try:
            r = sess.request(method, url, timeout=600, **kw)
            if r.status_code not in (429, 500, 502, 503, 504):
                return r
            err = f"HTTP {r.status_code}"
        except requests.RequestException as e:
            err = type(e).__name__
        print(f"{now()} retry {i + 1}/{tries} {method} {url.split('?')[0]}: {err}", file=sys.stderr, flush=True)
        time.sleep(min(60, 2 ** i * 2))
    raise Failed(f"{method} {url.split('?')[0]}: {err} after {tries} tries")


def download(url, workdir):
    """Stream to a temp file; returns (path, size, sha1, sha256, sha512)."""
    sess, limiter = (art, art_lim) if url.startswith(ART) else (pub, Limiter(20))
    r = call(sess, limiter, "GET", url, stream=True)
    if r.status_code != 200:
        raise Failed(f"download HTTP {r.status_code}")
    hs = [hashlib.sha1(), hashlib.sha256(), hashlib.sha512()]
    fd, path = tempfile.mkstemp(dir=workdir)
    size = 0
    with os.fdopen(fd, "wb") as f:
        for chunk in r.iter_content(1 << 20):
            f.write(chunk)
            size += len(chunk)
            for h in hs:
                h.update(chunk)
    return path, size, hs[0].hexdigest(), hs[1].hexdigest(), hs[2].digest()


class State:
    def __init__(self, path):
        self.path, self.done = path, {}
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    rec = json.loads(line)
                    self.done[rec["key"]] = rec["status"]
        self.f = open(path, "a")

    def has(self, key, dry):
        return self.done.get(key) in (("verified", "pushed", "exists") if dry else ("pushed", "exists"))

    def put(self, key, status, **extra):
        with lock:
            self.done[key] = status
            self.f.write(json.dumps({"key": key, "status": status, "at": now(), **extra}) + "\n")
            self.f.flush()


def nuget_pkg(p, st, a):
    idl = p["id"].lower()
    for v in p["versions"]:
        ver, key = v["version"], f"nuget:{idl}/{v['version'].lower()}"
        t0 = time.monotonic()
        try:
            if not st.has(key, a.dry_run):
                path, size, _, sha256, _ = download(v["url"], a.workdir)
                try:
                    if v["sha256"] and sha256 != v["sha256"]:
                        raise Failed(f"sha256 mismatch {sha256} != {v['sha256']}")
                    if not zipfile.is_zipfile(path):
                        raise Failed("not a zip")
                    if a.dry_run:
                        status = "verified"
                    else:
                        # Bytes, not the file object: a retry must resend the whole package.
                        with open(path, "rb") as f:
                            pkg = f.read()
                        r = call(nora, nora_lim, "PUT", f"{NORA}/nuget/v3/package/",
                                 headers={"X-NuGet-ApiKey": a.token},
                                 files={"package": (f"{idl}.{ver}.nupkg", pkg, "application/octet-stream")})
                        if r.status_code not in (201, 202, 409):
                            raise Failed(f"push HTTP {r.status_code} {r.text[:200]}")
                        status = "exists" if r.status_code == 409 else "pushed"
                finally:
                    os.unlink(path)
                st.put(key, status, sha256=sha256, size=size, origin=v["origin"])
                log("nuget", p["id"], ver, status, size, time.monotonic() - t0, v["origin"])
            if not v["listed"] and not a.dry_run and not st.has(key + ":unlisted", False):
                r = call(nora, nora_lim, "DELETE", f"{NORA}/nuget/v3/package/{p['id']}/{ver}",
                         headers={"X-NuGet-ApiKey": a.token})
                if r.status_code not in (200, 204):
                    raise Failed(f"unlist HTTP {r.status_code} {r.text[:200]}")
                st.put(key + ":unlisted", "pushed")
                log("nuget", p["id"], ver, "unlisted")
        except (Failed, OSError) as e:
            st.put(key, "failed", reason=str(e))
            log("nuget", p["id"], ver, "failed", 0, time.monotonic() - t0, str(e))


def npm_pkg(p, st, a):
    name = p["name"]
    q = urllib.parse.quote(name, safe="@")
    r = call(art, art_lim, "GET", f"{ART}/api/npm/npm-local/{q}")
    if r.status_code != 200:
        log("npm", name, "-", "failed", detail=f"packument HTTP {r.status_code}")
        return
    doc = r.json()
    short = name.split("/")[-1]
    for v in p["versions"]:
        ver, key = v["version"], f"npm:{name}@{v['version']}"
        if st.has(key, a.dry_run):
            continue
        t0 = time.monotonic()
        try:
            path, size, sha1, _, sha512 = download(v["url"], a.workdir)
            try:
                integ = v.get("integrity") or ""
                if integ.startswith("sha512-") and base64.b64decode(integ[7:]) != sha512:
                    raise Failed("integrity (sha512) mismatch")
                if not integ.startswith("sha512-") and v.get("shasum") and v["shasum"] != sha1:
                    raise Failed("shasum mismatch")
                if a.dry_run:
                    status = "verified"
                else:
                    with open(path, "rb") as f:
                        data = base64.b64encode(f.read()).decode()
                    body = {k: doc[k] for k in ("_id", "name", "description", "readme", "license") if k in doc}
                    body.update({"name": name, "dist-tags": {}, "versions": {ver: doc["versions"][ver]},
                                 "_attachments": {f"{name}-{ver}.tgz": {"content_type": "application/octet-stream",
                                                                        "data": data, "length": size}}})
                    r = call(nora, nora_lim, "PUT", f"{NORA}/npm/{q}", json=body,
                             headers={"Authorization": f"Bearer {a.token}"})
                    if r.status_code not in (200, 201, 409):
                        raise Failed(f"publish HTTP {r.status_code} {r.text[:200]}")
                    status = "exists" if r.status_code == 409 else "pushed"
            finally:
                os.unlink(path)
            st.put(key, status, size=size)
            log("npm", name, ver, status, size, time.monotonic() - t0, short)
        except (Failed, OSError) as e:
            st.put(key, "failed", reason=str(e))
            log("npm", name, ver, "failed", 0, time.monotonic() - t0, str(e))
    if a.dry_run:
        return
    imported = {v["version"] for v in p["versions"] if st.done.get(f"npm:{name}@{v['version']}") in ("pushed", "exists")}
    for tag, ver in doc.get("dist-tags", {}).items():
        if ver not in imported:
            log("npm", name, ver, "tag-skipped", detail=f"dist-tag {tag}: version not imported")
            continue
        r = call(nora, nora_lim, "PUT", f"{NORA}/npm/-/package/{q}/dist-tags/{urllib.parse.quote(tag)}",
                 json=ver, headers={"Authorization": f"Bearer {a.token}"})
        log("npm", name, ver, "tagged" if r.status_code in (200, 201, 204) else "tag-failed", detail=f"{tag} HTTP {r.status_code}")


def pypi_pkg(p, st, a):
    for v in p["files"]:
        key = f"pypi:{p['name']}/{v['filename']}"
        if st.has(key, a.dry_run):
            continue
        t0 = time.monotonic()
        try:
            path, size, _, sha256, _ = download(v["url"], a.workdir)
            try:
                if v["sha256"] and sha256 != v["sha256"]:
                    raise Failed("sha256 mismatch")
                final = os.path.join(os.path.dirname(path), v["filename"])  # twine reads metadata from the name
                os.rename(path, final)
                path = final
                if a.dry_run:
                    status = "verified"
                else:
                    envv = {**os.environ, "TWINE_USERNAME": "__token__", "TWINE_PASSWORD": a.token}
                    out = subprocess.run([sys.executable, "-m", "twine", "upload", "--non-interactive", "--skip-existing",
                                          "--repository-url", f"{NORA}/simple/", path], env=envv, capture_output=True, text=True)
                    if out.returncode:
                        raise Failed(f"twine: {(out.stdout + out.stderr)[-300:]}")
                    status = "pushed"
            finally:
                os.unlink(path)
            st.put(key, status, size=size)
            log("pypi", p["name"], v["filename"], status, size, time.monotonic() - t0)
        except (Failed, OSError) as e:
            st.put(key, "failed", reason=str(e))
            log("pypi", p["name"], v["filename"], "failed", 0, time.monotonic() - t0, str(e))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--workdir", default=None, help="temp dir for downloads (default: a fresh tempdir)")
    ap.add_argument("--formats", default="nuget,npm,pypi")
    ap.add_argument("--packages", default="", help="comma-separated IDs/names to restrict to")
    ap.add_argument("--limit-packages", type=int, default=0, help="first N packages per format (pilot)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--rps", type=float, default=8, help="max requests/s to each of Artifactory and nora")
    ap.add_argument("--dry-run", action="store_true", help="download and verify only, push nothing")
    a = ap.parse_args()
    a.token = "" if a.dry_run else env("NORA_TOKEN")
    a.workdir = a.workdir or tempfile.mkdtemp(prefix="nora-import-")
    art_lim.gap = nora_lim.gap = 1.0 / a.rps
    m = json.load(open(a.manifest))
    st = State(a.state)
    only = {x.strip().lower() for x in a.packages.split(",") if x.strip()}
    jobs = []
    for fmt, fn, key, items in (("nuget", nuget_pkg, "id", m["nuget"]), ("npm", npm_pkg, "name", m["npm"]),
                                ("pypi", pypi_pkg, "name", m["pypi"])):
        if fmt not in a.formats.split(","):
            continue
        sel = [p for p in items if not only or p[key].lower() in only]
        if fmt == "pypi":
            for p in sel:
                if p.get("status") != 200:
                    log("pypi", p["name"], "-", "source-unavailable", detail=f"index HTTP {p.get('status')}")
        sel = sel[: a.limit_packages] if a.limit_packages else sel
        jobs += [(fn, p) for p in sel]
    # Biggest packages first, so the longest sequential chain starts at once.
    jobs.sort(key=lambda j: -len(j[1].get("versions") or j[1].get("files") or []))
    t0 = time.monotonic()
    print(f"{now()} start: {len(jobs)} packages, workers={a.workers}, rps={a.rps}, dry_run={a.dry_run}", flush=True)
    with ThreadPoolExecutor(a.workers) as ex:
        for f in [ex.submit(fn, p, st, a) for fn, p in jobs]:
            f.result()
    summary = {"finished_at": now(), "duration_s": round(time.monotonic() - t0),
               "counts": {f"{k[0]}:{k[1]}": n for k, n in sorted(stats.items())}, "bytes": dict(nbytes)}
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
