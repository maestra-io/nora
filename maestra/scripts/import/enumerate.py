# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""Enumerate the internal NuGet / npm / PyPI packages on artifactory.mindbox.ru into a manifest.

Read-only: GET/HEAD only, with the CI read token (Vault maestra
github/shared/artifactory/PRIVATE_PACKAGES_TOKEN, field `value`) in ART_TOKEN.

    ART_TOKEN=... uv run maestra/scripts/import/enumerate.py --out manifest.json

NuGet: every `Mindbox.*` / strays `.nupkg` in `nuget-local` (versions and the listed flag from the
local registration). For an ID that is also on nuget.org, its nuget.org-only versions are added
with origin `nuget.org` and fetched from nuget.org itself: once the ID is hosted in nora, nora
stops proxying it upstream, so they must be imported too to stay resolvable.
npm: every `@mindbox-cloud/*` package in `npm-local` (packument from the local repo).
PyPI: the four internal names from the `pypi` virtual repo's simple index.

nuget.org only (no ART_TOKEN): the public `Mindbox.*` IDs listed in a file, every version from the
nuget.org registration with its catalog `packageHash` (sha512), origin `nuget.org`. With
--missing-only (NORA_TOKEN, read is enough) only versions nora does not host yet: the daily sync
(.github/workflows/maestra-sync-public-ids.yml), since nora never proxies an ID it hosts.

    uv run maestra/scripts/import/enumerate.py --nuget-org-ids maestra/scripts/import/public-ids.txt \
        [--missing-only] --out manifest.json
"""
import argparse
import html.parser
import json
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

from common import ART, NORA, NPM_SCOPE, NUGET_ID, PYPI_NAMES, Limiter, art_session, env, is_pr_prerelease, split_nupkg, version_key

lim = Limiter(8)
art = art_session()
pub = requests.Session()


def get(s, url, **kw):
    if s is art:
        lim.wait()
    r = s.get(url, timeout=120, **kw)
    return r


def head_meta(s, url):
    if s is art:
        lim.wait()
    r = s.head(url, timeout=60, allow_redirects=True)
    r.raise_for_status()
    return int(r.headers.get("content-length", 0)), r.headers.get("x-checksum-sha256")


def storage_list(repo):
    r = get(art, f"{ART}/api/storage/{repo}?list&deep=1&listFolders=0")
    r.raise_for_status()
    return r.json()["files"]


def registration(base, idl):
    r = get(art if base.startswith(ART) else pub, f"{base}/{idl}/index.json")
    if r.status_code == 404:
        return []
    r.raise_for_status()
    out = []
    for page in r.json()["items"]:
        items = page.get("items")
        if items is None:
            p = get(art if base.startswith(ART) else pub, page["@id"])
            p.raise_for_status()
            items = p.json()["items"]
        for it in items:
            ce = it["catalogEntry"]
            out.append({"version": ce["version"], "listed": ce.get("listed", True), "url": it["packageContent"],
                        "leaf": ce.get("@id")})
    return out


def nuget(files):
    by_file, ids = {}, {}
    for f in files:
        name = f["uri"].lstrip("/")
        parts = split_nupkg(name) if "/" not in name else None
        if parts and NUGET_ID.match(parts[0]):
            by_file[name.lower()] = f
            ids.setdefault(parts[0].lower(), parts[0])
    print(f"nuget-local: {len(by_file)} in-scope files, {len(ids)} candidate IDs", file=sys.stderr)

    def one(idl):
        local = registration(f"{ART}/api/nuget/v3/nuget-local/registration-semver2", idl)
        pkg_id, versions, seen = ids[idl], [], set()
        for e in local:
            f = by_file.pop(f"{idl}.{e['version'].lower()}.nupkg", None)
            size, sha = (f["size"], f["sha2"]) if f else head_meta(art, e["url"])
            versions.append({**e, "size": size, "sha256": sha, "origin": "artifactory"})
            seen.add(e["version"].lower())
        upstream = registration("https://api.nuget.org/v3/registration5-gz-semver2", idl)
        for e in upstream:
            if e["version"].lower() not in seen:
                size, _ = head_meta(pub, e["url"])
                versions.append({**e, "size": size, "sha256": None, "origin": "nuget.org"})
        versions.sort(key=lambda v: version_key(v["version"]))
        return {"id": pkg_id, "on_nuget_org": bool(upstream), "versions": versions}

    with ThreadPoolExecutor(8) as ex:
        pkgs = [p for p in ex.map(one, sorted(ids)) if p["versions"]]
    # by_file now holds files no registration entry claimed (odd file names): import them as-is.
    stray = [{"file": k, "size": f["size"], "sha256": f["sha2"]} for k, f in by_file.items()]
    return pkgs, stray


NUGET_ORG_REG = "https://api.nuget.org/v3/registration5-gz-semver2"


def nuget_org(ids, missing_only):
    """Versions of public IDs from nuget.org, verified later against the catalog leaf's packageHash."""
    auth = {"Authorization": "Bearer " + env("NORA_TOKEN")} if missing_only else {}

    def one(pkg_id):
        idl, have = pkg_id.lower(), set()
        if missing_only:
            r = pub.get(f"{NORA}/nuget/v3/flatcontainer/{idl}/index.json", headers=auth, timeout=120)
            if r.status_code != 404:
                r.raise_for_status()
                have = {v.lower() for v in r.json()["versions"]}
        versions = []
        for e in registration(NUGET_ORG_REG, idl):
            if e["version"].split("+", 1)[0].lower() in have:
                continue
            leaf = get(pub, e["leaf"])
            leaf.raise_for_status()
            leaf = leaf.json()
            if leaf.get("packageHashAlgorithm", "").upper() != "SHA512":
                sys.exit(f"{pkg_id} {e['version']}: unexpected packageHashAlgorithm {leaf.get('packageHashAlgorithm')}")
            versions.append({**e, "size": leaf["packageSize"], "sha256": None, "sha512": leaf["packageHash"],
                             "origin": "nuget.org"})
        versions.sort(key=lambda v: version_key(v["version"]))
        return {"id": pkg_id, "on_nuget_org": True, "versions": versions}

    with ThreadPoolExecutor(8) as ex:
        return list(ex.map(one, ids))


def npm(files):
    sizes, names = {}, set()
    for f in files:
        p = f["uri"].lstrip("/")
        if p.startswith(NPM_SCOPE) and p.endswith(".tgz"):
            sizes[p] = f["size"]
            names.add(NPM_SCOPE + p.split("/")[1])

    def one(name):
        r = get(art, f"{ART}/api/npm/npm-local/{urllib.parse.quote(name, safe='@')}")
        r.raise_for_status()
        doc = r.json()
        versions = []
        for ver, vd in doc.get("versions", {}).items():
            url = vd["dist"]["tarball"]
            path = urllib.parse.unquote(url.split("/api/npm/npm-local/", 1)[-1])
            size = sizes.get(path) or head_meta(art, url)[0]
            versions.append({"version": ver, "url": url, "size": size,
                             "integrity": vd["dist"].get("integrity"), "shasum": vd["dist"].get("shasum")})
        versions.sort(key=lambda v: version_key(v["version"]))
        pubr = pub.get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}", timeout=60)
        return {"name": name, "dist_tags": doc.get("dist-tags", {}), "time": doc.get("time", {}),
                "npmjs_versions": len(pubr.json().get("versions", {})) if pubr.ok else 0, "versions": versions}

    with ThreadPoolExecutor(8) as ex:
        return list(ex.map(one, sorted(names)))


class Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href = [], None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")

    def handle_data(self, data):
        if self._href:
            self.links.append((data.strip(), self._href))
            self._href = None


def pypi():
    out = []
    for name in PYPI_NAMES:
        base = f"{ART}/api/pypi/pypi/simple/{name}/"
        r = get(art, base)
        entry = {"name": name, "status": r.status_code, "files": []}
        if r.ok:
            p = Links()
            p.feed(r.text)
            for fn, href in p.links:
                url, _, frag = urllib.parse.urljoin(base, href).partition("#")
                size, _ = head_meta(art, url)
                entry["files"].append({"filename": fn, "url": url, "size": size,
                                       "sha256": frag.split("=", 1)[1] if frag.startswith("sha256=") else None})
        else:
            entry["error"] = r.text[:300]
        out.append(entry)
    return out


def totals(items, key):
    vs = [v for p in items for v in p[key]]
    pr = [v for v in vs if is_pr_prerelease(v.get("version") or v.get("filename", ""))]
    return {"packages": len(items), "artifacts": len(vs), "bytes": sum(v["size"] for v in vs),
            "gb": round(sum(v["size"] for v in vs) / 1e9, 2), "pr_dev_prerelease": len(pr),
            "pr_dev_bytes": sum(v["size"] for v in pr)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--nuget-org-ids", help="file of public NuGet IDs (one per line, # comments): nuget.org only")
    ap.add_argument("--missing-only", action="store_true", help="with --nuget-org-ids: skip versions nora hosts")
    args = ap.parse_args()
    started = datetime.now(timezone.utc)
    if args.nuget_org_ids:
        with open(args.nuget_org_ids) as f:
            ids = [ln.split("#", 1)[0].strip() for ln in f]
        pkgs = nuget_org([i for i in ids if i], args.missing_only)
        t = {"nuget": totals(pkgs, "versions")}
        manifest = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": "https://api.nuget.org",
                    "totals": t, "nuget": pkgs, "npm": [], "pypi": []}
        with open(args.out, "w") as f:
            json.dump(manifest, f, indent=1)
        print(json.dumps({"generated_at": manifest["generated_at"], "totals": t,
                          "missing": {p["id"]: len(p["versions"]) for p in pkgs if p["versions"]}}, indent=1))
        return
    nuget_pkgs, nuget_stray = nuget(storage_list("nuget-local"))
    npm_pkgs = npm(storage_list("npm-local"))
    pypi_pkgs = pypi()
    t = {"nuget": totals(nuget_pkgs, "versions"), "npm": totals(npm_pkgs, "versions"), "pypi": totals(pypi_pkgs, "files")}
    t["nuget"]["from_nuget_org"] = sum(1 for p in nuget_pkgs for v in p["versions"] if v["origin"] == "nuget.org")
    t["nuget"]["unlisted"] = sum(1 for p in nuget_pkgs for v in p["versions"] if not v["listed"])
    t["nuget"]["unmatched_files"] = len(nuget_stray)
    manifest = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": ART, "totals": t,
                "nuget": nuget_pkgs, "nuget_unmatched_files": nuget_stray, "npm": npm_pkgs, "pypi": pypi_pkgs}
    with open(args.out, "w") as f:
        json.dump(manifest, f, indent=1)
    print(json.dumps({"generated_at": manifest["generated_at"], "totals": t}, indent=1))


if __name__ == "__main__":
    main()
