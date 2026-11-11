"""Run: uv run --with requests python maestra/scripts/import/test_import.py

What import.py decides around each write to the registry: what is already done and skipped, what
is refused before the push, and which dist-tags move. Every HTTP call is answered from a table
(fakes.Http) and the download is a local file; nothing is sent.
"""
import base64
import hashlib
import importlib
import io
import json
import os
import tempfile
import types
import zipfile
from unittest import mock

from fakes import Http, Response

imp = importlib.import_module("import")
imp.art_lim.wait = imp.nora_lim.wait = lambda: None
NUPKG_PUT = f"{imp.NORA}/nuget/v3/package/"


def nupkg():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.nuspec", "<package/>")
    return buf.getvalue()


class Run:
    """One import run in a temp dir: a state file, the bytes every download answers, nora's answers."""

    def __init__(self, routes, body=None, dry_run=False):
        self.dir = tempfile.TemporaryDirectory()
        self.state_path = os.path.join(self.dir.name, "state.jsonl")
        self.body = nupkg() if body is None else body
        self.nora, self.downloads = Http(routes), []
        self.args = types.SimpleNamespace(dry_run=dry_run, workdir=self.dir.name, token="test-token")

    def download(self, url, workdir):
        self.downloads.append(url)
        fd, path = tempfile.mkstemp(dir=workdir)
        with os.fdopen(fd, "wb") as f:
            f.write(self.body)
        h = [hashlib.new(n, self.body) for n in ("sha1", "sha256", "sha512")]
        return path, len(self.body), h[0].hexdigest(), h[1].hexdigest(), h[2].digest()

    def go(self, fn, pkg, dry_run=None):
        if dry_run is not None:
            self.args.dry_run = dry_run
        st = imp.State(self.state_path)
        with mock.patch.multiple(imp, nora=self.nora, art=self.nora, download=self.download), \
                mock.patch("builtins.print"):
            fn(pkg, st, self.args)
        st.f.close()
        return st.done

    def leftovers(self):
        return [f for f in os.listdir(self.dir.name) if f != "state.jsonl"]


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def nuget_version(ver, body, listed=True, **extra):
    return {"version": ver, "url": f"src/{ver}", "sha256": sha256(body), "listed": listed, "origin": "nuget.org", **extra}


def test_state_resumes_and_counts_only_a_push_as_done():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "state.jsonl")
        st = imp.State(path)
        for key, status in (("a", "pushed"), ("b", "exists"), ("c", "verified"), ("d", "failed"), ("e", "failed")):
            st.put(key, status)
        st.put("e", "pushed")  # a retry that went through: the last record wins
        st.f.close()
        st = imp.State(path)
        assert st.done == {"a": "pushed", "b": "exists", "c": "verified", "d": "failed", "e": "pushed"}
        assert [k for k in "abcdez" if st.has(k, dry=False)] == ["a", "b", "e"]
        assert [k for k in "abcdez" if st.has(k, dry=True)] == ["a", "b", "c", "e"]
        st.f.close()


def test_call_retries_a_busy_server_and_gives_up_after_its_tries():
    busy = lambda: Response(503)  # noqa: E731
    http = Http({"u": [busy(), Response(429), Response(404)]})
    with mock.patch.object(imp.time, "sleep") as slept, mock.patch("builtins.print"):
        assert imp.call(http, imp.nora_lim, "GET", "u").status_code == 404
        assert [c.args[0] for c in slept.call_args_list] == [2, 4]
        http = Http({"u?token=x": [busy(), busy(), busy()]})
        try:
            imp.call(http, imp.nora_lim, "GET", "u?token=x", tries=3)
        except imp.Failed as e:
            assert str(e) == "GET u: HTTP 503 after 3 tries"
        else:
            raise AssertionError("a server that stays busy is not a success")


def test_a_pushed_version_is_not_pushed_again():
    run = Run({("PUT", NUPKG_PUT): [Response(201), Response(409)]})
    pkg = {"id": "Mindbox.A", "versions": [nuget_version("1.0.0", run.body), nuget_version("1.1.0-RC", run.body)]}
    done = run.go(imp.nuget_pkg, pkg)
    # nora's 409 on a version it already holds is done, not a failure.
    assert done == {"nuget:mindbox.a/1.0.0": "pushed", "nuget:mindbox.a/1.1.0-rc": "exists"}
    assert run.downloads == ["src/1.0.0", "src/1.1.0-RC"] and len(run.nora.sent("PUT")) == 2
    assert run.go(imp.nuget_pkg, pkg) == done
    assert len(run.downloads) == 2 and len(run.nora.sent("PUT")) == 2, "the second run pushed again"
    assert run.leftovers() == []


def test_a_package_that_differs_from_its_source_digest_is_not_pushed():
    good = nupkg()
    wrong512 = base64.b64encode(hashlib.sha512(b"other").digest()).decode()
    right512 = base64.b64encode(hashlib.sha512(good).digest()).decode()
    cases = [("sha256 mismatch", good, {"sha256": sha256(b"other")}),
             ("sha512 mismatch", good, {"sha256": None, "sha512": wrong512}),
             ("not a zip", b"<html>", {"sha256": sha256(b"<html>")})]
    for reason, body, fields in cases:
        run = Run({}, body=body)  # no route: a push would fail the test
        version = {**nuget_version("1.0.0", body), **fields}
        done = run.go(imp.nuget_pkg, {"id": "Mindbox.A", "versions": [version]})
        assert done == {"nuget:mindbox.a/1.0.0": "failed"}, reason
        with open(run.state_path) as f:
            assert reason in json.loads(f.readline())["reason"], reason
        assert run.leftovers() == [], reason
    run = Run({("PUT", NUPKG_PUT): Response(201)})
    version = nuget_version("1.0.0", good, sha256=None, sha512=right512)
    assert run.go(imp.nuget_pkg, {"id": "Mindbox.A", "versions": [version]}) == {"nuget:mindbox.a/1.0.0": "pushed"}


def test_a_failed_version_is_tried_again_and_the_others_still_go():
    run = Run({("PUT", NUPKG_PUT): [Response(403, text="denied"), Response(201), Response(201)]})
    pkg = {"id": "Mindbox.A", "versions": [nuget_version("1.0.0", run.body), nuget_version("2.0.0", run.body)]}
    assert run.go(imp.nuget_pkg, pkg) == {"nuget:mindbox.a/1.0.0": "failed", "nuget:mindbox.a/2.0.0": "pushed"}
    assert run.go(imp.nuget_pkg, pkg) == {"nuget:mindbox.a/1.0.0": "pushed", "nuget:mindbox.a/2.0.0": "pushed"}
    assert run.downloads == ["src/1.0.0", "src/2.0.0", "src/1.0.0"]


def test_a_dry_run_pushes_nothing_and_does_not_count_as_pushed():
    run = Run({("PUT", NUPKG_PUT): Response(201), ("DELETE", f"{NUPKG_PUT}Mindbox.A/1.0.0"): Response(204)}, dry_run=True)
    pkg = {"id": "Mindbox.A", "versions": [nuget_version("1.0.0", run.body, listed=False)]}
    assert run.go(imp.nuget_pkg, pkg) == {"nuget:mindbox.a/1.0.0": "verified"}
    assert run.nora.calls == []
    assert run.go(imp.nuget_pkg, pkg) == {"nuget:mindbox.a/1.0.0": "verified"}
    assert len(run.downloads) == 1, "a verified version was downloaded again by the next dry run"
    done = run.go(imp.nuget_pkg, pkg, dry_run=False)
    assert done == {"nuget:mindbox.a/1.0.0": "pushed", "nuget:mindbox.a/1.0.0:unlisted": "pushed"}


def test_an_unlisted_version_is_unlisted_once():
    unlist = ("DELETE", f"{NUPKG_PUT}Mindbox.A/1.0.0")
    run = Run({("PUT", NUPKG_PUT): Response(409), unlist: [Response(500), Response(500), Response(204)]})
    pkg = {"id": "Mindbox.A", "versions": [nuget_version("1.0.0", run.body, listed=False)]}
    with mock.patch.object(imp.time, "sleep"):
        done = run.go(imp.nuget_pkg, pkg)
        assert done == {"nuget:mindbox.a/1.0.0": "exists", "nuget:mindbox.a/1.0.0:unlisted": "pushed"}
        assert run.go(imp.nuget_pkg, pkg) == done
    assert len(run.nora.sent("DELETE")) == 3 and len(run.nora.sent("PUT")) == 1


def npm_run(nora_tags, source_tags, versions=("1.0.0", "2.0.0"), put=201, nora_packument=200):
    name, q = "@mindbox-cloud/a", "@mindbox-cloud%2Fa"
    body = b"tarball"
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode()
    doc = {"name": name, "dist-tags": source_tags, "versions": {v: {"version": v} for v in versions}}
    routes = {("GET", f"{imp.ART}/api/npm/npm-local/{q}"): Response(body=doc),
              ("PUT", f"{imp.NORA}/npm/{q}"): Response(put),
              ("GET", f"{imp.NORA}/npm/{q}"): Response(nora_packument, body={"dist-tags": nora_tags})}
    for tag in source_tags:
        routes[("PUT", f"{imp.NORA}/npm/-/package/{q}/dist-tags/{tag}")] = Response(200)
    run = Run(routes, body=body)
    pkg = {"name": name, "versions": [{"version": v, "url": f"src/{v}", "integrity": integrity} for v in versions]}
    return run, pkg, f"{imp.NORA}/npm/-/package/{q}/dist-tags/"


def tags_set(run, base):
    return {url[len(base):]: kw["json"] for m, url, kw in run.nora.calls if m == "PUT" and url.startswith(base)}


def test_a_dist_tag_moves_forward_and_never_back():
    source = {"latest": "2.0.0", "next": "2.0.0", "old": "1.0.0", "gone": "0.9.0", "same": "2.0.0"}
    nora = {"latest": "3.0.0", "old": "1.0.0-rc.1", "same": "2.0.0"}
    run, pkg, base = npm_run(nora, source)
    run.go(imp.npm_pkg, pkg)
    # latest: nora is ahead; same: equal; gone: its version is not in this import.
    assert tags_set(run, base) == {"next": "2.0.0", "old": "1.0.0"}


def test_tags_follow_versions_nora_already_had_and_wait_for_failed_ones():
    run, pkg, base = npm_run({}, {"latest": "2.0.0"}, put=409)
    assert run.go(imp.npm_pkg, pkg)["npm:@mindbox-cloud/a@2.0.0"] == "exists"
    assert tags_set(run, base) == {"latest": "2.0.0"}
    run, pkg, base = npm_run({}, {"latest": "2.0.0"}, put=403)
    assert run.go(imp.npm_pkg, pkg)["npm:@mindbox-cloud/a@2.0.0"] == "failed"
    assert tags_set(run, base) == {}


def test_tags_stay_when_nora_does_not_answer_its_packument_and_the_run_is_marked_failed():
    run, pkg, base = npm_run({}, {"latest": "2.0.0"}, nora_packument=404)
    done = run.go(imp.npm_pkg, pkg)
    assert done["npm-tags:@mindbox-cloud/a"] == "failed" and tags_set(run, base) == {}


def test_npm_integrity_is_checked_before_the_publish():
    run, pkg, _ = npm_run({}, {})
    pkg["versions"][0]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(b"other").digest()).decode()
    pkg["versions"][1].update(integrity=None, shasum="00")
    done = run.go(imp.npm_pkg, pkg)
    assert done == {"npm:@mindbox-cloud/a@1.0.0": "failed", "npm:@mindbox-cloud/a@2.0.0": "failed"}
    assert run.nora.sent("PUT") == [] and run.leftovers() == []


def test_artifactory_is_read_only():
    s = imp.art
    for method in ("PUT", "POST", "DELETE", "PATCH"):
        try:
            s.request(method, "http://127.0.0.1:9/never-sent")
        except RuntimeError as e:
            assert str(e) == f"refusing {method} to Artifactory"
        else:
            raise AssertionError(f"{method} to Artifactory was not refused")


for name, test in sorted(globals().items()):
    if name.startswith("test_"):
        test()
print("ok")
