"""Run: uv run --with requests python maestra/scripts/import/test_enumerate.py

What the daily sync (maestra-sync-public-ids.yml) decides before it writes to the registry: which
versions are missing, in which order they go, and what stops the run. Every HTTP call is answered
from a table (fakes.Http); nothing is sent.
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest import mock

import enumerate as en
from fakes import Http, Response

REG = en.NUGET_ORG_REG
os.environ["NORA_TOKEN"] = "test-token"
en.lim.wait = lambda: None


def raises_exit(fn):
    try:
        fn()
    except SystemExit as e:
        return str(e.code)
    return None


def entry(ver, listed=True):
    return {"catalogEntry": {"version": ver, "listed": listed, "@id": f"leaf/{ver}"}, "packageContent": f"pkg/{ver}"}


def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).isoformat()


OLD = ago(days=10)


def leaf(size=10, algo="SHA512", **dates):
    """A catalog leaf; released 10 days ago unless `created` / `published` are given (None drops the field)."""
    dates = {k: v for k, v in (dates or {"created": OLD}).items() if v is not None}
    return Response(body={"packageSize": size, "packageHash": "aGFzaA==", "packageHashAlgorithm": algo, **dates})


def reg(*entries):
    return Response(body={"items": [{"items": list(entries)}]})


def with_http(routes):
    http = Http(routes)
    return http, mock.patch.multiple(en, pub=http, art=http)


def test_registration_reads_inline_and_linked_pages():
    index = {"items": [{"items": [entry("1.0.0"), entry("1.1.0", listed=False)]}, {"@id": "page/2"}]}
    http, patched = with_http({f"{REG}/mindbox.a/index.json": Response(body=index),
                               "page/2": Response(body={"items": [entry("2.0.0")]}),
                               f"{REG}/mindbox.none/index.json": Response(404)})
    with patched:
        got = en.registration(REG, "mindbox.a")
        assert en.registration(REG, "mindbox.none") == []
    assert [(e["version"], e["listed"], e["url"], e["leaf"]) for e in got] == [
        ("1.0.0", True, "pkg/1.0.0", "leaf/1.0.0"), ("1.1.0", False, "pkg/1.1.0", "leaf/1.1.0"),
        ("2.0.0", True, "pkg/2.0.0", "leaf/2.0.0")]


def test_missing_only_keeps_what_nora_does_not_host_in_version_order():
    upstream = ["10.0.0", "1.0.0", "2.0.0-beta+build.7", "9.0.0", "2.0.0"]
    routes = {f"{REG}/mindbox.a/index.json": Response(body={"items": [{"items": [entry(v) for v in upstream]}]}),
              # nora answers without build metadata and in its own case.
              f"{en.NORA}/nuget/v3/flatcontainer/mindbox.a/index.json": Response(body={"versions": ["1.0.0", "2.0.0-BETA"]}),
              # Only the missing versions have a leaf here: asking for a hosted one fails the test.
              "leaf/2.0.0": leaf(20), "leaf/9.0.0": leaf(90), "leaf/10.0.0": leaf(100)}
    http, patched = with_http(routes)
    with patched:
        [pkg] = en.nuget_org(["Mindbox.A"], missing_only=True)
    assert pkg["id"] == "Mindbox.A" and pkg["on_nuget_org"] is True
    assert [(v["version"], v["size"]) for v in pkg["versions"]] == [("2.0.0", 20), ("9.0.0", 90), ("10.0.0", 100)]
    assert all(v["sha512"] == "aGFzaA==" and v["sha256"] is None and v["origin"] == "nuget.org" for v in pkg["versions"])
    # The token goes to nora and to nobody else.
    for _, url, kw in http.calls:
        assert ("Authorization" in kw.get("headers", {})) == url.startswith(en.NORA), url


def test_an_id_nora_does_not_know_is_missing_whole():
    routes = {f"{REG}/mindbox.new/index.json": Response(body={"items": [{"items": [entry("1.0.0"), entry("0.9.0")]}]}),
              f"{en.NORA}/nuget/v3/flatcontainer/mindbox.new/index.json": Response(404),
              "leaf/1.0.0": leaf(), "leaf/0.9.0": leaf()}
    _, patched = with_http(routes)
    with patched:
        [pkg] = en.nuget_org(["Mindbox.New"], missing_only=True)
    assert [v["version"] for v in pkg["versions"]] == ["0.9.0", "1.0.0"]


def test_without_missing_only_nora_is_not_asked():
    routes = {f"{REG}/mindbox.a/index.json": Response(body={"items": [{"items": [entry("1.0.0")]}]}),
              "leaf/1.0.0": leaf()}
    http, patched = with_http(routes)
    with patched:
        [pkg] = en.nuget_org(["Mindbox.A"], missing_only=False)
    assert [v["version"] for v in pkg["versions"]] == ["1.0.0"]
    assert not [url for url in http.sent("GET") if url.startswith(en.NORA)]


def test_a_nora_error_stops_the_run_instead_of_reimporting_everything():
    routes = {f"{en.NORA}/nuget/v3/flatcontainer/mindbox.a/index.json": Response(503)}
    _, patched = with_http(routes)
    with patched:
        try:
            en.nuget_org(["Mindbox.A"], missing_only=True)
        except AssertionError as e:
            assert "503" in str(e)
        else:
            raise AssertionError("a 503 from nora was read as 'nora hosts nothing'")


def test_a_hash_that_is_not_sha512_stops_the_run():
    routes = {f"{REG}/mindbox.a/index.json": Response(body={"items": [{"items": [entry("1.0.0")]}]}),
              "leaf/1.0.0": leaf(algo="SHA256")}
    _, patched = with_http(routes)
    with patched:
        assert "unexpected packageHashAlgorithm SHA256" in raises_exit(lambda: en.nuget_org(["Mindbox.A"], False))


def npm_version(ver, integrity="sha512-AAAA"):
    return {"version": ver, "url": f"tgz/{ver}", "size": 1, "integrity": integrity, "shasum": "ab"}


def test_npm_missing_drops_hosted_versions_and_whole_packages():
    pkgs = [{"name": "@mindbox-cloud/a", "versions": [npm_version("1.0.0"), npm_version("1.1.0")]},
            {"name": "@mindbox-cloud/done", "versions": [npm_version("3.0.0")]},
            {"name": "@mindbox-cloud/new", "versions": [npm_version("0.1.0")]}]
    routes = {f"{en.NORA}/npm/@mindbox-cloud%2Fa": Response(body={"versions": {"1.0.0": {}}}),
              f"{en.NORA}/npm/@mindbox-cloud%2Fdone": Response(body={"versions": {"3.0.0": {}, "4.0.0": {}}}),
              f"{en.NORA}/npm/@mindbox-cloud%2Fnew": Response(404)}
    _, patched = with_http(routes)
    with patched:
        got = en.npm_missing(pkgs)
    assert [(p["name"], [v["version"] for v in p["versions"]]) for p in got] == [
        ("@mindbox-cloud/a", ["1.1.0"]), ("@mindbox-cloud/new", ["0.1.0"])]


def test_npm_missing_refuses_a_version_without_a_sha512_integrity():
    for weak in ("sha1-AAAA", "", None):
        pkgs = [{"name": "@mindbox-cloud/a", "versions": [npm_version("1.0.0", integrity=weak)]}]
        _, patched = with_http({f"{en.NORA}/npm/@mindbox-cloud%2Fa": Response(404)})
        with patched:
            assert "@mindbox-cloud/a@1.0.0" in raises_exit(lambda: en.npm_missing(pkgs)), weak


def test_nuget_adds_nuget_org_versions_only_for_listed_public_ids():
    # audit A002: an in-scope name on Artifactory does not make its nuget.org owner trusted.
    art_reg = f"{en.ART}/api/nuget/v3/nuget-local/registration-semver2"
    files = [{"uri": "/Mindbox.A.1.0.0.nupkg", "size": 5, "sha2": "aa"},
             {"uri": "/Mindbox.A.odd-name.1.0.nupkg", "size": 6, "sha2": "bb"},
             {"uri": "/Other.Lib.1.0.0.nupkg", "size": 7, "sha2": "cc"},
             {"uri": "/nested/Mindbox.B.1.0.0.nupkg", "size": 8, "sha2": "dd"}]
    routes = {f"{art_reg}/mindbox.a/index.json": reg(entry("1.0.0", listed=False)),
              f"{REG}/mindbox.a/index.json": reg(entry("1.0.0"), entry("0.5.0")),
              f"{art_reg}/mindbox.a.odd-name/index.json": Response(404),
              "leaf/1.0.0": leaf(), "leaf/0.5.0": leaf(size=11)}
    http, patched = with_http(routes)
    with patched:
        pkgs, stray = en.nuget(files, set(), timedelta(days=3))
    assert not [url for url in http.sent("GET") if url.startswith(REG) or url.startswith("leaf/")]
    assert [p["id"] for p in pkgs] == ["Mindbox.A"] and pkgs[0]["on_nuget_org"] is False
    assert [(v["version"], v["origin"], v["size"], v["sha256"], v["listed"]) for v in pkgs[0]["versions"]] == [
        ("1.0.0", "artifactory", 5, "aa", False)]
    assert stray == [{"file": "mindbox.a.odd-name.1.0.nupkg", "size": 6, "sha256": "bb"}]

    _, patched = with_http(routes)
    with patched:
        pkgs, _ = en.nuget(files, {"mindbox.a"}, timedelta(days=3))
    assert pkgs[0]["on_nuget_org"] is True
    assert [(v["version"], v["origin"], v["size"], v.get("sha512"), v["listed"]) for v in pkgs[0]["versions"]] == [
        ("0.5.0", "nuget.org", 11, "aGFzaA==", True), ("1.0.0", "artifactory", 5, None, False)]


def test_a_version_younger_than_min_age_is_deferred():
    # audit A102: a fresh nuget.org release waits out the same cooldown curation gives proxied ones.
    routes = {f"{REG}/mindbox.a/index.json": reg(*(entry(v) for v in ("1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"))),
              "leaf/1.0.0": leaf(created=OLD),
              "leaf/1.1.0": leaf(created=ago(hours=1)),
              "leaf/1.2.0": leaf(created=None),  # no date at all
              "leaf/1.3.0": leaf(published=OLD),  # no `created`: `published` dates it
              "leaf/1.4.0": leaf(published="1900-01-01T00:00:00+00:00"),  # nuget.org's unlisted marker
              "leaf/1.5.0": leaf(created="not a date")}
    _, patched = with_http(routes)
    with patched, mock.patch("builtins.print"):
        [pkg] = en.nuget_org(["Mindbox.A"], False, timedelta(days=3))
        assert [v["version"] for v in pkg["versions"]] == ["1.0.0", "1.3.0"]
        [pkg] = en.nuget_org(["Mindbox.A"], False, timedelta(0))
        assert [v["version"] for v in pkg["versions"]] == ["1.0.0", "1.1.0", "1.3.0"]
        [pkg] = en.nuget_org(["Mindbox.A"], False)
        assert [v["version"] for v in pkg["versions"]] == ["1.0.0", "1.3.0"], "the default is not 3 days"


def test_min_age_parses_days_and_hours_only():
    assert en.parse_age("3d") == timedelta(days=3) and en.parse_age("12h") == timedelta(hours=12)
    assert en.parse_age("0d") == timedelta(0)
    for bad in ("", "3", "-1d", "3w", "1.5d", "3d; x"):
        try:
            en.parse_age(bad)
        except en.argparse.ArgumentTypeError:
            continue
        raise AssertionError(f"{bad!r} parsed")


def test_a_listed_id_missing_on_nuget_org_stops_the_run():
    # audit A102: an unregistered listed ID would be imported whole once anyone registers it.
    _, patched = with_http({f"{REG}/mindbox.gone/index.json": Response(404)})
    with patched:
        assert "Mindbox.Gone" in raises_exit(lambda: en.nuget_org(["Mindbox.Gone"], False))


def test_hosted_version_unlisted_upstream_is_emitted_unlist_only():
    # audit A102: an unlist on nuget.org after the import reaches nora; no leaf is fetched for it.
    routes = {f"{REG}/mindbox.a/index.json": reg(entry("1.0.0", listed=False), entry("1.1.0"), entry("2.0.0")),
              f"{en.NORA}/nuget/v3/flatcontainer/mindbox.a/index.json": Response(body={"versions": ["1.0.0", "1.1.0"]}),
              "leaf/2.0.0": leaf()}
    _, patched = with_http(routes)
    with patched:
        [pkg] = en.nuget_org(["Mindbox.A"], missing_only=True)
    assert pkg["versions"][0] == {"version": "1.0.0", "listed": False, "unlist_only": True, "size": 0,
                                  "origin": "nuget.org"}
    assert [v["version"] for v in pkg["versions"]] == ["1.0.0", "2.0.0"]
    assert en.totals([pkg], "versions")["artifacts"] == 2


def test_pypi_reads_only_the_repository_the_operator_names():
    # audit A002: the `pypi` virtual repository also answers from its public remotes.
    os.environ.pop("ART_PYPI_REPO", None)
    assert "ART_PYPI_REPO" in raises_exit(en.pypi)
    routes = {f"{en.ART}/api/pypi/pypi-local/simple/{n}/": Response(404, text="nf") for n in en.PYPI_NAMES}
    http, patched = with_http(routes)
    with patched, mock.patch.dict(os.environ, {"ART_PYPI_REPO": "pypi-local"}):
        got = en.pypi()
    assert [e["status"] for e in got] == [404] * len(en.PYPI_NAMES) and len(http.calls) == len(en.PYPI_NAMES)


def test_links_and_totals():
    p = en.Links()
    p.feed('<a href="../../f/a-1.0.tar.gz#sha256=ab">a-1.0.tar.gz</a><br><a href="b.whl"> b.whl </a>')
    assert p.links == [("a-1.0.tar.gz", "../../f/a-1.0.tar.gz#sha256=ab"), ("b.whl", "b.whl")]
    items = [{"versions": [{"version": "1.0.0", "size": 10}, {"version": "1.0.1-pr.4", "size": 5}]},
             {"versions": [{"version": "2.0.0-dev.1", "size": 1}]}]
    assert en.totals(items, "versions") == {"packages": 2, "artifacts": 3, "bytes": 16, "gb": 0.0,
                                            "pr_dev_prerelease": 2, "pr_dev_bytes": 6}


def test_main_reads_the_id_file_without_comments_and_blank_lines():
    with tempfile.TemporaryDirectory() as d:
        ids, out = os.path.join(d, "ids.txt"), os.path.join(d, "manifest.json")
        with open(ids, "w") as f:
            f.write("# public IDs\nMindbox.A\n\n  Mindbox.B  # moved in 2026\n#Mindbox.C\n")
        seen = {}

        def fake_nuget_org(id_list, missing_only, min_age):
            seen.update(ids=id_list, missing_only=missing_only, min_age=min_age)
            return [{"id": i, "on_nuget_org": True, "versions": []} for i in id_list]

        argv = ["enumerate.py", "--nuget-org-ids", ids, "--missing-only", "--min-age", "0d", "--out", out]
        with mock.patch.object(en, "nuget_org", fake_nuget_org), mock.patch.object(sys, "argv", argv), \
                mock.patch("builtins.print"):
            en.main()
        assert seen == {"ids": ["Mindbox.A", "Mindbox.B"], "missing_only": True, "min_age": timedelta(0)}
        with open(out) as f:
            manifest = json.load(f)
        assert [p["id"] for p in manifest["nuget"]] == ["Mindbox.A", "Mindbox.B"]
        assert manifest["npm"] == [] and manifest["pypi"] == [] and manifest["source"] == "https://api.nuget.org"


for name, test in sorted(globals().items()):
    if name.startswith("test_"):
        test()
print("ok")
