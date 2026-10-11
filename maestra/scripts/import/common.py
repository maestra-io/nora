"""Shared bits for the one-time Artifactory -> nora import (issues-maestra#1442, W0e)."""
import os
import re
import sys
import threading
import time

import requests

ART = os.environ.get("ART_URL", "https://artifactory.mindbox.ru/artifactory")
NORA = os.environ.get("NORA_URL", "https://packages.maestra.io")
# NuGet IDs in scope: Mindbox.* plus the two strays found in the consumer graph.
NUGET_ID = re.compile(r"(?i)^(mindbox\..+|mobilepush\.cassandra|websitescanner)$")
NPM_SCOPE = "@mindbox-cloud/"
PYPI_NAMES = ["mindbox-ml-commons", "python-mindbox-sdk", "python-mindbox-chat-ast", "mindbox-finance-mcp"]
# PR / dev builds; retention for these is an open question, so they are counted apart.
PR_PRERELEASE = re.compile(r"(?i)-(pr|dev)([.\d-]|$)")
_NUPKG = re.compile(r"(?i)^(?P<id>.+?)\.(?P<ver>\d+(\.\d+){1,3}(-[0-9a-z][0-9a-z.-]*)?(\+[0-9a-z.-]+)?)\.nupkg$")


def env(name):
    v = os.environ.get(name)
    if not v:
        sys.exit(f"{name} is not set")
    return v


class Limiter:
    """Global minimum interval between requests to one host (thread-safe)."""

    def __init__(self, rps):
        self.gap, self.next, self.lock = 1.0 / rps, 0.0, threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            delay, self.next = max(0.0, self.next - now), max(now, self.next) + self.gap
        if delay:
            time.sleep(delay)


def art_session():
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + env("ART_TOKEN")
    # Read-only on Artifactory: refuse anything but GET/HEAD at the session level.
    orig = s.request

    def guarded(method, url, *a, **kw):
        if method.upper() not in ("GET", "HEAD"):
            raise RuntimeError(f"refusing {method} to Artifactory")
        return orig(method, url, *a, **kw)

    s.request = guarded
    return s


def split_nupkg(filename):
    """'Mindbox.Foo.1.2.3-dev.4.nupkg' -> ('Mindbox.Foo', '1.2.3-dev.4'), else None."""
    m = _NUPKG.match(filename)
    return (m["id"], m["ver"]) if m else None


def version_key(v):
    """SemVer 2 precedence (NuGet/npm order); build metadata ignored, 4th numeric part allowed."""
    v = v.split("+", 1)[0]
    core, _, pre = v.partition("-")
    nums = tuple(int(x) for x in core.split(".")) + (0,) * (4 - len(core.split(".")))
    if not pre:
        return nums, 1, ()
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p.lower()) for p in pre.split("."))
    return nums, 0, ids


def is_pr_prerelease(v):
    return bool(PR_PRERELEASE.search(v))
