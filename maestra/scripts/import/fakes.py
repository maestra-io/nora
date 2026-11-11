"""Test doubles for test_enumerate.py and test_import.py: HTTP answered from a table, never sent."""
import json


class Response:
    def __init__(self, status=200, body=None, text=""):
        self.status_code, self._body, self.text = status, body, text or json.dumps(body)
        self.ok = status < 400
        self.headers = {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if not self.ok:
            raise AssertionError(f"HTTP {self.status_code}")


class Http:
    """A session whose every request is looked up in `routes` ({url or (method, url): Response or
    a list of them, answered in turn}) and recorded in `calls`. An unknown URL fails the test: no
    test reaches a real host."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        answer = self.routes.get((method, url), self.routes.get(url))
        assert answer is not None, f"unexpected {method} {url}"
        return answer.pop(0) if isinstance(answer, list) else answer

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def sent(self, method):
        return [url for m, url, _ in self.calls if m == method]
