"""Run: uv run --with requests python maestra/scripts/import/test_common.py"""
from common import is_pr_prerelease, split_nupkg, version_key

assert split_nupkg("Mindbox.Foo.Bar.1.2.3.nupkg") == ("Mindbox.Foo.Bar", "1.2.3")
assert split_nupkg("Mindbox.Analyzers.V3.2.0.0-dev.12.nupkg") == ("Mindbox.Analyzers.V3", "2.0.0-dev.12")
assert split_nupkg("Mindbox.X.1.0.0-pr.5+sha.abc.nupkg") == ("Mindbox.X", "1.0.0-pr.5+sha.abc")
assert split_nupkg("readme.txt") is None
order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.0.1", "1.10.0"]
assert sorted(reversed(order), key=version_key) == order
assert is_pr_prerelease("1.2.3-pr.17") and is_pr_prerelease("1.2.3-dev.4") and is_pr_prerelease("1.0.0-dev")
assert not is_pr_prerelease("1.0.0-rc.1") and not is_pr_prerelease("1.0.0-devops.1")
print("ok")
