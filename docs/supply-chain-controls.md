# Supply-chain controls

NORA does not scan the content of uploaded or proxied artifacts with an antivirus
engine (ASVS V5.4.3). This page records why, and which controls cover that
requirement instead.

## Why there is no in-line antivirus

- Malicious packages in npm, PyPI, NuGet, crates and similar ecosystems are new code
  (install scripts, typosquats, hijacked releases). Signature engines such as ClamAV
  find almost none of them: there is no signature yet when the package is fetched.
- A scanner in the upload and first-proxy-fill path sits on every CI restore and image
  pull. Its latency and its failures (outage, false positive) would turn into 5xx and
  403 for every build, while catching little.

## Controls that cover the threat

| Control | Setting | What it stops |
|---------|---------|---------------|
| Authenticated writes | `[auth]`, tokens with role `write`; OIDC `namespace_scope` | Anonymous or out-of-scope publishing |
| Release age | `curation.mode = "enforce"`, `curation.min_release_age`, per-registry overrides | Versions too new to have been reviewed and pulled by their ecosystem |
| Blocklist / allowlist | `curation.blocklist_path`, `curation.allowlist_path` (with `curation.require_integrity`, each allowlist entry pins a hash) | Known-bad names and versions; with an allowlist, everything not reviewed |
| Internal namespaces | `curation.internal_namespaces` | Dependency confusion: these names are never proxied upstream, in every mode |
| Digest quarantine | `curation.quarantine`, `curation.quarantine_ttl` | Proxied content whose digest NORA has not seen before: held (`enforce`) or logged (`observe`) for the TTL |
| Digest verification | Content-addressed formats (OCI blobs, checksummed indexes) are checked against their digest | Tampered or truncated content between upstream and client |
| Downstream scanning | Image scanners (e.g. trivy) and dependency alerts on repositories | Known vulnerable or malicious content that reached a consumer |

## Future hook

When a content feed is wanted, the better hook is the OSV `MAL-*` advisory feed
driving the existing blocklist, not content AV. Any scanner added later starts in
observe mode and fails open on scanner errors, so it can never take restores down.
