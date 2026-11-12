// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
use axum::http::{Method, StatusCode};

/// Poll the validator sidecar of `key` until a background revalidation stamps it.
async fn wait_for_stamp(storage: &crate::Storage, key: &str) -> String {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(d) = storage.get(&crate::registry::validators_key(key)).await {
            let s = String::from_utf8_lossy(&d).into_owned();
            if s.contains("validated_at") {
                return s;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{key} never revalidated"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A body of `len` bytes that is not one repeated byte (so a splice shows).
fn big_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// C17: a .nupkg above `server.stream_threshold_mb` is spooled on a cold miss:
/// six concurrent restores make one upstream fetch, all get the full package from
/// the leader's spool file, and it lands in storage pinned to its digest.
#[tokio::test]
async fn test_large_cold_nupkg_is_spooled_and_shared() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let nupkg = big_body(3 * 1024 * 1024 + 17);
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(nupkg.clone())
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(upstream.uri());
        cfg.server.stream_threshold_mb = 1;
    });
    let uri = "/nuget/v3/flatcontainer/bigpkg/1.0.0/bigpkg.1.0.0.nupkg";
    let resps =
        futures::future::join_all((0..6).map(|_| send(&ctx.app, Method::GET, uri, ""))).await;
    for resp in resps {
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()["content-length"],
            nupkg.len().to_string().as_str()
        );
        assert!(body_bytes(resp).await[..] == nupkg[..]);
    }
    let fetches = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with(".nupkg"))
        .count();
    assert_eq!(fetches, 1);

    let key = "nuget/flatcontainer/bigpkg/1.0.0/bigpkg.1.0.0.nupkg";
    let want = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&nupkg))
    };
    for _ in 0..100 {
        if ctx.state.storage.pin(key).await.as_deref() == Some(want.as_str()) {
            // Every holder dropped: the spool files are gone.
            let spool =
                std::path::Path::new(&ctx.state.config.storage.path).join("tmp/proxy-spool");
            for _ in 0..100 {
                if std::fs::read_dir(&spool).map_or(0, |d| d.count()) == 0 {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            panic!("spool files left behind");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("large nupkg was not cached with its pin");
}

/// C17: a cached .nupkg above the threshold streams from storage (no upstream),
/// whole and with its length; a Range request on it is served from storage too.
#[tokio::test]
async fn test_large_cached_nupkg_streams() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".into());
        cfg.server.stream_threshold_mb = 1;
    });
    let nupkg = big_body(2 * 1024 * 1024);
    let key = "nuget/flatcontainer/bighit/1.0.0/bighit.1.0.0.nupkg";
    ctx.state.storage.put(key, &nupkg).await.unwrap();
    let uri = "/nuget/v3/flatcontainer/bighit/1.0.0/bighit.1.0.0.nupkg";
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-length"],
        nupkg.len().to_string().as_str()
    );
    assert!(body_bytes(resp).await[..] == nupkg[..]);

    let resp = crate::test_helpers::send_with_headers(
        &ctx.app,
        Method::GET,
        uri,
        vec![("range", "bytes=10-19")],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(&body_bytes(resp).await[..], &nupkg[10..20]);
}

/// C17 + C54: a streamed cache hit whose bytes no longer match the pin is cut off
/// before the last frame (the client never gets a complete download), the bad
/// copy is dropped, and the next request refetches and re-caches the package.
#[tokio::test]
async fn test_large_tampered_nupkg_aborts_then_self_heals() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let nupkg = big_body(2 * 1024 * 1024);
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(nupkg.clone()))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(upstream.uri());
        cfg.server.stream_threshold_mb = 1;
    });
    let key = "nuget/flatcontainer/tamper/1.0.0/tamper.1.0.0.nupkg";
    ctx.state.storage.put(key, &nupkg).await.unwrap();
    // Corrupt the bytes at rest; the recorded pin stays.
    let mut bad = nupkg.clone();
    bad[1_500_000] ^= 0xff;
    std::fs::write(
        std::path::Path::new(&ctx.state.config.storage.path).join(key),
        &bad,
    )
    .unwrap();

    let uri = "/nuget/v3/flatcontainer/tamper/1.0.0/tamper.1.0.0.nupkg";
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK, "headers go out before EOF");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    assert!(body.is_err(), "a pin mismatch must abort the body");

    let mut healed = false;
    for _ in 0..100 {
        if ctx.state.storage.stat(key).await.is_none() {
            healed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(healed, "the bad copy is dropped");
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_bytes(resp).await[..] == nupkg[..]);
    for _ in 0..100 {
        if let Ok(data) = ctx.state.storage.get(key).await {
            assert!(data[..] == nupkg[..]);
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the refetched package was not re-cached");
}

/// C54: a small cached .nupkg failing its pin is refetched and the cache repaired
/// (the immutable write used to skip the existing bad key forever).
#[tokio::test]
async fn test_tampered_cached_nupkg_is_repaired() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"good-nupkg".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(upstream.uri());
    });
    let key = "nuget/flatcontainer/fixme/1.0.0/fixme.1.0.0.nupkg";
    ctx.state.storage.put(key, b"good-nupkg").await.unwrap();
    std::fs::write(
        std::path::Path::new(&ctx.state.config.storage.path).join(key),
        b"evil-nupkg",
    )
    .unwrap();

    let uri = "/nuget/v3/flatcontainer/fixme/1.0.0/fixme.1.0.0.nupkg";
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"good-nupkg");
    for _ in 0..100 {
        if let Ok(data) = ctx.state.storage.get(key).await {
            assert_eq!(&data[..], b"good-nupkg");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the cache was not repaired");
}

/// N concurrent restores of an uncached .nupkg: one upstream download, every
/// client gets the package, and it is cached.
#[tokio::test]
async fn test_concurrent_cold_nupkg_misses_fetch_once() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(b"nupkg-bytes".to_vec())
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(upstream.uri());
    });
    let uri = "/nuget/v3/flatcontainer/coldpkg/1.0.0/coldpkg.1.0.0.nupkg";

    let resps =
        futures::future::join_all((0..6).map(|_| send(&ctx.app, Method::GET, uri, ""))).await;
    for resp in resps {
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"nupkg-bytes");
    }
    let nupkg_fetches = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with(".nupkg"))
        .count();
    assert_eq!(nupkg_fetches, 1);

    let key = "nuget/flatcontainer/coldpkg/1.0.0/coldpkg.1.0.0.nupkg";
    for _ in 0..50 {
        if ctx.state.storage.stat(key).await.is_some() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("nupkg was not cached");
}

/// C48: concurrent cold misses on the registration index, a registration page and
/// the version list each make one upstream request; every client gets the body.
#[tokio::test]
async fn test_concurrent_cold_metadata_misses_fetch_once() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"versions":["1.0.0"],"items":[]}"#)
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(upstream.uri());
    });
    for (uri, upstream_suffix) in [
        (
            "/nuget/v3/registration/meta.pkg/index.json",
            "/registration5-gz-semver2/meta.pkg/index.json",
        ),
        (
            "/nuget/v3/registration/meta.pkg/page/1.0.0/2.0.0.json",
            "/registration5-gz-semver2/meta.pkg/page/1.0.0/2.0.0.json",
        ),
        (
            "/nuget/v3/flatcontainer/meta.pkg/index.json",
            "/v3-flatcontainer/meta.pkg/index.json",
        ),
    ] {
        let resps =
            futures::future::join_all((0..6).map(|_| send(&ctx.app, Method::GET, uri, ""))).await;
        for resp in resps {
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        }
        let fetches = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().ends_with(upstream_suffix))
            .count();
        assert_eq!(fetches, 1, "{uri}");
    }
}

/// `dotnet package search` resolves search only via `SearchQueryService/3.0.0-beta`
/// (or `/3.4.0`, `/Versioned`); without it: "The source does not have a Search service!".
#[tokio::test]
async fn test_service_index_advertises_search_types_from_public_url() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.server.public_url = Some("https://packages.example.com/".to_string());
    });
    let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let ids: std::collections::HashMap<&str, &str> = json["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["@type"].as_str().unwrap(), r["@id"].as_str().unwrap()))
        .collect();
    for v in ["", "/3.0.0-beta", "/3.0.0-rc", "/3.5.0"] {
        assert_eq!(
            ids.get(format!("SearchQueryService{v}").as_str()),
            Some(&"https://packages.example.com/nuget/v3/query"),
            "SearchQueryService{v}"
        );
        assert_eq!(
            ids.get(format!("SearchAutocompleteService{v}").as_str()),
            Some(&"https://packages.example.com/nuget/v3/autocomplete"),
            "SearchAutocompleteService{v}"
        );
    }
}

/// A .nuspec's record: its id, its version normalized with the labels in their own case, and
/// its dependencies — in groups, or listed without one as a group for every framework.
#[test]
fn a_nuspec_record_keeps_its_id_version_and_dependencies() {
    let grouped = br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>
  <id>Corp.Lib</id><version>01.2-RC.1+sha.5</version><authors>a &amp; b</authors>
  <dependencies>
    <group targetFramework=".NETStandard2.0"><dependency id="A" version="[1.0,2.0)"/></group>
    <group targetFramework="net8.0"/>
  </dependencies>
</metadata></package>"#;
    let record = super::parse_nuspec(grouped).unwrap();
    assert_eq!(record.id, "Corp.Lib");
    assert_eq!(record.version, "1.2.0-RC.1");
    assert_eq!(record.authors, "a & b");
    assert_eq!(record.dependency_groups.len(), 2);
    assert_eq!(
        record.dependency_groups[0].target_framework,
        ".NETStandard2.0"
    );
    assert_eq!(record.dependency_groups[0].dependencies[0].id, "A");
    assert_eq!(
        record.dependency_groups[0].dependencies[0].range,
        "[1.0,2.0)"
    );
    assert!(record.dependency_groups[1].dependencies.is_empty());

    let flat = br#"<package><metadata><id>Flat</id><version>1.0.0</version>
  <dependencies><dependency id="A" version="1.0"/><dependency id="B"/></dependencies>
</metadata></package>"#;
    let record = super::parse_nuspec(flat).unwrap();
    assert_eq!(record.dependency_groups.len(), 1);
    assert_eq!(record.dependency_groups[0].target_framework, "");
    let ids: Vec<&str> = record.dependency_groups[0]
        .dependencies
        .iter()
        .map(|d| d.id.as_str())
        .collect();
    assert_eq!(ids, ["A", "B"]);

    for bad in [
        &b"<package><metadata><id>X</id></metadata></package>"[..],
        b"<package><metadata><version>1.0</version></metadata></package>",
        b"<package><metadata><id>a/b</id><version>1.0</version></metadata></package>",
        b"<package><metadata><id>X</id><version>1.0</version>",
    ] {
        assert!(
            super::parse_nuspec(bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// The flat-container key of a package is the one a client asks for: id and normalized
/// version in lowercase.
#[test]
fn a_package_key_is_the_one_a_client_asks_for() {
    assert_eq!(
        super::package_key("Corp.Lib", "01.2-RC.1+sha.5").as_deref(),
        Some("nuget/flatcontainer/corp.lib/1.2.0-rc.1/corp.lib.1.2.0-rc.1.nupkg")
    );
    assert_eq!(super::package_key("a/b", "1.0"), None);
    assert_eq!(super::package_key("Corp.Lib", "latest"), None);
}

#[tokio::test]
async fn test_nuget_disabled_returns_404() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = false;
    });
    let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_nuget_cached_nupkg() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
    });

    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
            b"nupkg-data",
        )
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    assert_eq!(&body[..], b"nupkg-data");
}

/// No cache + unreachable upstream → 502: an outage, not a missing package
/// (a 404 is NU1101, which NuGet never retries).
#[tokio::test]
async fn test_nuget_unreachable_proxy() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.proxy_timeout = 1;
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/test-package/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

/// Stale cache + unreachable upstream + serve_stale=true → 200 with X-Nora-Stale header (#409)
#[tokio::test]
async fn test_serve_stale_version_list() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.proxy_timeout = 1;
        cfg.nuget.metadata_ttl = 0; // force TTL expiry
        cfg.nuget.serve_stale = true;
    });
    // Seed cache
    let versions = br#"{"versions":["1.0.0","2.0.0"]}"#;
    ctx.state
        .storage
        .put("nuget/flatcontainer/test-package/index.json", versions)
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/test-package/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
        Some(b"true".as_slice())
    );
    let body = body_bytes(resp).await;
    assert!(body.starts_with(b"{\"versions\""));
}

/// Stale cache + unreachable upstream + serve_stale=false → 502, no stale body (#409)
#[tokio::test]
async fn test_serve_stale_disabled_returns_502() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.proxy_timeout = 1;
        cfg.nuget.metadata_ttl = 0;
        cfg.nuget.serve_stale = false;
    });
    // Seed cache
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/test-package/index.json",
            br#"{"versions":["1.0.0"]}"#,
        )
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/test-package/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(resp.headers().get("x-nora-stale").is_none());
}

/// Uncached .nupkg + unreachable upstream → 502, which NuGet retries; a 404
/// would be NU1101 "package not found", failing the restore outright.
#[tokio::test]
async fn test_uncached_nupkg_unreachable_upstream_returns_502() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.proxy_timeout = 1;
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/nosuch-pkg/1.0.0/nosuch-pkg.1.0.0.nupkg",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

/// Stale registration index is served with URL rewriting (#409)
#[tokio::test]
async fn test_serve_stale_registration_index() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.proxy_timeout = 1;
        cfg.nuget.metadata_ttl = 0;
        cfg.nuget.serve_stale = true;
    });
    // Seed registration cache
    let reg_json =
        br#"{"items":[{"@id":"http://127.0.0.1:1/v3/registration/test-pkg/index.json"}]}"#;
    ctx.state
        .storage
        .put("nuget/registration/test-pkg/index.json", reg_json)
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration/test-pkg/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
        Some(b"true".as_slice())
    );
    // RegistrationsBaseUrl/3.6.0 is gzip, stale or not.
    assert_eq!(resp.headers()["content-encoding"], "gzip");
}

/// A NuGet proxy whose upstream refuses connections: dates come from the cache only.
fn date_ctx(trust: bool) -> crate::test_helpers::TestContext {
    create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.metadata_proxy_timeout = 1;
        cfg.server.trust_upstream_dates = trust;
    })
}

#[tokio::test]
async fn test_nuget_publish_date_found() {
    let ctx = date_ctx(true);
    let storage = &ctx.state.storage;
    let meta = serde_json::json!({
        "items": [{
            "items": [{
                "catalogEntry": {
                    "version": "6.0.0",
                    "published": "2023-11-14T10:30:00Z"
                }
            }]
        }]
    });
    storage
        .put(
            "nuget/registration/newtonsoft.json/index.json",
            serde_json::to_vec(&meta).unwrap().as_slice(),
        )
        .await
        .unwrap();

    let result = super::nuget_publish_date(&ctx.state, "newtonsoft.json", "6.0.0", true).await;
    assert!(result.is_some());
}

#[tokio::test]
async fn test_nuget_publish_date_version_not_found() {
    let ctx = date_ctx(true);
    let storage = &ctx.state.storage;
    let meta = serde_json::json!({
        "items": [{"items": [{"catalogEntry": {"version": "1.0.0", "published": "2023-01-01T00:00:00Z"}}]}]
    });
    storage
        .put(
            "nuget/registration/test/index.json",
            serde_json::to_vec(&meta).unwrap().as_slice(),
        )
        .await
        .unwrap();

    let result = super::nuget_publish_date(&ctx.state, "test", "9.9.9", true).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_nuget_publish_date_no_metadata() {
    let ctx = date_ctx(true);

    let result = super::nuget_publish_date(&ctx.state, "nonexistent", "1.0.0", true).await;
    assert!(result.is_none());
}

/// Regression test for #535: pages without inline items must not abort
/// date extraction for subsequent pages.
#[tokio::test]
async fn test_nuget_publish_date_sparse_pages() {
    let ctx = date_ctx(true);
    let storage = &ctx.state.storage;
    // Page 0: non-inline (only @id, no items array).
    // Page 1: inline with the target version.
    let meta = serde_json::json!({
        "items": [
            { "@id": "https://upstream/page/0" },
            {
                "items": [{
                    "catalogEntry": {
                        "version": "2.0.0",
                        "published": "2024-06-15T12:00:00Z"
                    }
                }]
            }
        ]
    });
    storage
        .put(
            "nuget/registration/sparse-pkg/index.json",
            serde_json::to_vec(&meta).unwrap().as_slice(),
        )
        .await
        .unwrap();

    // Before #535 fix: this returned None because page 0 had no "items".
    let result = super::nuget_publish_date(&ctx.state, "sparse-pkg", "2.0.0", true).await;
    assert!(result.is_some(), "date must be found despite sparse page 0");
}

/// ISO 8601 for `secs_ago` seconds before now.
fn iso_ago(secs_ago: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(secs_ago))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn leaf(version: &str, published: &str) -> serde_json::Value {
    serde_json::json!({ "catalogEntry": { "version": version, "published": published } })
}

/// A proxy with a 7d cooldown in enforce mode, trusting upstream dates.
async fn cooldown_upstream(
    trust: bool,
    allow: &[&str],
    quarantine: bool,
) -> (wiremock::MockServer, crate::test_helpers::TestContext) {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"\.nupkg$"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"nupkg".to_vec()))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let allow: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.server.trust_upstream_dates = trust;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
        cfg.curation.nuget.allow = allow;
        if quarantine {
            cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("1d".to_string());
        }
    });
    (upstream, ctx)
}

async fn mount_json(upstream: &wiremock::MockServer, p: &str, body: serde_json::Value) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(upstream)
        .await;
}

fn nupkg_uri(id: &str, ver: &str) -> String {
    format!("/nuget/v3/flatcontainer/{id}/{ver}/{id}.{ver}.nupkg")
}

/// Q01: a `dotnet restore`-shaped request order (flat-container `index.json`, then
/// the `.nupkg`, no registration request) still dates the version from the inlined
/// registration index: the young version is held, the old one is served.
#[tokio::test]
async fn test_flatcontainer_restore_enforces_cooldown_inlined_registration() {
    let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
    mount_json(
        &upstream,
        "/v3-flatcontainer/fresh.pkg/index.json",
        serde_json::json!({ "versions": ["1.0.0", "2.0.0"] }),
    )
    .await;
    mount_json(
        &upstream,
        "/v3/registration5-gz-semver2/fresh.pkg/index.json",
        serde_json::json!({ "items": [{
            "lower": "1.0.0", "upper": "2.0.0",
            "items": [leaf("1.0.0", &iso_ago(30 * 86400)), leaf("2.0.0", &iso_ago(1800))]
        }] }),
    )
    .await;

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/fresh.pkg/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("fresh.pkg", "2.0.0"), "").await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "30-minute-old version must be held"
    );
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("fresh.pkg", "1.0.0"), "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        ctx.state
            .storage
            .stat("nuget/registration/fresh.pkg/index.json")
            .await
            .is_some(),
        "the registration index must be cached for the next request"
    );
}

/// Q01: an ID with more than 128 versions has no inlined pages; the page covering
/// the version is fetched (and cached) and dates it.
#[tokio::test]
async fn test_flatcontainer_restore_enforces_cooldown_paged_registration() {
    let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
    let base = upstream.uri();
    mount_json(
        &upstream,
        "/v3/registration5-gz-semver2/big.pkg/index.json",
        serde_json::json!({ "count": 2, "items": [
            { "@id": format!("{base}/v3/registration5-gz-semver2/big.pkg/page/1.0.0/1.9.0.json"),
              "count": 128, "lower": "1.0.0", "upper": "1.9.0" },
            { "@id": format!("{base}/v3/registration5-gz-semver2/big.pkg/page/2.0.0/3.0.0-beta.json"),
              "count": 2, "lower": "2.0.0", "upper": "3.0.0-beta" }
        ] }),
    )
    .await;
    mount_json(
        &upstream,
        "/v3/registration5-gz-semver2/big.pkg/page/2.0.0/3.0.0-beta.json",
        serde_json::json!({ "lower": "2.0.0", "upper": "3.0.0-beta",
            "items": [leaf("2.0.0", &iso_ago(30 * 86400)), leaf("3.0.0-beta", &iso_ago(600))] }),
    )
    .await;

    let resp = send(
        &ctx.app,
        Method::GET,
        &nupkg_uri("big.pkg", "3.0.0-beta"),
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "10-minute-old version must be held"
    );
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("big.pkg", "2.0.0"), "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let pages = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().contains("/page/"))
        .count();
    assert_eq!(
        pages, 1,
        "the page is fetched once, then read from the cache"
    );
    assert!(ctx
        .state
        .storage
        .stat("nuget/registration/big.pkg/page/2.0.0/3.0.0-beta.json")
        .await
        .is_some());
}

/// Q01: a cached index that predates the version is refetched, so a version
/// published after the last metadata refresh is still dated (and held).
#[tokio::test]
async fn test_flatcontainer_refetches_registration_missing_the_version() {
    let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
    let stale =
        serde_json::json!({ "items": [{ "items": [leaf("1.0.0", &iso_ago(30 * 86400))] }] });
    ctx.state
        .storage
        .put(
            "nuget/registration/late.pkg/index.json",
            stale.to_string().as_bytes(),
        )
        .await
        .unwrap();
    mount_json(
        &upstream,
        "/v3/registration5-gz-semver2/late.pkg/index.json",
        serde_json::json!({ "items": [{ "items": [
            leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(60))
        ] }] }),
    )
    .await;
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("late.pkg", "1.1.0"), "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Q03: an allowlisted young version passes the cooldown; its neighbour does not.
#[tokio::test]
async fn test_flatcontainer_allowlisted_young_version_served() {
    let (upstream, ctx) = cooldown_upstream(true, &["Fresh.Pkg@2.0.0"], false).await;
    mount_json(
        &upstream,
        "/v3/registration5-gz-semver2/fresh.pkg/index.json",
        serde_json::json!({ "items": [{ "items": [
            leaf("2.0.0", &iso_ago(1800)), leaf("2.0.1", &iso_ago(1800))
        ] }] }),
    )
    .await;
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("fresh.pkg", "2.0.0"), "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("fresh.pkg", "2.0.1"), "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A prefix `allow` entry (`Microsoft.NETCore.*`, the .NET servicing case): every
/// young version of every ID under it is listed in the flat `index.json` and
/// served; a young version of an ID outside it stays hidden and held.
#[tokio::test]
async fn test_flatcontainer_allow_prefix_lists_and_serves_young_versions() {
    let (upstream, ctx) = cooldown_upstream(
        true,
        &["Microsoft.NETCore.*", "Microsoft.AspNetCore.*@*"],
        false,
    )
    .await;
    let ids = [
        "microsoft.netcore.app.runtime.linux-x64",
        "microsoft.aspnetcore.app.runtime.linux-x64",
        "microsoft.netcoreapp.other",
        "microsoft.extensions.logging",
    ];
    for id in ids {
        mount_json(
            &upstream,
            &format!("/v3-flatcontainer/{id}/index.json"),
            serde_json::json!({ "versions": ["10.0.12", "10.0.13"] }),
        )
        .await;
        mount_json(
            &upstream,
            &format!("/v3/registration5-gz-semver2/{id}/index.json"),
            serde_json::json!({ "items": [{ "lower": "10.0.12", "upper": "10.0.13", "items": [
                leaf("10.0.12", &iso_ago(30 * 86400)), leaf("10.0.13", &iso_ago(19 * 3600))
            ] }] }),
        )
        .await;
    }
    let [netcore, aspnetcore, lookalike, other] = ids;
    for id in [netcore, aspnetcore] {
        assert_eq!(
            flat_versions(&ctx, id).await,
            serde_json::json!(["10.0.12", "10.0.13"]),
            "{id}: the young version stays listed"
        );
        let resp = send(&ctx.app, Method::GET, &nupkg_uri(id, "10.0.13"), "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{id}: the young version is served"
        );
    }
    for id in [lookalike, other] {
        assert_eq!(
            flat_versions(&ctx, id).await,
            serde_json::json!(["10.0.12"]),
            "{id}: the young version stays hidden"
        );
        let resp = send(&ctx.app, Method::GET, &nupkg_uri(id, "10.0.13"), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{id}: held");
        let resp = send(&ctx.app, Method::GET, &nupkg_uri(id, "10.0.12"), "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{id}: the old version is served"
        );
    }
}

/// A prefix `allow` entry never reaches an internal-namespace ID: it is not
/// proxied at all, whatever its age.
#[tokio::test]
async fn test_allow_prefix_does_not_proxy_an_internal_namespace() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"nupkg".to_vec()))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.server.trust_upstream_dates = true;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
        cfg.curation.internal_namespaces = vec!["corp.*".to_string()];
        cfg.curation.nuget.allow = vec!["Corp.*".to_string(), "corp.lib".to_string()];
    });
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("corp.lib", "1.0.0"), "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/corp.lib/index.json",
        "",
    )
    .await;
    assert_ne!(resp.status(), StatusCode::OK);
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "an internal ID is never asked upstream"
    );
}

/// An unlisted version is dated 1900-01-01 by NuGet: unknown, not ancient.
#[test]
fn test_unlisted_sentinel_date_is_unknown() {
    let date = |s: &str| super::nuget_date(Some(&serde_json::json!(s)));
    assert_eq!(date("1900-01-01T00:00:00+00:00"), None);
    assert_eq!(date("1949-12-31T23:59:59Z"), None);
    assert_eq!(date("not a date"), None);
    assert_eq!(super::nuget_date(None), None);
    assert_eq!(date("2026-10-12T03:21:10.437Z"), Some(1_791_775_270));
    let leaves = [leaf("1.0.0", "1900-01-01T00:00:00+00:00")];
    assert!(super::find_leaf(&leaves, "1.0.0").is_some());
    assert!(super::find_leaf(&leaves, "2.0.0").is_none());
}

/// A registration leaf of an unlisted version as nuget.org serves it
/// (squil.sqlserver 1.0.0-beta.206, 12.10.2026): `published` 1900-01-01, the real
/// date only in the catalog leaf at `catalogEntry.@id`.
fn unlisted_leaf(base: &str, id: &str, version: &str, committed: &str) -> serde_json::Value {
    serde_json::json!({
        "@id": format!("{base}/v3/registration5-gz-semver2/{id}/{version}.json"),
        "@type": "Package",
        "commitId": "891f12ff-077f-4182-8232-37dfde0f100c",
        "commitTimeStamp": committed,
        "catalogEntry": {
            "@id": format!("{base}/v3/catalog0/data/2026.10.12.03.30.25/{id}.{version}.json"),
            "@type": "PackageDetails",
            "id": id,
            "listed": false,
            "published": "1900-01-01T00:00:00+00:00",
            "version": version
        },
        "packageContent": format!("{base}/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg")
    })
}

/// The catalog leaf of an unlisted version (the real document's date fields).
fn catalog_leaf(id: &str, version: &str, created: &str) -> serde_json::Value {
    serde_json::json!({
        "@type": ["PackageDetails", "catalog:Permalink"],
        "catalog:commitId": "06705cfd-dce0-4e52-8dd0-0daf0abbc88b",
        "catalog:commitTimeStamp": iso_ago(3000),
        "created": created,
        "id": id,
        "lastEdited": iso_ago(3000),
        "listed": false,
        "published": "1900-01-01T00:00:00Z",
        "version": version
    })
}

/// `unl.pkg` on `upstream`, every version unlisted: 0.9.0 committed 30 days ago,
/// 1.0.0 created 30 days ago and 2.0.0 an hour ago, both re-committed an hour ago.
/// The catalog leaves are mounted when `leaves`.
async fn mount_unlisted(upstream: &wiremock::MockServer, leaves: bool) {
    let base = upstream.uri();
    let reg = |v: &str, c: &str| unlisted_leaf(&base, "unl.pkg", v, c);
    mount_json(
        upstream,
        "/v3/registration5-gz-semver2/unl.pkg/index.json",
        serde_json::json!({ "items": [{ "items": [
            reg("0.9.0", &iso_ago(30 * 86400)),
            reg("1.0.0", &iso_ago(3600)),
            reg("2.0.0", &iso_ago(3600)),
        ] }] }),
    )
    .await;
    mount_json(
        upstream,
        "/v3-flatcontainer/unl.pkg/index.json",
        serde_json::json!({ "versions": ["0.9.0", "1.0.0", "2.0.0"] }),
    )
    .await;
    if leaves {
        for (v, created) in [("1.0.0", 30 * 86400), ("2.0.0", 3600)] {
            let path = format!("/v3/catalog0/data/2026.10.12.03.30.25/unl.pkg.{v}.json");
            mount_json(
                upstream,
                &path,
                catalog_leaf("unl.pkg", v, &iso_ago(created)),
            )
            .await;
        }
    }
}

/// Upstream requests for `unl.pkg`'s catalog leaves, by version.
async fn catalog_fetches(upstream: &wiremock::MockServer) -> super::HashMap<String, usize> {
    let mut by_version = super::HashMap::new();
    for r in upstream.received_requests().await.unwrap() {
        if let Some(leaf) = r.url.path().strip_prefix("/v3/catalog0/") {
            let v = leaf.trim_end_matches(".json").rsplit("unl.pkg.").next();
            *by_version.entry(v.unwrap().to_string()).or_default() += 1;
        }
    }
    by_version
}

/// Live on iota 12.10.2026: an unlisted version (dated 1900-01-01) passed the
/// cooldown on both paths. It is dated from its catalog leaf: a young one is hidden
/// and refused, an old one served; each leaf is fetched once, and none for a
/// version whose registration commit is already past the cooldown.
#[tokio::test]
async fn test_unlisted_version_dated_from_catalog_leaf() {
    let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
    mount_unlisted(&upstream, true).await;
    assert_eq!(
        flat_versions(&ctx, "unl.pkg").await,
        serde_json::json!(["0.9.0", "1.0.0"])
    );
    let doc = json_body(
        send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/unl.pkg/index.json",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["0.9.0", "1.0.0"]);
    for _ in 0..2 {
        for (v, status) in [
            ("0.9.0", StatusCode::OK),
            ("1.0.0", StatusCode::OK),
            ("2.0.0", StatusCode::FORBIDDEN),
        ] {
            let resp = send(&ctx.app, Method::GET, &nupkg_uri("unl.pkg", v), "").await;
            assert_eq!(resp.status(), status, "{v}");
        }
    }
    let fetches = catalog_fetches(&upstream).await;
    assert_eq!(fetches.get("1.0.0"), Some(&1), "{fetches:?}");
    assert_eq!(fetches.get("2.0.0"), Some(&1), "{fetches:?}");
    assert_eq!(fetches.get("0.9.0"), None, "{fetches:?}");
}

/// An unlisted version whose catalog leaf cannot be read: `curation.on_failure`
/// decides, `closed` hides and refuses it, `open` serves it. The one dated by its
/// old registration commit is served either way.
#[tokio::test]
async fn test_unlisted_version_without_catalog_leaf_follows_on_failure() {
    use crate::config::CurationOnFailure;
    for on_failure in [CurationOnFailure::Closed, CurationOnFailure::Open] {
        let (upstream, _) = cooldown_upstream(true, &[], false).await;
        mount_unlisted(&upstream, false).await;
        let (uri, mode) = (upstream.uri(), on_failure.clone());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
            cfg.curation.on_failure = mode;
        });
        let closed = on_failure == CurationOnFailure::Closed;
        let listed = if closed {
            serde_json::json!(["0.9.0"])
        } else {
            serde_json::json!(["0.9.0", "1.0.0", "2.0.0"])
        };
        assert_eq!(
            flat_versions(&ctx, "unl.pkg").await,
            listed,
            "{on_failure:?}"
        );
        for (v, status) in [
            ("0.9.0", StatusCode::OK),
            (
                "1.0.0",
                if closed {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::OK
                },
            ),
        ] {
            let resp = send(&ctx.app, Method::GET, &nupkg_uri("unl.pkg", v), "").await;
            assert_eq!(resp.status(), status, "{on_failure:?} {v}");
        }
    }
}

/// C49: with `trust_upstream_dates = false` the cache mtime is no publish date:
/// a freshly cached registration index yields no date at all.
#[tokio::test]
async fn test_nuget_publish_date_untrusted_ignores_mtime() {
    let untrusted = date_ctx(false);
    let storage = &untrusted.state.storage;
    let meta =
        serde_json::json!({ "items": [{ "items": [leaf("1.0.0", "2020-01-01T00:00:00Z")] }] });
    storage
        .put(
            "nuget/registration/pkg/index.json",
            meta.to_string().as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(
        super::nuget_publish_date(&untrusted.state, "pkg", "1.0.0", true).await,
        None
    );
    let trusted =
        crate::test_helpers::create_test_context_with_storage_and_config(storage.clone(), |cfg| {
            cfg.server.trust_upstream_dates = true;
        });
    assert!(
        super::nuget_publish_date(&trusted.state, "pkg", "1.0.0", true)
            .await
            .is_some()
    );
}

/// C49: untrusted dates + quarantine — an old cached registration index no longer
/// seeds a new version's first-seen, so the quarantine holds it on nora's clock;
/// and a just-refreshed index no longer makes min-release-age hold every version.
#[tokio::test]
async fn test_untrusted_dates_quarantine_uses_own_clock() {
    let (_upstream, ctx) = cooldown_upstream(false, &[], true).await;
    let index =
        serde_json::json!({ "items": [{ "items": [leaf("1.0.0", "2020-01-01T00:00:00Z")] }] });
    ctx.state
        .storage
        .put(
            "nuget/registration/q.pkg/index.json",
            index.to_string().as_bytes(),
        )
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("q.pkg", "1.0.0"), "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        resp.headers().contains_key("x-nora-quarantine"),
        "held by the quarantine on nora's clock, not by min-release-age on a cache mtime"
    );
}

/// Body of a (possibly gzip-encoded) JSON response.
async fn json_body(resp: axum::http::Response<axum::body::Body>) -> serde_json::Value {
    assert_eq!(resp.status(), StatusCode::OK);
    let gz = resp.headers().contains_key("content-encoding");
    let raw = body_bytes(resp).await;
    let mut out = Vec::new();
    if gz {
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut out).unwrap();
    } else {
        out = raw.to_vec();
    }
    serde_json::from_slice(&out).unwrap()
}

fn leaf_versions(leaves: &serde_json::Value) -> Vec<String> {
    leaves
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["catalogEntry"]["version"].as_str().unwrap().to_string())
        .collect()
}

/// A paged registration (two non-inlined pages) for `big.pkg`, plus its flat index:
/// 1.0.0 / 2.0.0 are old, 2.1.0 and 3.0.0-beta are young.
async fn mount_paged(upstream: &wiremock::MockServer) {
    let base = upstream.uri();
    let reg = "/v3/registration5-gz-semver2/big.pkg";
    mount_json(
        upstream,
        &format!("{reg}/index.json"),
        serde_json::json!({ "count": 2, "items": [
            { "@id": format!("{base}{reg}/page/1.0.0/2.0.0.json"), "count": 2, "lower": "1.0.0", "upper": "2.0.0" },
            { "@id": format!("{base}{reg}/page/2.1.0/3.0.0-beta.json"), "count": 2, "lower": "2.1.0", "upper": "3.0.0-beta" }
        ] }),
    )
    .await;
    mount_json(
        upstream,
        &format!("{reg}/page/1.0.0/2.0.0.json"),
        serde_json::json!({ "count": 2, "lower": "1.0.0", "upper": "2.0.0",
            "items": [leaf("1.0.0", &iso_ago(90 * 86400)), leaf("2.0.0", &iso_ago(30 * 86400))] }),
    )
    .await;
    mount_json(
        upstream,
        &format!("{reg}/page/2.1.0/3.0.0-beta.json"),
        serde_json::json!({ "count": 2, "lower": "2.1.0", "upper": "3.0.0-beta",
            "items": [leaf("2.1.0", &iso_ago(3600)), leaf("3.0.0-beta", &iso_ago(600))] }),
    )
    .await;
    mount_json(
        upstream,
        "/v3-flatcontainer/big.pkg/index.json",
        serde_json::json!({ "versions": ["1.0.0", "2.0.0", "2.1.0", "3.0.0-beta"] }),
    )
    .await;
}

async fn flat_versions(ctx: &crate::test_helpers::TestContext, id: &str) -> serde_json::Value {
    let uri = format!("/nuget/v3/flatcontainer/{id}/index.json");
    json_body(send(&ctx.app, Method::GET, &uri, "").await).await["versions"].clone()
}

/// Storage `get`s of one warm `.nupkg` download (its second request).
async fn nupkg_gets(
    ctx: &crate::test_helpers::TestContext,
    ops: &crate::test_helpers::OpCounts,
    uri: &str,
) -> usize {
    let _ = send(&ctx.app, Method::GET, uri, "").await;
    ops.reset();
    assert_eq!(
        send(&ctx.app, Method::GET, uri, "").await.status(),
        StatusCode::OK
    );
    ops.snapshot().get("get").copied().unwrap_or(0)
}

/// R2-43: dating a `.nupkg` (trusted upstream dates) reads each registration
/// document once: the index, plus the page for a paged ID.
#[tokio::test]
async fn test_nupkg_download_reads_each_registration_doc_once() {
    use crate::test_helpers::{create_test_context_with_storage_and_config, op_counting_storage};
    let (storage, ops) = op_counting_storage();
    let old = iso_ago(30 * 86400);
    let docs = [
        (
            "nuget/registration/dated.pkg/index.json",
            serde_json::json!({ "items": [{ "items": [leaf("1.0.0", &old)] }] }),
        ),
        (
            "nuget/registration/paged.pkg/index.json",
            serde_json::json!({ "items": [{ "lower": "1.0.0", "upper": "2.0.0" }] }),
        ),
        (
            "nuget/registration/paged.pkg/page/1.0.0/2.0.0.json",
            serde_json::json!({ "items": [leaf("1.0.0", &old)] }),
        ),
    ];
    for (key, doc) in docs {
        storage.put(key, doc.to_string().as_bytes()).await.unwrap();
    }
    for id in ["dated.pkg", "paged.pkg"] {
        let key = format!("nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
        storage.put(&key, b"nupkg").await.unwrap();
    }
    let ctx = |trust: bool| {
        create_test_context_with_storage_and_config(storage.clone(), move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.server.trust_upstream_dates = trust;
        })
    };
    let (plain, trusted) = (ctx(false), ctx(true));
    for (id, docs) in [("dated.pkg", 1), ("paged.pkg", 2)] {
        let uri = nupkg_uri(id, "1.0.0");
        let base = nupkg_gets(&plain, &ops, &uri).await;
        let dated = nupkg_gets(&trusted, &ops, &uri).await;
        assert_eq!(dated - base, docs, "{id}");
    }
}

/// R2-12: concurrent cold `.nupkg` downloads of one ID prime its registration with
/// one upstream request (the proxy handlers' single-flight), and the prime stores
/// the upstream validators with the body before the download answers.
#[tokio::test]
async fn test_registration_prime_is_single_flight_with_validators() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
    let index =
        serde_json::json!({ "items": [{ "items": [leaf("1.0.0", &iso_ago(30 * 86400))] }] });
    Mock::given(method("GET"))
        .and(path("/v3/registration5-gz-semver2/prime.pkg/index.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"r1\"")
                .set_body_json(index)
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&upstream)
        .await;
    let uri = nupkg_uri("prime.pkg", "1.0.0");
    let all =
        futures::future::join_all((0..4).map(|_| send(&ctx.app, Method::GET, &uri, ""))).await;
    assert!(all.iter().all(|r| r.status() == StatusCode::OK));
    let fetches = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().contains("/registration"))
        .count();
    assert_eq!(fetches, 1);
    let key = "nuget/registration/prime.pkg/index.json";
    let v = crate::registry::read_validators(&ctx.state.storage, key).await;
    assert_eq!(v.and_then(|v| v.etag).as_deref(), Some("\"r1\""));
}

/// R2-30/R2-37: the Q04 filter refreshes a stale registration index with a
/// conditional request (304: only the sidecar is stamped, the body is not
/// re-uploaded), under the handlers' single-flight.
#[tokio::test]
async fn test_q04_stale_registration_revalidates_once_conditionally() {
    use crate::registry::{write_validators, Validators};
    use crate::test_helpers::{create_test_context_with_storage_and_config, op_counting_storage};
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    let reg = "/v3/registration5-gz-semver2/small.pkg/index.json";
    Mock::given(method("GET"))
        .and(path(reg))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304).set_delay(std::time::Duration::from_millis(300)))
        .mount(&upstream)
        .await;
    mount_json(
        &upstream,
        "/v3-flatcontainer/small.pkg/index.json",
        serde_json::json!({ "versions": ["1.0.0", "1.1.0"] }),
    )
    .await;
    let (storage, ops) = op_counting_storage();
    let uri = upstream.uri();
    let ctx = create_test_context_with_storage_and_config(storage, move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.metadata_ttl = 0; // always stale, no memo
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    let key = "nuget/registration/small.pkg/index.json";
    let index = serde_json::json!({ "items": [{ "items": [
        leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(600))
    ] }] });
    let st = &ctx.state.storage;
    st.put(key, index.to_string().as_bytes()).await.unwrap();
    let v = Validators {
        etag: Some("\"r1\"".to_string()),
        last_modified: None,
    };
    write_validators(st, key, &v).await;
    ops.reset();

    let (a, b) = tokio::join!(
        flat_versions(&ctx, "small.pkg"),
        flat_versions(&ctx, "small.pkg")
    );
    assert_eq!(a, serde_json::json!(["1.0.0"]));
    assert_eq!(b, a);
    // The stale index dates both listed versions, so it is revalidated behind the
    // responses: wait for its 304 stamp.
    wait_for_stamp(st, key).await;
    let reg_requests: Vec<_> = upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == reg)
        .collect();
    assert_eq!(reg_requests.len(), 1, "one flight for both requests");
    assert!(reg_requests[0].headers.contains_key("if-none-match"));
    // Puts: the flat index (fetched once, coalesced) and the 304 stamp. Never the
    // registration body.
    assert_eq!(ops.snapshot().get("put"), Some(&2), "{:?}", ops.snapshot());
}

/// A Q04 context over `upstream`: every metadata document always stale, 7d cooldown.
fn stale_cooldown_ctx(upstream: &wiremock::MockServer) -> crate::test_helpers::TestContext {
    let uri = upstream.uri();
    create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.metadata_ttl = 0;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    })
}

/// The stale registration index is not trusted for a version it does not know: the
/// flat list from upstream carries 1.1.0 (10 minutes old), the cached index only
/// 1.0.0. Hiding is decided on the refreshed index, so 1.1.0 stays hidden; judged
/// on the stale one it would pass the 7d cooldown unseen.
#[tokio::test]
async fn test_q04_stale_index_missing_a_listed_version_is_refreshed_first() {
    let upstream = wiremock::MockServer::start().await;
    mount_json(
        &upstream,
        "/v3-flatcontainer/new.pkg/index.json",
        serde_json::json!({ "versions": ["1.0.0", "1.1.0"] }),
    )
    .await;
    mount_json(
        &upstream,
        "/v3/registration5-gz-semver2/new.pkg/index.json",
        serde_json::json!({ "items": [{ "items": [
            leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(600))
        ] }] }),
    )
    .await;
    let ctx = stale_cooldown_ctx(&upstream);
    let stale = serde_json::json!({ "items": [{ "items": [
        leaf("1.0.0", &iso_ago(30 * 86400))
    ] }] });
    ctx.state
        .storage
        .put(
            &super::registration_key("new.pkg"),
            stale.to_string().as_bytes(),
        )
        .await
        .unwrap();

    assert_eq!(
        flat_versions(&ctx, "new.pkg").await,
        serde_json::json!(["1.0.0"])
    );
}

/// A stale registration index that dates every listed version is used as is: the
/// flat list does not wait for its (slow) refresh.
#[tokio::test]
async fn test_q04_stale_index_dating_listed_versions_does_not_wait() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let upstream = wiremock::MockServer::start().await;
    let index = serde_json::json!({ "items": [{ "items": [
        leaf("1.0.0", &iso_ago(30 * 86400))
    ] }] });
    Mock::given(method("GET"))
        .and(path("/v3/registration5-gz-semver2/old.pkg/index.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(index.clone())
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&upstream)
        .await;
    mount_json(
        &upstream,
        "/v3-flatcontainer/old.pkg/index.json",
        serde_json::json!({ "versions": ["1.0.0"] }),
    )
    .await;
    let ctx = stale_cooldown_ctx(&upstream);
    let st = &ctx.state.storage;
    st.put(
        &super::registration_key("old.pkg"),
        index.to_string().as_bytes(),
    )
    .await
    .unwrap();
    st.put(
        "nuget/flatcontainer/old.pkg/index.json",
        br#"{"versions":["1.0.0"]}"#,
    )
    .await
    .unwrap();

    let started = std::time::Instant::now();
    assert_eq!(
        flat_versions(&ctx, "old.pkg").await,
        serde_json::json!(["1.0.0"])
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "waited {:?} on the registration refresh",
        started.elapsed()
    );
}

/// An expired hidden-versions memo entry that judged every listed version answers
/// at once and is recomputed behind the response: the registration index is gone
/// from the store and its upstream is slow, yet the flat list is served in time,
/// still without the young 1.1.0. The recompute reaches upstream afterwards.
#[tokio::test]
async fn test_q04_expired_hidden_memo_is_served_and_recomputed_behind() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let upstream = wiremock::MockServer::start().await;
    let reg = "/v3/registration5-gz-semver2/memo.pkg/index.json";
    let index = serde_json::json!({ "items": [{ "items": [
        leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(600))
    ] }] });
    Mock::given(method("GET"))
        .and(path(reg))
        .respond_with(ResponseTemplate::new(200).set_body_json(index.clone()))
        .up_to_n_times(1)
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(reg))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(index)
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&upstream)
        .await;
    mount_json(
        &upstream,
        "/v3-flatcontainer/memo.pkg/index.json",
        serde_json::json!({ "versions": ["1.0.0", "1.1.0"] }),
    )
    .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.metadata_ttl = 1;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    assert_eq!(
        flat_versions(&ctx, "memo.pkg").await,
        serde_json::json!(["1.0.0"])
    );

    // The memo entry expires on tokio's clock; storage and wiremock keep real time.
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_millis(1100)).await;
    tokio::time::resume();
    let _ = ctx
        .state
        .storage
        .delete(&super::registration_key("memo.pkg"))
        .await;
    let started = std::time::Instant::now();
    assert_eq!(
        flat_versions(&ctx, "memo.pkg").await,
        serde_json::json!(["1.0.0"])
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "waited {:?} on the hidden-versions recompute",
        started.elapsed()
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let hits = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == reg)
            .count();
        if hits >= 2 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no recompute behind");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// An upstream 404 in a background refresh drops the stale copy and its validators:
/// it is served once more (the response is already out), then the ID is a 404, as
/// the synchronous path answers.
#[tokio::test]
async fn test_nuget_background_404_drops_the_stale_document() {
    use crate::registry::{validators_key, write_validators, Validators};
    use wiremock::matchers::any;
    use wiremock::{Mock, ResponseTemplate};
    let upstream = wiremock::MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(404))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.metadata_ttl = 0;
    });
    let key = "nuget/flatcontainer/gone.pkg/index.json";
    let st = &ctx.state.storage;
    st.put(key, br#"{"versions":["1.0.0"]}"#).await.unwrap();
    let v = Validators {
        etag: Some("\"g1\"".to_string()),
        last_modified: None,
    };
    write_validators(st, key, &v).await;
    let uri = "/nuget/v3/flatcontainer/gone.pkg/index.json";

    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-nora-stale"], "true");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while st.stat(key).await.is_some() || st.stat(&validators_key(key)).await.is_some() {
        assert!(tokio::time::Instant::now() < deadline, "stale copy kept");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// R2-30: within `metadata_ttl` a proxied ID's hidden versions are not recomputed
/// per request: the second flat `index.json` reads no registration document.
#[tokio::test]
async fn test_q04_hidden_versions_memoized_within_ttl() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.metadata_proxy_timeout = 1;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    let st = &ctx.state.storage;
    let reg = "nuget/registration/memo.pkg/index.json";
    let index = serde_json::json!({ "items": [{ "items": [
        leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(600))
    ] }] });
    st.put(reg, index.to_string().as_bytes()).await.unwrap();
    st.put(
        "nuget/flatcontainer/memo.pkg/index.json",
        br#"{"versions":["1.0.0","1.1.0"]}"#,
    )
    .await
    .unwrap();
    assert_eq!(
        flat_versions(&ctx, "memo.pkg").await,
        serde_json::json!(["1.0.0"])
    );
    st.delete(reg).await.unwrap();
    assert_eq!(
        flat_versions(&ctx, "memo.pkg").await,
        serde_json::json!(["1.0.0"]),
        "served from the memo, not recomputed from the (now missing) registration"
    );
}

/// R2-46: a stale registration page is revalidated like the index: a conditional
/// request, and on 304 only the sidecar is written.
#[tokio::test]
async fn test_registration_page_revalidates_with_304() {
    use crate::registry::{write_validators, Validators};
    use crate::test_helpers::{create_test_context_with_storage_and_config, op_counting_storage};
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&upstream)
        .await;
    let (storage, ops) = op_counting_storage();
    let uri = upstream.uri();
    let ctx = create_test_context_with_storage_and_config(storage, move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.metadata_ttl = 0;
    });
    let key = "nuget/registration/pg.pkg/page/1.0.0/2.0.0.json";
    let page = serde_json::json!({ "count": 1, "items": [leaf("1.0.0", "2020-01-01T00:00:00Z")] });
    let st = &ctx.state.storage;
    st.put(key, page.to_string().as_bytes()).await.unwrap();
    let v = Validators {
        etag: Some("\"p1\"".to_string()),
        last_modified: None,
    };
    write_validators(st, key, &v).await;
    ops.reset();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration/pg.pkg/page/1.0.0/2.0.0.json",
        "",
    )
    .await;
    assert_eq!(json_body(resp).await["count"], 1);
    // The revalidation runs behind the response (stale-while-revalidate).
    assert!(wait_for_stamp(st, key).await.contains("validated_at"));
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    assert_eq!(ops.snapshot().get("put"), Some(&1), "{:?}", ops.snapshot());
}

/// Q04: `dotnet restore` resolves ranges against the flat-container version list:
/// young versions are gone from it (dated through the paged registration), the
/// registration page drops them too, and an allowlisted one stays.
#[tokio::test]
async fn test_q04_flat_index_and_pages_hide_young_versions() {
    let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
    mount_paged(&upstream).await;
    assert_eq!(
        flat_versions(&ctx, "big.pkg").await,
        serde_json::json!(["1.0.0", "2.0.0"])
    );
    let page = json_body(
        send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/big.pkg/page/2.1.0/3.0.0-beta.json",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(page["count"], 0);
    assert!(page["items"].as_array().unwrap().is_empty());

    let (upstream, ctx) = cooldown_upstream(true, &["Big.Pkg@2.1.0"], false).await;
    mount_paged(&upstream).await;
    assert_eq!(
        flat_versions(&ctx, "big.pkg").await,
        serde_json::json!(["1.0.0", "2.0.0", "2.1.0"])
    );
}

/// Q04: an inlined registration index loses its young leaves (count fixed); the
/// cache keeps the upstream original. Audit mode filters nothing.
#[tokio::test]
async fn test_q04_registration_index_hides_young_leaves_enforce_only() {
    let index = serde_json::json!({ "count": 1, "items": [{ "count": 2, "lower": "1.0.0", "upper": "1.1.0",
        "items": [leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(600))] }] });
    let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
    mount_json(
        &upstream,
        "/v3/registration5-gz-semver2/fresh.pkg/index.json",
        index.clone(),
    )
    .await;
    let uri = "/nuget/v3/registration/fresh.pkg/index.json";
    let doc = json_body(send(&ctx.app, Method::GET, uri, "").await).await;
    assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["1.0.0"]);
    assert_eq!(doc["items"][0]["count"], 1);
    for _ in 0..50 {
        if let Ok(raw) = ctx
            .state
            .storage
            .get("nuget/registration/fresh.pkg/index.json")
            .await
        {
            let cached: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(
                leaf_versions(&cached["items"][0]["items"]),
                ["1.0.0", "1.1.0"]
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let upstream = wiremock::MockServer::start().await;
    mount_json(
        &upstream,
        "/v3/registration5-gz-semver2/fresh.pkg/index.json",
        index,
    )
    .await;
    let up = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(up);
        cfg.curation.mode = crate::config::CurationMode::Audit;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    let doc = json_body(send(&ctx.app, Method::GET, uri, "").await).await;
    assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["1.0.0", "1.1.0"]);
}

/// Q04: search moves a hit's `version` to the newest allowed one; autocomplete
/// `?id=` lists only allowed versions.
#[tokio::test]
async fn test_q04_search_and_autocomplete_hide_young_versions() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let upstream = wiremock::MockServer::start().await;
    let (up, search, auto) = (
        upstream.uri(),
        format!("{}/query", upstream.uri()),
        format!("{}/autocomplete", upstream.uri()),
    );
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(up);
        cfg.nuget.search_service = search;
        cfg.nuget.autocomplete = auto;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    mount_paged(&upstream).await;
    let hit = serde_json::json!({ "totalHits": 1, "data": [{ "id": "Big.Pkg", "version": "3.0.0-beta",
        "versions": [{ "version": "1.0.0" }, { "version": "2.0.0" }, { "version": "2.1.0" }, { "version": "3.0.0-beta" }] }] });
    Mock::given(method("GET"))
        .and(path("/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(hit))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/autocomplete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({ "totalHits": 4, "data": ["1.0.0", "2.0.0", "2.1.0", "3.0.0-beta"] }),
        ))
        .mount(&upstream)
        .await;
    let doc = json_body(
        send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/query?q=big&prerelease=true",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(doc["data"][0]["version"], "2.0.0");
    assert_eq!(doc["data"][0]["versions"].as_array().unwrap().len(), 2);
    let doc = json_body(
        send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/autocomplete?id=big.pkg&prerelease=true",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(doc["data"], serde_json::json!(["1.0.0", "2.0.0"]));
}

/// Q04: a hosted package and an internal-namespace one are served as stored, even
/// with versions published a minute ago.
#[tokio::test]
async fn test_q04_hosted_and_internal_packages_not_filtered() {
    use super::hosted::test_support::{multipart, nupkg};
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.metadata_proxy_timeout = 1;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
        cfg.curation.internal_namespaces = vec!["corp.*".to_string()];
        // No upstream date can be read: a proxied version would be held (on_failure).
        cfg.server.trust_upstream_dates = true;
    });
    let (ct, body) = multipart(&nupkg("Own.Lib", "1.0.0", ""));
    let resp = crate::test_helpers::send_with_headers(
        &ctx.app,
        Method::PUT,
        "/nuget/v3/package/",
        vec![("content-type", ct.as_str())],
        body,
    )
    .await;
    assert!(resp.status().is_success(), "push: {}", resp.status());
    assert_eq!(
        flat_versions(&ctx, "own.lib").await,
        serde_json::json!(["1.0.0"])
    );
    let resp = send(&ctx.app, Method::GET, &nupkg_uri("own.lib", "1.0.0"), "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = json_body(
        send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/own.lib/index.json",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["1.0.0"]);

    let index = serde_json::json!({ "items": [{ "items": [leaf("2.0.0", &iso_ago(60))] }] });
    ctx.state
        .storage
        .put(
            "nuget/registration/corp.lib/index.json",
            index.to_string().as_bytes(),
        )
        .await
        .unwrap();
    let doc = json_body(
        send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/corp.lib/index.json",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["2.0.0"]);
}

#[tokio::test]
async fn test_local_search_empty_query() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    // Populate index for two packages (index.json + .nupkg)
    for id in &["packagea", "packageb"] {
        let index = serde_json::json!({"versions": ["1.0.0"]});
        ctx.state
            .storage
            .put(
                &format!("nuget/flatcontainer/{}/index.json", id),
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &format!("nuget/flatcontainer/{}/1.0.0/{}.1.0.0.nupkg", id, id),
                b"fake-nupkg",
            )
            .await
            .unwrap();
    }
    ctx.state.repo_index.invalidate("nuget");

    let resp = send(&ctx.app, Method::GET, "/nuget/v3/query", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["totalHits"].as_u64().unwrap() >= 2);
    assert!(json["data"].as_array().unwrap().len() >= 2);
}

#[tokio::test]
async fn test_local_search_substring_match() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    let index = serde_json::json!({"versions": ["13.0.1"]});
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/newtonsoft.json/index.json",
            serde_json::to_vec(&index).unwrap().as_slice(),
        )
        .await
        .unwrap();
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
            b"fake-nupkg",
        )
        .await
        .unwrap();
    ctx.state.repo_index.invalidate("nuget");

    let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=Newton", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["totalHits"].as_u64().unwrap(), 1);
    assert_eq!(json["data"][0]["id"].as_str().unwrap(), "newtonsoft.json");
}

#[tokio::test]
async fn test_local_search_case_insensitive() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    let index = serde_json::json!({"versions": ["13.0.1"]});
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/newtonsoft.json/index.json",
            serde_json::to_vec(&index).unwrap().as_slice(),
        )
        .await
        .unwrap();
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
            b"fake-nupkg",
        )
        .await
        .unwrap();
    ctx.state.repo_index.invalidate("nuget");

    let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=newton", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["totalHits"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn test_local_search_pagination() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    for id in &["alpha", "beta", "gamma"] {
        let index = serde_json::json!({"versions": ["1.0.0"]});
        ctx.state
            .storage
            .put(
                &format!("nuget/flatcontainer/{}/index.json", id),
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &format!("nuget/flatcontainer/{}/1.0.0/{}.1.0.0.nupkg", id, id),
                b"fake-nupkg",
            )
            .await
            .unwrap();
    }
    ctx.state.repo_index.invalidate("nuget");

    let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?skip=1&take=1", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["totalHits"].as_u64().unwrap(), 3);
    assert_eq!(json["data"].as_array().unwrap().len(), 1);
    // Sorted alphabetically: alpha, beta, gamma — skip 1 = beta
    assert_eq!(json["data"][0]["id"].as_str().unwrap(), "beta");
}

#[tokio::test]
async fn test_search_response_format() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    let index = serde_json::json!({"versions": ["1.0.0", "2.0.0"]});
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/testpkg/index.json",
            serde_json::to_vec(&index).unwrap().as_slice(),
        )
        .await
        .unwrap();
    for ver in &["1.0.0", "2.0.0"] {
        ctx.state
            .storage
            .put(
                &format!("nuget/flatcontainer/testpkg/{}/testpkg.{}.nupkg", ver, ver),
                b"fake-nupkg",
            )
            .await
            .unwrap();
    }
    ctx.state.repo_index.invalidate("nuget");

    let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=testpkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Validate top-level structure
    assert!(json["totalHits"].is_number());
    assert!(json["data"].is_array());

    // Validate entry structure
    let entry = &json["data"][0];
    assert!(entry["id"].is_string());
    assert!(entry["version"].is_string());
    assert!(entry["versions"].is_array());
    assert_eq!(entry["version"].as_str().unwrap(), "2.0.0");
    assert_eq!(entry["versions"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_local_search_sem_ver_level_filters_v2() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    // Package with SemVer 2.0 version (dot-separated pre-release)
    let index = serde_json::json!({"versions": ["1.0.0", "2.0.0-rc.1"]});
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/semver2pkg/index.json",
            serde_json::to_vec(&index).unwrap().as_slice(),
        )
        .await
        .unwrap();
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/semver2pkg/1.0.0/semver2pkg.1.0.0.nupkg",
            b"fake-nupkg",
        )
        .await
        .unwrap();
    ctx.state.repo_index.invalidate("nuget");

    // Without semVerLevel → SemVer2 version hidden, only 1.0.0 visible
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/query?q=semver2pkg&prerelease=true",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entry = &json["data"][0];
    let versions = entry["versions"].as_array().unwrap();
    assert_eq!(
        versions.len(),
        1,
        "without semVerLevel, SemVer2 must be hidden"
    );
    assert_eq!(versions[0]["version"].as_str().unwrap(), "1.0.0");

    // With semVerLevel=2.0.0 → both versions visible
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/query?q=semver2pkg&prerelease=true&semVerLevel=2.0.0",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entry = &json["data"][0];
    let versions = entry["versions"].as_array().unwrap();
    assert_eq!(
        versions.len(),
        2,
        "with semVerLevel=2.0.0, SemVer2 must be visible"
    );
}

#[tokio::test]
async fn test_autocomplete_no_upstream_returns_empty() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/autocomplete?q=Newtonsoft&take=5",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["totalHits"].as_u64().unwrap(), 0);
    assert!(json["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_autocomplete_unreachable_upstream_returns_empty() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.proxy_timeout = 1;
        cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
    });

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/autocomplete?q=Newtonsoft&take=5",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["totalHits"].as_u64().unwrap(), 0);
    assert!(json["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_registration_page_rejects_path_traversal() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
    });

    // Path traversal in version
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration/foo/page/1.0.0/../../etc/passwd.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Path traversal in package id — axum normalizes ../ so route doesn't match (404)
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration/../evil/page/1.0.0/2.0.0.json",
        "",
    )
    .await;
    assert_ne!(resp.status(), StatusCode::OK);
}

/// No cache + unreachable upstream → 502 (an outage, not a missing package)
#[tokio::test]
async fn test_registration_page_unreachable_upstream() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.proxy_timeout = 1;
    });

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration/dotnet-ef/page/0.0.1-alpha/3.1.27.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

/// Search fallback adds X-Nora-Stale header when upstream is unreachable (#422)
#[tokio::test]
async fn test_search_fallback_has_stale_header() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.search_service = "http://127.0.0.1:1/query".to_string();
        cfg.nuget.serve_stale = true;
    });
    let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=test", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
        Some(b"true".as_slice())
    );
}

/// Search returns 503 when serve_stale=false and upstream is down (#422)
#[tokio::test]
async fn test_search_serve_stale_disabled_returns_503() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.search_service = "http://127.0.0.1:1/query".to_string();
        cfg.nuget.serve_stale = false;
    });
    let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=test", "").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().get("x-nora-stale").is_none());
}

/// Autocomplete fallback adds X-Nora-Stale header when upstream is unreachable (#422)
#[tokio::test]
async fn test_autocomplete_fallback_has_stale_header() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
        cfg.nuget.serve_stale = true;
    });
    let resp = send(&ctx.app, Method::GET, "/nuget/v3/autocomplete?q=test", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
        Some(b"true".as_slice())
    );
}

/// Autocomplete returns 503 when serve_stale=false and upstream is down (#422)
#[tokio::test]
async fn test_autocomplete_serve_stale_disabled_returns_503() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
        cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
        cfg.nuget.serve_stale = false;
    });
    let resp = send(&ctx.app, Method::GET, "/nuget/v3/autocomplete?q=test", "").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().get("x-nora-stale").is_none());
}

/// A cached .nupkg resumes: 206 for a satisfiable range, 416 once the client
/// already holds the whole package, `Accept-Ranges` on the full 200.
#[tokio::test]
async fn test_nuget_nupkg_range_request() {
    use crate::test_helpers::send_with_headers;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
    });
    let nupkg = b"0123456789";
    ctx.state
        .storage
        .put("nuget/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg", nupkg)
        .await
        .unwrap();
    let url = "/nuget/v3/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg";

    let resp =
        send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes 2-5/10"
    );
    assert_eq!(
        resp.headers()
            .get("accept-ranges")
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(&body_bytes(resp).await[..], b"2345");

    let resp =
        send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=10-")], "").await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        resp.headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes */10"
    );

    let resp = send(&ctx.app, Method::GET, url, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("accept-ranges")
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(&body_bytes(resp).await[..], nupkg);
}

/// A Range request on a cached .nupkg reads the object once: the 206 is cut from
/// the body the integrity and quarantine gates already loaded, not a second, ranged
/// GET of the same object. The one extra round-trip is the `stat` (a HEAD, no body)
/// that tells a small object from a large one (R2-13).
#[tokio::test]
async fn test_nuget_range_on_cache_hit_reads_storage_once() {
    use crate::test_helpers::{
        create_test_context_with_storage_and_config, op_counting_storage, send_with_headers,
    };

    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.nuget.enabled = true;
    });
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg",
            b"0123456789",
        )
        .await
        .unwrap();
    let url = "/nuget/v3/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg";
    // Warm up once (hosted index load), then compare a full and a ranged hit.
    let _ = send(&ctx.app, Method::GET, url, "").await;
    ops.reset();
    let resp = send(&ctx.app, Method::GET, url, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let full = ops.snapshot();
    ops.reset();
    let resp =
        send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(&body_bytes(resp).await[..], b"2345");
    let mut ranged = ops.snapshot();
    assert_eq!(ranged.remove("stat"), Some(1), "{ranged:?}");
    assert_eq!(ranged, full, "a ranged hit must read what a full hit reads");
    assert_eq!(ranged.get("get_range"), None, "{ranged:?}");
}

/// R2-13: a Range request on a cached .nupkg above `stream_threshold_mb` is one
/// `stat` and one ranged read: the whole object is never opened for streaming first.
#[tokio::test]
async fn test_nuget_range_on_large_cache_hit_opens_one_ranged_read() {
    use crate::test_helpers::{
        create_test_context_with_storage_and_config, op_counting_storage, send_with_headers,
    };

    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.nuget.enabled = true;
        cfg.server.stream_threshold_mb = 1;
    });
    let nupkg: Vec<u8> = (0..(2 * 1024 * 1024 + 7))
        .map(|i| (i % 251) as u8)
        .collect();
    let key = "nuget/flatcontainer/bigpkg/1.0.0/bigpkg.1.0.0.nupkg";
    ctx.state.storage.put(key, &nupkg).await.unwrap();
    let url = "/nuget/v3/flatcontainer/bigpkg/1.0.0/bigpkg.1.0.0.nupkg";
    let _ = send(&ctx.app, Method::GET, url, "").await; // hosted index load
    ops.reset();
    let range = vec![("range", "bytes=1048576-1048585")];
    let resp = send_with_headers(&ctx.app, Method::GET, url, range, "").await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(&body_bytes(resp).await[..], &nupkg[1048576..=1048585]);
    let ranged = ops.snapshot();
    assert_eq!(ranged.get("get_reader"), None, "{ranged:?}");
    assert_eq!(ranged.get("get_range"), Some(&1), "{ranged:?}");
    assert_eq!(ranged.get("stat"), Some(&1), "{ranged:?}");

    // The full download still streams it, with its length.
    let resp = send(&ctx.app, Method::GET, url, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-length"],
        nupkg.len().to_string().as_str()
    );
    assert_eq!(body_bytes(resp).await.len(), nupkg.len());
}

/// Upstream failures on a cold .nupkg miss: only a 404 stays a 404; an outage is
/// 502, a timeout 504, throttling 503 with the upstream Retry-After, and an auth
/// refusal 502 — none of them may reach `dotnet restore` as NU1101.
#[tokio::test]
async fn test_cold_miss_upstream_errors_map_to_5xx() {
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    for (name, resp) in [
        ("gone", ResponseTemplate::new(404)),
        ("down", ResponseTemplate::new(503)),
        (
            "throttled",
            ResponseTemplate::new(429).insert_header("retry-after", "7"),
        ),
        ("denied", ResponseTemplate::new(403)),
        (
            "slow",
            ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(3)),
        ),
    ] {
        Mock::given(path(format!(
            "/v3-flatcontainer/{name}/1.0.0/{name}.1.0.0.nupkg"
        )))
        .respond_with(resp)
        .mount(&upstream)
        .await;
    }
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.proxy_timeout = 1;
    });

    for (name, want) in [
        ("gone", StatusCode::NOT_FOUND),
        ("down", StatusCode::BAD_GATEWAY),
        ("throttled", StatusCode::SERVICE_UNAVAILABLE),
        ("denied", StatusCode::BAD_GATEWAY),
        ("slow", StatusCode::GATEWAY_TIMEOUT),
    ] {
        let url = format!("/nuget/v3/flatcontainer/{name}/1.0.0/{name}.1.0.0.nupkg");
        let resp = send(&ctx.app, Method::GET, &url, "").await;
        assert_eq!(resp.status(), want, "{name}");
        if name == "throttled" {
            assert_eq!(resp.headers()["retry-after"], "7");
        }
    }
}

/// A stale cached registration survives an upstream 429: it used to be collapsed
/// into a 404 that discarded the cache.
#[tokio::test]
async fn test_registration_upstream_429_serves_stale_cache() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(429))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.metadata_ttl = 0;
        cfg.nuget.serve_stale = true;
    });
    ctx.state
        .storage
        .put(
            "nuget/registration/test-package/index.json",
            br#"{"count":0,"items":[]}"#,
        )
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration/test-package/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-nora-stale"], "true");
}

/// The stored metadata documents of `stale.pkg` and the requests that read them:
/// version list, registration index, registration page.
const STALE_DOCS: [(&str, &str, &str); 3] = [
    (
        "nuget/flatcontainer/stale.pkg/index.json",
        "/nuget/v3/flatcontainer/stale.pkg/index.json",
        "/v3-flatcontainer/stale.pkg/index.json",
    ),
    (
        "nuget/registration/stale.pkg/index.json",
        "/nuget/v3/registration/stale.pkg/index.json",
        "/v3/registration5-gz-semver2/stale.pkg/index.json",
    ),
    (
        "nuget/registration/stale.pkg/page/1.0.0/2.0.0.json",
        "/nuget/v3/registration/stale.pkg/page/1.0.0/2.0.0.json",
        "/v3/registration5-gz-semver2/stale.pkg/page/1.0.0/2.0.0.json",
    ),
];

/// An upstream that answers every document of [`STALE_DOCS`] with the version the
/// cached copies lack, and a context whose copies were written `days` ago.
async fn stale_docs(
    days: u64,
    max_stale: Option<i64>,
) -> (wiremock::MockServer, crate::test_helpers::TestContext) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::builder().start().await;
    for (_, _, upstream_path) in STALE_DOCS {
        Mock::given(method("GET"))
            .and(path(upstream_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"versions":["1.0.0","2.1.0"],"items":[]}"#),
            )
            .mount(&upstream)
            .await;
    }
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.metadata_ttl = 0; // every copy is past its TTL
        if let Some(max_stale) = max_stale {
            cfg.nuget.max_stale = max_stale;
        }
    });
    for (key, _, _) in STALE_DOCS {
        crate::test_helpers::put_written_days_ago(
            &ctx,
            key,
            br#"{"versions":["1.0.0"],"items":[]}"#,
            days,
        )
        .await;
    }
    (upstream, ctx)
}

/// R4-R02: a copy older than `nuget.max_stale` is not served as it is. A version list
/// last asked for six days ago lacked the version published since, and the first
/// `dotnet restore` naming it failed with NU1102; now the copy is revalidated before
/// the answer, on all three metadata documents.
#[tokio::test]
async fn test_copy_past_max_stale_is_refreshed_before_the_answer() {
    let (_upstream, ctx) = stale_docs(6, None).await;
    for (_, uri, _) in STALE_DOCS {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert!(resp.headers().get("x-nora-stale").is_none(), "{uri}");
        assert_eq!(
            json_body(resp).await["versions"],
            serde_json::json!(["1.0.0", "2.1.0"]),
            "{uri}: the upstream's document, not the six-day-old copy"
        );
    }
}

/// Inside the window the stale copy still answers at once and is refreshed behind the
/// response, and `max_stale = -1` puts no bound on its age.
#[tokio::test]
async fn test_copy_within_max_stale_is_served_stale() {
    for (days, max_stale) in [(0, None), (6, Some(7 * 86400)), (6, Some(-1))] {
        let (_upstream, ctx) = stale_docs(days, max_stale).await;
        for (_, uri, _) in STALE_DOCS {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(
                resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
                Some(&b"true"[..]),
                "{uri} written {days}d ago, max_stale {max_stale:?}"
            );
            assert_eq!(
                json_body(resp).await["versions"],
                serde_json::json!(["1.0.0"])
            );
        }
    }
}

/// R4-R10: a 304 for a document whose cached body is gone (deleted by hand, the
/// validators left behind) is not a 502 for as long as the upstream keeps answering
/// 304: the validators are dropped and the document is fetched whole.
#[tokio::test]
async fn test_304_for_a_missing_body_refetches_whole() {
    use crate::registry::{read_validators, write_validators, Validators};
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::builder().start().await;
    Mock::given(method("GET"))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v2\"")
                .set_body_string(r#"{"versions":["1.0.0"]}"#),
        )
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.nuget.serve_stale = false;
    });
    let key = "nuget/flatcontainer/gone.pkg/index.json";
    let orphan = Validators {
        etag: Some("\"v1\"".to_string()),
        last_modified: None,
    };
    write_validators(&ctx.state.storage, key, &orphan).await;

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/gone.pkg/index.json",
        "",
    )
    .await;
    assert_eq!(
        json_body(resp).await["versions"],
        serde_json::json!(["1.0.0"])
    );
    let conditional: Vec<bool> = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.headers.contains_key("if-none-match"))
        .collect();
    assert_eq!(conditional, [true, false], "one 304, then one whole fetch");
    assert_eq!(
        read_validators(&ctx.state.storage, key)
            .await
            .unwrap_or_default()
            .etag
            .as_deref(),
        Some("\"v2\""),
        "the validators describe the body just stored"
    );
}

/// R4-P13: a registration document too big for the request's own task is rewritten and
/// compressed on the blocking pool, and reads the same as a small one rendered inline.
#[tokio::test]
async fn test_big_registration_document_renders_as_a_small_one() {
    let upstream = "https://api.nuget.org";
    let leaf = format!(r#"{{"@id":"{upstream}/v3/registration5-gz-semver2/big.pkg/1.0.0.json"}}"#);
    for leaves in [1, 2000] {
        let doc = format!(r#"{{"items":[{}]}}"#, vec![leaf.as_str(); leaves].join(","));
        assert_eq!(doc.len() > super::REGISTRATION_INLINE_MAX, leaves > 1);
        let resp = super::registration_response(
            super::Bytes::from(doc.clone()),
            upstream,
            "http://nora.test",
        )
        .await;
        assert_eq!(resp.headers()["content-encoding"], "gzip");
        let expected: serde_json::Value = serde_json::from_str(&super::rewrite_registration_urls(
            &doc,
            upstream,
            "http://nora.test",
        ))
        .unwrap();
        assert!(!expected.to_string().contains("api.nuget.org"));
        assert_eq!(json_body(resp).await, expected);
    }
}
