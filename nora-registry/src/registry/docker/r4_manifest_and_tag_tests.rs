// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::DockerUpstream;
use crate::test_helpers::{
    body_bytes, create_test_context, create_test_context_with_config,
    create_test_context_with_storage, send, send_with_headers, TestContext,
};
use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use sha2::Digest;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CFG: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const V2: &str = "application/vnd.docker.distribution.manifest.v2+json";

fn manifest() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": V2,
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": CFG
        },
        "layers": []
    }))
    .unwrap()
}

fn digest_of(body: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(body)))
}

fn upstream(url: String, namespace: &str) -> DockerUpstream {
    DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url,
        auth: None,
        auth_env: None,
        namespace: Some(namespace.into()),
        prefix: None,
        namespaces: Vec::new(),
    }
}

async fn push(ctx: &TestContext, repo: &str, tag: &str) -> StatusCode {
    ctx.state
        .storage
        .put(&format!("docker/{repo}/blobs/{CFG}"), b"x")
        .await
        .unwrap();
    send(
        &ctx.app,
        Method::PUT,
        &format!("/v2/{repo}/manifests/{tag}"),
        Body::from(manifest()),
    )
    .await
    .status()
}

async fn status(ctx: &TestContext, method: Method, uri: &str) -> StatusCode {
    send(&ctx.app, method, uri, Body::empty()).await.status()
}

/// R4-R01: two tags answer with one manifest. Deleting one keeps the digest copy the other
/// is pulled by; deleting the last one removes it. With and without an upstream configured
/// (the tag then has a namespaced key and a bare one).
#[tokio::test]
async fn deleting_one_tag_keeps_the_digest_another_tag_answers_with() {
    for with_upstream in [false, true] {
        let ctx = create_test_context_with_config(|cfg| {
            if with_upstream {
                cfg.docker.upstreams = vec![upstream("http://127.0.0.1:1".into(), "docker.io")];
            }
        });
        assert_eq!(push(&ctx, "team/app", "abc123").await, StatusCode::CREATED);
        assert_eq!(push(&ctx, "team/app", "latest").await, StatusCode::CREATED);
        let by_digest = format!("/v2/team/app/manifests/{}", digest_of(&manifest()));

        assert_eq!(
            status(&ctx, Method::DELETE, "/v2/team/app/manifests/abc123").await,
            StatusCode::ACCEPTED
        );
        // Gone here: 404 hosted-only, 502 when the unreachable upstream is asked for it.
        let gone = if with_upstream {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::NOT_FOUND
        };
        assert_eq!(
            status(&ctx, Method::GET, "/v2/team/app/manifests/abc123").await,
            gone
        );
        assert_eq!(
            status(&ctx, Method::GET, &by_digest).await,
            StatusCode::OK,
            "the digest copy went with the first tag (upstream: {with_upstream})"
        );
        assert_eq!(
            status(&ctx, Method::GET, "/v2/team/app/manifests/latest").await,
            StatusCode::OK
        );

        // The last tag takes the digest copy and its metadata with it.
        assert_eq!(
            status(&ctx, Method::DELETE, "/v2/team/app/manifests/latest").await,
            StatusCode::ACCEPTED
        );
        let left = ctx.state.storage.list("docker/team/app/manifests/").await;
        assert_eq!(left.unwrap(), Vec::<String>::new());
    }
}

/// R4-R14: a body that is not a schemaVersion 2 JSON object, or whose mediaType is not the
/// request's Content-Type, is 400 MANIFEST_INVALID and nothing is stored.
#[tokio::test]
async fn a_push_that_is_not_a_manifest_is_refused() {
    let ctx = create_test_context();
    ctx.state
        .storage
        .put(&format!("docker/app/blobs/{CFG}"), b"x")
        .await
        .unwrap();
    let schema1 = br#"{"schemaVersion":1,"name":"app"}"#.to_vec();
    let cases: [(Vec<u8>, Option<&str>); 4] = [
        (b"<html>not a manifest</html>".to_vec(), None),
        (b"[1,2]".to_vec(), None),
        (schema1, None),
        (
            manifest(),
            Some("application/vnd.oci.image.manifest.v1+json"),
        ),
    ];
    for (body, content_type) in cases {
        let headers = content_type
            .map(|c| vec![("content-type", c)])
            .unwrap_or_default();
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/v2/app/manifests/latest",
            headers,
            Body::from(body),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(json["errors"][0]["code"], "MANIFEST_INVALID");
    }
    let stored = ctx.state.storage.list("docker/app/manifests/").await;
    assert_eq!(stored.unwrap(), Vec::<String>::new());

    // The manifest's own media type, with a parameter, is accepted.
    let resp = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/v2/app/manifests/latest",
        vec![(
            "content-type",
            "application/vnd.docker.distribution.manifest.v2+json; charset=utf-8",
        )],
        Body::from(manifest()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// R4-R14: the digest copy is written before the tag, so a push whose digest write fails
/// answers 500 with the tag still where it was.
#[tokio::test]
async fn a_push_whose_digest_copy_fails_does_not_move_the_tag() {
    let (storage, counts) = crate::test_helpers::op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    let digest_key = format!("{}.json", digest_of(&manifest()));
    counts.fail_puts_ending(Some(&digest_key));
    assert_eq!(
        push(&ctx, "app", "latest").await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(ctx
        .state
        .storage
        .stat("docker/app/manifests/latest.json")
        .await
        .is_none());
}

async fn proxy_ctx(server: &MockServer) -> TestContext {
    let url = server.uri();
    create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream(url, "up.example")];
    })
}

/// R4-R15: a 200 that is not a manifest, or one over the manifest cap, is a failed upstream:
/// not served and not cached under the tag.
#[tokio::test]
async fn an_upstream_answer_that_is_not_a_manifest_is_not_served_or_cached() {
    let oversized = format!(
        r#"{{"schemaVersion":2,"pad":"{}"}}"#,
        "a".repeat(super::MAX_MANIFEST_BYTES)
    );
    for (content_type, body) in [
        ("text/html", b"<html>login</html>".to_vec()),
        (V2, oversized.into_bytes()),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", content_type)
                    .set_body_bytes(body),
            )
            .mount(&server)
            .await;
        let ctx = proxy_ctx(&server).await;
        let holders = ctx.state.storage.holders();
        assert_eq!(
            status(&ctx, Method::GET, "/v2/library/alpine/manifests/3.20").await,
            StatusCode::BAD_GATEWAY,
            "{content_type}"
        );
        crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
        assert_eq!(
            ctx.state.storage.list("docker/").await.unwrap(),
            Vec::<String>::new()
        );
    }
}

/// R4-R15: a manifest the upstream labels with something that is no manifest media type is
/// served with the type read off the manifest.
#[tokio::test]
async fn an_upstream_manifest_with_a_foreign_content_type_gets_its_own() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_bytes(manifest()),
        )
        .mount(&server)
        .await;
    let ctx = proxy_ctx(&server).await;
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/library/alpine/manifests/3.20",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], V2);
}

/// R4-R16: on the fallback chain the second upstream answers. The tag, the digest copy and
/// both metadata files are all cached under the chain's namespace (its first upstream's),
/// where a pull by digest and the publish-date read look for them.
#[tokio::test]
async fn a_chain_fetch_caches_every_copy_under_one_namespace() {
    let first = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&first)
        .await;
    let second = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/prom/x/manifests/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", V2)
                .set_body_bytes(manifest()),
        )
        .mount(&second)
        .await;
    let (a, b) = (first.uri(), second.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream(a, "first.example"), upstream(b, "second.example")];
    });
    let holders = ctx.state.storage.holders();
    assert_eq!(
        status(&ctx, Method::GET, "/v2/prom/x/manifests/1").await,
        StatusCode::OK
    );
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;

    let digest = digest_of(&manifest());
    let mut keys = ctx.state.storage.list("docker/").await.unwrap();
    keys.sort();
    let dir = "docker/first.example/prom/x/manifests";
    let mut expected = vec![
        format!("{dir}/1.json"),
        format!("{dir}/1.meta.json"),
        format!("{dir}/{digest}.json"),
        format!("{dir}/{digest}.meta.json"),
    ];
    expected.sort();
    assert_eq!(keys, expected);

    // The digest is served from that cache with both upstreams gone.
    drop((first, second));
    assert_eq!(
        status(&ctx, Method::GET, &format!("/v2/prom/x/manifests/{digest}")).await,
        StatusCode::OK
    );
}

async fn tags(ctx: &TestContext, uri: &str) -> (StatusCode, Option<String>, serde_json::Value) {
    let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
    let status = resp.status();
    let link = resp
        .headers()
        .get(header::LINK)
        .map(|v| v.to_str().unwrap().to_string());
    let json = serde_json::from_slice(&body_bytes(resp).await).unwrap_or_default();
    (status, link, json)
}

/// R4-R09: `n` caps the page and a Link names the next one, `last` starts after a tag,
/// `n=0` is an empty list without a Link, a bad `n` is 400.
#[tokio::test]
async fn tags_list_pages_with_n_last_and_link() {
    let ctx = create_test_context();
    for tag in ["c", "a", "b"] {
        assert_eq!(push(&ctx, "team/app", tag).await, StatusCode::CREATED);
    }
    let (status, link, json) = tags(&ctx, "/v2/team/app/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(link, None);
    assert_eq!(json["tags"], serde_json::json!(["a", "b", "c"]));

    let (_, link, json) = tags(&ctx, "/v2/team/app/tags/list?n=2").await;
    assert_eq!(json["tags"], serde_json::json!(["a", "b"]));
    assert_eq!(
        link.as_deref(),
        Some(r#"</v2/team/app/tags/list?n=2&last=b>; rel="next""#)
    );

    let (_, link, json) = tags(&ctx, "/v2/team/app/tags/list?n=2&last=b").await;
    assert_eq!(json["tags"], serde_json::json!(["c"]));
    assert_eq!(link, None);

    let (_, link, json) = tags(&ctx, "/v2/team/app/tags/list?last=a").await;
    assert_eq!(json["tags"], serde_json::json!(["b", "c"]));
    assert_eq!(link, None);

    let (status, link, json) = tags(&ctx, "/v2/team/app/tags/list?n=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tags"], serde_json::json!([]));
    assert_eq!(link, None);

    let (status, _, json) = tags(&ctx, "/v2/team/app/tags/list?n=many").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["errors"][0]["code"], "PAGINATION_NUMBER_INVALID");
}

/// R4-R09: a repository NORA holds nothing of is 404 NAME_UNKNOWN; one that holds only a
/// blob (a push in flight) exists and has no tags.
#[tokio::test]
async fn tags_list_of_an_unknown_repository_is_name_unknown() {
    let ctx = create_test_context();
    let (status, _, json) = tags(&ctx, "/v2/team/typo/tags/list").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["errors"][0]["code"], "NAME_UNKNOWN");

    ctx.state
        .storage
        .put(&format!("docker/team/app/blobs/{CFG}"), b"x")
        .await
        .unwrap();
    let (status, _, json) = tags(&ctx, "/v2/team/app/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tags"], serde_json::json!([]));
}

/// A proxied tag NORA holds: the manifest under the upstream's namespace, as a pull caches it.
async fn cache_proxied_tag(ctx: &TestContext, ns: &str, repo: &str, tag: &str) {
    ctx.state
        .storage
        .put(
            &format!("docker/{ns}/{repo}/manifests/{tag}.json"),
            &manifest(),
        )
        .await
        .unwrap();
}

fn tag_page(tags: &[&str]) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({"name": "x", "tags": tags}))
}

/// R4-R09: a proxied repository lists the upstream's tags (every page the upstream sends)
/// with the ones NORA holds, sorted, and pages the union with `n`, `last` and Link as a
/// local list.
#[tokio::test]
async fn tags_list_of_a_proxied_repository_merges_the_upstream() {
    use wiremock::matchers::{query_param, query_param_is_missing};
    let hub = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/team/app/tags/list"))
        .and(query_param_is_missing("last"))
        .respond_with(
            tag_page(&["d", "b"])
                .insert_header("Link", r#"</v2/team/app/tags/list?last=d&n=2>; rel="next""#),
        )
        .expect(3)
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/team/app/tags/list"))
        .and(query_param("last", "d"))
        .respond_with(tag_page(&["e"]))
        .expect(3)
        .mount(&hub)
        .await;
    let url = hub.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream(url, "hub")];
    });
    cache_proxied_tag(&ctx, "hub", "team/app", "a").await;
    cache_proxied_tag(&ctx, "hub", "team/app", "b").await;

    let (status, link, json) = tags(&ctx, "/v2/team/app/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(link, None);
    assert_eq!(json["tags"], serde_json::json!(["a", "b", "d", "e"]));

    let (_, link, json) = tags(&ctx, "/v2/team/app/tags/list?n=2").await;
    assert_eq!(json["tags"], serde_json::json!(["a", "b"]));
    assert_eq!(
        link.as_deref(),
        Some(r#"</v2/team/app/tags/list?n=2&last=b>; rel="next""#)
    );
    let (_, link, json) = tags(&ctx, "/v2/team/app/tags/list?n=2&last=b").await;
    assert_eq!(json["tags"], serde_json::json!(["d", "e"]));
    assert_eq!(link, None);
}

/// R4-R09: a repository something was pushed to is NORA's own and its tags are local, unless a
/// prefix routes the name to an upstream; a single-segment name is asked as `library/<name>`.
#[tokio::test]
async fn tags_list_asks_the_upstream_only_for_a_proxied_repository() {
    let (hub, mirror) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .and(path("/v2/team/app/tags/list"))
        .respond_with(tag_page(&["hub"]))
        .expect(0)
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/team/app/tags/list"))
        .respond_with(tag_page(&["upstream"]))
        .expect(1)
        .mount(&mirror)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/library/alpine/tags/list"))
        .respond_with(tag_page(&["3.20"]))
        .expect(1)
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/alpine/tags/list"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&hub)
        .await;
    let (url, mirror_url) = (hub.uri(), mirror.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        let mut routed = upstream(mirror_url, "mirror");
        routed.prefix = Some("mirror".into());
        cfg.docker.upstreams = vec![upstream(url, "hub"), routed];
    });
    assert_eq!(push(&ctx, "team/app", "v1").await, StatusCode::CREATED);

    let (status, _, json) = tags(&ctx, "/v2/team/app/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tags"], serde_json::json!(["v1"]));

    let (status, _, json) = tags(&ctx, "/v2/mirror/team/app/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tags"], serde_json::json!(["upstream", "v1"]));

    let (status, _, json) = tags(&ctx, "/v2/alpine/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tags"], serde_json::json!(["3.20"]));
}

/// R4-R09: an upstream that fails leaves the local tags; with none, the answer is the
/// upstream's failure (502 UNAVAILABLE), not 404. An upstream that has no such repository
/// is 404 NAME_UNKNOWN, as a local miss. A next page off the upstream's origin is not
/// followed: NORA's credential would go there.
#[tokio::test]
async fn tags_list_when_the_upstream_fails() {
    let hub = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/team/down/tags/list"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/team/cached/tags/list"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/team/elsewhere/tags/list"))
        .respond_with(tag_page(&["a"]).insert_header(
            "Link",
            r#"<http://other.example/v2/team/elsewhere/tags/list?last=a>; rel="next""#,
        ))
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&hub)
        .await;
    let url = hub.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream(url, "hub")];
    });
    cache_proxied_tag(&ctx, "hub", "team/cached", "1.0").await;

    let (status, _, json) = tags(&ctx, "/v2/team/cached/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tags"], serde_json::json!(["1.0"]));

    for repo in ["team/down", "team/elsewhere"] {
        let (status, _, json) = tags(&ctx, &format!("/v2/{repo}/tags/list")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{repo}");
        assert_eq!(json["errors"][0]["code"], "UNAVAILABLE", "{repo}");
    }

    let (status, _, json) = tags(&ctx, "/v2/team/typo/tags/list").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["errors"][0]["code"], "NAME_UNKNOWN");
}

/// R4-R09: the upstream's answer is kept. With the default `metadata_ttl` every list asks
/// again and a failed ask serves the kept answer (`serve_stale`); within a positive
/// `metadata_ttl` the kept answer is served without asking.
#[tokio::test]
async fn tags_list_keeps_the_upstream_answer() {
    for ttl in [-1, 300] {
        let hub = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/team/app/tags/list"))
            .respond_with(tag_page(&["1.0"]))
            .up_to_n_times(1)
            .expect(1)
            .mount(&hub)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .expect(if ttl > 0 { 0 } else { 1 })
            .mount(&hub)
            .await;
        let url = hub.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![upstream(url, "hub")];
            cfg.docker.metadata_ttl = ttl;
        });
        for _ in 0..2 {
            let (status, _, json) = tags(&ctx, "/v2/team/app/tags/list").await;
            assert_eq!(status, StatusCode::OK, "ttl {ttl}");
            assert_eq!(json["tags"], serde_json::json!(["1.0"]), "ttl {ttl}");
        }
        hub.verify().await;
    }
}

/// R4-R09 (review): a redirect off the upstream's origin is not followed, as a next page off
/// it is not.
#[tokio::test]
async fn tags_list_does_not_follow_a_redirect_off_the_upstream_origin() {
    let (hub, other) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(tag_page(&["elsewhere"]))
        .expect(0)
        .mount(&other)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/team/app/tags/list"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/v2/team/app/tags/list", other.uri())),
        )
        .mount(&hub)
        .await;
    let url = hub.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream(url, "hub")];
    });
    let (status, _, _) = tags(&ctx, "/v2/team/app/tags/list").await;
    assert_ne!(status, StatusCode::OK);
}

/// R4-R09 (review): one upstream without the repository and another failing is not "no such
/// repository": the kept answer is served stale.
#[tokio::test]
async fn tags_list_serves_stale_when_one_upstream_misses_and_another_fails() {
    let (first, second) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&first)
        .await;
    Mock::given(method("GET"))
        .respond_with(tag_page(&["1.0"]))
        .up_to_n_times(1)
        .mount(&second)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&second)
        .await;
    let (a, b) = (first.uri(), second.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream(a, "first"), upstream(b, "second")];
    });
    for _ in 0..2 {
        let (status, _, json) = tags(&ctx, "/v2/team/app/tags/list").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tags"], serde_json::json!(["1.0"]));
    }
}

/// R4-R09 (review): the kept answer is per route. The chain's answer from its second upstream
/// is not the answer of a prefix route to the first upstream alone, though both store under
/// the first upstream's namespace.
#[tokio::test]
async fn tags_list_keeps_answers_per_route() {
    let (first, second) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&first)
        .await;
    Mock::given(method("GET"))
        .respond_with(tag_page(&["from-second"]))
        .mount(&second)
        .await;
    let (a, b) = (first.uri(), second.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        let mut routed = upstream(a, "first");
        routed.prefix = Some("p".into());
        cfg.docker.upstreams = vec![routed, upstream(b, "second")];
        cfg.docker.metadata_ttl = 300;
    });
    let (status, _, json) = tags(&ctx, "/v2/team/app/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tags"], serde_json::json!(["from-second"]));
    let (status, _, json) = tags(&ctx, "/v2/p/team/app/tags/list").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["errors"][0]["code"], "NAME_UNKNOWN");
}

/// R4-R09 (review): a relative next page is resolved against the page that carried it, which a
/// same-origin redirect may have moved.
#[tokio::test]
async fn tags_list_resolves_the_next_page_against_the_redirected_page() {
    use wiremock::matchers::{query_param, query_param_is_missing};
    let hub = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/team/app/tags/list"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            format!("{}/registry/v2/team/app/tags/list", hub.uri()),
        ))
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .and(path("/registry/v2/team/app/tags/list"))
        .and(query_param_is_missing("last"))
        .respond_with(tag_page(&["a"]).insert_header("Link", r#"<?last=a>; rel="next""#))
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .and(path("/registry/v2/team/app/tags/list"))
        .and(query_param("last", "a"))
        .respond_with(tag_page(&["b"]))
        .mount(&hub)
        .await;
    let url = hub.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream(url, "hub")];
    });
    let (status, _, json) = tags(&ctx, "/v2/team/app/tags/list").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["tags"], serde_json::json!(["a", "b"]));
}
