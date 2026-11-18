// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::apply_security_headers;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

async fn header_of(app: &Router, path: &str, name: &str) -> Option<String> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_string())
}

// A handler that sets its own CSP (the raw download handler, `sandbox`) keeps it; a handler
// that sets none gets the permissive UI default. The default must not override a stricter
// handler policy, or raw's user-uploaded bytes would run under the UI's `unsafe-inline`.
#[tokio::test]
async fn a_handler_csp_survives_the_default() {
    let app = apply_security_headers(
        Router::<()>::new()
            .route(
                "/raw-like",
                get(|| async { ([(header::CONTENT_SECURITY_POLICY, "sandbox")], "bytes") }),
            )
            .route("/ui-like", get(|| async { "page" })),
    );
    assert_eq!(
        header_of(&app, "/raw-like", "content-security-policy").await,
        Some("sandbox".to_string())
    );
    let default = header_of(&app, "/ui-like", "content-security-policy")
        .await
        .expect("a route without its own CSP gets the default");
    assert!(
        default.contains("script-src 'self' 'unsafe-inline'"),
        "default UI CSP expected, got {default}"
    );
    // nosniff is uniform and overrides, on both.
    for path in ["/raw-like", "/ui-like"] {
        assert_eq!(
            header_of(&app, path, "x-content-type-options").await,
            Some("nosniff".to_string())
        );
    }
}

// B08: HSTS on every route, without includeSubDomains (an apex deployment would pin its
// sibling hosts), and a handler's own value wins.
#[tokio::test]
async fn hsts_is_set_on_every_route_without_subdomains() {
    let app = apply_security_headers(
        Router::<()>::new()
            .route("/ui-like", get(|| async { "page" }))
            .route(
                "/own",
                get(|| async { ([(header::STRICT_TRANSPORT_SECURITY, "max-age=60")], "x") }),
            ),
    );
    assert_eq!(
        header_of(&app, "/ui-like", "strict-transport-security").await,
        Some("max-age=31536000".to_string())
    );
    assert_eq!(
        header_of(&app, "/own", "strict-transport-security").await,
        Some("max-age=60".to_string())
    );
}

mod authenticated_caching {
    use crate::test_helpers::*;
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sha2::Digest;

    const PEP691_JSON: &str = "application/vnd.pypi.simple.v1+json";

    fn basic() -> String {
        format!("Basic {}", STANDARD.encode("u:p"))
    }

    async fn get_as(
        ctx: &TestContext,
        uri: &str,
        auth: Option<&str>,
        accept: Option<&str>,
    ) -> axum::http::Response<Body> {
        let mut headers = Vec::new();
        if let Some(a) = auth {
            headers.push(("authorization", a));
        }
        if let Some(a) = accept {
            headers.push(("accept", a));
        }
        send_with_headers(&ctx.app, Method::GET, uri, headers, "").await
    }

    fn cache_control(resp: &axum::http::Response<Body>) -> String {
        resp.headers()
            .get(header::CACHE_CONTROL)
            .expect("cache-control")
            .to_str()
            .unwrap()
            .to_string()
    }

    fn assert_private(resp: &axum::http::Response<Body>, uri: &str) {
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let cc = cache_control(resp);
        assert!(cc.contains("private"), "{uri}: {cc}");
        assert!(!cc.contains("public"), "{uri}: {cc}");
    }

    // A084: an authenticated answer is never `public`; the other directives stay.
    #[tokio::test]
    async fn authenticated_downloads_are_private() {
        let ctx = create_test_context_with_auth(&[("u", "p")]);
        let auth = basic();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"tarball")
            .await
            .unwrap();
        let jar = "/maven2/com/example/lib/1.0/lib-1.0.jar";
        let put = send_with_headers(
            &ctx.app,
            Method::PUT,
            jar,
            vec![("authorization", auth.as_str())],
            Body::from(&b"jar"[..]),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"blob")));
        let post = send_with_headers(
            &ctx.app,
            Method::POST,
            &format!("/v2/team/app/blobs/uploads/?digest={digest}"),
            vec![("authorization", auth.as_str())],
            Body::from(&b"blob"[..]),
        )
        .await;
        assert_eq!(post.status(), StatusCode::CREATED);

        for uri in [
            "/simple/flask/flask-2.0.tar.gz".to_string(),
            jar.to_string(),
            format!("/v2/team/app/blobs/{digest}"),
        ] {
            let resp = get_as(&ctx, &uri, Some(&auth), None).await;
            assert_private(&resp, &uri);
            let cc = cache_control(&resp);
            assert!(cc.contains("max-age=31536000"), "{uri}: {cc}");
            assert!(cc.contains("immutable"), "{uri}: {cc}");
        }
        // The 401 without a credential is unchanged.
        let resp = get_as(&ctx, jar, None, None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // A084: the PyPI index pages answer HTML or JSON by Accept, so they say so.
    #[tokio::test]
    async fn pypi_index_pages_are_private_and_vary_on_accept() {
        let ctx = create_test_context_with_auth(&[("u", "p")]);
        let auth = basic();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"tarball")
            .await
            .unwrap();
        for uri in ["/simple/", "/simple/flask/"] {
            for accept in ["text/html", PEP691_JSON] {
                let resp = get_as(&ctx, uri, Some(&auth), Some(accept)).await;
                // The per-project page sends no Cache-Control at all; the index sends one.
                if uri == "/simple/" || resp.headers().contains_key(header::CACHE_CONTROL) {
                    assert_private(&resp, uri);
                }
                assert_eq!(resp.status(), StatusCode::OK, "{uri}");
                let vary = resp
                    .headers()
                    .get(header::VARY)
                    .map(|v| v.to_str().unwrap().to_string())
                    .unwrap_or_default();
                assert!(vary.contains("Accept"), "{uri} {accept}: vary={vary}");
            }
        }
    }

    // A084: under anonymous_read an anonymous read stays `public`; the same read with a
    // credential does not.
    #[tokio::test]
    async fn anonymous_reads_stay_public() {
        let ctx = create_test_context_with_anonymous_read(&[("u", "p")]);
        let auth = basic();
        let jar = "/maven2/com/example/lib/1.0/lib-1.0.jar";
        let put = send_with_headers(
            &ctx.app,
            Method::PUT,
            jar,
            vec![("authorization", auth.as_str())],
            Body::from(&b"jar"[..]),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);
        let resp = get_as(&ctx, jar, None, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(cache_control(&resp).contains("public"));
        let resp = get_as(&ctx, jar, Some(&auth), None).await;
        assert_private(&resp, jar);
    }

    // A084 / review R17: the bypass token is honoured with auth off too, so its answer is
    // `private` there as well; a plain read with auth off stays `public`.
    #[tokio::test]
    async fn bypass_answers_are_private_with_auth_off() {
        let ctx = create_test_context();
        assert!(!ctx.state.config.auth.enabled);
        let jar = "/maven2/com/example/lib/1.0/lib-1.0.jar";
        let put = send(&ctx.app, Method::PUT, jar, Body::from(&b"jar"[..])).await;
        assert_eq!(put.status(), StatusCode::CREATED);
        let resp = get_as(&ctx, jar, None, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(cache_control(&resp).contains("public"));
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            jar,
            vec![("x-nora-bypass-token", "dummy-token")],
            "",
        )
        .await;
        assert_private(&resp, jar);
    }
}
