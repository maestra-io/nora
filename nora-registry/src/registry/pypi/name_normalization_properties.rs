// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::normalize_name;
use proptest::prelude::*;

/// PEP 503: `re.sub(r"[-_.]+", "-", name).lower()`.
fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_run {
                out.push('-');
            }
            in_run = true;
        } else {
            out.extend(c.to_lowercase());
            in_run = false;
        }
    }
    out
}

proptest! {
    // Any PEP 508 project name normalizes as PEP 503 says.
    #[test]
    fn a_project_name_normalizes_as_pep_503_says(
        name in "[A-Za-z0-9]([A-Za-z0-9._-]{0,20}[A-Za-z0-9])?"
    ) {
        prop_assert_eq!(normalize_name(&name), pep503(&name));
    }

    // Normalizing twice changes nothing.
    #[test]
    fn normalization_is_idempotent(name in "[A-Za-z0-9._-]{1,24}") {
        let once = normalize_name(&name);
        prop_assert_eq!(normalize_name(&once), once);
    }
}

// An upload under a name with a run of separators is listed under the key pip asks for.
#[tokio::test]
async fn an_upload_is_listed_under_the_name_pip_asks_for() {
    use super::local_index_cost_tests::{upload_body, BOUNDARY};
    use crate::test_helpers::{body_bytes, create_test_context, send_with_headers};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context();
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let filename = "foo_bar-1.0-py3-none-any.whl";
    let body = upload_body("Foo__Bar", "1.0", filename, b"wheel");
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/simple/",
        vec![("content-type", content_type.as_str())],
        body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/foo-bar/",
        vec![("accept", "text/html")],
        Vec::new(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(html.contains(filename), "{html}");
}

#[test]
fn a_run_of_separators_is_one_dash() {
    for (name, normalized) in [
        ("foo__bar", "foo-bar"),
        ("Foo._-Bar", "foo-bar"),
        ("a--b", "a-b"),
    ] {
        assert_eq!(normalize_name(name), normalized, "{name}");
    }
}
