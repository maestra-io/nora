// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{create_test_context_with_config, send, upstream_paths};
use axum::http::Method;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

// maven-resolver writes metadata at three levels: `group/maven-metadata.xml`,
// `group/artifact/maven-metadata.xml` and `group/artifact/version/maven-metadata.xml`
// (resolver 1.9.27 `Maven2RepositoryLayoutFactory.java:196-213`; testdata/maven/layout.tsv),
// and Maven reads the version level for a snapshot before its files
// (testdata/maven/client-requests.tsv: `org/example/snap/1.0-SNAPSHOT/maven-metadata.xml`).
// `com/mycorp/lib/1.0-SNAPSHOT/maven-metadata.xml` is metadata of `com.mycorp:lib`.
#[tokio::test]
async fn version_metadata_of_an_internal_artifact_is_not_asked_upstream() {
    for pattern in ["com.mycorp:*", "com.mycorp:lib"] {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<metadata><groupId>com.mycorp</groupId><artifactId>lib</artifactId><version>1.0-SNAPSHOT</version></metadata>",
            ))
            .mount(&up)
            .await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(uri)];
            cfg.curation.internal_namespaces = vec![pattern.to_string()];
        });
        for path in [
            "/maven2/com/mycorp/lib/maven-metadata.xml",
            "/maven2/com/mycorp/lib/1.0-SNAPSHOT/lib-1.0-20261012.120000-1.jar",
            "/maven2/com/mycorp/lib/1.0-SNAPSHOT/maven-metadata.xml",
            "/maven2/com/mycorp/lib/1.0-SNAPSHOT/maven-metadata.xml.sha1",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            let sent = upstream_paths(&up).await;
            assert!(
                sent.is_empty(),
                "{pattern} {path}: {} sent {sent:?}",
                resp.status()
            );
        }
    }
}

// The group level, `com/mycorp/maven-metadata.xml`, is metadata of the group `com.mycorp`
// (the plugins it holds): a namespace on the whole group holds for it, one on a single
// artifact does not, and that twin shows the path does reach the upstream.
#[tokio::test]
async fn group_metadata_of_an_internal_group_is_not_asked_upstream() {
    for (pattern, internal) in [
        ("com.mycorp:*", true),
        ("com.mycorp.**", true),
        ("com.mycorp:lib", false),
    ] {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<metadata><plugins/></metadata>"),
            )
            .mount(&up)
            .await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(uri)];
            cfg.curation.internal_namespaces = vec![pattern.to_string()];
        });
        let path = "/maven2/com/mycorp/maven-metadata.xml";
        let resp = send(&ctx.app, Method::GET, path, "").await;
        let sent = upstream_paths(&up).await;
        assert_eq!(
            sent.is_empty(),
            internal,
            "{pattern} {path}: {} sent {sent:?}",
            resp.status()
        );
    }
}
