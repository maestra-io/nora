// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::http::header;
use axum::response::IntoResponse;

/// Embedded Tailwind CSS (purged, minified)
const TAILWIND_CSS: &str = include_str!("static/tailwind.css");

/// Embedded htmx 1.9.10 (minified)
const HTMX_JS: &str = include_str!("static/htmx.min.js");

/// The sidebar's "N◯RA" ring as an icon, served for `/favicon.ico` too.
const FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#1e293b"/><circle cx="16" cy="16" r="9" fill="none" stroke="#e2e8f0" stroke-width="4"/></svg>"##;

pub async fn serve_tailwind_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        TAILWIND_CSS,
    )
}

pub async fn serve_htmx_js() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        HTMX_JS,
    )
}

pub async fn serve_favicon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        FAVICON_SVG,
    )
}
