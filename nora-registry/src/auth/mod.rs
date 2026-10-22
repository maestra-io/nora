// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Authentication module — middleware, providers, and token routes.
//!
//! Supports:
//! - Basic auth via htpasswd files
//! - Bearer token auth (opaque tokens with Argon2 verification)
//! - Brute-force protection with exponential backoff

mod htpasswd;
mod namespace;
pub mod oidc;
pub mod teleport;
mod token_routes;

pub use htpasswd::HtpasswdAuth;
pub use namespace::{enforce_namespace_scope, NamespaceAuthority};
pub use oidc::OidcValidator;
pub use teleport::TeleportValidator;
pub use token_routes::{token_routes, TokenListItem, TokenListResponse};

/// Authenticated username carried in request extensions after successful auth.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser(pub String);

/// The verified role carried in request extensions after successful auth.
/// Basic-auth (htpasswd) identities are recorded as `Write`, or `Read` when
/// listed in `auth.read_only_users`, never admin, so role-gated owner-scope
/// treats them as non-admin.
#[derive(Clone, Debug)]
pub struct AuthenticatedRole(pub crate::tokens::Role);

/// The lifetime ceiling (seconds) the caller's own credential imposes on any
/// token it mints. Inserted ONLY for OIDC identities — the provider's
/// `max_token_lifetime_secs`, which already bounds the JWT itself. Absent for
/// Basic and opaque (`nra_`) callers, which carry no such ceiling. A UI mint
/// reads it to cap the new token so a short-lived federated identity cannot
/// bootstrap a long-lived static one (#1094).
#[derive(Clone, Copy, Debug)]
pub struct MintLifetimeCeiling(pub u64);

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::AppState;

/// Resolve the audit actor for a request-driven event (#985): the authenticated
/// username, or `anonymous` when the request carries no identity. Write handlers
/// take `user: Option<axum::Extension<AuthenticatedUser>>` (which never fails to
/// extract) and pass this to `AuditEntry::new` instead of a hardcoded actor.
pub fn audit_actor(user: &Option<axum::Extension<AuthenticatedUser>>) -> &str {
    match user {
        Some(axum::Extension(AuthenticatedUser(name))) => name,
        None => "anonymous",
    }
}

/// Tracks failed password attempts per client IP and username for brute-force
/// protection.
///
/// After `max_failures` consecutive failures, that username from that IP is locked
/// out with exponential backoff: 2^(failures - max_failures) seconds, capped at 15
/// minutes. Keyed per username so one stale password behind a shared NAT or SNAT-ed
/// runner pool never locks out the other users behind it. Only guessable
/// credentials (htpasswd passwords) are tracked: an `nra_` token or a JWT cannot be
/// brute-forced, so a Bearer credential is never refused by the lockout.
pub struct AuthFailureTracker {
    /// (IP, username hash) -> (consecutive failures, last failure time, a 429 of
    /// the current lockout already logged). The hash keeps an entry fixed-size
    /// whatever username a client sends.
    entries: parking_lot::Mutex<HashMap<(IpAddr, u64), (u32, Instant, bool)>>,
    user_hasher: std::collections::hash_map::RandomState,
    /// Number of failures before lockout kicks in (default: 5)
    max_failures: u32,
    /// Maximum lockout duration in seconds (default: 900 = 15 minutes)
    max_lockout_secs: u64,
}

impl AuthFailureTracker {
    pub fn new(max_failures: u32, max_lockout_secs: u64) -> Self {
        Self {
            entries: parking_lot::Mutex::new(HashMap::new()),
            user_hasher: Default::default(),
            max_failures,
            max_lockout_secs,
        }
    }

    fn key(&self, ip: IpAddr, user: &str) -> (IpAddr, u64) {
        use std::hash::BuildHasher;
        (ip, self.user_hasher.hash_one(user))
    }

    /// Check if `user` from `ip` is currently locked out. Returns remaining lockout
    /// seconds if blocked.
    pub fn check_blocked(&self, ip: &IpAddr, user: &str) -> Option<u64> {
        let entries = self.entries.lock();
        let (failures, last_failure, _) = entries.get(&self.key(*ip, user))?;
        if *failures < self.max_failures {
            return None;
        }
        let lockout_secs = self.lockout_secs(*failures);
        let elapsed = last_failure.elapsed().as_secs();
        if elapsed < lockout_secs {
            Some(lockout_secs - elapsed)
        } else {
            None
        }
    }

    /// Lockout length after `failures` consecutive failures (`failures >= max_failures`).
    fn lockout_secs(&self, failures: u32) -> u64 {
        let exponent = (failures - self.max_failures).min(20);
        (1u64 << exponent).min(self.max_lockout_secs)
    }

    /// Record a failed auth attempt of `user` from `ip`. Returns the lockout length
    /// when this failure starts a lockout. A locked-out pair is refused before its
    /// credentials are checked, so every failure at or past the threshold starts a
    /// new (longer) lockout: one WARN per lockout, never one per 429.
    pub fn record_failure(&self, ip: IpAddr, user: &str) -> Option<u64> {
        let failures = {
            let mut entries = self.entries.lock();
            let entry = entries
                .entry(self.key(ip, user))
                .or_insert_with(|| (0, Instant::now(), false));
            entry.0 += 1;
            entry.1 = Instant::now();
            entry.2 = false;
            entry.0
        };
        if failures < self.max_failures {
            return None;
        }
        let lockout_secs = self.lockout_secs(failures);
        crate::metrics::AUTH_LOCKOUTS_TOTAL.inc();
        let username: String = user.chars().take(64).collect();
        tracing::warn!(
            client_ip = %ip,
            username = %username,
            failures,
            lockout_secs,
            "auth lockout: too many failed Basic logins, answering 429"
        );
        Some(lockout_secs)
    }

    /// True for the first 429 of the current lockout of `user` from `ip`: the
    /// refusals of one lockout are logged once, not once per request.
    pub fn first_refusal(&self, ip: &IpAddr, user: &str) -> bool {
        let mut entries = self.entries.lock();
        entries
            .get_mut(&self.key(*ip, user))
            .is_some_and(|e| !std::mem::replace(&mut e.2, true))
    }

    /// Clear the failure count of `user` from `ip` on successful auth.
    pub fn record_success(&self, ip: &IpAddr, user: &str) {
        let mut entries = self.entries.lock();
        entries.remove(&self.key(*ip, user));
    }

    /// Remove entries older than max_lockout_secs (call periodically).
    pub fn cleanup(&self) {
        let mut entries = self.entries.lock();
        entries.retain(|_, (_, last, _)| last.elapsed().as_secs() < self.max_lockout_secs * 2);
    }
}

/// Check if path is public (no auth required)
/// Paths that are public UNCONDITIONALLY: probes (a gated /health takes the
/// whole deployment down behind an LB) and the token endpoints, which do
/// their own credential handling.
fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/" | "/health" | "/ready" | "/api/tokens" | "/api/tokens/list" | "/api/tokens/revoke"
    ) || is_static_asset(path)
}

/// The UI's embedded assets and the favicon: no data, served to any caller, also
/// under `auth.teleport.require_for_ui` (a browser fetches `/favicon.ico` without
/// the app session, so it logged a 401 per page load).
fn is_static_asset(path: &str) -> bool {
    matches!(
        path,
        "/favicon.ico"
            | "/ui/static/favicon.svg"
            | "/ui/static/tailwind.css"
            | "/ui/static/htmx.min.js"
    )
}

/// The browse web surface: UI pages, their JSON API, and the API docs. All
/// of it enumerates repositories and packages, so under an auth-enabled
/// deployment it is gated unless `anonymous_read` or `public_web_ui` opens
/// it (token-management pages stay ALWAYS gated — they were before, too).
fn is_web_surface(path: &str) -> bool {
    if path.starts_with("/ui/tokens") || path.starts_with("/api/ui/tokens") {
        return false;
    }
    path.starts_with("/ui") || path.starts_with("/api/ui") || path.starts_with("/api-docs")
}

/// Check if a path belongs to the Docker/OCI registry (`/v2`, `/v2/…`).
///
/// Docker anonymous access is governed by `docker_anon_pull` (separate from
/// the general `anonymous_read`), so all `/v2` paths are matched as one group:
/// the `/v2/` auth-challenge ping and every manifest/blob/tag endpoint. Per the
/// Docker Registry V2 spec, an unauthenticated `GET /v2/` returns 401 with a
/// WWW-Authenticate header (so clients send credentials) UNLESS anonymous Docker
/// pull is explicitly enabled.
fn is_docker_path(path: &str) -> bool {
    path == "/v2" || path.starts_with("/v2/")
}

/// Check if path is an admin-only control-plane endpoint.
///
/// Admin paths require a token whose role satisfies `can_admin()` regardless of
/// HTTP method, and are never served anonymously (not even under
/// `anonymous_read`). Basic-auth has no role concept, so it can never satisfy
/// an admin path — it is denied fail-closed. Scoped strictly to `/api/v1/admin/`
/// so it never widens the privilege bar of existing routes (e.g. `/raw/-/reindex`
/// stays at write-level).
fn is_admin_path(path: &str) -> bool {
    path.starts_with("/api/v1/admin/")
}

/// Extract client IP from request, honoring XFF/X-Real-IP only from trusted proxies.
///
/// If the direct peer IP is not in `trusted_proxies`, XFF/X-Real-IP headers are
/// ignored and the peer IP is returned. This prevents attackers from spoofing
/// their IP to bypass `AuthFailureTracker` lockout.
pub(crate) fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &crate::config::TrustedProxies,
) -> IpAddr {
    // One key per client whether it arrived over IPv4 or as `::ffff:` on a
    // dual-stack listener (or was written that way by a proxy).
    let peer = crate::config::canonical_ip(peer);
    if !trusted_proxies.contains(peer) {
        if headers.contains_key("x-forwarded-for") {
            warn_untrusted_forwarded_once(peer);
        }
        return peer;
    }

    if let Some(ip) = forwarded_for_client(headers, trusted_proxies) {
        return ip;
    }
    // Try X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(s) = xri.to_str() {
            if let Ok(ip) = s.trim().parse::<IpAddr>() {
                return crate::config::canonical_ip(ip);
            }
        }
    }
    // No forwarding headers — use peer IP
    peer
}

/// Warn once per process when a peer outside `trusted_proxies` sends X-Forwarded-For.
///
/// Behind a reverse proxy that is not listed, every client shares the proxy's IP for
/// the auth lockout and the rate limiters; this is the only signal of that misconfig.
fn warn_untrusted_forwarded_once(peer: IpAddr) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            peer = %peer,
            "X-Forwarded-For from a peer outside auth.trusted_proxies is ignored: auth lockout \
             and rate limits key on the peer IP. If NORA runs behind a reverse proxy, add it to \
             NORA_AUTH_TRUSTED_PROXIES, or every client shares one lockout/rate-limit bucket"
        );
    });
}

/// The client X-Forwarded-For names, read from the right. Each proxy appends the address it
/// received the request from, so the left part of the header is whatever the client sent: the
/// client is the rightmost address that is not a trusted proxy, or the leftmost when every
/// address is one. An entry that is not an address ends the walk at the hop that wrote it. Every
/// header line counts, in order; `None` when no entry is readable.
fn forwarded_for_client(
    headers: &HeaderMap,
    trusted_proxies: &crate::config::TrustedProxies,
) -> Option<IpAddr> {
    let entries: Vec<&[u8]> = headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|line| line.as_bytes().split(|b| *b == b','))
        .collect();
    let mut nearest = None;
    for entry in entries.into_iter().rev() {
        let Some(ip) = std::str::from_utf8(entry)
            .ok()
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .map(crate::config::canonical_ip)
        else {
            break;
        };
        if !trusted_proxies.contains(ip) {
            return Some(ip);
        }
        nearest = Some(ip);
    }
    nearest
}

fn extract_client_ip(
    request: &Request<Body>,
    trusted_proxies: &crate::config::TrustedProxies,
) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())?;
    Some(resolve_client_ip(peer, request.headers(), trusted_proxies))
}

/// Insert the anonymous identity (read-only role, unrestricted namespace) and
/// run the downstream handler. Shared by the `anonymous_read` (non-Docker) and
/// `docker_anon_pull` (Docker `/v2`) bypass paths.
async fn anonymous_read_passthrough(mut request: Request<Body>, next: Next) -> Response {
    request
        .extensions_mut()
        .insert(NamespaceAuthority::Unrestricted);
    request
        .extensions_mut()
        .insert(AuthenticatedUser("anonymous".to_string()));
    request
        .extensions_mut()
        .insert(AuthenticatedRole(crate::tokens::Role::Read));
    next.run(request).await
}

/// Why `authenticate` refused a presented credential. Put on the response at the
/// refusal; `auth_middleware` logs it with the request context. Never a secret.
#[derive(Clone)]
struct AuthRejection {
    /// Bounded: wrong_password, token_invalid, malformed, basic_not_configured,
    /// no_oidc, locked_out, or an OIDC class from `oidc::classify_rejection`.
    reason: &'static str,
    /// Counted in `nora_auth_oidc_rejected_total` already.
    oidc: bool,
    /// Off for the repeated 429s of one lockout (counted, not logged).
    log: bool,
    retry_after: Option<u64>,
    /// The OIDC validator's error text (no token material).
    detail: Option<String>,
    /// `sub` and `repository` of a well-formed JWT refused for expiry or audience,
    /// read WITHOUT signature verification: names the CI job, proves nothing.
    unverified_claims: Option<(String, String)>,
}

impl AuthRejection {
    fn new(reason: &'static str) -> Self {
        Self {
            reason,
            oidc: false,
            log: true,
            retry_after: None,
            detail: None,
            unverified_claims: None,
        }
    }

    fn on(self, mut response: Response) -> Response {
        response.extensions_mut().insert(self);
        response
    }
}

/// The credential a request presented, read before `authenticate` rewrites
/// headers. `None` = no credential (the anonymous NuGet/Docker challenge round:
/// never logged). `kind` is bounded; `username` is the Basic user, truncated.
fn presented_credential(request: &Request<Body>) -> Option<(&'static str, Option<String>)> {
    let headers = request.headers();
    let Some(auth) = headers.get(header::AUTHORIZATION) else {
        let nuget_key =
            request.uri().path().starts_with("/nuget/") && headers.contains_key("x-nuget-apikey");
        return nuget_key.then_some(("x_nuget_apikey", None));
    };
    let auth = auth.to_str().unwrap_or("");
    if let Some(token) = auth.strip_prefix("Bearer ") {
        let kind = if token.trim().starts_with("nra_") {
            "bearer_nra"
        } else {
            "bearer_jwt"
        };
        return Some((kind, None));
    }
    let Some((user, password)) = auth
        .strip_prefix("Basic ")
        .and_then(|e| STANDARD.decode(e.trim()).ok())
        .and_then(|d| String::from_utf8(d).ok())
        .and_then(|c| {
            c.split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        })
    else {
        return Some(("malformed", None));
    };
    let kind = if password.starts_with("nra_") {
        "basic_nra"
    } else if password.starts_with("eyJ") && password.split('.').count() == 3 {
        "basic_jwt"
    } else {
        "basic_htpasswd"
    };
    Some((kind, Some(user.chars().take(64).collect())))
}

/// `sub` and `repository` of a JWT, decoded WITHOUT verifying the signature.
/// Only for logging a token already refused for expiry or audience.
fn unverified_ci_claims(token: &str) -> Option<(String, String)> {
    #[derive(serde::Deserialize)]
    struct Ci {
        sub: Option<String>,
        repository: Option<String>,
    }
    // Same order of size as the largest real CI token (GitHub ~1.5 KB).
    if token.len() > 16 * 1024 {
        return None;
    }
    let ci = jsonwebtoken::dangerous::insecure_decode::<Ci>(token)
        .ok()?
        .claims;
    let cut = |v: Option<String>| v.unwrap_or_default().chars().take(128).collect();
    Some((cut(ci.sub), cut(ci.repository)))
}

/// Auth middleware - supports Basic auth, Bearer tokens, OIDC JWT and (Maestra
/// fork) Teleport app-access JWT on the web UI.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Maestra: with the UI behind Teleport, a browser never gets a Basic
    // challenge, so no password dialog on the public hostname.
    let drop_challenge = state.teleport.as_ref().is_some_and(|t| t.require_for_ui())
        && teleport::is_browser(request.headers());
    let presented = presented_credential(&request);
    let client_ip = extract_client_ip(&request, &state.config.auth.trusted_proxies);
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let mut response = authenticate(state, request, next).await;
    if let Some(rej) = response.extensions_mut().remove::<AuthRejection>() {
        if let Some((kind, username)) = presented {
            log_rejection(&rej, kind, username.as_deref(), client_ip, &method, &path);
        }
    }
    if drop_challenge && response.status() == StatusCode::UNAUTHORIZED {
        response.headers_mut().remove(header::WWW_AUTHENTICATE);
    }
    response
}

fn log_rejection(
    rej: &AuthRejection,
    kind: &'static str,
    username: Option<&str>,
    client_ip: Option<IpAddr>,
    method: &axum::http::Method,
    path: &str,
) {
    if !rej.oidc {
        crate::metrics::AUTH_REJECTED_TOTAL
            .with_label_values(&[kind, rej.reason])
            .inc();
    }
    if !rej.log {
        return;
    }
    let (sub, repository) = rej.unverified_claims.clone().unwrap_or_default();
    tracing::warn!(
        client_ip = %client_ip.map_or_else(|| "-".to_string(), |ip| ip.to_string()),
        kind,
        reason = rej.reason,
        username = username.unwrap_or("-"),
        method = %method,
        path,
        retry_after = rej.retry_after.unwrap_or(0),
        detail = rej.detail.as_deref().unwrap_or("-"),
        unverified_sub = sub.as_str(),
        unverified_repository = repository.as_str(),
        "auth rejected: credential refused"
    );
}

async fn authenticate(state: AppState, mut request: Request<Body>, next: Next) -> Response {
    // Skip auth if disabled (neither htpasswd nor OIDC configured)
    if !state.config.auth.enabled {
        request
            .extensions_mut()
            .insert(NamespaceAuthority::Unrestricted);
        request
            .extensions_mut()
            .insert(AuthenticatedUser("anonymous".to_string()));
        return next.run(request).await;
    }

    // Maestra: the web UI takes its identity from Teleport app access
    // (auth/teleport.rs); registry paths never look at the Teleport header.
    if let Some(teleport) = state.teleport.as_deref() {
        let path = request.uri().path();
        if teleport::is_ui_path(path) && !is_static_asset(path) {
            let jwt = teleport.trusted_header(&request);
            let id = match jwt {
                Some(jwt) => teleport.identify(&jwt).await,
                None => None,
            };
            if let Some(id) = id {
                request
                    .extensions_mut()
                    .insert(NamespaceAuthority::Unrestricted);
                request
                    .extensions_mut()
                    .insert(AuthenticatedUser(id.username));
                request.extensions_mut().insert(AuthenticatedRole(id.role));
                return next.run(request).await;
            }
            if teleport.require_for_ui() {
                return teleport::ui_only_response();
            }
        }
    }

    // Maestra: htpasswd passwords only from auth.htpasswd_allowed_peers (TCP
    // peer). Elsewhere no password is checked (no bcrypt reachable), the
    // password token-mint routes are refused, and Basic carries tokens/JWTs only.
    let htpasswd_peer_ok = match &state.config.auth.htpasswd_allowed_peers {
        None => true,
        Some(allowed) => request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|ci| allowed.contains(ci.0.ip())),
    };
    if !htpasswd_peer_ok && request.uri().path().starts_with("/api/tokens") {
        return (
            StatusCode::FORBIDDEN,
            "Password authentication is not accepted from this address",
        )
            .into_response();
    }
    let htpasswd = state.auth.as_deref().filter(|_| htpasswd_peer_ok);

    // NuGet clients send the push/delete credential as `X-NuGet-ApiKey`, never as
    // Authorization (#983): verify it as a Bearer credential (nra_ token or OIDC JWT).
    if request.uri().path().starts_with("/nuget/")
        && !request.headers().contains_key(header::AUTHORIZATION)
    {
        if let Some(bearer) = request
            .headers()
            .get("x-nuget-apikey")
            .and_then(|k| k.to_str().ok())
            .and_then(|k| axum::http::HeaderValue::from_str(&format!("Bearer {}", k.trim())).ok())
        {
            request.headers_mut().insert(header::AUTHORIZATION, bearer);
        }
    }
    // Workload identity over Basic: NuGet `packageSourceCredentials`, BuildKit secrets,
    // twine and docker only speak Basic. A Basic password that is an API token or a JWT
    // is verified exactly as the same credential sent as Bearer (same role_rules,
    // namespace_scope and audit identity); the Basic username is ignored. An nra_
    // password takes this shortcut only where no htpasswd applies to the peer (the
    // production shape, auth.htpasswd_allowed_peers): with htpasswd, the Basic path
    // checks htpasswd first and the token store second (#1094 order), so a
    // password that merely looks like a token cannot borrow a token's identity.
    let nra_shortcut = htpasswd.is_none() && state.tokens.is_some();
    if let Some(bearer) = basic_token_as_bearer(request.headers(), nra_shortcut) {
        request.headers_mut().insert(header::AUTHORIZATION, bearer);
    }

    // Skip auth for public endpoints
    {
        let path = request.uri().path();
        // Unconditional publics (probes, token endpoints), plus the web
        // surface and /metrics when the config opens them. The web surface
        // enumerates every repository, so it follows `anonymous_read` (the
        // registry read APIs would expose the same names) or the explicit
        // `public_web_ui` escape; /metrics has its own default-open switch —
        // labels carry registry formats, not repository names.
        let config = &state.config.auth;
        // `npm login` / `npm adduser`: the npm handler only answers how to set up a
        // token, and the client that needs that answer has no credentials yet.
        let npm_login =
            *request.method() == axum::http::Method::PUT && path.starts_with("/npm/-/user/");
        let open = is_public_path(path)
            || npm_login
            || (is_web_surface(path) && (config.anonymous_read || config.public_web_ui))
            || (path == "/metrics" && config.public_metrics);
        // Probes and metrics never validate credentials: a Basic header there
        // would buy any client an unlimited, unauthenticated bcrypt per request.
        let is_probe = matches!(path, "/health" | "/ready" | "/metrics");
        if open {
            // Opportunistic auth: if the caller provided credentials on an
            // open path, try to validate them so downstream handlers can
            // distinguish "anonymous browse" from "authenticated browse"
            // (e.g. to gate proxy_upstreams disclosure). If validation fails
            // we fall through to anonymous — the path is open regardless.
            let client_ip = extract_client_ip(&request, &state.config.auth.trusted_proxies);
            let mut open_rejection = None;
            if let Some(auth_val) = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .filter(|_| !is_probe)
            {
                if let Some(encoded) = auth_val.strip_prefix("Basic ") {
                    // A locked-out username is not validated (no bcrypt) on the open path.
                    let lockout_key = client_ip.zip(basic_username(encoded));
                    let retry_after = lockout_key
                        .as_ref()
                        .and_then(|(ip, user)| state.auth_failures.check_blocked(ip, user));
                    let blocked = retry_after.is_some();
                    let identity = match blocked {
                        true => None,
                        false => try_basic_auth(encoded, &state, htpasswd).await,
                    };
                    if let Some((username, role)) = identity {
                        request
                            .extensions_mut()
                            .insert(NamespaceAuthority::Unrestricted);
                        request.extensions_mut().insert(AuthenticatedUser(username));
                        request.extensions_mut().insert(AuthenticatedRole(role));
                        return next.run(request).await;
                    }
                    // A wrong Basic credential counts toward lockout here too,
                    // or the open path is an unthrottled password oracle.
                    open_rejection = Some(match (&lockout_key, retry_after) {
                        (Some((ip, user)), Some(secs)) => AuthRejection {
                            log: state.auth_failures.first_refusal(ip, user),
                            retry_after: Some(secs),
                            ..AuthRejection::new("locked_out")
                        },
                        _ => AuthRejection::new("wrong_password"),
                    });
                    if let Some((ip, user)) = lockout_key.filter(|_| !blocked) {
                        state.auth_failures.record_failure(ip, &user);
                    }
                } else if let Some(token) = auth_val.strip_prefix("Bearer ") {
                    if let Some(ref token_store) = state.tokens {
                        if let Ok((user, role)) = token_store.verify_token(token).await {
                            request
                                .extensions_mut()
                                .insert(NamespaceAuthority::Unrestricted);
                            request.extensions_mut().insert(AuthenticatedUser(user));
                            request.extensions_mut().insert(AuthenticatedRole(role));
                            return next.run(request).await;
                        }
                    }
                }
            }
            // No credentials or validation failed — anonymous browse
            let mut request = request;
            request
                .extensions_mut()
                .insert(NamespaceAuthority::Unrestricted);
            request
                .extensions_mut()
                .insert(AuthenticatedUser("anonymous".to_string()));
            let response = next.run(request).await;
            return match open_rejection {
                Some(rejection) => rejection.on(response),
                None => response,
            };
        }
        // A gated web-surface request without credentials gets a Basic
        // challenge so browsers prompt instead of rendering a bare 401.
        if (is_web_surface(path) || path == "/metrics")
            && request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .is_none()
        {
            return axum::http::Response::builder()
                .status(axum::http::StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"nora\"")
                .body(axum::body::Body::from("Authentication required"))
                .expect("valid response");
        }
    }

    let path = request.uri().path();

    // Docker/OCI paths (`/v2`, `/v2/…`) are governed by `docker_anon_pull`,
    // NOT the general `anonymous_read`: anonymous Docker pull changes the `/v2/`
    // auth-challenge handshake, so it is opted into explicitly and enabling
    // anonymous Maven/raw/npm never silently exposes container images.
    let is_docker = is_docker_path(path);

    // `/v2/_catalog` enumerates every repository — never served anonymously, even
    // under docker_anon_pull (anonymous pull-by-name is not list-all-repos).
    let is_docker_catalog = path == "/v2/_catalog";

    // Token management always requires auth, even with anonymous_read
    let is_token_management = path.starts_with("/ui/tokens") || path.starts_with("/api/ui/tokens");

    // npm whoami always requires auth (otherwise it returns "anonymous" for every user)
    let is_whoami = path.ends_with("/-/whoami");

    // Admin control-plane paths always require an admin token — never anonymous,
    // even under anonymous_read, and method-independent (covers a future GET).
    let is_admin = is_admin_path(path);

    let is_read_method = matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    );

    // npm audit (#597) is a read-semantics query that npm sends as a POST (npm7
    // `advisories/bulk`, npm6 `audits/quick`). Treat it as read-eligible under
    // `anonymous_read` so anonymous `npm audit` works wherever anonymous install
    // works. Safe: the handler (registry/npm.rs) mutates nothing (forwards to the
    // configured upstream, returns advisories), caps the body, strips internal
    // package names under a filter, and never forwards the client credential.
    // Same for pnpm's `audits` path, and a read-only token may audit too: the
    // write-method gates below exempt it (#1055 measured pnpm's path).
    let is_npm_audit = *request.method() == axum::http::Method::POST
        && (path == "/npm/-/npm/v1/security/advisories/bulk"
            || path == "/npm/-/npm/v1/security/audits/quick"
            || path == "/npm/-/npm/v1/security/audits");

    // A request that presents credentials is always validated below (honest
    // `docker login`, correct audit attribution) — never short-circuited to
    // anonymous. Anonymous Docker bypass applies only when no Authorization sent.
    let has_auth_header = request.headers().contains_key(header::AUTHORIZATION);

    // Anonymous read for non-Docker registries (Maven/raw/npm/…) if configured.
    // Token management, whoami, admin, and all Docker `/v2` paths are excluded.
    if state.config.auth.anonymous_read
        && (is_read_method || is_npm_audit)
        && !is_docker
        && !is_token_management
        && !is_whoami
        && !is_admin
    {
        return anonymous_read_passthrough(request, next).await;
    }

    // Anonymous Docker/OCI pull, when explicitly enabled. The `/v2/` ping then
    // returns 200 (so the client proceeds without a Basic challenge) and
    // manifest/blob/tag reads are served without auth; writes (POST/PUT/PATCH/
    // DELETE) are not read methods, so they fall through and still require auth.
    // With the flag off (default), `/v2/` returns 401 + WWW-Authenticate: Basic
    // so `docker login` works and the basic-auth-accepts-api-token contract holds.
    if state.config.auth.docker_anon_pull
        && is_read_method
        && is_docker
        && !is_docker_catalog
        && !has_auth_header
    {
        return anonymous_read_passthrough(request, next).await;
    }

    // Compute realm from public_url for WWW-Authenticate header
    let realm = state.config.server.public_url.as_deref().unwrap_or("Nora");

    // The brute-force lockout applies to Basic passwords only (see AuthFailureTracker).
    let client_ip = extract_client_ip(&request, &state.config.auth.trusted_proxies);

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let auth_header = match auth_header {
        Some(h) => h,
        None => return unauthorized_response("Authentication required", realm),
    };

    // Try Bearer token first (opaque nra_ tokens, then OIDC JWT)
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        // 1. Try opaque token (nra_ prefix)
        if let Some(ref token_store) = state.tokens {
            match token_store.verify_token(token).await {
                Ok((user, role)) => {
                    if is_write_method(request.method()) && !is_npm_audit && !role.can_write() {
                        return (StatusCode::FORBIDDEN, "Read-only token").into_response();
                    }
                    if is_admin && !role.can_admin() {
                        return (StatusCode::FORBIDDEN, "Admin role required").into_response();
                    }
                    // Opaque (nra_) tokens are not namespace-scoped (#583 is OIDC-only).
                    request
                        .extensions_mut()
                        .insert(NamespaceAuthority::Unrestricted);
                    request.extensions_mut().insert(AuthenticatedUser(user));
                    request.extensions_mut().insert(AuthenticatedRole(role));
                    return next.run(request).await;
                }
                // A store I/O/parse failure is not a credential verdict. Only an
                // `nra_`-prefixed token reaches disk (anything else returns
                // `InvalidFormat` first), so there is no OIDC identity to fall
                // through to: answer 503 so the client retries, instead of a 401
                // that makes valid creds flap during a storage blip.
                Err(crate::tokens::TokenError::Storage(e)) => {
                    tracing::error!(error = %e, "token store read failed during Bearer auth");
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Token verification unavailable",
                    )
                        .into_response();
                }
                Err(_) => {
                    // Token verification failed — fall through to OIDC
                }
            }
        }

        // An nra_ token that failed above can never be a JWT: no OIDC attempt.
        if token.starts_with("nra_") {
            return AuthRejection::new("token_invalid")
                .on(unauthorized_response("Invalid or expired token", realm));
        }

        // 2. Try OIDC JWT validation
        let mut rejection = AuthRejection::new("no_oidc");
        if let Some(ref oidc_validator) = state.oidc {
            if oidc_validator.is_active() {
                match oidc_validator.validate_token(token).await {
                    Ok(identity) => {
                        tracing::debug!(
                            provider = %identity.provider,
                            subject = %identity.subject,
                            role = ?identity.role,
                            "OIDC authentication successful"
                        );
                        // Maestra (R2-01): a workload identity (short-lived, namespace-
                        // scoped CI JWT) must not exchange itself for a long-lived,
                        // unscoped nra_ token; token management is for people only.
                        if is_token_management {
                            return (
                                StatusCode::FORBIDDEN,
                                "Workload identities cannot manage API tokens",
                            )
                                .into_response();
                        }
                        if is_write_method(request.method())
                            && !is_npm_audit
                            && !identity.role.can_write()
                        {
                            return (StatusCode::FORBIDDEN, "Read-only OIDC identity")
                                .into_response();
                        }
                        if is_admin && !identity.role.can_admin() {
                            return (StatusCode::FORBIDDEN, "Admin role required").into_response();
                        }
                        // Carry the namespace scopes into the request so write
                        // handlers can enforce them on the artifact coordinate
                        // (#583). Provider scope and rule scope are a conjunction:
                        // the provider scope is a ceiling a rule cannot widen.
                        let authority = NamespaceAuthority::from_oidc_scopes(
                            &identity.provider,
                            std::iter::once(identity.namespace_scope.as_slice())
                                .chain(identity.rule_namespace_scope.as_deref()),
                            identity.namespace_scope_enforcement,
                        );
                        request.extensions_mut().insert(authority);
                        // Carry the provider's lifetime ceiling so a token minted
                        // by this identity cannot outlive it (#1094). Taken from
                        // the identity — i.e. the provider that actually validated
                        // this JWT — never re-looked-up by name, since provider
                        // names are not unique (#1094 N2).
                        request
                            .extensions_mut()
                            .insert(MintLifetimeCeiling(identity.max_token_lifetime_secs));
                        request
                            .extensions_mut()
                            .insert(AuthenticatedUser(identity.subject.clone()));
                        request
                            .extensions_mut()
                            .insert(AuthenticatedRole(identity.role));
                        return next.run(request).await;
                    }
                    Err(reason) => {
                        // #994 — surface *why* OIDC rejected the token: a bounded
                        // metric bucket for alerting plus the full reason in a warn
                        // log (never the token). Without this a lifetime ceiling, a
                        // wrong audience and a missing role rule are indistinguishable.
                        let class = crate::auth::oidc::classify_rejection(&reason);
                        crate::metrics::record_oidc_rejection(class);
                        // Logged with the client by auth_middleware (log_rejection).
                        let named = reason.contains("ExpiredSignature")
                            || reason.contains("InvalidAudience");
                        rejection = AuthRejection {
                            oidc: true,
                            unverified_claims: named.then(|| unverified_ci_claims(token)).flatten(),
                            detail: Some(reason),
                            ..AuthRejection::new(class)
                        };
                    }
                }
            }
        }

        // Both token and OIDC failed. Not counted toward the lockout: an nra_ token
        // or a signed JWT cannot be guessed, and counting a stale token or an expired
        // JWT would only lock out the valid credentials sharing its egress IP.
        return rejection.on(unauthorized_response("Invalid or expired token", realm));
    }

    // Parse Basic auth
    if !auth_header.starts_with("Basic ") {
        return AuthRejection::new("malformed").on(unauthorized_response(
            "Basic or Bearer authentication required",
            realm,
        ));
    }

    // Basic carries either an htpasswd password or an API token (#736): it is
    // unusable only when neither store is configured.
    if htpasswd.is_none() && state.tokens.is_none() {
        return AuthRejection::new("basic_not_configured")
            .on(unauthorized_response("Basic auth not configured", realm));
    }

    let encoded = &auth_header[6..];
    let decoded = match STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(_) => {
            return AuthRejection::new("malformed")
                .on(unauthorized_response("Invalid credentials encoding", realm))
        }
    };

    let credentials = match String::from_utf8(decoded) {
        Ok(c) => c,
        Err(_) => {
            return AuthRejection::new("malformed")
                .on(unauthorized_response("Invalid credentials encoding", realm))
        }
    };

    let (username, password) = match credentials.split_once(':') {
        Some((u, p)) => (u, p),
        None => {
            return AuthRejection::new("malformed")
                .on(unauthorized_response("Invalid credentials format", realm))
        }
    };

    // Brute-force lockout of this username from this client IP.
    if let Some((ip, retry_after)) =
        client_ip.and_then(|ip| Some((ip, state.auth_failures.check_blocked(&ip, username)?)))
    {
        return AuthRejection {
            log: state.auth_failures.first_refusal(&ip, username),
            retry_after: Some(retry_after),
            ..AuthRejection::new("locked_out")
        }
        .on((
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::RETRY_AFTER, retry_after.to_string()),
                (header::CONTENT_TYPE, "application/json".to_string()),
            ],
            format!(
                r#"{{"error":"Too many failed attempts. Retry after {} seconds."}}"#,
                retry_after
            ),
        )
            .into_response());
    }
    // Verify credentials: htpasswd first, then the token store (#736, #1094);
    // `decide_basic_auth` has the rules, this applies its decision. Maestra: the
    // htpasswd check (async bcrypt) runs here, only from a peer in
    // auth.htpasswd_allowed_peers (`htpasswd` is None otherwise), and the decision
    // sees its verdict; `npm audit` POSTs with a read token, so it is gated as a
    // read (is_npm_audit).
    let htpasswd_matched = htpasswd.is_some() && htpasswd_ok(htpasswd, username, password).await;
    let gate_method = if is_npm_audit {
        Method::GET
    } else {
        request.method().clone()
    };
    // The token store reads storage (async), so its verdict is taken here, only when
    // decide_basic_auth would ask for it: htpasswd did not match.
    let token_verdict = match &state.tokens {
        Some(store) if !htpasswd_matched => Some(store.verify_token(password).await),
        _ => None,
    };
    let decision = decide_basic_auth(
        encoded,
        htpasswd.map(|_| move |_: &str, _: &str| htpasswd_matched),
        token_verdict.map(|verdict| move |_: &str| verdict),
        &gate_method,
        is_admin,
    );
    match decision {
        BasicDecision::Authenticated { user, role } => {
            // Auth successful — clear failure counter
            if let Some(ip) = client_ip {
                state.auth_failures.record_success(&ip, username);
            }
            // Maestra: an htpasswd user carries the role of auth.read_only_users;
            // a token carries its own (decide_basic_auth gated that one already).
            let role = if htpasswd_matched {
                let role = state.config.auth.htpasswd_role(username);
                if is_write_method(&gate_method) && !role.can_write() {
                    return (StatusCode::FORBIDDEN, "Read-only account").into_response();
                }
                role
            } else {
                role
            };
            // Basic-auth identities and opaque (nra_) tokens are not
            // namespace-scoped (#583 is OIDC-only).
            request
                .extensions_mut()
                .insert(NamespaceAuthority::Unrestricted);
            request.extensions_mut().insert(AuthenticatedUser(user));
            request.extensions_mut().insert(AuthenticatedRole(role));
            next.run(request).await
        }
        BasicDecision::Forbidden(reason) => {
            // Valid credentials, not authorized: the credential still counts as good.
            if let Some(ip) = client_ip {
                state.auth_failures.record_success(&ip, username);
            }
            (StatusCode::FORBIDDEN, reason).into_response()
        }
        BasicDecision::Unauthorized {
            message,
            record_failure,
        } => {
            if record_failure {
                // Maestra: only a password htpasswd could have matched is a guess
                // worth counting; a token is not guessable, and with no htpasswd
                // for this peer a count would only lock out the valid credentials
                // sharing the egress IP (CI runners).
                if let Some(ip) = client_ip.filter(|_| htpasswd.is_some()) {
                    state.auth_failures.record_failure(ip, username);
                }
                let reason = if password.starts_with("nra_") {
                    "token_invalid"
                } else {
                    "wrong_password"
                };
                AuthRejection::new(reason).on(unauthorized_response(message, realm))
            } else {
                AuthRejection::new("malformed").on(unauthorized_response(message, realm))
            }
        }
        BasicDecision::ServiceUnavailable(e) => {
            tracing::error!(error = %e, "token store read failed during Basic auth fallback");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Token verification unavailable",
            )
                .into_response()
        }
        BasicDecision::NotConfigured => AuthRejection::new("basic_not_configured")
            .on(unauthorized_response("Basic auth not configured", realm)),
    }
}

/// What the Basic branch of [`auth_middleware`] does with a request, as
/// decided by [`decide_basic_auth`].
#[derive(Clone, Debug, PartialEq)]
enum BasicDecision {
    /// Valid credentials, authorized: run the request as `user` with `role`.
    Authenticated {
        user: String,
        role: crate::tokens::Role,
    },
    /// Valid credentials, not authorized for this request (403). The
    /// credentials still count as a success for the failure tracker.
    Forbidden(&'static str),
    /// Credentials malformed or wrong (401). Only a wrong credential counts
    /// toward the per-IP lockout (`record_failure`), a malformed header does not.
    Unauthorized {
        message: &'static str,
        record_failure: bool,
    },
    /// The token store could not be read (503): an outage, not a credential
    /// verdict, so it is not counted (#912).
    ServiceUnavailable(String),
    /// Neither htpasswd nor a token store to check a Basic password against (401).
    NotConfigured,
}

/// Decide a Basic-auth request from its credentials (`encoded`, the header
/// value after `Basic `), the method and whether the path is an admin one.
///
/// `htpasswd` and `tokens` check a username/password and a password against
/// the htpasswd file and the token store; `None` when the deployment has no
/// such store. The function does no I/O of its own and decides whether each
/// check runs at all:
/// - Basic needs htpasswd or the token store; with neither the answer is
///   [`BasicDecision::NotConfigured`] whatever the header. An OIDC-only setup
///   (#996) has no htpasswd, but API tokens sent as the Basic password must
///   still work there: Docker, twine and Maven have no other way to present
///   one (#1094).
/// - htpasswd first. A match is that user with the `Write` role, never admin,
///   and the token store is not read — not even for a password shaped like an
///   API token, so a store failure cannot turn a valid login into a 503 and a
///   colliding token cannot lend its owner or role.
/// - Otherwise the password may be an API token (`nra_…`): Docker, twine and
///   Maven send the token as the Basic-auth password and never use Bearer (the
///   `/v2/` challenge is Basic) (#736). A valid token is its owner with its
///   role, never the Basic username, and is gated like on the Bearer path: a
///   read token may not write ([`is_write_method`]), an admin path needs an
///   admin token. A store I/O/parse failure is not "wrong password": a 401
///   would make valid token creds flap and feed the failure tracker toward
///   lockout for the duration of a storage blip.
fn decide_basic_auth<H, T>(
    encoded: &str,
    htpasswd: Option<H>,
    tokens: Option<T>,
    method: &Method,
    is_admin: bool,
) -> BasicDecision
where
    H: FnOnce(&str, &str) -> bool,
    T: FnOnce(&str) -> Result<(String, crate::tokens::Role), crate::tokens::TokenError>,
{
    if htpasswd.is_none() && tokens.is_none() {
        return BasicDecision::NotConfigured;
    }
    let malformed = |message| BasicDecision::Unauthorized {
        message,
        record_failure: false,
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return malformed("Invalid credentials encoding");
    };
    let Ok(credentials) = String::from_utf8(decoded) else {
        return malformed("Invalid credentials encoding");
    };
    let Some((username, password)) = credentials.split_once(':') else {
        return malformed("Invalid credentials format");
    };

    if htpasswd.is_some_and(|check| check(username, password)) {
        // Basic-auth carries no role, so it can never satisfy an admin path:
        // deny fail-closed (403 — authenticated but not authorized).
        if is_admin {
            return BasicDecision::Forbidden("Admin role required");
        }
        return BasicDecision::Authenticated {
            user: username.to_string(),
            role: crate::tokens::Role::Write,
        };
    }

    match tokens.map(|verify| verify(password)) {
        Some(Ok((user, role))) => {
            if is_write_method(method) && !role.can_write() {
                BasicDecision::Forbidden("Read-only token")
            } else if is_admin && !role.can_admin() {
                // An API token sent as the Basic password is a full bearer
                // identity (#737), so it must clear the admin gate too.
                BasicDecision::Forbidden("Admin role required")
            } else {
                BasicDecision::Authenticated { user, role }
            }
        }
        Some(Err(crate::tokens::TokenError::Storage(e))) => BasicDecision::ServiceUnavailable(e),
        Some(Err(_)) | None => BasicDecision::Unauthorized {
            message: "Invalid username or password",
            record_failure: true,
        },
    }
}

/// The methods a read-only identity may not use: exactly PUT, POST, DELETE and
/// PATCH. Every other method is a read — HEAD included, which is how
/// `docker pull` starts.
fn is_write_method(method: &Method) -> bool {
    [Method::PUT, Method::POST, Method::DELETE, Method::PATCH].contains(method)
}

/// `Authorization: Basic` whose password is an `nra_` API token or a JWT (three
/// dot-separated segments, JSON header), rewritten as `Bearer <password>`. Any other
/// Basic credential (an htpasswd password) is left alone.
fn basic_token_as_bearer(headers: &HeaderMap, nra: bool) -> Option<axum::http::HeaderValue> {
    let encoded = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (_, password) = decoded.split_once(':')?;
    let is_jwt = password.starts_with("eyJ") && password.split('.').count() == 3;
    if !((nra && password.starts_with("nra_")) || is_jwt) {
        return None;
    }
    axum::http::HeaderValue::from_str(&format!("Bearer {password}")).ok()
}

/// The username of an `Authorization: Basic` credential (the lockout key).
fn basic_username(encoded: &str) -> Option<String> {
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    decoded.split_once(':').map(|(user, _)| user.to_string())
}

async fn htpasswd_ok(auth: Option<&HtpasswdAuth>, username: &str, password: &str) -> bool {
    match auth {
        Some(auth) => auth.authenticate(username, password).await,
        None => false,
    }
}

/// Attempt to validate a Base64-encoded Basic auth credential against the
/// token store (`nra_` passwords) and the htpasswd store. Returns the
/// identity and role on success, `None` on any failure.
/// Used by the opportunistic-auth path on open web surfaces so that
/// authenticated users get their real identity even on publicly browsable
/// pages.
async fn try_basic_auth(
    encoded: &str,
    state: &AppState,
    htpasswd: Option<&HtpasswdAuth>,
) -> Option<(String, crate::tokens::Role)> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
    let (username, password) = decoded.split_once(':')?;
    // An API token as the password is checked first, without paying a bcrypt.
    if password.starts_with("nra_") {
        if let Some(store) = &state.tokens {
            if let Ok(identity) = store.verify_token(password).await {
                return Some(identity);
            }
        }
    }
    htpasswd_ok(htpasswd, username, password).await.then(|| {
        (
            username.to_string(),
            state.config.auth.htpasswd_role(username),
        )
    })
}

fn unauthorized_response(message: &str, realm: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                header::WWW_AUTHENTICATE,
                format!("Basic realm=\"{}\"", realm),
            ),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        format!(r#"{{"error":"{}"}}"#, message),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn audit_actor_resolves_user_or_anonymous() {
        // #985 — the audit actor is the authenticated username (whatever auth
        // transport set AuthenticatedUser: API token or Basic-auth), or
        // `anonymous` when the request carries no identity.
        let token_user = Some(axum::Extension(AuthenticatedUser("ci-bot".to_string())));
        assert_eq!(audit_actor(&token_user), "ci-bot");

        let basic_user = Some(axum::Extension(AuthenticatedUser("alice".to_string())));
        assert_eq!(audit_actor(&basic_user), "alice");

        let anonymous: Option<axum::Extension<AuthenticatedUser>> = None;
        assert_eq!(audit_actor(&anonymous), "anonymous");
    }

    #[test]
    fn test_public_path_classification() {
        // Unconditional publics: probes + token endpoints only.
        for p in [
            "/",
            "/health",
            "/ready",
            "/api/tokens",
            "/api/tokens/list",
            "/api/tokens/revoke",
        ] {
            assert!(is_public_path(p), "{p}");
        }
        // The web surface is NOT unconditionally public any more — it is
        // config-gated in the middleware (repository enumeration).
        for p in [
            "/ui",
            "/ui/dashboard",
            "/api-docs",
            "/api-docs/openapi.json",
            "/api/ui/stats",
            "/metrics",
        ] {
            assert!(!is_public_path(p), "{p}");
        }
        for p in ["/ui", "/ui/rpm", "/api/ui/stats", "/api-docs"] {
            assert!(is_web_surface(p), "{p}");
        }
        // The UI's embedded assets and the favicon carry no data: always public.
        for p in [
            "/favicon.ico",
            "/ui/static/tailwind.css",
            "/ui/static/htmx.min.js",
        ] {
            assert!(is_public_path(p), "{p}");
        }
        for p in ["/ui/static/", "/ui/static/../tokens", "/favicon.ico/x"] {
            assert!(!is_public_path(p), "{p}");
        }
        // Token pages are part of the always-gated set, not the web surface.
        assert!(!is_web_surface("/ui/tokens"));
        assert!(!is_web_surface("/api/ui/tokens"));
        // Docker /v2/ is neither.
        assert!(!is_public_path("/v2/"));
        assert!(!is_web_surface("/v2/"));
    }

    #[test]
    fn test_is_public_path_health() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/ready"));
        // /metrics is config-gated now (auth.public_metrics), not unconditional.
        assert!(!is_public_path("/metrics"));
    }

    #[test]
    fn test_v2_is_not_public_path() {
        // Docker /v2/ must NOT be public — it needs auth challenge per V2 spec
        assert!(!is_public_path("/v2/"));
        assert!(!is_public_path("/v2"));
        // The /v2/ ping and all sub-paths are Docker registry paths, gated as a
        // group by docker_anon_pull.
        assert!(is_docker_path("/v2/"));
        assert!(is_docker_path("/v2"));
        assert!(is_docker_path("/v2/alpine/manifests/latest"));
        // Non-Docker paths are not.
        assert!(!is_docker_path("/raw/file.txt"));
        assert!(!is_docker_path("/v2x/sneaky"));
    }

    #[test]
    fn test_is_public_path_ui() {
        // The UI is the config-gated web surface, not unconditionally public.
        for p in ["/ui", "/ui/dashboard", "/ui/repos"] {
            assert!(!is_public_path(p), "{p}");
            assert!(is_web_surface(p), "{p}");
        }
    }

    #[test]
    fn test_is_public_path_api_docs() {
        for p in ["/api-docs", "/api-docs/openapi.json", "/api/ui"] {
            assert!(!is_public_path(p), "{p}");
            assert!(is_web_surface(p), "{p}");
        }
    }

    #[test]
    fn test_is_public_path_tokens() {
        assert!(is_public_path("/api/tokens"));
        assert!(is_public_path("/api/tokens/list"));
        assert!(is_public_path("/api/tokens/revoke"));
    }

    #[test]
    fn test_is_public_path_root() {
        assert!(is_public_path("/"));
    }

    #[test]
    fn test_is_not_public_path_registry() {
        assert!(!is_public_path("/v2/library/alpine/manifests/latest"));
        assert!(!is_public_path("/npm/lodash"));
        assert!(!is_public_path("/maven/com/example"));
        assert!(!is_public_path("/pypi/simple/flask"));
    }

    #[test]
    fn test_is_not_public_path_random() {
        assert!(!is_public_path("/admin"));
        assert!(!is_public_path("/secret"));
        assert!(!is_public_path("/api/data"));
    }

    #[test]
    fn test_token_ui_paths_not_public() {
        // Token management UI must require authentication
        assert!(!is_public_path("/ui/tokens"));
        assert!(!is_public_path("/ui/tokens/"));
        assert!(!is_public_path("/api/ui/tokens/create"));
        assert!(!is_public_path("/api/ui/tokens/list"));
        assert!(!is_public_path("/api/ui/tokens/abcd1234abcd1234/revoke"));
    }

    #[test]
    fn test_xff_trusted_proxy_uses_forwarded_ip() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("127.0.0.1,::1");
        let mut request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "1.2.3.4, 127.0.0.1")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            1234,
        )));
        let ip = extract_client_ip(&request, &proxies);
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
    }

    /// A reverse proxy appends the address it received the request from to whatever
    /// X-Forwarded-For the client sent, so the left part of the header is the client's to choose.
    /// The client is the rightmost address that is not a trusted proxy.
    #[test]
    fn a_client_behind_a_trusted_proxy_cannot_choose_its_address() {
        use crate::config::TrustedProxies;
        let loopback = TrustedProxies::default_loopback();
        let hops = TrustedProxies::parse("127.0.0.1,10.0.0.0/8");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let resolve = |lines: &[&str], real_ip: Option<&str>, trusted: &TrustedProxies| {
            let mut headers = HeaderMap::new();
            for line in lines {
                headers.append("x-forwarded-for", line.parse().unwrap());
            }
            if let Some(ip) = real_ip {
                headers.insert("x-real-ip", ip.parse().unwrap());
            }
            resolve_client_ip(peer, &headers, trusted).to_string()
        };
        let cases: [(&[&str], Option<&str>, &TrustedProxies, &str); 9] = [
            // nginx `$proxy_add_x_forwarded_for`: the client's header, then the real address
            (&["6.6.6.6, 203.0.113.9"], None, &loopback, "203.0.113.9"),
            (&["6.6.6.6,203.0.113.9"], None, &loopback, "203.0.113.9"),
            // a proxy that adds its own header line after the client's
            (&["6.6.6.6", "203.0.113.9"], None, &loopback, "203.0.113.9"),
            // a chain of trusted hops is walked past
            (
                &["6.6.6.6, 198.51.100.7, 10.0.0.5"],
                None,
                &hops,
                "198.51.100.7",
            ),
            // every address a trusted proxy: the leftmost
            (&["10.0.0.7, 10.0.0.5"], None, &hops, "10.0.0.7"),
            // a proxy that replaces the header: its one address
            (&["203.0.113.9"], None, &loopback, "203.0.113.9"),
            // an entry that is not an address ends the walk at the hop that wrote it
            (&["6.6.6.6, unknown, 10.0.0.5"], None, &hops, "10.0.0.5"),
            // nothing readable in X-Forwarded-For: X-Real-IP, as before
            (&["unknown"], Some("203.0.113.9"), &loopback, "203.0.113.9"),
            (&[], None, &loopback, "127.0.0.1"),
        ];
        for (lines, real_ip, trusted, want) in cases {
            assert_eq!(resolve(lines, real_ip, trusted), want, "{lines:?}");
        }
    }

    #[test]
    fn test_xff_ignores_client_supplied_entries_left_of_trusted_hops() {
        use crate::config::TrustedProxies;
        // An appending proxy chain: the client spoofed "9.9.9.9", the edge proxy
        // (trusted 10.60.8.1) appended the real client 1.2.3.4.
        let proxies = TrustedProxies::parse("10.60.8.0/24");
        let mut request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "9.9.9.9, 1.2.3.4, 10.60.8.2")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "10.60.8.1".parse().unwrap(),
            1234,
        )));
        let ip = extract_client_ip(&request, &proxies);
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_xff_untrusted_proxy_uses_peer_ip() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("127.0.0.1,::1");
        let mut request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        // Peer is NOT in trusted list
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "5.6.7.8".parse().unwrap(),
            1234,
        )));
        let ip = extract_client_ip(&request, &proxies);
        assert_eq!(ip, Some("5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn test_xff_no_header_uses_peer_ip() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("127.0.0.1,::1");
        let mut request = Request::builder().uri("/test").body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            1234,
        )));
        let ip = extract_client_ip(&request, &proxies);
        assert_eq!(ip, Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_parse_cidr() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("10.0.0.0/8");
        assert!(proxies.contains("10.1.2.3".parse().unwrap()));
        assert!(proxies.contains("10.255.255.255".parse().unwrap()));
        assert!(!proxies.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_parse_single_ip() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("192.168.1.1");
        assert!(proxies.contains("192.168.1.1".parse().unwrap()));
        assert!(!proxies.contains("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_match_ipv4_mapped_peers() {
        // A `[::]` listener reports IPv4 peers as `::ffff:a.b.c.d`.
        use crate::config::TrustedProxies;
        let pods = TrustedProxies::parse("10.62.0.0/16");
        assert!(pods.contains("::ffff:10.62.2.90".parse().unwrap()));
        assert!(!pods.contains("::ffff:10.63.0.1".parse().unwrap()));
        let loopback = TrustedProxies::parse("127.0.0.1");
        assert!(loopback.contains("::ffff:127.0.0.1".parse().unwrap()));
        // Real IPv6 peers still match IPv6 entries only.
        let v6 = TrustedProxies::parse("fd00:62::/32");
        assert!(v6.contains("fd00:62::5".parse().unwrap()));
        assert!(!v6.contains("fd00:63::5".parse().unwrap()));
        assert!(!pods.contains("fd00:62::5".parse().unwrap()));
        // Mapped notation in the config means the IPv4 address / net.
        let mapped_cfg = TrustedProxies::parse("::ffff:10.62.0.0/112,::ffff:127.0.0.1");
        assert!(mapped_cfg.contains("10.62.9.9".parse().unwrap()));
        assert!(mapped_cfg.contains("127.0.0.1".parse().unwrap()));
        assert!(!mapped_cfg.contains("10.63.0.1".parse().unwrap()));
        // A v6 CIDR wider than /96 keeps covering mapped peers (CodeRabbit #44).
        let wide = TrustedProxies::parse("::ffff:0:0/95");
        assert!(wide.contains("::ffff:10.62.2.90".parse().unwrap()));
        let all_v6 = TrustedProxies::parse("::/0");
        assert!(all_v6.contains("::ffff:10.62.2.90".parse().unwrap()));
        assert!(!all_v6.contains("10.62.2.90".parse().unwrap()));
    }

    #[test]
    fn test_resolve_client_ip_canonicalises_mapped_addresses() {
        use crate::config::TrustedProxies;
        let trusted = TrustedProxies::parse("10.62.0.0/16");
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        // traefik on cilium_host, seen as a mapped peer: XFF is honoured.
        assert_eq!(
            resolve_client_ip("::ffff:10.62.2.90".parse().unwrap(), &headers, &trusted),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        // A mapped XFF hop keys the same as its plain IPv4 form.
        headers.insert("x-forwarded-for", "::ffff:203.0.113.7".parse().unwrap());
        assert_eq!(
            resolve_client_ip("10.62.2.90".parse().unwrap(), &headers, &trusted),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        // An untrusted mapped peer is keyed by its IPv4 form, one bucket per client.
        assert_eq!(
            resolve_client_ip("::ffff:198.51.100.1".parse().unwrap(), &headers, &trusted),
            "198.51.100.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_trusted_proxies_default_loopback() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::default_loopback();
        assert!(proxies.contains("127.0.0.1".parse().unwrap()));
        assert!(proxies.contains("::1".parse().unwrap()));
        assert!(!proxies.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_auth_failure_tracker_allows_under_threshold() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..4 {
            tracker.record_failure(ip, "u");
        }
        assert!(tracker.check_blocked(&ip, "u").is_none());
    }

    #[test]
    fn test_auth_failure_tracker_blocks_at_threshold() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 {
            tracker.record_failure(ip, "u");
        }
        assert!(tracker.check_blocked(&ip, "u").is_some());
    }

    #[test]
    fn test_auth_failure_tracker_reports_lockout_once_per_lockout() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let started: Vec<_> = (0..5).map(|_| tracker.record_failure(ip, "u")).collect();
        assert_eq!(started, [None, None, None, None, Some(1)]);
        // Next failure (after the lockout ran out) starts the next, longer lockout.
        assert_eq!(tracker.record_failure(ip, "u"), Some(2));
    }

    #[test]
    fn test_auth_failure_tracker_success_clears() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..10 {
            tracker.record_failure(ip, "u");
        }
        assert!(tracker.check_blocked(&ip, "u").is_some());
        tracker.record_success(&ip, "u");
        assert!(tracker.check_blocked(&ip, "u").is_none());
    }

    #[test]
    fn test_auth_failure_tracker_independent_ips() {
        let tracker = AuthFailureTracker::new(3, 900);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..3 {
            tracker.record_failure(ip1, "u");
        }
        assert!(tracker.check_blocked(&ip1, "u").is_some());
        assert!(tracker.check_blocked(&ip2, "u").is_none());
    }

    #[test]
    fn test_auth_failure_tracker_cleanup() {
        let tracker = AuthFailureTracker::new(3, 1); // 1 sec max lockout
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 {
            tracker.record_failure(ip, "u");
        }
        // Cleanup should remove entries older than 2x max_lockout_secs
        std::thread::sleep(std::time::Duration::from_secs(3));
        tracker.cleanup();
        assert!(tracker.check_blocked(&ip, "u").is_none());
    }

    #[test]
    fn test_auth_failure_tracker_exponential_backoff() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // 5 failures = threshold, lockout = 2^0 = 1 sec
        for _ in 0..5 {
            tracker.record_failure(ip, "u");
        }
        let retry1 = tracker.check_blocked(&ip, "u").unwrap();
        assert!(
            retry1 <= 1,
            "first lockout should be ~1 sec, got {}",
            retry1
        );

        // 6 failures = 2^1 = 2 sec
        tracker.record_failure(ip, "u");
        let retry2 = tracker.check_blocked(&ip, "u").unwrap();
        assert!(
            retry2 <= 2,
            "second lockout should be ~2 sec, got {}",
            retry2
        );

        // 7 failures = 2^2 = 4 sec
        tracker.record_failure(ip, "u");
        let retry3 = tracker.check_blocked(&ip, "u").unwrap();
        assert!(
            retry3 <= 4,
            "third lockout should be ~4 sec, got {}",
            retry3
        );
    }
}

/// #1094 — the Basic branch of `auth_middleware` as a table: every row runs
/// `decide_basic_auth` on one input and compares the decision, plus whether the
/// token store was read at all. The router and binary tests cover the wiring
/// around it (`state.auth`/`state.tokens` into the verifiers, the decision into
/// the response and the failure tracker).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod basic_decision_tests {
    use super::{decide_basic_auth, BasicDecision};
    use crate::tokens::Role::{Admin, Read, Write};
    use crate::tokens::{Role, TokenError};
    use axum::http::Method;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::cell::Cell;

    /// The htpasswd users of the table. `svc`'s password is a live admin token
    /// of another owner, `ops`'s one the token store fails to read: htpasswd
    /// matching first must keep both away from the store.
    const HTPASSWD: &[(&str, &str)] = &[
        ("alice", "secret"),
        ("svc", "nra_collides"),
        ("ops", "nra_broken"),
    ];

    /// Owner of the table's tokens; no Basic username of the table is it.
    const OWNER: &str = "ci-bot";

    /// The token store of the table, by password.
    fn token_store(password: &str) -> Result<(String, Role), TokenError> {
        match password {
            "nra_read" => Ok((OWNER.into(), Read)),
            "nra_write" => Ok((OWNER.into(), Write)),
            "nra_admin" => Ok((OWNER.into(), Admin)),
            "nra_collides" => Ok(("token-owner".into(), Admin)),
            "nra_broken" => Err(TokenError::Storage("torn token file".into())),
            "nra_expired" => Err(TokenError::Expired),
            p if p.starts_with("nra_") => Err(TokenError::NotFound),
            _ => Err(TokenError::InvalidFormat),
        }
    }

    /// Which credential stores the deployment has.
    #[derive(Clone, Copy, Debug)]
    enum Setup {
        Both,
        HtpasswdOnly,
        TokensOnly,
        Neither,
    }
    use Setup::{Both, HtpasswdOnly, Neither, TokensOnly};

    /// The decision for one request, and whether the token store was read.
    fn decide(
        setup: Setup,
        encoded: &str,
        method: &Method,
        is_admin: bool,
    ) -> (BasicDecision, bool) {
        let read = Cell::new(false);
        let htpasswd = |user: &str, password: &str| HTPASSWD.contains(&(user, password));
        let tokens = |password: &str| {
            read.set(true);
            token_store(password)
        };
        let (htpasswd, tokens) = match setup {
            Both => (Some(htpasswd), Some(tokens)),
            HtpasswdOnly => (Some(htpasswd), None),
            TokensOnly => (None, Some(tokens)),
            Neither => (None, None),
        };
        let decision = decide_basic_auth(encoded, htpasswd, tokens, method, is_admin);
        (decision, read.get())
    }

    fn ok(user: &str, role: Role) -> BasicDecision {
        BasicDecision::Authenticated {
            user: user.into(),
            role,
        }
    }

    fn wrong() -> BasicDecision {
        BasicDecision::Unauthorized {
            message: "Invalid username or password",
            record_failure: true,
        }
    }

    fn malformed(message: &'static str) -> BasicDecision {
        BasicDecision::Unauthorized {
            message,
            record_failure: false,
        }
    }

    fn unavailable() -> BasicDecision {
        BasicDecision::ServiceUnavailable("torn token file".into())
    }

    const READ_ONLY: BasicDecision = BasicDecision::Forbidden("Read-only token");
    const NOT_ADMIN: BasicDecision = BasicDecision::Forbidden("Admin role required");
    const GET: Method = Method::GET;
    const PUT: Method = Method::PUT;
    const POST: Method = Method::POST;
    const DELETE: Method = Method::DELETE;

    /// Every method the table sweeps: the standard ones and an extension one.
    fn methods() -> Vec<Method> {
        vec![
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::TRACE,
            Method::CONNECT,
            Method::PUT,
            Method::POST,
            Method::DELETE,
            Method::PATCH,
            Method::from_bytes(b"PROPFIND").unwrap(),
        ]
    }

    /// The invariant's write set, spelled out: exactly these four.
    fn is_write(method: &Method) -> bool {
        [Method::PUT, Method::POST, Method::DELETE, Method::PATCH].contains(method)
    }

    struct Row {
        setup: Setup,
        encoded: String,
        method: Method,
        is_admin: bool,
        want: BasicDecision,
        token_store_read: bool,
    }

    impl Row {
        /// The same request on an admin path (`/api/v1/admin/*`).
        fn admin(self) -> Self {
            Row {
                is_admin: true,
                ..self
            }
        }
    }

    /// One row: the Basic credentials `user:password` sent with `method` to a
    /// non-admin path; the decision wanted and whether the store is read.
    fn row(
        setup: Setup,
        credentials: &str,
        method: Method,
        want: BasicDecision,
        read: bool,
    ) -> Row {
        Row {
            setup,
            encoded: STANDARD.encode(credentials),
            method,
            is_admin: false,
            want,
            token_store_read: read,
        }
    }

    fn rows() -> Vec<Row> {
        let mut rows = vec![
            // htpasswd matched → its identity (Write, never admin); the token
            // store is not read, even for an `nra_` password that is a live
            // admin token of someone else (H3/H4) or one the store fails on.
            row(Both, "alice:secret", GET, ok("alice", Write), false),
            row(Both, "alice:secret", PUT, ok("alice", Write), false),
            row(Both, "alice:secret", GET, NOT_ADMIN, false).admin(),
            row(
                HtpasswdOnly,
                "alice:secret",
                DELETE,
                ok("alice", Write),
                false,
            ),
            row(Both, "svc:nra_collides", GET, ok("svc", Write), false),
            row(Both, "svc:nra_collides", POST, ok("svc", Write), false),
            row(Both, "svc:nra_collides", POST, NOT_ADMIN, false).admin(),
            row(Both, "ops:nra_broken", GET, ok("ops", Write), false),
            // htpasswd missed → the password may be a token (#736): identity and
            // role are the token's, never the Basic username's (H3).
            row(Both, "alice:nra_write", PUT, ok(OWNER, Write), true),
            row(Both, "svc:nra_read", GET, ok(OWNER, Read), true),
            row(Both, "alice:nra_read", PUT, READ_ONLY, true),
            row(Both, "alice:nra_admin", POST, ok(OWNER, Admin), true).admin(),
            row(Both, "alice:wrong", GET, wrong(), true),
            row(Both, "alice:nra_broken", GET, unavailable(), true),
            // No htpasswd (OIDC-only, #1094): the token is the credential.
            row(TokensOnly, "docker:nra_write", GET, ok(OWNER, Write), true),
            row(TokensOnly, "docker:nra_write", PUT, ok(OWNER, Write), true),
            row(TokensOnly, ":nra_write", GET, ok(OWNER, Write), true),
            row(TokensOnly, "alice:nra_admin", GET, ok(OWNER, Admin), true),
            // Admin paths need an admin token; the write gate is checked first.
            row(TokensOnly, "docker:nra_admin", POST, ok(OWNER, Admin), true).admin(),
            row(TokensOnly, "docker:nra_write", POST, NOT_ADMIN, true).admin(),
            row(TokensOnly, "docker:nra_write", GET, NOT_ADMIN, true).admin(),
            row(TokensOnly, "docker:nra_read", GET, NOT_ADMIN, true).admin(),
            row(TokensOnly, "docker:nra_read", POST, READ_ONLY, true).admin(),
            // A wrong token is a credential verdict: 401, counted.
            row(TokensOnly, "docker:nra_00000000", GET, wrong(), true),
            row(TokensOnly, "docker:nra_expired", GET, wrong(), true),
            row(TokensOnly, "docker:secret", GET, wrong(), true),
            row(TokensOnly, "alice:secret", GET, wrong(), true),
            row(TokensOnly, "docker:", GET, wrong(), true),
            // A store failure is an outage: 503 before any role gate, uncounted.
            row(TokensOnly, "docker:nra_broken", GET, unavailable(), true),
            row(TokensOnly, "docker:nra_broken", PUT, unavailable(), true).admin(),
            // htpasswd only: no token fallback to reach.
            row(HtpasswdOnly, "alice:wrong", GET, wrong(), false),
            row(HtpasswdOnly, "docker:nra_write", GET, wrong(), false),
            row(
                HtpasswdOnly,
                "svc:nra_collides",
                GET,
                ok("svc", Write),
                false,
            ),
        ];

        // Write = exactly {PUT, POST, DELETE, PATCH} (H8): a read token passes
        // every other method — HEAD is how `docker pull` starts — and is refused
        // those four; a write token and an htpasswd user pass all of them.
        for method in methods() {
            for setup in [Both, TokensOnly] {
                let read_want = if is_write(&method) {
                    READ_ONLY
                } else {
                    ok(OWNER, Read)
                };
                rows.push(row(
                    setup,
                    "docker:nra_read",
                    method.clone(),
                    read_want,
                    true,
                ));
                let write_want = ok(OWNER, Write);
                rows.push(row(
                    setup,
                    "docker:nra_write",
                    method.clone(),
                    write_want,
                    true,
                ));
            }
            rows.push(row(Both, "alice:secret", method, ok("alice", Write), false));
        }

        // "Not configured" exactly when there is neither htpasswd nor a token
        // store, both ways (H6/H7) — and it is decided before the header is
        // parsed, so malformed credentials get it too.
        let malformed_headers = [
            ("!!!".to_string(), "Invalid credentials encoding"),
            (
                STANDARD.encode([0xff, 0xfe, b':']),
                "Invalid credentials encoding",
            ),
            (STANDARD.encode("nra_write"), "Invalid credentials format"),
        ];
        for setup in [Both, HtpasswdOnly, TokensOnly, Neither] {
            let has_tokens = matches!(setup, Both | TokensOnly);
            let token_want = match setup {
                Both | TokensOnly => ok(OWNER, Write),
                HtpasswdOnly => wrong(),
                Neither => BasicDecision::NotConfigured,
            };
            rows.push(row(setup, "docker:nra_write", GET, token_want, has_tokens));
            for (encoded, message) in &malformed_headers {
                let want = match setup {
                    Neither => BasicDecision::NotConfigured,
                    _ => malformed(message),
                };
                rows.push(Row {
                    encoded: encoded.clone(),
                    ..row(setup, "", GET, want, false)
                });
            }
        }
        rows
    }

    #[test]
    fn basic_auth_decision_table() {
        let rows = rows();
        assert_eq!(rows.len(), 99);
        for (i, row) in rows.iter().enumerate() {
            let (got, read) = decide(row.setup, &row.encoded, &row.method, row.is_admin);
            let credentials = STANDARD
                .decode(&row.encoded)
                .map(|d| String::from_utf8_lossy(&d).into_owned());
            let context = format!(
                "row {i}: {:?} {credentials:?} {} admin={}",
                row.setup, row.method, row.is_admin
            );
            assert_eq!(got, row.want, "{context}");
            assert_eq!(read, row.token_store_read, "token store read? {context}");
        }
    }

    /// The table's verifiers answer as the rows assume — a control that a
    /// green table is not a vacuous one.
    #[test]
    fn basic_auth_decision_table_verifiers() {
        assert!(HTPASSWD.contains(&("svc", "nra_collides")));
        assert!(token_store("nra_collides").unwrap().1.can_admin());
        assert!(matches!(
            token_store("nra_broken"),
            Err(TokenError::Storage(_))
        ));
        assert_eq!(methods().iter().filter(|m| is_write(m)).count(), 4);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[tokio::test]
    async fn test_auth_disabled_passes_all() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::PUT, "/raw/test.txt", b"data".to_vec()).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_public_paths_always_pass() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send(&ctx.app, Method::GET, "/ready", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Docker Registry V2 spec: GET /v2/ without credentials must return 401
    /// with WWW-Authenticate header when auth is enabled (issue #219)
    #[tokio::test]
    async fn test_docker_v2_requires_auth_when_enabled() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);

        // Without credentials: must return 401 + WWW-Authenticate
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("www-authenticate"));

        // With valid credentials: must return 200
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Docker /v2/ must NOT pass through anonymous_read bypass.
    /// Even with anonymous_read=true, /v2/ must require auth so Docker
    /// clients know to send credentials on subsequent push/pull requests.
    #[tokio::test]
    async fn test_docker_v2_ignores_anonymous_read() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

        // /v2/ without auth: must still return 401 even with anonymous_read=true
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("www-authenticate"));

        // Other read endpoints should still work anonymously
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --- #778: anonymous Docker pull via the `docker_anon_pull` opt-in ---

    /// docker_anon_pull=true: the `GET /v2/` ping is served anonymously
    /// (200, no challenge) so the Docker client proceeds without credentials.
    #[tokio::test]
    async fn test_docker_anon_pull_allows_v2_ping() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// docker_anon_pull=true: an anonymous manifest read passes the auth
    /// gate and reaches the handler (404 for a missing tag, NOT 401).
    #[tokio::test]
    async fn test_docker_anon_pull_allows_manifest_read() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
        let response = send(&ctx.app, Method::GET, "/v2/alpine/manifests/latest", "").await;
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "anonymous manifest read must pass the auth gate under docker_anon_pull"
        );
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// docker_anon_pull=true: writes are not read methods → still require
    /// auth. The Docker handler does not self-check role, so the middleware is
    /// the only write-stop — anonymous push/delete MUST be rejected.
    #[tokio::test]
    async fn test_docker_anon_pull_blocks_anonymous_writes() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

        // Start a blob upload (push) anonymously -> 401.
        let response = send(&ctx.app, Method::POST, "/v2/alpine/blobs/uploads/", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Push a manifest anonymously -> 401.
        let response = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Delete a manifest anonymously -> 401.
        let response = send(
            &ctx.app,
            Method::DELETE,
            "/v2/alpine/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// docker_anon_pull=true must NOT break authenticated push: a write with
    /// valid credentials starts the upload (202), exactly as without the flag.
    #[tokio::test]
    async fn test_docker_anon_pull_authenticated_push_still_works() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    /// docker_anon_pull=true: `/v2/_catalog` stays authenticated — anonymous
    /// repository enumeration is not part of anonymous pull-by-name.
    #[tokio::test]
    async fn test_docker_anon_pull_catalog_requires_auth() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

        let response = send(&ctx.app, Method::GET, "/v2/_catalog", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/_catalog",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// docker_anon_pull=true: presented credentials are still validated —
    /// the anonymous bypass applies only when no Authorization header is sent.
    /// Wrong creds on the `/v2/` ping return 401 (honest `docker login`).
    #[tokio::test]
    async fn test_docker_anon_pull_validates_presented_credentials() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

        let bad = format!("Basic {}", STANDARD.encode("admin:wrong"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &bad)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let good = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &good)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The general `anonymous_read` switch must NOT open Docker (#778): with
    /// anonymous_read=true but docker_anon_pull=false, Docker `/v2` paths
    /// still require auth, so exposing Maven/raw never exposes images.
    #[tokio::test]
    async fn test_anonymous_read_does_not_open_docker() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

        // /v2/ ping still challenges.
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Manifest read still requires auth — the general flag does not open Docker.
        let response = send(&ctx.app, Method::GET, "/v2/alpine/manifests/latest", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// When auth is disabled, /v2/ should pass through normally
    #[tokio::test]
    async fn test_docker_v2_passes_when_auth_disabled() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_blocks_without_credentials() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send(&ctx.app, Method::PUT, "/raw/test.txt", b"data".to_vec()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("www-authenticate"));
    }

    #[tokio::test]
    async fn test_auth_basic_works() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_basic_wrong_password() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:wrong"));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// R2-48: the lockout is per client IP and username, and never refuses a Bearer
    /// credential. Five wrong passwords for alice lock out alice only; bob behind the
    /// same IP and a valid API token from it still authenticate (404 = past auth).
    #[tokio::test]
    async fn test_lockout_is_per_user_and_skips_bearer() {
        let ctx = create_test_context_with_auth(&[("alice", "pw-a"), ("bob", "pw-b")]);
        let get = |auth: String| {
            let app = &ctx.app;
            async move {
                send_with_headers(
                    app,
                    Method::GET,
                    "/raw/missing.txt",
                    vec![("authorization", &auth)],
                    "",
                )
                .await
                .status()
            }
        };
        let basic = |cred: &str| format!("Basic {}", STANDARD.encode(cred));
        for _ in 0..5 {
            assert_eq!(get(basic("alice:wrong")).await, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            get(basic("alice:pw-a")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "alice is locked out, even with her password"
        );
        assert_eq!(get(basic("bob:pw-b")).await, StatusCode::NOT_FOUND);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Write)
            .await
            .unwrap();
        for _ in 0..10 {
            assert_eq!(
                get("Bearer nra_stale".to_string()).await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(get(format!("Bearer {token}")).await, StatusCode::NOT_FOUND);
        assert_eq!(
            get(basic(&format!("ci:{token}"))).await,
            StatusCode::NOT_FOUND
        );
    }

    /// #736: an API token presented as the Basic-auth password (any username) must
    /// authenticate — Docker/twine/Maven send the token as the Basic password and never
    /// use Bearer, so without this the documented `docker login -u token -p nra_…` fails.
    #[tokio::test]
    async fn test_basic_auth_accepts_api_token() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, crate::tokens::Role::Write)
            .await
            .unwrap();
        // Docker sends Basic base64("<user>:<token>"); the username is ignored.
        let header_val = format!("Basic {}", STANDARD.encode(format!("token:{token}")));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// #736: a read-only API token as the Basic-auth password must be rejected for writes,
    /// matching the Bearer path's role gate.
    #[tokio::test]
    async fn test_basic_auth_read_only_token_cannot_write() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, crate::tokens::Role::Read)
            .await
            .unwrap();
        let header_val = format!("Basic {}", STANDARD.encode(format!("token:{token}")));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// The storage key of a token's record.
    fn token_key(token: &str) -> String {
        use sha2::Digest;
        let prefix = hex::encode(sha2::Sha256::digest(token.as_bytes()));
        format!("{}{}.json", crate::tokens::STORAGE_PREFIX, &prefix[..16])
    }

    async fn put_token_record(ctx: &crate::test_helpers::TestContext, token: &str, body: &[u8]) {
        ctx.state
            .storage
            .put(&token_key(token), body)
            .await
            .unwrap();
    }

    /// A token-store read failure (torn/corrupt file, I/O error) is an outage,
    /// not a credential verdict: Basic auth with a valid-format token must
    /// answer 503 (retryable), never 401 — a 401 makes valid creds flap and
    /// walks the per-IP failure tracker toward lockout for the duration of a
    /// storage blip. Regression for the 2026-08 same-creds 200↔401 flap.
    #[tokio::test]
    async fn test_basic_auth_token_store_error_returns_503_not_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Read)
            .await
            .unwrap();
        // Corrupt the file the way a torn in-place rewrite would. The token was
        // never verified, so the in-memory cache is cold and the disk is read.
        put_token_record(&ctx, &token, b"{\"token_ha").await;

        let header_val = format!("Basic {}", STANDARD.encode(format!("ci:{token}")));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Same rule on the Bearer path: an `nra_` token that cannot be verified
    /// because the store read failed must 503, not fall through to OIDC and 401.
    #[tokio::test]
    async fn test_bearer_token_store_error_returns_503_not_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Read)
            .await
            .unwrap();
        put_token_record(&ctx, &token, b"{\"token_ha").await;

        let header_val = format!("Bearer {token}");
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// htpasswd is verified BEFORE the token store: when both exist, a password
    /// that merely *looks* like an API token (`nra_…`) authenticates against
    /// htpasswd and never reaches token verification. The order has held since
    /// #736 (htpasswd first, token on fallback), but no test pinned it — an
    /// acceptance mutant that tried the token store first survived the #1094 net
    /// (M12). Without the order a token-store blip would turn a valid htpasswd
    /// login into a 503, and an htpasswd password that collided with a live token
    /// would borrow the token's role and owner instead of the htpasswd identity.
    /// Correct order: htpasswd matches, store never read → 200. Token-first: the
    /// corrupt token file is read → Storage error → 503.
    #[tokio::test]
    async fn test_basic_auth_htpasswd_checked_before_token_store() {
        // htpasswd user whose password is shaped like an `nra_` token, so a
        // token-first order would try to verify it against the store.
        let ctx = create_test_context_with_auth(&[("svc", "nra_witness")]);
        assert!(ctx.state.auth.is_some(), "htpasswd provider present");
        assert!(ctx.state.tokens.is_some(), "token store present");
        // Corrupt the file the store would read for this password: reaching it at
        // all yields a Storage error (→503). htpasswd-first never reads it.
        put_token_record(&ctx, "nra_witness", b"{\"token_ha").await;

        let header_val = basic_header("svc", "nra_witness");
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        // htpasswd matched first → authenticated; the token store was never
        // consulted, so the corrupt file never mattered.
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Write a legacy token file (unsalted SHA-256 hash) for `token`: the first
    /// time the store reads it, it rewrites the file with an Argon2 hash.
    async fn write_legacy_token(ctx: &crate::test_helpers::TestContext, token: &str, owner: &str) {
        use sha2::Digest;
        let info = serde_json::json!({
            "token_hash": hex::encode(sha2::Sha256::digest(token.as_bytes())),
            "user": owner,
            "created_at": 0,
            "expires_at": u64::MAX,
            "last_used": null,
            "description": null,
            "role": "admin",
        });
        put_token_record(ctx, token, info.to_string().as_bytes()).await;
    }

    async fn token_file_migrated(ctx: &crate::test_helpers::TestContext, token: &str) -> bool {
        let record = ctx.state.storage.get(&token_key(token)).await.unwrap();
        String::from_utf8_lossy(&record).contains("$argon2")
    }

    /// htpasswd matched → the token store is not read at all, not even for a
    /// result that is then thrown away (H4), and the identity is the htpasswd
    /// user (H3). The password is a live admin token of another owner, kept as a
    /// legacy file: any store read migrates it to Argon2, so a file still legacy
    /// after the requests was never read. The control token proves the witness:
    /// one store read migrates its file.
    #[tokio::test]
    async fn test_basic_auth_htpasswd_match_never_reads_token_store() {
        let ctx = create_test_context_with_auth(&[("svc", "nra_witness")]);
        write_legacy_token(&ctx, "nra_witness", "token-owner").await;
        write_legacy_token(&ctx, "nra_control", "token-owner").await;
        let store = ctx.state.tokens.as_ref().unwrap();
        assert_eq!(
            store.verify_token("nra_control").await.unwrap().0,
            "token-owner"
        );
        assert!(
            token_file_migrated(&ctx, "nra_control").await,
            "witness control"
        );

        let header_val = basic_header("svc", "nra_witness");
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/-/whoami",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["username"], "svc");

        // The token is admin; the htpasswd identity is not.
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/v1/admin/tokens",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/json"),
            ],
            br#"{"username":"x","ttl_days":1,"role":"read"}"#.to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        assert!(
            !token_file_migrated(&ctx, "nra_witness").await,
            "htpasswd matched, yet the token store read the password's token file"
        );
    }

    /// Auth enabled with no htpasswd file — the OIDC-only setup (#996). The
    /// token store is there, as main.rs always creates it when auth is enabled.
    fn create_test_context_without_htpasswd() -> crate::test_helpers::TestContext {
        let ctx = create_test_context_with_auth(&[]);
        assert!(ctx.state.auth.is_none(), "no htpasswd provider");
        assert!(ctx.state.tokens.is_some(), "token store present");
        ctx
    }

    /// Owner of the tokens `mint` creates. The Basic username the tests send
    /// (`docker`) differs, so a request attributed to the Basic username
    /// instead of the token's owner shows.
    const TOKEN_OWNER: &str = "ci-bot";

    async fn mint(ctx: &crate::test_helpers::TestContext, role: crate::tokens::Role) -> String {
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .create_token(TOKEN_OWNER, 30, None, role)
            .await
            .unwrap()
    }

    fn basic_header(user: &str, pass: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
    }

    /// The test client's address (`send_with_headers` connects from it).
    const CLIENT_IP: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    /// Record failures for the test client up to one short of lockout: the
    /// test tracker locks out at its 5th, so whether the next request counts
    /// as a failure decides whether the client ends up blocked.
    fn one_failure_from_lockout(tracker: &super::AuthFailureTracker, user: &str) {
        for _ in 0..4 {
            tracker.record_failure(CLIENT_IP, user);
        }
        assert!(tracker.check_blocked(&CLIENT_IP, user).is_none());
    }

    /// #1094: without htpasswd, an API token sent as the Basic password is
    /// still a credential — `docker login` (the `/v2/` ping) and a write with a
    /// write token pass, as they do with htpasswd (#736).
    #[tokio::test]
    async fn test_basic_auth_api_token_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let token = mint(&ctx, crate::tokens::Role::Write).await;
        let header_val = basic_header("docker", &token);

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await.as_ref(), b"data");
    }

    /// #1094: a write identity may not mint an ADMIN token through the
    /// UI create path, even over a Basic-token credential in OIDC-only — the
    /// caller's role gates the request, not the form. Without the gate any write
    /// token escalates to admin (GHSA-78cx-cfhm-rgmx class, the UI create path
    /// had missed it).
    #[tokio::test]
    async fn test_ui_token_create_write_caller_cannot_mint_admin() {
        let ctx = create_test_context_without_htpasswd();
        let write_token = mint(&ctx, crate::tokens::Role::Write).await;
        let header_val = basic_header("victim-admin", &write_token);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=admin".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a write identity minted an admin token via the UI"
        );
        // Nothing was minted: only the original write token remains.
        assert_eq!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .await
                .len(),
            1,
            "a token was created despite the 403"
        );
    }

    /// #1094: the UI create path owns the new token to the AUTHENTICATED
    /// caller (the token owner), never to the forgeable Basic-header username (H3).
    #[tokio::test]
    async fn test_ui_token_create_owner_is_the_caller_not_the_basic_username() {
        let ctx = create_test_context_without_htpasswd();
        let write_token = mint(&ctx, crate::tokens::Role::Write).await;
        let header_val = basic_header("not-the-owner", &write_token);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let owners: Vec<String> = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .into_iter()
            .map(|t| t.user)
            .collect();
        assert!(
            !owners.iter().any(|u| u == "not-the-owner"),
            "the new token was owned by the forged Basic username: {owners:?}"
        );
    }

    /// #1094: the new token is owned by EXACTLY the authenticated
    /// token owner — not merely "not the forged Basic username" (F2). A mutant
    /// that sets the owner to any other constant source (`"admin"`,
    /// `x-remote-user`, a form field) passes F2 but fails here.
    #[tokio::test]
    async fn ui_token_create_owner_is_exactly_the_token_owner() {
        let ctx = create_test_context_without_htpasswd();
        let write_token = mint(&ctx, crate::tokens::Role::Write).await;
        let header_val = basic_header("not-the-owner", &write_token);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let owners: Vec<String> = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .into_iter()
            .map(|t| t.user)
            .collect();
        assert_eq!(
            owners,
            vec![TOKEN_OWNER.to_string(), TOKEN_OWNER.to_string()],
            "the minted token's owner is not exactly the authenticated caller"
        );
    }

    /// #1094: the admin gate is by ROLE, not by name. A write
    /// identity whose name happens to be `admin` (an htpasswd user, an OIDC
    /// subject, or a token owner called `admin`) still cannot mint an admin
    /// token. A mutant that gates on `user != "admin"` passes F1 (which only
    /// exercises the `ci-bot` caller) but fails here.
    #[tokio::test]
    async fn ui_token_create_admin_named_write_caller_cannot_mint_admin() {
        let ctx = create_test_context_without_htpasswd();
        let write_token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, crate::tokens::Role::Write)
            .await
            .unwrap();
        let header_val = basic_header("docker", &write_token);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=admin".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a write identity named 'admin' minted an admin token via the UI"
        );
        assert_eq!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .await
                .len(),
            1,
            "a token was created despite the 403"
        );
    }

    /// #1094: the role gate holds on the htpasswd-less Basic path — a read
    /// token reads but cannot write (403), as over Bearer and with htpasswd.
    /// The 403 is about the request, not the credential: it clears the per-IP
    /// failure count instead of adding to it, so a client with a valid read
    /// token is never locked out for trying to write.
    #[tokio::test]
    async fn test_basic_auth_read_only_token_cannot_write_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let token = mint(&ctx, crate::tokens::Role::Read).await;
        let header_val = basic_header("docker", &token);
        let tracker = &ctx.state.auth_failures;

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        for method in [Method::PUT, Method::POST, Method::DELETE, Method::PATCH] {
            tracker.record_success(&CLIENT_IP, "docker");
            one_failure_from_lockout(tracker, "docker");
            let response = send_with_headers(
                &ctx.app,
                method.clone(),
                "/raw/test.txt",
                vec![("authorization", &header_val)],
                b"data".to_vec(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
            assert!(
                tracker.check_blocked(&CLIENT_IP, "docker").is_none(),
                "{method}: a valid read token's 403 counted as a failure"
            );
        }
    }

    /// #1094: a token over Basic without htpasswd authenticates as the token's
    /// owner with the token's role, not as the Basic username: npm whoami
    /// names the owner, and the token list shows a write token only its
    /// owner's tokens while an admin token sees every user's (GHSA-78cx).
    #[tokio::test]
    async fn test_basic_auth_token_identity_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let store = ctx.state.tokens.as_ref().unwrap();
        store
            .create_token(
                "other",
                30,
                Some("theirs".into()),
                crate::tokens::Role::Read,
            )
            .await
            .unwrap();
        let write = basic_header("docker", &mint(&ctx, crate::tokens::Role::Write).await);
        let admin = basic_header("docker", &mint(&ctx, crate::tokens::Role::Admin).await);

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/-/whoami",
            vec![("authorization", &write)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["username"], TOKEN_OWNER);

        for (header_val, sees_theirs) in [(&write, false), (&admin, true)] {
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/api/ui/tokens/list",
                vec![("authorization", header_val)],
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
            assert!(body.contains(TOKEN_OWNER), "{body}");
            assert_eq!(body.contains("theirs"), sees_theirs, "{body}");
        }
    }

    /// #1094: the admin gate holds too — a write token over Basic cannot reach
    /// /api/v1/admin/*, an admin token can (an OIDC-only admin mints tokens
    /// there, #808, and hands them to Basic-only clients).
    #[tokio::test]
    async fn test_basic_auth_token_admin_gate_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let body = br#"{"username":"svc","ttl_days":1,"role":"read"}"#;
        for (role, want) in [
            (crate::tokens::Role::Write, StatusCode::FORBIDDEN),
            (crate::tokens::Role::Admin, StatusCode::OK),
        ] {
            let header_val = basic_header("docker", &mint(&ctx, role.clone()).await);
            let response = send_with_headers(
                &ctx.app,
                Method::POST,
                "/api/v1/admin/tokens",
                vec![
                    ("authorization", &header_val),
                    ("content-type", "application/json"),
                ],
                body.to_vec(),
            )
            .await;
            assert_eq!(response.status(), want, "{role:?}");
        }
    }

    /// #1094: a token-store failure on the htpasswd-less Basic path is an
    /// outage (503), not a credential verdict (401), and is not counted.
    #[tokio::test]
    async fn test_basic_auth_token_store_error_returns_503_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let token = mint(&ctx, crate::tokens::Role::Read).await;
        put_token_record(&ctx, &token, b"{\"token_ha").await;

        one_failure_from_lockout(&ctx.state.auth_failures, "docker");
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &basic_header("docker", &token))],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(ctx
            .state
            .auth_failures
            .check_blocked(&CLIENT_IP, "docker")
            .is_none());
    }

    /// #1094: an unknown, malformed or expired token over Basic without
    /// htpasswd answers 401. Maestra: it is NOT counted toward the lockout
    /// (as over Bearer): an nra_ token cannot be guessed, and counting a stale
    /// one would lock out the valid credentials sharing its egress IP (CI
    /// runners). A valid token leaves the count alone too.
    #[tokio::test]
    async fn test_basic_auth_bad_token_without_htpasswd_is_401_and_not_counted() {
        let ctx = create_test_context_without_htpasswd();
        let tracker = &ctx.state.auth_failures;
        let expired = mint(&ctx, crate::tokens::Role::Write).await;
        let record = ctx.state.storage.get(&token_key(&expired)).await.unwrap();
        let mut info: serde_json::Value = serde_json::from_slice(&record).unwrap();
        info["expires_at"] = 0.into();
        put_token_record(&ctx, &expired, info.to_string().as_bytes()).await;

        let bad = [
            "nra_00000000000000000000000000000000".to_string(),
            "secret".to_string(),
            expired,
        ];
        for password in &bad {
            one_failure_from_lockout(tracker, "docker");
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/v2/",
                vec![("authorization", &basic_header("docker", password))],
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{password}");
            assert!(response.headers().contains_key("www-authenticate"));
            assert!(
                tracker.check_blocked(&CLIENT_IP, "docker").is_none(),
                "{password}: a token was counted as a failure"
            );
            tracker.record_success(&CLIENT_IP, "docker");
        }

        one_failure_from_lockout(tracker, "docker");
        let token = mint(&ctx, crate::tokens::Role::Read).await;
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &basic_header("docker", &token))],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            tracker.check_blocked(&CLIENT_IP, "docker").is_none(),
            "a valid token added to the count"
        );
    }

    /// With neither htpasswd nor a token store, Basic has nothing to check
    /// against: the answer stays 401 "Basic auth not configured", uncounted.
    #[tokio::test]
    async fn test_basic_auth_without_htpasswd_or_token_store_not_configured() {
        let ctx = create_test_context_without_htpasswd();
        let mut state = ctx.state.clone();
        state.tokens = None;
        let app = crate::request_layers(crate::registry::docker_routes(), &state)
            .with_state(state.clone());

        one_failure_from_lockout(&state.auth_failures, "docker");
        let response = send_with_headers(
            &app,
            Method::GET,
            "/v2/",
            vec![(
                "authorization",
                &basic_header("docker", "nra_00000000000000000000000000000000"),
            )],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_bytes(response).await.as_ref(),
            br#"{"error":"Basic auth not configured"}"#
        );
        assert!(state
            .auth_failures
            .check_blocked(&CLIENT_IP, "docker")
            .is_none());
    }

    /// `npm install`/`npm audit`/`pnpm audit` POST their audit with the same read
    /// token they install with; the write-method gate must not refuse it.
    #[tokio::test]
    async fn test_read_token_may_post_npm_audit() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Read)
            .await
            .unwrap();
        let bearer = format!("Bearer {token}");
        let basic = format!("Basic {}", STANDARD.encode(format!("ci:{token}")));
        for path in [
            "/npm/-/npm/v1/security/advisories/bulk",
            "/npm/-/npm/v1/security/audits",
        ] {
            for header_val in [&bearer, &basic] {
                let response = send_with_headers(
                    &ctx.app,
                    Method::POST,
                    path,
                    vec![("authorization", header_val)],
                    b"{}".to_vec(),
                )
                .await;
                assert_ne!(response.status(), StatusCode::FORBIDDEN, "{path}");
                assert_ne!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            }
        }
        // Any other write with the same token is still refused.
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/npm/some-pkg",
            vec![("authorization", &bearer)],
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_auth_anonymous_read() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);
        // Upload with auth
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        // Read without auth should work
        let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        // Write without auth should fail
        let response = send(&ctx.app, Method::PUT, "/raw/test2.txt", b"data".to_vec()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Token management must require auth even with anonymous_read=true (#221)
    #[tokio::test]
    async fn test_token_ui_requires_auth_with_anonymous_read() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

        // GET /ui/tokens without auth must return 401 even with anonymous_read
        let response = send(&ctx.app, Method::GET, "/ui/tokens", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // GET /api/ui/tokens/list without auth must also return 401
        let response = send(&ctx.app, Method::GET, "/api/ui/tokens/list", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // With auth, token UI should work
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/ui/tokens",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Other read endpoints should still work anonymously
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_token_ui_requires_auth() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);

        // Token UI page without auth should return 401
        let response = send(&ctx.app, Method::GET, "/ui/tokens", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Token UI page with auth should work
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/ui/tokens",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_token_ui_create_requires_htmx() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

        // POST without HX-Request header should be rejected (CSRF)
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            "description=test&role=read&ttl_days=30",
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // POST with HX-Request header should work
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/x-www-form-urlencoded"),
                ("hx-request", "true"),
            ],
            "description=test&role=read&ttl_days=30",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_token_ui_revoke_validates_file_id() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

        // Invalid file_id (not hex, no slashes so route matches)
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/not_valid_hex_xx/revoke",
            vec![("authorization", &header_val), ("hx-request", "true")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Valid hex but non-existent
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/abcd1234abcd1234/revoke",
            vec![("authorization", &header_val), ("hx-request", "true")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Token API endpoints are public (in is_public_path) because they validate
    /// credentials in the handler body. Verify that empty/missing credentials
    /// are properly rejected with 401 — defense-in-depth against any future
    /// refactor that might accidentally remove body-level auth checks.
    #[tokio::test]
    async fn test_token_create_without_credentials_returns_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/tokens",
            vec![("content-type", "application/json")],
            r#"{}"#,
        )
        .await;
        // Empty JSON body has no username/password — serde fails or handler rejects
        assert!(
            response.status() == StatusCode::UNAUTHORIZED
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
                || response.status() == StatusCode::BAD_REQUEST,
            "Expected 401/422/400, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_token_list_without_credentials_returns_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/tokens/list",
            vec![("content-type", "application/json")],
            r#"{}"#,
        )
        .await;
        assert!(
            response.status() == StatusCode::UNAUTHORIZED
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
                || response.status() == StatusCode::BAD_REQUEST,
            "Expected 401/422/400, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_token_revoke_without_credentials_returns_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/tokens/revoke",
            vec![("content-type", "application/json")],
            r#"{}"#,
        )
        .await;
        assert!(
            response.status() == StatusCode::UNAUTHORIZED
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
                || response.status() == StatusCode::BAD_REQUEST,
            "Expected 401/422/400, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_token_ui_full_lifecycle() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

        // Create a token via UI endpoint
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/x-www-form-urlencoded"),
                ("hx-request", "true"),
            ],
            "description=CI+Pipeline&role=write&ttl_days=30",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        assert!(body.contains("nra_"), "Response should contain raw token");

        // List tokens
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/tokens/list",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        assert!(body.contains("CI Pipeline"), "List should show description");

        // Get file_id from the token store directly for revoke test
        let tokens = ctx.state.tokens.as_ref().unwrap().list_all_tokens().await;
        assert_eq!(tokens.len(), 1);
        let file_id = &tokens[0].file_id;

        // Revoke
        let revoke_url = format!("/api/ui/tokens/{}/revoke", file_id);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            &revoke_url,
            vec![("authorization", &header_val), ("hx-request", "true")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Verify token is gone
        let tokens = ctx.state.tokens.as_ref().unwrap().list_all_tokens().await;
        assert_eq!(tokens.len(), 0);
    }

    /// POST a UI token-create form with the given Authorization header.
    pub(super) async fn ui_create_token(
        ctx: &TestContext,
        authorization: &str,
        role: &str,
    ) -> axum::http::Response<axum::body::Body> {
        send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", authorization),
                ("content-type", "application/x-www-form-urlencoded"),
                ("hx-request", "true"),
            ],
            format!("description=x&role={}&ttl_days=30", role),
        )
        .await
    }

    /// A write token sent as the Basic password under a made-up username must
    /// not mint an admin token, and whatever it mints belongs to the token's
    /// verified owner, not to the Basic username.
    #[tokio::test]
    async fn test_token_ui_create_uses_verified_owner_and_refuses_admin() {
        let ctx = create_test_context_with_auth_and_config(&[("admin", "secret")], |cfg| {
            cfg.auth.admin_users = vec!["mallory".to_string()];
        });
        let store = ctx.state.tokens.as_ref().unwrap();
        let write_token = store
            .create_token("ci", 30, None, crate::tokens::Role::Write)
            .await
            .unwrap();
        let spoofed = format!(
            "Basic {}",
            STANDARD.encode(format!("mallory:{}", write_token))
        );

        let response = ui_create_token(&ctx, &spoofed, "admin").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = ui_create_token(&ctx, &spoofed, "write").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(store.list_tokens("mallory").await.is_empty());
        assert_eq!(store.list_tokens("ci").await.len(), 2);

        // htpasswd identities are Write-role: no admin mint either.
        let basic = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = ui_create_token(&ctx, &basic, "admin").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Admin mint needs an admin-role credential AND an auth.admin_users entry.
    #[tokio::test]
    async fn test_token_ui_create_admin_requires_admin_role_and_allowlist() {
        let ctx = create_test_context_with_auth_and_config(&[("admin", "secret")], |cfg| {
            cfg.auth.admin_users = vec!["boss".to_string()];
        });
        let store = ctx.state.tokens.as_ref().unwrap();
        let boss = store
            .create_token("boss", 30, None, crate::tokens::Role::Admin)
            .await
            .unwrap();
        let eve = store
            .create_token("eve", 30, None, crate::tokens::Role::Admin)
            .await
            .unwrap();

        let response = ui_create_token(&ctx, &format!("Bearer {}", eve), "admin").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = ui_create_token(&ctx, &format!("Bearer {}", boss), "admin").await;
        assert_eq!(response.status(), StatusCode::OK);
        let minted = store.list_tokens("boss").await;
        assert_eq!(minted.len(), 2);
        assert!(minted.iter().all(|t| t.role == crate::tokens::Role::Admin));
    }

    /// An htpasswd account in auth.read_only_users authenticates as Read: it
    /// pulls but cannot push; other htpasswd accounts keep Write.
    #[tokio::test]
    async fn test_htpasswd_read_only_user_cannot_write() {
        let ctx = create_test_context_with_auth_and_config(
            &[("admin", "secret"), ("viewer", "pw")],
            |cfg| cfg.auth.read_only_users = vec!["viewer".to_string()],
        );
        let admin = format!("Basic {}", STANDARD.encode("admin:secret"));
        let viewer = format!("Basic {}", STANDARD.encode("viewer:pw"));
        let app = &ctx.app;
        let put = |auth: String| async move {
            send_with_headers(
                app,
                Method::PUT,
                "/raw/test.txt",
                vec![("authorization", &auth)],
                b"data".to_vec(),
            )
            .await
            .status()
        };
        assert_eq!(put(viewer.clone()).await, StatusCode::FORBIDDEN);
        assert_eq!(put(admin).await, StatusCode::OK);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &viewer)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// No self-service mint outranks the caller: a read-only htpasswd account
    /// gets read tokens only from POST /api/tokens, and a read credential
    /// cannot mint write through the UI. Write accounts are unchanged.
    #[tokio::test]
    async fn test_token_mint_capped_at_caller_role() {
        let ctx = create_test_context_with_auth_and_config(
            &[("admin", "secret"), ("viewer", "pw")],
            |cfg| cfg.auth.read_only_users = vec!["viewer".to_string()],
        );
        let store = ctx.state.tokens.as_ref().unwrap();
        let app = &ctx.app;
        let api_mint = |user: &'static str, pass: &'static str, role: &'static str| async move {
            send_with_headers(
                app,
                Method::POST,
                "/api/tokens",
                vec![("content-type", "application/json")],
                format!(r#"{{"username":"{user}","password":"{pass}","role":"{role}"}}"#),
            )
            .await
            .status()
        };
        assert_eq!(
            api_mint("viewer", "pw", "write").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            api_mint("viewer", "pw", "admin").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(api_mint("viewer", "pw", "read").await, StatusCode::OK);
        let minted = store.list_tokens("viewer").await;
        assert_eq!(minted.len(), 1);
        assert_eq!(minted[0].role, crate::tokens::Role::Read);
        assert_eq!(api_mint("admin", "secret", "write").await, StatusCode::OK);

        let viewer = format!("Basic {}", STANDARD.encode("viewer:pw"));
        let response = ui_create_token(&ctx, &viewer, "write").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let read_token = store
            .create_token("ro", 30, None, crate::tokens::Role::Read)
            .await
            .unwrap();
        let response = ui_create_token(&ctx, &format!("Bearer {read_token}"), "write").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(store.list_tokens("viewer").await.len(), 1);
        assert_eq!(store.list_tokens("ro").await.len(), 1);
    }
}

// ---------------------------------------------------------------------------
// OIDC Integration Tests — full middleware flow with mock JWKS server
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod oidc_integration_tests {
    use crate::auth::oidc::OidcValidator;
    use crate::config::{OidcConfig, OidcProvider, OidcRoleRule};
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Test RSA private key (2048-bit, for test JWT signing only)
    pub(crate) const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7657FVL7gwmjj
PEfl4A+ajG3DFj6YHmS9gargHMChpdLMbt8ybqu1hHPUNKQyndUvFJ6q+xJFEds3
eBtjB5GLLtlj9lScvGPsV7386rypeHq30IErgm2beQJyF9ldtrVHBBPbz7eAo4+i
wCJ/m5IsuoLCYZPQrDUdpax0dUEa/eP6badqjZ2r0recnHw1+zGyozzSHNvPtK9I
PsKwBcbGjt5n5+9nWN322/mISAuLNwtv7l3Lja8U7m0ixH0ZLwFSgTLtzEfJISux
+ngGR4k2PBVeo+yDOZtuatx7Aixa1FerOwiq2xsoGOs2dhXagwFGdwbs8x/MvEj0
67Mm3OrLAgMBAAECggEAHXZkjyWpQ43XagESeKz3ZVCtCNAdAjaJrth8lOSNIwrf
kOO1JLALRcs9acDTGYh7WwVNlxsEE0Yoa3ruOEmAfSTcOnrtayFyPSTIibW33I4i
F12eUtcBHkYLpx2sG7BAnaC7CFR5vbZnF6ot/nnCojaft6Aaz7WgIkTOU/fqPDPb
WOSn4PQmgZS34non7y0NWmxxeIwqJk3aBeeEKisO2AS0YCHOgx2uBTIt2lcIzjK8
RHwQjLRRfhzxuhHuQtz/hMVQ17W3l7ehYTnW0D+UJJTXBjPgElICmWdGm9NMX9YH
HzVSBdH+tzTZ/hUhKe+nEZ5vrWT2wqx/h0med2P3eQKBgQDYNURqK7dfo2QBsy/F
pdUg7UaXfWe+c6guu32aZhnxYsHUE68cuV7Bz/awjMJYvF9VKhoJ+iuHI0myo9In
HITzbSDwFrWCme7DAIPbfbQU9nQqJLK/g3nUpYSpjFQEnIPJSr1aS/fVpUURAoBg
RSktyRTY3ak7+6x1I54HLxPk3QKBgQDegZEqK6B28fQklCPgdimwnNr92oJe5hoY
9cHUDz3A1Uyek40LQ1yR7W/imDCJMcQXqM7Lo54+55eHEkBvh6H/TTmnGMzj5L7t
HoKYMjYdBK7waFYGM6ULfVXqs6JqVmKFU7LX+ZVmOB5kgcQMQrAhio0GrG97iDqz
aKHqOthfxwKBgQDKa+SnulIumlzRMqAxXfdSopOK1YBB0SrOxf7shVcYpitukRdL
v0m2DyyZUs/KIGLo60gBu1TxatpfA/2HXK4k8jD6V2iM4+2kaGELKH9neO59Xmpz
33Y63tR7oMQwpRDFbtIlLibUwa0OJddnSpkpIq//8le1rwVhjn0voKXxiQKBgQDS
2qPO+6LHtQewdjX9atydAjfAooYzGgkXKCTzKTJS/47pI1hgmQgrPX9uktxD1sZF
yXGWpsm6QMtmc5ReXIDWp77/q0/WkpmfqO8G/WYsX5jMN4N1wxEfbzmw/WPnM0+P
mz56zoiWYo3intpC6Bty3ZJBBb1rqjA+feQaTINpVwKBgF/M0Lj9Sq9G2Ec7yBnm
xhBlLwCNzAk33Fy+6w6ANXTsGRwMm0zGdTjC3e6LHMrD0ZtF0M2blWAUh3sZ6ItQ
2Ak5ScO0q3MRQvo4HZkFK2wuZvNLYExq6gGy3P6l8xXbvQTzg5nl9UWDKfY1gifz
Jd74nq6dNCjpWG4drIsyhqX+
-----END PRIVATE KEY-----"#;

    // Corresponding JWKS (public key in JWK format)
    pub(crate) const TEST_JWKS_JSON: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"u-uexVS-4MJo4zxH5eAPmoxtwxY-mB5kvYGq4BzAoaXSzG7fMm6rtYRz1DSkMp3VLxSeqvsSRRHbN3gbYweRiy7ZY_ZUnLxj7Fe9_Oq8qXh6t9CBK4Jtm3kCchfZXba1RwQT28-3gKOPosAif5uSLLqCwmGT0Kw1HaWsdHVBGv3j-m2nao2dq9K3nJx8NfsxsqM80hzbz7SvSD7CsAXGxo7eZ-fvZ1jd9tv5iEgLizcLb-5dy42vFO5tIsR9GS8BUoEy7cxHySErsfp4BkeJNjwVXqPsgzmbbmrcewIsWtRXqzsIqtsbKBjrNnYV2oMBRncG7PMfzLxI9OuzJtzqyw","e":"AQAB"}]}"#;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Create a signed JWT with given claims.
    fn make_jwt(issuer: &str, subject: &str, audience: &str, iat: u64, exp: u64) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());

        let claims = json!({
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": iat,
            "exp": exp,
        });

        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    /// Build a TestContext with OIDC enabled, pointing at the given mock JWKS URL.
    fn create_oidc_test_context(mock_issuer_url: &str) -> TestContext {
        create_oidc_test_context_scoped(mock_issuer_url, &["*"], None)
    }

    /// Like [`create_oidc_test_context`], with the provider `namespace_scope`
    /// and the main-branch rule's `namespace_scope` injectable.
    fn create_oidc_test_context_scoped(
        mock_issuer_url: &str,
        provider_scope: &[&str],
        main_rule_scope: Option<Vec<String>>,
    ) -> TestContext {
        let issuer = mock_issuer_url.to_string();
        let provider_scope: Vec<String> = provider_scope.iter().map(|s| s.to_string()).collect();
        let mut ctx = create_test_context_with_config(move |cfg| {
            cfg.auth.enabled = true;
            cfg.auth.anonymous_read = false;
            cfg.auth.oidc = OidcConfig {
                enabled: true,
                leeway_secs: 60,
                jwks_cache_secs: 300,
                providers: vec![OidcProvider {
                    name: "test-ci".to_string(),
                    issuer: issuer.clone(),
                    jwks_uri: None,
                    audience: "nora".to_string(),
                    algorithms: vec!["RS256".to_string()],
                    max_token_lifetime_secs: 900,
                    namespace_scope: provider_scope.clone(),
                    namespace_scope_enforcement: crate::config::ScopeEnforcement::Enforce,
                    enabled: true,
                    role_rules: vec![
                        // Admin ROLE with a RESTRICTED scope, and admin role with
                        // no rule scope (unrestricted under provider `["*"]`).
                        // Distinct `admin-scoped`/`admin-free` segments so these
                        // never match the `repo:myorg/app:*` subjects other OIDC
                        // tests mint (first-match-wins). Used by the admin-mint
                        // scope-escape test.
                        OidcRoleRule {
                            pattern: "repo:myorg/admin-scoped:*".to_string(),
                            role: "admin".to_string(),
                            namespace_scope: Some(vec!["ci-transport/**".to_string()]),
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/admin-free:*".to_string(),
                            role: "admin".to_string(),
                            namespace_scope: None,
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/*:ref:refs/heads/main".to_string(),
                            role: "write".to_string(),
                            namespace_scope: main_rule_scope.clone(),
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/*:pull_request".to_string(),
                            role: "write".to_string(),
                            namespace_scope: Some(vec!["ci-transport/**".to_string()]),
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/*".to_string(),
                            role: "read".to_string(),
                            namespace_scope: None,
                        },
                    ],
                }],
            };
        });

        // Wire up the OidcValidator on the existing state
        let oidc_validator =
            OidcValidator::new(ctx.state.config.auth.oidc.clone(), reqwest::Client::new());
        // We need to rebuild the state with oidc set — use Arc::get_mut or rebuild
        let state = crate::AppState {
            storage: ctx.state.storage.clone(),
            config: ctx.state.config.clone(),
            enabled_registries: ctx.state.enabled_registries.clone(),
            start_time: ctx.state.start_time,
            startup_duration_ms: ctx.state.startup_duration_ms,
            auth: ctx.state.auth.clone(),
            // Prod builds a token store whenever `auth.enabled` (main.rs:1782);
            // the base builder keyed it off its `auth_enabled` arg (false here,
            // the `enabled` tweak comes from `customize`), leaving OIDC
            // identities' token operations untested. Mirror prod so the store is
            // present for an OIDC caller that reaches a token handler.
            tokens: Some(crate::tokens::TokenStore::new(ctx.state.storage.clone())),
            metrics: Arc::new(crate::dashboard_metrics::DashboardMetrics::new()),
            activity: Arc::new(crate::activity_log::ActivityLog::new(50)),
            audit: ctx.state.audit.clone(),
            docker_auth: Arc::new(crate::registry::DockerAuth::new(reqwest::Client::new(), 5)),
            repo_index: Arc::new(crate::repo_index::RepoIndex::new()),
            http_client: reqwest::Client::new(),
            http_client_no_redirect: reqwest::Client::new(),
            hf_canonical_ids: Arc::default(),
            upload_sessions: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
            publish_locks: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
            reloadable: Arc::new(arc_swap::ArcSwap::from_pointee(crate::ReloadableConfig {
                curation_engine: crate::curation::CurationEngine::new(
                    crate::config::CurationConfig::default(),
                ),
                bypass_token: None,
            })),
            auth_failures: Arc::new(crate::auth::AuthFailureTracker::new(5, 900)),
            oidc: Some(Arc::new(oidc_validator)),
            teleport: None,
            circuit_breaker: Arc::new(crate::circuit_breaker::CircuitBreakerRegistry::new(
                ctx.state.config.circuit_breaker.clone(),
            )),
            proxy_coalesce: crate::proxy_coalesce::InflightMap::new(),
            artifact_flights: crate::proxy_coalesce::InflightMap::new(),
            spool: ctx.state.spool.clone(),
            blob_flights: crate::proxy_coalesce::InflightMap::new(),
            packument_memo: Arc::default(),
            digest_store: ctx.state.digest_store.clone(),
            signer: ctx.state.signer.clone(),
            leak_finders: ctx.state.leak_finders.clone(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            nuget_hosted: Default::default(),
            maintenance_heartbeat: Default::default(),
            pull_stats: std::sync::Arc::new(
                crate::registry::docker::PullStatsAccumulator::default(),
            ),
        };

        // Rebuild router with new state
        use axum::{extract::DefaultBodyLimit, middleware, Router};
        let mut registry_routes = Router::new();
        for reg in state.enabled_registries.iter() {
            match reg {
                crate::registry_type::RegistryType::Raw => {
                    registry_routes = registry_routes.merge(crate::registry::raw_routes());
                }
                _ => {}
            }
        }
        let public_routes = Router::new().merge(crate::health::routes());
        let app_routes = Router::new()
            .merge(crate::auth::token_routes())
            .merge(crate::ui::routes())
            .merge(crate::admin::routes())
            .merge(registry_routes);
        let app = Router::new()
            .merge(public_routes)
            .merge(app_routes)
            .layer(DefaultBodyLimit::max(
                state.config.server.body_limit_mb * 1024 * 1024,
            ))
            .layer(middleware::from_fn(
                crate::request_id::request_id_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::auth::auth_middleware,
            ))
            .with_state(state.clone());

        ctx.state = state;
        ctx.app = app;
        ctx
    }

    #[tokio::test]
    async fn test_oidc_valid_jwt_write_access() {
        let mock_server = MockServer::start().await;

        // Serve JWKS at /.well-known/jwks.json
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/oidc-test.txt",
            vec![("authorization", &bearer)],
            b"hello from ci".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Write with main-branch OIDC token should succeed"
        );
    }

    #[tokio::test]
    async fn test_oidc_rule_scope_narrows_writes() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // pull_request rule: role=write, namespace_scope=["ci-transport/**"]
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:pull_request",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {}", token);

        // In-scope write is allowed…
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/ci-transport/run-1/artifact.txt",
            vec![("authorization", &bearer)],
            b"transport".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "PR token should write inside its rule scope"
        );

        // …but the same identity cannot write outside the rule's scope, even
        // though the provider scope is ["*"].
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/prod/artifact.txt",
            vec![("authorization", &bearer)],
            b"escape".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "PR token must not write outside its rule scope"
        );
    }

    /// #1094: a namespace-scoped OIDC identity must not escalate by
    /// minting an unrestricted opaque token through the UI create path. The
    /// write handlers enforce the scope (the control below), and the UI mint
    /// now refuses a scoped caller (`decide_ui_token_mint`) instead of handing
    /// it an `nra_` token that writes anywhere. Before the fix the mint returned
    /// 200 and that token wrote to `prod/`; on `github/main` the UI path
    /// required Basic auth and returned 400.
    #[tokio::test]
    async fn test_oidc_scoped_identity_cannot_mint_unrestricted_token_via_ui() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // pull_request rule: role=write, namespace_scope=["ci-transport/**"].
        let jwt = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:pull_request",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {}", jwt);

        // Control: the identity cannot write to prod/ directly — scope enforced.
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/prod/a.txt",
            vec![("authorization", &bearer)],
            b"x".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "control: a ci-transport-scoped identity must not write to prod/"
        );

        // The UI mint refuses the scoped caller: nothing is handed out.
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &bearer),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write&ttl_days=3650".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a namespace-scoped identity minted an unrestricted token via the UI"
        );
        assert!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .await
                .is_empty(),
            "a token was minted for a scoped caller despite the 403"
        );
    }

    /// #1094 (admin sibling): the admin-gated mint route `POST
    /// /api/v1/admin/tokens` is reachable by every identity the admin gate
    /// admits — including an OIDC identity assigned the `admin` ROLE with a
    /// RESTRICTED `namespace_scope`. Admin role is not admin authority: the
    /// opaque token minted here is always namespace-unrestricted, so a scoped
    /// admin must be refused (403, nothing minted) or it escalates past its own
    /// `ci-transport/**` scope through the token. The non-vacuous pair: an
    /// UNRESTRICTED admin (rule scope `None`, provider `["*"]`) is NOT refused —
    /// the refusal keys on the caller's scope, not on the route.
    #[tokio::test]
    async fn test_oidc_scoped_admin_cannot_mint_unrestricted_token_via_admin_route() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();

        // Scoped admin: role=admin WITH namespace_scope=["ci-transport/**"].
        let scoped = make_jwt(
            &mock_server.uri(),
            "repo:myorg/admin-scoped:deploy",
            "nora",
            now,
            now + 600,
        );
        let scoped_bearer = format!("Bearer {}", scoped);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/v1/admin/tokens",
            vec![
                ("authorization", &scoped_bearer),
                ("content-type", "application/json"),
            ],
            br#"{"username":"svc","role":"write","ttl_days":36500}"#.to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a namespace-scoped admin minted an unrestricted token via the admin route"
        );
        assert!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .await
                .is_empty(),
            "a token was minted for a scoped admin despite the 403"
        );

        // Non-vacuous pair: an unrestricted admin (rule scope None, provider
        // ["*"]) IS allowed — the refusal keys on scope, not on the route.
        let free = make_jwt(
            &mock_server.uri(),
            "repo:myorg/admin-free:deploy",
            "nora",
            now,
            now + 600,
        );
        let free_bearer = format!("Bearer {}", free);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/v1/admin/tokens",
            vec![
                ("authorization", &free_bearer),
                ("content-type", "application/json"),
            ],
            br#"{"username":"svc","role":"write","ttl_days":30}"#.to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an unrestricted admin must still be able to mint via the admin route"
        );
        assert_eq!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .await
                .len(),
            1,
            "exactly one token minted by the unrestricted admin"
        );
    }

    /// #1094: a token minted by an OIDC identity through the UI must not outlive
    /// the provider's `max_token_lifetime_secs` (900s here). An unrestricted
    /// write identity (main-ref rule, provider `["*"]`) may mint — it is not
    /// scope-refused — but the 3650-day request is capped to the 1-day floor.
    /// Maestra (R2-01): the mint is refused outright instead — a workload
    /// identity never exchanges itself for an nra_ token, capped or not.
    #[tokio::test]
    async fn test_oidc_identity_cannot_mint_tokens() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // main-ref rule: role=write, no rule scope, provider scope ["*"] -> an
        // UNRESTRICTED identity (not refused by the scope gate).
        let jwt = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {}", jwt);

        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &bearer),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write&ttl_days=3650".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a workload identity minted a token (R2-01)"
        );
        assert!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .await
                .is_empty(),
            "a token was minted despite the 403"
        );
    }

    #[tokio::test]
    async fn test_oidc_rule_scope_cannot_widen_provider_ceiling() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        // Narrow provider ceiling, rule that tries to widen to ["*"].
        let ctx = create_oidc_test_context_scoped(
            &mock_server.uri(),
            &["myorg/**"],
            Some(vec!["*".to_string()]),
        );
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {}", token);

        // Inside the provider ceiling: allowed.
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/myorg/repo/artifact.txt",
            vec![("authorization", &bearer)],
            b"inside".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // The rule's ["*"] must not lift the provider ceiling.
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/other/artifact.txt",
            vec![("authorization", &bearer)],
            b"escape".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a rule namespace_scope of [\"*\"] must not widen past the provider scope"
        );
    }

    #[tokio::test]
    async fn test_oidc_valid_jwt_read_only_blocks_write() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // dev branch → read-only role
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/dev",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/oidc-test.txt",
            vec![("authorization", &bearer)],
            b"hello".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Write with read-only OIDC token should be forbidden"
        );
    }

    #[tokio::test]
    async fn test_oidc_valid_jwt_read_only_allows_get() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/dev",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        // GET should succeed (even if file doesn't exist — 404 not 401/403)
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/nonexistent.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Read with valid OIDC token should not be 401"
        );
        assert_ne!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Read with read-only OIDC token should not be 403"
        );
    }

    #[tokio::test]
    async fn test_oidc_expired_token_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        // Token expired 2 minutes ago (beyond 60s leeway)
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now - 600,
            now - 120,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Expired OIDC token should be rejected"
        );
    }

    #[tokio::test]
    async fn test_oidc_wrong_issuer_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Token has a different issuer than configured
        let token = make_jwt(
            "https://evil-issuer.example.com",
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Token with wrong issuer should be rejected"
        );
    }

    #[tokio::test]
    async fn test_oidc_wrong_audience_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Token has wrong audience
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "wrong-audience",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Token with wrong audience should be rejected"
        );
    }

    #[tokio::test]
    async fn test_oidc_no_matching_role_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Subject from a different org → no role_rules match
        let token = make_jwt(
            &mock_server.uri(),
            "repo:otherorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Token with no matching role should be rejected"
        );
    }

    #[tokio::test]
    async fn test_oidc_token_lifetime_exceeded() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Token lifetime = 2000s, exceeds max_token_lifetime_secs = 900
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 2000,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Token exceeding max lifetime should be rejected"
        );
    }

    #[tokio::test]
    async fn test_oidc_jwks_fetch_failure_returns_401() {
        let mock_server = MockServer::start().await;

        // Don't mount any mock → JWKS fetch will 404
        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Should fail gracefully when JWKS cannot be fetched"
        );
    }

    #[tokio::test]
    async fn test_oidc_symmetric_algorithm_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();

        // Create token signed with HS256 (symmetric) — should be rejected
        // even before JWKS fetch because of algorithm whitelist
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key-1".to_string());
        let claims = json!({
            "iss": mock_server.uri(),
            "sub": "repo:myorg/app:ref:refs/heads/main",
            "aud": "nora",
            "iat": now,
            "exp": now + 600,
        });
        let key = EncodingKey::from_secret(b"fake-secret");
        let token = encode(&header, &claims, &key).unwrap();

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "HS256 tokens must be rejected for OIDC"
        );
    }

    /// A rejected JWT (unknown `kid` after the JWKS refetch, wrong audience, expiry,
    /// bad signature) stays 401 but never feeds the lockout (R2-48): a JWT cannot
    /// be guessed, so a stream of stale ones from a shared CI egress IP must not
    /// lock out the valid JWT that follows from the same IP.
    #[tokio::test]
    async fn test_oidc_rejected_jwts_never_lock_out_a_valid_one() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;
        let ctx = create_oidc_test_context(&mock_server.uri());
        let issuer = mock_server.uri();
        let sub = "repo:myorg/app:ref:refs/heads/main";
        let now = now_secs();
        let get = |token: String| {
            let app = &ctx.app;
            async move {
                let bearer = format!("Bearer {token}");
                send_with_headers(
                    app,
                    Method::GET,
                    "/raw/test.txt",
                    vec![("authorization", &bearer)],
                    "",
                )
                .await
                .status()
            }
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rotated-key-2".to_string());
        let claims =
            json!({"iss": issuer, "sub": sub, "aud": "nora", "iat": now, "exp": now + 600});
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
        let unknown_kid = encode(&header, &claims, &key).unwrap();
        for _ in 0..10 {
            assert_eq!(get(unknown_kid.clone()).await, StatusCode::UNAUTHORIZED);
        }

        let valid = make_jwt(&issuer, sub, "nora", now, now + 600);
        let (signed, _) = valid.rsplit_once('.').unwrap();
        let bad_signature = format!("{signed}.{}", "A".repeat(342));
        for token in [
            make_jwt(&issuer, sub, "wrong-audience", now, now + 600),
            make_jwt(&issuer, sub, "wrong-audience", now, now + 600),
            make_jwt(&issuer, sub, "nora", now - 600, now - 120),
            make_jwt(&issuer, sub, "nora", now - 600, now - 120),
            bad_signature,
        ] {
            assert_eq!(get(token).await, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            get(valid).await,
            StatusCode::NOT_FOUND,
            "valid JWT authenticates"
        );
    }

    /// R2-01: a workload identity (CI OIDC JWT, 15-min, namespace-scoped) must not
    /// exchange itself for a long-lived, unscoped nra_ token, nor list/revoke tokens.
    #[tokio::test]
    async fn test_oidc_identity_cannot_manage_api_tokens() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;
        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        let jwt = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {jwt}");
        let basic = format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("x:{jwt}")
            )
        );
        for auth in [&bearer, &basic] {
            let resp = super::integration_tests::ui_create_token(&ctx, auth, "write").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "mint via {auth:.6}");
            // Nor through /ui/setup's "Generate token" (JS or JS-free post).
            for extra in [("hx-request", "true"), ("sec-fetch-site", "same-origin")] {
                let resp = send_with_headers(
                    &ctx.app,
                    Method::POST,
                    "/api/ui/tokens/create",
                    vec![
                        ("authorization", auth),
                        ("content-type", "application/x-www-form-urlencoded"),
                        ("accept", "application/json"),
                        extra,
                    ],
                    "description=x&role=read&ui=setup",
                )
                .await;
                assert_eq!(
                    resp.status(),
                    StatusCode::FORBIDDEN,
                    "setup mint via {auth:.6}"
                );
            }
            let resp = send_with_headers(
                &ctx.app,
                Method::GET,
                "/api/ui/tokens/list",
                vec![("authorization", auth)],
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            let resp = send_with_headers(
                &ctx.app,
                Method::POST,
                "/api/ui/tokens/0123456789abcdef/revoke",
                vec![("authorization", auth), ("hx-request", "true")],
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
        // The same JWT still writes to the registry.
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/ci.txt",
            vec![("authorization", &bearer)],
            b"x".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod web_surface_gating_tests {
    use crate::test_helpers::{
        body_bytes, create_test_context_with_anonymous_read,
        create_test_context_with_anonymous_read_and_config, create_test_context_with_auth, send,
        send_with_headers,
    };
    use axum::http::{Method, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn basic(user: &str, pass: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        )
    }

    /// With auth on and no anonymous read, the whole web surface requires
    /// credentials — it enumerates every repository — while probes stay open.
    #[tokio::test]
    async fn test_web_surface_gated_when_private() {
        let ctx = create_test_context_with_auth(&[("alice", "pw")]);

        for p in [
            "/ui/",
            "/ui/rpm",
            "/api/ui/stats",
            "/api/ui/dashboard",
            "/api-docs/openapi.json",
        ] {
            let resp = send(&ctx.app, Method::GET, p, "").await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{p}");
            assert!(
                resp.headers().get("www-authenticate").is_some(),
                "{p} must challenge so browsers prompt"
            );
        }
        // Probes stay unconditionally open (LB/liveness would break).
        for p in ["/health", "/ready"] {
            let resp = send(&ctx.app, Method::GET, p, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{p}");
        }
        // /metrics defaults to open for scrapers.
        let resp = send(&ctx.app, Method::GET, "/metrics", "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Valid credentials open the web surface.
        let cred = basic("alice", "pw");
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/stats",
            vec![("authorization", cred.as_str())],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// anonymous_read (which already exposes repo names through the registry
    /// read APIs) or the explicit public_web_ui switch reopen the surface;
    /// public_metrics=false closes /metrics.
    #[tokio::test]
    async fn test_gating_switches() {
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.auth.enabled = true;
            c.auth.anonymous_read = true;
        });
        let resp = send(&ctx.app, Method::GET, "/ui/", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "anonymous_read opens the UI");

        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.auth.enabled = true;
            c.auth.public_web_ui = true;
        });
        let resp = send(&ctx.app, Method::GET, "/api/ui/stats", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "public_web_ui opens the UI");

        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.auth.enabled = true;
            c.auth.public_metrics = false;
        });
        let resp = send(&ctx.app, Method::GET, "/metrics", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "public_metrics=false gates metrics"
        );
    }

    /// Token management pages stay gated even when the web surface is open.
    #[tokio::test]
    async fn test_token_pages_stay_gated() {
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.auth.enabled = true;
            c.auth.public_web_ui = true;
        });
        let resp = send(&ctx.app, Method::GET, "/api/ui/tokens", "").await;
        assert_ne!(resp.status(), StatusCode::OK);
    }

    // -- #934: opportunistic auth on open web surfaces --

    /// try_basic_auth returns the username for valid htpasswd credentials.
    #[tokio::test]
    async fn test_try_basic_auth_valid() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let encoded = STANDARD.encode("admin:secret");
        assert_eq!(
            super::try_basic_auth(&encoded, &ctx.state, ctx.state.auth.as_deref()).await,
            Some(("admin".to_string(), crate::tokens::Role::Write))
        );
    }

    /// try_basic_auth returns None for wrong password.
    #[tokio::test]
    async fn test_try_basic_auth_wrong_password() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let encoded = STANDARD.encode("admin:wrong");
        assert_eq!(
            super::try_basic_auth(&encoded, &ctx.state, ctx.state.auth.as_deref()).await,
            None
        );
    }

    /// try_basic_auth returns None when no htpasswd store is available.
    #[tokio::test]
    async fn test_try_basic_auth_no_store() {
        let ctx = create_test_context_with_auth(&[]);
        let encoded = STANDARD.encode("admin:secret");
        assert_eq!(
            super::try_basic_auth(&encoded, &ctx.state, ctx.state.auth.as_deref()).await,
            None
        );
    }

    /// try_basic_auth returns None for garbage base64.
    #[tokio::test]
    async fn test_try_basic_auth_invalid_base64() {
        let ctx = create_test_context_with_auth(&[]);
        assert_eq!(
            super::try_basic_auth("%%%not-base64%%%", &ctx.state, ctx.state.auth.as_deref()).await,
            None
        );
    }

    /// A bcrypt hash at cost 31: verifying it takes days, so any test that
    /// finishes while this user is in htpasswd proves bcrypt never ran.
    fn unverifiable_hash() -> String {
        bcrypt::hash("irrelevant", 4)
            .unwrap()
            .replacen("$04$", "$31$", 1)
    }

    /// Run `f` on its own runtime with a deadline; on timeout the runtime is
    /// abandoned instead of joined, so a stray bcrypt fails the test, not hangs it.
    fn within_deadline<F: std::future::Future<Output = ()>>(f: F) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt
            .block_on(async { tokio::time::timeout(std::time::Duration::from_secs(10), f).await });
        rt.shutdown_background();
        assert!(res.is_ok(), "request ran an htpasswd bcrypt verify");
    }

    /// An `nra_` token as the Basic password works when no htpasswd is loaded
    /// (missing or empty file): the token store does not depend on htpasswd.
    #[tokio::test]
    async fn test_basic_api_token_without_htpasswd() {
        let ctx = create_test_context_with_auth(&[]);
        assert!(ctx.state.auth.is_none());
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Write)
            .await
            .unwrap();
        let good = format!("Basic {}", STANDARD.encode(format!("token:{token}")));
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/t.txt",
            vec![("authorization", &good)],
            b"x".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bad = format!("Basic {}", STANDARD.encode("token:nra_bogus"));
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/t.txt",
            vec![("authorization", &bad)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Probes never validate a Basic header: no bcrypt, no lockout bookkeeping.
    #[test]
    fn test_probe_ignores_basic_credentials() {
        let hash = unverifiable_hash();
        let ctx = create_test_context_with_auth(&[("admin", hash.as_str())]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:wrong"));
        within_deadline(async {
            for _ in 0..6 {
                let resp = send_with_headers(
                    &ctx.app,
                    Method::GET,
                    "/health",
                    vec![("authorization", &header_val)],
                    "",
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
            }
        });
        let ip: std::net::IpAddr = [127, 0, 0, 1].into();
        assert!(ctx
            .state
            .auth_failures
            .check_blocked(&ip, "admin")
            .is_none());
    }

    /// A wrong Basic credential on an open path counts toward the lockout, and
    /// once locked the open path stops validating (no more bcrypt) but stays open.
    #[tokio::test]
    async fn test_open_path_bad_basic_counts_toward_lockout() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:wrong"));
        for _ in 0..5 {
            let resp = send_with_headers(
                &ctx.app,
                Method::GET,
                "/",
                vec![("authorization", &header_val)],
                "",
            )
            .await;
            assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let ip: std::net::IpAddr = [127, 0, 0, 1].into();
        assert!(ctx
            .state
            .auth_failures
            .check_blocked(&ip, "admin")
            .is_some());
    }

    /// On an open web surface (anonymous_read=true), valid Basic credentials
    /// must produce a real AuthenticatedUser — not "anonymous". Verified via
    /// /api/ui/dashboard: anonymous sees empty proxy_upstreams; authenticated
    /// sees the configured npm upstream.
    #[tokio::test]
    async fn test_opportunistic_basic_auth_on_open_surface() {
        let ctx = create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], |c| {
            c.npm.proxy = Some("https://registry.npmjs.org".into());
        });

        // Anonymous: proxy_upstreams redacted
        let resp = send(&ctx.app, Method::GET, "/api/ui/dashboard", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for mp in json["mount_points"].as_array().unwrap() {
            assert!(
                mp["proxy_upstreams"].as_array().unwrap().is_empty(),
                "anonymous must see empty proxy_upstreams"
            );
        }

        // Valid Basic creds: proxy_upstreams populated
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/dashboard",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let npm = json["mount_points"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["registry"].as_str() == Some("npm"))
            .expect("npm mount");
        assert!(
            !npm["proxy_upstreams"].as_array().unwrap().is_empty(),
            "authenticated must see populated proxy_upstreams for npm"
        );
    }

    /// On an open web surface, invalid Basic credentials fall through to
    /// anonymous (the path is open — no 401).
    #[tokio::test]
    async fn test_opportunistic_bad_creds_fall_through_to_anonymous() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

        let bad = format!("Basic {}", STANDARD.encode("admin:wrong"));
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/dashboard",
            vec![("authorization", &bad)],
            "",
        )
        .await;
        // Open path — no 401 even with bad creds
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// On an open web surface, a valid Bearer token must produce a real
    /// AuthenticatedUser, enabling proxy_upstreams disclosure.
    #[tokio::test]
    async fn test_opportunistic_bearer_auth_on_open_surface() {
        let ctx = create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], |c| {
            c.npm.proxy = Some("https://registry.npmjs.org".into());
        });

        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, crate::tokens::Role::Write)
            .await
            .unwrap();

        let header_val = format!("Bearer {token}");
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/dashboard",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let npm = json["mount_points"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["registry"].as_str() == Some("npm"))
            .expect("npm mount");
        assert!(
            !npm["proxy_upstreams"].as_array().unwrap().is_empty(),
            "bearer-authenticated must see populated proxy_upstreams"
        );
    }

    /// Captures the formatted log of the current thread (tokio::test is single-threaded).
    #[derive(Clone, Default)]
    struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
        type Writer = LogSink;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl LogSink {
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            let subscriber = tracing_subscriber::fmt()
                .json()
                .with_writer(self.clone())
                .with_max_level(tracing::Level::WARN)
                .finish();
            tracing::subscriber::set_default(subscriber)
        }
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    async fn get_with_auth(ctx: &crate::test_helpers::TestContext, auth: &str) -> StatusCode {
        send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", auth)],
            "",
        )
        .await
        .status()
    }

    /// A refused credential is logged with its client, kind and reason, and the
    /// secret itself (password, nra_ token, JWT) never reaches the log.
    #[tokio::test]
    async fn rejected_credentials_are_logged_without_the_secret() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let sink = LogSink::default();
        let _guard = sink.install();
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYW5hcnktc3ViIn0.c2lnbmF0dXJlLWNhbmFyeQ";
        let basic = |p: &str| format!("Basic {}", STANDARD.encode(format!("admin:{p}")));
        let tried = [
            (basic("canary-pass-1"), "basic_htpasswd", "wrong_password"),
            (
                basic("nra_canarytoken0000000000000000"),
                "basic_nra",
                "token_invalid",
            ),
            (
                "Bearer nra_canarytoken1111111111111111".to_string(),
                "bearer_nra",
                "token_invalid",
            ),
            (format!("Bearer {jwt}"), "bearer_jwt", "no_oidc"),
            ("Digest canary-digest".to_string(), "malformed", "malformed"),
        ];
        for (auth, kind, reason) in &tried {
            assert_eq!(get_with_auth(&ctx, auth).await, StatusCode::UNAUTHORIZED);
            let out = sink.text();
            let line = out
                .lines()
                .rfind(|l| l.contains("auth rejected: credential refused"))
                .unwrap_or_else(|| panic!("{kind}: no rejection logged in {out}"));
            assert!(line.contains(&format!(r#""kind":"{kind}""#)), "{line}");
            assert!(line.contains(&format!(r#""reason":"{reason}""#)), "{line}");
            assert!(line.contains(r#""client_ip":"127.0.0.1""#), "{line}");
        }
        let out = sink.text();
        for secret in ["canary", "nra_", "eyJ", "c2lnbmF0dXJl", "Basic ", "Bearer "] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
    }

    /// The anonymous round of the NuGet/Docker challenge (no Authorization) is half
    /// of all traffic: answered 401, never logged.
    #[tokio::test]
    async fn anonymous_challenge_is_not_logged() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let sink = LogSink::default();
        let _guard = sink.install();
        let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(sink.text(), "");
    }

    /// One lockout: one WARN at its start, one for its refusals, however many 429s.
    #[tokio::test]
    async fn lockout_refusals_are_logged_once() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let sink = LogSink::default();
        let _guard = sink.install();
        let wrong = format!("Basic {}", STANDARD.encode("admin:wrong"));
        for _ in 0..5 {
            assert_eq!(get_with_auth(&ctx, &wrong).await, StatusCode::UNAUTHORIZED);
        }
        for _ in 0..3 {
            assert_eq!(
                get_with_auth(&ctx, &wrong).await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        let out = sink.text();
        assert_eq!(out.matches("auth lockout:").count(), 1, "{out}");
        assert_eq!(out.matches(r#""reason":"locked_out""#).count(), 1, "{out}");
        assert_eq!(
            out.matches(r#""reason":"wrong_password""#).count(),
            5,
            "{out}"
        );
    }
}
