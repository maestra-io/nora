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
pub mod oidc_session;
pub mod teleport;
mod token_routes;

pub use htpasswd::HtpasswdAuth;
pub use namespace::{enforce_namespace_scope, NamespaceAuthority};
pub use oidc::OidcValidator;
pub use teleport::TeleportValidator;
pub use token_routes::{token_routes, MintedTokenResponse, TokenListItem, TokenListResponse};

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
/// token it mints. Inserted ONLY for OIDC identities: the shorter of the
/// provider's `max_token_lifetime_secs` and what is left of the JWT until its
/// `exp`, so a minted token never outlives the JWT that minted it (0 once the
/// JWT has expired, inside the validator's leeway). Absent for Basic and opaque
/// (`nra_`) callers, which carry no such ceiling. Every mint route an OIDC
/// identity reaches (the UI and the admin route) reads it to cap the new token
/// so a short-lived federated identity cannot bootstrap a long-lived static one
/// (#1094).
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

use crate::config::canonical_ip;
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

/// Tracks wrong passwords for brute-force protection, per account and per
/// address.
///
/// An account is a username at a client address. After `max_failures`
/// consecutive failures it is locked out of password authentication with
/// exponential backoff: 2^(failures - max_failures) seconds, capped at
/// `max_lockout_secs`. Guesses at one account do not lock out another behind
/// the same address, and only a login as that username clears its count.
///
/// An address is also held, whatever the username, once it has sent
/// [`ADDRESS_FAILURES_PER_ACCOUNT`] times `max_failures` wrong passwords, with
/// the same backoff, so guessing across usernames gains nothing. A login does
/// not clear the address count, which ends after `2 * max_lockout_secs`
/// without a failure ([`AuthFailureTracker::cleanup`]).
///
/// Bearer credentials (API tokens, OIDC JWTs) cannot be guessed and are
/// neither counted nor refused.
pub struct AuthFailureTracker {
    entries: parking_lot::Mutex<FailureCounts>,
    /// Number of failures before lockout kicks in (default: 5)
    max_failures: u32,
    /// Maximum lockout duration in seconds (default: 900 = 15 minutes)
    max_lockout_secs: u64,
}

/// How many accounts' worth of failures an address may send before it is held
/// whatever the username. An account adds at most `max_failures` failures
/// before its own lockout stops counting it, so the address ceiling is reached
/// only by failing many accounts, which is guessing across usernames rather
/// than a mistyped password; ten accounts (50 failures at the default 5) keep
/// an office of mistyping users clear of it.
pub const ADDRESS_FAILURES_PER_ACCOUNT: u32 = 10;

/// Failure counts: (consecutive failures, last failure).
#[derive(Default)]
struct FailureCounts {
    /// By address and SHA-256 of the username: a fixed-size key whatever the
    /// username a client sends.
    accounts: HashMap<(IpAddr, [u8; 32]), (u32, Instant)>,
    /// By address, for every username.
    addresses: HashMap<IpAddr, (u32, Instant)>,
    /// Accounts whose current lockout already logged a 429.
    refusals_logged: std::collections::HashSet<(IpAddr, [u8; 32])>,
}

fn account_key(ip: IpAddr, username: &str) -> (IpAddr, [u8; 32]) {
    use sha2::{Digest, Sha256};
    (ip, Sha256::digest(username.as_bytes()).into())
}

impl AuthFailureTracker {
    pub fn new(max_failures: u32, max_lockout_secs: u64) -> Self {
        Self {
            entries: parking_lot::Mutex::new(FailureCounts::default()),
            max_failures,
            max_lockout_secs,
        }
    }

    /// Seconds left of a lockout at `threshold` failures, if one is running.
    fn lockout_left(&self, count: Option<&(u32, Instant)>, threshold: u32) -> Option<u64> {
        let (failures, last_failure) = count?;
        if *failures < threshold {
            return None;
        }
        let exponent = (*failures - threshold).min(20);
        let lockout_secs = (1u64 << exponent).min(self.max_lockout_secs);
        let elapsed = last_failure.elapsed().as_secs();
        (elapsed < lockout_secs).then(|| lockout_secs - elapsed)
    }

    /// Seconds left until `username` at `ip` may try a password again, if it
    /// is locked out: the account itself, or the address for every username.
    pub fn check_blocked(&self, ip: &IpAddr, username: &str) -> Option<u64> {
        let entries = self.entries.lock();
        let account = self.lockout_left(
            entries.accounts.get(&account_key(*ip, username)),
            self.max_failures,
        );
        let address = self.lockout_left(
            entries.addresses.get(ip),
            self.max_failures
                .saturating_mul(ADDRESS_FAILURES_PER_ACCOUNT),
        );
        account.max(address)
    }

    /// Apply to the counts of `username` at `ip` what [`lockout_rule`]
    /// decided an attempt does to them: the one way an attempt changes them.
    pub(crate) fn count(&self, ip: IpAddr, username: &str, count: LockoutCount) {
        match count {
            LockoutCount::Nothing => {}
            LockoutCount::Failure => {
                self.record_failure(ip, username);
            }
            LockoutCount::Clear => self.record_success(&ip, username),
        }
    }

    /// Record a wrong password for `username` at `ip`. Returns the lockout length
    /// when this failure starts a lockout of the account: an account locked out is
    /// refused before its password is checked, so every failure at or past the
    /// threshold starts a new (longer) lockout, logged and counted once.
    fn record_failure(&self, ip: IpAddr, username: &str) -> Option<u64> {
        let now = Instant::now();
        let key = account_key(ip, username);
        let failures = {
            let mut entries = self.entries.lock();
            let account = entries.accounts.entry(key).or_insert((0, now));
            *account = (account.0.saturating_add(1), now);
            let failures = account.0;
            let address = entries.addresses.entry(ip).or_insert((0, now));
            *address = (address.0.saturating_add(1), now);
            entries.refusals_logged.remove(&key);
            failures
        };
        if failures < self.max_failures {
            return None;
        }
        let exponent = (failures - self.max_failures).min(20);
        let lockout_secs = (1u64 << exponent).min(self.max_lockout_secs);
        crate::metrics::AUTH_LOCKOUTS_TOTAL.inc();
        let username: String = username.chars().take(64).collect();
        tracing::warn!(
            client_ip = %ip,
            username = %username,
            failures,
            lockout_secs,
            "auth lockout: too many failed Basic logins, answering 429"
        );
        Some(lockout_secs)
    }

    /// True for the first 429 of the current lockout of `username` at `ip`: the
    /// refusals of one lockout are logged once, not once per request.
    pub fn first_refusal(&self, ip: &IpAddr, username: &str) -> bool {
        self.entries
            .lock()
            .refusals_logged
            .insert(account_key(*ip, username))
    }

    /// A login as `username` from `ip`: clears that account's failures, not
    /// the address's.
    fn record_success(&self, ip: &IpAddr, username: &str) {
        let key = account_key(*ip, username);
        let mut entries = self.entries.lock();
        entries.accounts.remove(&key);
        entries.refusals_logged.remove(&key);
    }

    /// Remove entries older than 2 x max_lockout_secs (call periodically).
    pub fn cleanup(&self) {
        let keep =
            |(_, last): &(u32, Instant)| last.elapsed().as_secs() < self.max_lockout_secs * 2;
        let mut entries = self.entries.lock();
        entries.accounts.retain(|_, count| keep(count));
        entries.addresses.retain(|_, count| keep(count));
        let FailureCounts {
            accounts,
            refusals_logged,
            ..
        } = &mut *entries;
        refusals_logged.retain(|key| accounts.contains_key(key));
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
    ) || path == oidc_session::SESSION_ROUTE
        || is_static_asset(path)
        || is_apk_public_key(path)
}

/// The apk proxy's public key (`/apk/keys/<name>`): what Dockerfiles `ADD` before they
/// hold a token, and public by nature.
fn is_apk_public_key(path: &str) -> bool {
    path.strip_prefix("/apk/keys/")
        .is_some_and(|name| !name.is_empty() && !name.contains('/'))
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
/// ignored (with one warning per setting) and the peer IP is returned. This
/// prevents attackers from spoofing their IP to bypass `AuthFailureTracker`
/// lockout. Every address is canonical: an IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`, an IPv4 peer of a dual-stack socket) is its IPv4
/// address, so one client is one key whichever socket or proxy it came by.
pub(crate) fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &crate::config::TrustedProxies,
) -> IpAddr {
    let peer = canonical_ip(peer);
    if !trusted_proxies.contains(peer) {
        if headers.contains_key("x-forwarded-for") || headers.contains_key("x-real-ip") {
            trusted_proxies.warn_untrusted_forwarding(peer);
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
                return canonical_ip(ip);
            }
        }
    }
    // No forwarding headers — use peer IP
    peer
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
            .map(canonical_ip)
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
    /// no_oidc, locked_out, session_invalid, or an OIDC class from `oidc::classify_rejection`.
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
        } else if token.trim().starts_with("nrs_") {
            "bearer_nrs"
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
    } else if password.starts_with("nrs_") {
        "basic_nrs"
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
        // Terraform package downloads carry no credentials; metadata served to an
        // authenticated client names them by signed URLs (registry/terraform.rs).
        let tf_signed_download =
            matches!(
                *request.method(),
                axum::http::Method::GET | axum::http::Method::HEAD
            ) && crate::registry::terraform::download_signature_valid(path, request.uri().query());
        let open = is_public_path(path)
            || npm_login
            || tf_signed_download
            || (is_web_surface(path) && (config.anonymous_read || config.public_web_ui))
            || (path == "/metrics" && config.public_metrics);
        // Probes and metrics never validate credentials: a Basic header there
        // would buy any client an unlimited, unauthenticated bcrypt per request.
        // Nor do the redirect at `/` and the static assets: their handlers use no
        // identity and sit behind no rate limiter, so a token there would buy an
        // unlimited storage read per request.
        let no_identity =
            matches!(path, "/health" | "/ready" | "/metrics" | "/") || is_static_asset(path);
        if open {
            // Opportunistic auth: if the caller provided credentials on an
            // open path, try to validate them so downstream handlers can
            // distinguish "anonymous browse" from "authenticated browse"
            // (e.g. to gate proxy_upstreams disclosure). If validation fails
            // we fall through to anonymous — the path is open regardless.
            if let Some(auth_val) = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .filter(|_| !no_identity)
            {
                if let Some(encoded) = auth_val.strip_prefix("Basic ") {
                    // No bcrypt here (an open path has no lockout and no limiter): an
                    // `nra_` password is checked as an API token, any other only if
                    // htpasswd has already accepted it on a gated path.
                    let token_identity = match (basic_credentials(encoded), &state.tokens) {
                        (Ok((_, password)), Some(store)) if password.starts_with("nra_") => {
                            store.verify_token(&password).await.ok()
                        }
                        _ => None,
                    };
                    let identity = token_identity.or_else(|| {
                        try_basic_auth(encoded, htpasswd).map(|username| {
                            let role = state.config.auth.htpasswd_role(&username);
                            (username, role)
                        })
                    });
                    if let Some((username, role)) = identity {
                        request
                            .extensions_mut()
                            .insert(NamespaceAuthority::Unrestricted);
                        request.extensions_mut().insert(AuthenticatedUser(username));
                        request.extensions_mut().insert(AuthenticatedRole(role));
                        return next.run(request).await;
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
            return next.run(request).await;
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
    // Token management, whoami, admin, and all Docker `/v2` paths are excluded,
    // and so is /metrics: here it is closed (`public_metrics = false`; an open one
    // was served above), and `anonymous_read` opens registry reads, not metrics.
    if state.config.auth.anonymous_read
        && (is_read_method || is_npm_audit)
        && path != "/metrics"
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

    // The client address the password lockout counts by.
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
        // 0. Maestra: an OIDC session token (nrs_), never a JWT or an nra_ token.
        if token.starts_with(oidc_session::SESSION_TOKEN_PREFIX) {
            let verdict = match state.oidc.as_deref() {
                Some(oidc) => oidc.verify_session(&state.storage, token).await,
                None => Err(oidc_session::SessionError::Invalid),
            };
            return match verdict {
                Ok(identity) => {
                    admit_workload(
                        identity,
                        request,
                        next,
                        is_token_management,
                        is_npm_audit,
                        is_admin,
                    )
                    .await
                }
                Err(oidc_session::SessionError::Storage(e)) => {
                    tracing::error!(error = %e, "session store read failed during Bearer auth");
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Token verification unavailable",
                    )
                        .into_response()
                }
                Err(oidc_session::SessionError::Invalid) => AuthRejection::new("session_invalid")
                    .on(unauthorized_response("Invalid or expired token", realm)),
            };
        }
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
                        return admit_workload(
                            identity,
                            request,
                            next,
                            is_token_management,
                            is_npm_audit,
                            is_admin,
                        )
                        .await;
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

        // Both token and OIDC failed. A Bearer credential cannot be guessed
        // (a random API token or a signed JWT), so a wrong one does not count
        // toward the password lockout: a client replaying an expired token
        // must not lock everyone behind its address out of their passwords.
        return rejection.on(unauthorized_response("Invalid or expired token", realm));
    }

    // Parse Basic auth
    if !auth_header.starts_with("Basic ") {
        return AuthRejection::new("malformed").on(unauthorized_response(
            "Basic or Bearer authentication required",
            realm,
        ));
    }

    // The account the password lockout counts by: the username at the client
    // address. A header that does not decode to `user:password` is refused
    // below without being counted.
    let encoded = &auth_header[6..];
    let credentials = basic_credentials(encoded).ok();
    let account = client_ip.zip(credentials.as_ref().map(|(user, _)| user.clone()));
    let locked_out = account
        .as_ref()
        .and_then(|(ip, user)| state.auth_failures.check_blocked(ip, user));

    // Verify credentials: htpasswd first, then the token store (#736, #1094);
    // `decide_basic_auth` has the rules, this applies its decision. The htpasswd check is
    // async (bcrypt runs off the async workers), so it runs here, on the credentials
    // `decide_basic_auth` reads, and hands it the verdict. A locked-out account gets no
    // password checked, so no bcrypt runs for it; an API token sent as the password
    // cannot be guessed, so it is still verified, as over Bearer: Docker has no other
    // way to present one. Maestra: htpasswd applies only to a peer in
    // auth.htpasswd_allowed_peers (`htpasswd` is None otherwise); `npm audit` POSTs
    // with a read token, so it is gated as a read (is_npm_audit).
    let htpasswd = htpasswd.filter(|_| locked_out.is_none());
    let htpasswd_matched = match (htpasswd, &credentials) {
        (Some(htpasswd), Some((user, password))) => htpasswd.verify(user, password).await,
        _ => false,
    };
    let gate_method = if is_npm_audit {
        Method::GET
    } else {
        request.method().clone()
    };
    // The token store reads storage (async), so its verdict is taken here, only when
    // decide_basic_auth would ask for it: htpasswd did not match.
    let token_verdict = match (&state.tokens, &credentials) {
        (Some(store), Some((_, password))) if !htpasswd_matched => {
            Some(store.verify_token(password).await)
        }
        // A header that does not decode: decide_basic_auth refuses it before it asks.
        (Some(_), None) => Some(Err(crate::tokens::TokenError::InvalidFormat)),
        _ => None,
    };
    let checked = decide_basic_auth(
        encoded,
        htpasswd.map(|_| move |_: &str, _: &str| htpasswd_matched),
        token_verdict.map(|verdict| move |_: &str| verdict),
        &gate_method,
        is_admin,
    );
    let (decision, count) = lockout_rule(
        locked_out,
        checked,
        account.as_ref().map(|(_, user)| user.as_str()),
    );
    // Maestra: only a password htpasswd could have matched is a guess worth counting;
    // with no htpasswd for this peer the password can only be a token, which is not
    // guessable, and a count would only lock out the valid credentials sharing the
    // egress IP (CI runners). Under a lockout nothing is counted anyway.
    let count = match count {
        LockoutCount::Failure if htpasswd.is_none() => LockoutCount::Nothing,
        count => count,
    };
    if let Some((ip, username)) = &account {
        state.auth_failures.count(*ip, username, count);
    }
    match decision {
        BasicDecision::Authenticated { user, role } => {
            // Maestra: an htpasswd user carries the role of auth.read_only_users;
            // a token carries its own (decide_basic_auth gated that one already).
            let role = if htpasswd_matched {
                let role = state.config.auth.htpasswd_role(&user);
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
        // Valid credentials, not authorized: not a wrong password, so not
        // counted.
        BasicDecision::Forbidden(reason) => (StatusCode::FORBIDDEN, reason).into_response(),
        BasicDecision::Unauthorized {
            message,
            record_failure,
        } => {
            let password = credentials
                .as_ref()
                .map_or("", |(_, password)| password.as_str());
            let reason = match (record_failure, password.starts_with("nra_")) {
                (false, _) => "malformed",
                (true, true) => "token_invalid",
                (true, false) => "wrong_password",
            };
            AuthRejection::new(reason).on(unauthorized_response(message, realm))
        }
        BasicDecision::LockedOut(retry_after) => AuthRejection {
            log: account
                .as_ref()
                .is_some_and(|(ip, user)| state.auth_failures.first_refusal(ip, user)),
            retry_after: Some(retry_after),
            ..AuthRejection::new("locked_out")
        }
        .on(too_many_failed_attempts(retry_after)),
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
pub(crate) enum BasicDecision {
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
    /// The account is locked out and the credential was not one served under
    /// a lockout (429, retry after so many seconds). Only [`lockout_rule`]
    /// answers it.
    LockedOut(u64),
}

/// What a password attempt does to the lockout counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockoutCount {
    /// Nothing: not a wrong password, or a password that was not checked.
    Nothing,
    /// A wrong password: one more failure for the username at the address
    /// and one more toward the address ceiling.
    Failure,
    /// A login as the username: its own failures are cleared, not the
    /// address's.
    Clear,
}

/// The rules of the password lockout, in one place: what a request with a
/// password is answered and what it does to the counts, from the lockout its
/// account is under (`locked_out`, seconds left), what checking its
/// credentials decided (`checked`) and the username it was sent for (`None`
/// when there is no account to count, a header that does not decode or no
/// client address).
///
/// - Under a lockout no password was checked: whatever did not pass is
///   refused as locked out and counted nowhere, not for the username and not
///   toward the address ceiling. What passes without a password, an API
///   token sent as one, is served (or refused 403, or 503 on an outage) as
///   without a lockout.
/// - Only a wrong password counts as a failure. A 403, an outage, a header
///   that does not decode and a missing store count nothing.
/// - A login clears the failures of its own username only: an API token of
///   another owner sent under the username clears nothing.
pub(crate) fn lockout_rule(
    locked_out: Option<u64>,
    checked: BasicDecision,
    username: Option<&str>,
) -> (BasicDecision, LockoutCount) {
    let served_locked_out = matches!(
        checked,
        BasicDecision::Authenticated { .. }
            | BasicDecision::Forbidden(_)
            | BasicDecision::ServiceUnavailable(_)
    );
    if let (Some(retry_after), false) = (locked_out, served_locked_out) {
        return (BasicDecision::LockedOut(retry_after), LockoutCount::Nothing);
    }
    let count = match &checked {
        BasicDecision::Authenticated { user, .. } if Some(user.as_str()) == username => {
            LockoutCount::Clear
        }
        BasicDecision::Unauthorized {
            record_failure: true,
            ..
        } => LockoutCount::Failure,
        BasicDecision::Authenticated { .. }
        | BasicDecision::Forbidden(_)
        | BasicDecision::Unauthorized { .. }
        | BasicDecision::ServiceUnavailable(_)
        | BasicDecision::NotConfigured
        | BasicDecision::LockedOut(_) => LockoutCount::Nothing,
    };
    (checked, count)
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
    let (username, password) = match basic_credentials(encoded) {
        Ok(credentials) => credentials,
        Err(message) => {
            return BasicDecision::Unauthorized {
                message,
                record_failure: false,
            }
        }
    };
    let (username, password) = (username.as_str(), password.as_str());

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

/// The username and password of a Basic credential (`encoded`, the header
/// value after `Basic `), or why it is malformed.
fn basic_credentials(encoded: &str) -> Result<(String, String), &'static str> {
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return Err("Invalid credentials encoding");
    };
    let Ok(credentials) = String::from_utf8(decoded) else {
        return Err("Invalid credentials encoding");
    };
    let Some((username, password)) = credentials.split_once(':') else {
        return Err("Invalid credentials format");
    };
    Ok((username.to_string(), password.to_string()))
}

/// The answer to a password from a locked-out account.
pub(crate) fn too_many_failed_attempts(retry_after: u64) -> Response {
    (
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
        .into_response()
}

/// Admit a workload identity, an OIDC JWT or a session exchanged for one
/// (auth/oidc_session.rs), with its role, namespace scope and lifetime ceiling.
async fn admit_workload(
    identity: oidc::OidcIdentity,
    mut request: Request<Body>,
    next: Next,
    is_token_management: bool,
    is_npm_audit: bool,
    is_admin: bool,
) -> Response {
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
    if is_write_method(request.method()) && !is_npm_audit && !identity.role.can_write() {
        return (StatusCode::FORBIDDEN, "Read-only OIDC identity").into_response();
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    request.extensions_mut().insert(MintLifetimeCeiling(
        identity
            .max_token_lifetime_secs
            .min(identity.expires_at.saturating_sub(now)),
    ));
    request
        .extensions_mut()
        .insert(AuthenticatedUser(identity.subject.clone()));
    request
        .extensions_mut()
        .insert(AuthenticatedRole(identity.role));
    next.run(request).await
}

/// The methods a read-only identity may not use: exactly PUT, POST, DELETE and
/// PATCH. Every other method is a read — HEAD included, which is how
/// `docker pull` starts.
fn is_write_method(method: &Method) -> bool {
    [Method::PUT, Method::POST, Method::DELETE, Method::PATCH].contains(method)
}

/// `Authorization: Basic` whose password is an `nra_` API token, an `nrs_` OIDC
/// session or a JWT (three
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
    // A session token has a fixed shape no htpasswd password takes by chance, so it
    // is a token on every peer, like a JWT (an `nra_` one only with the shortcut).
    let is_session = oidc_session::is_session_token(password);
    if !((nra && password.starts_with("nra_")) || is_session || is_jwt) {
        return None;
    }
    axum::http::HeaderValue::from_str(&format!("Bearer {password}")).ok()
}

/// The username of a Base64-encoded Basic credential that htpasswd has already accepted,
/// `None` otherwise. Used by the opportunistic-auth path on open web surfaces so that
/// authenticated users get their real identity even on publicly browsable pages. It runs
/// no bcrypt: an open path has no lockout and no limiter, so a flood of Basic
/// headers there would cost a bcrypt each. Credentials count once a gated path (where the
/// browser is challenged) has checked them.
fn try_basic_auth(encoded: &str, auth: Option<&HtpasswdAuth>) -> Option<String> {
    let (username, password) = basic_credentials(encoded).ok()?;
    (auth?.verified(&username, &password) == Some(true)).then_some(username)
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
mod tests;

/// #1094 — the Basic branch of `auth_middleware` as a table: every row runs
/// `decide_basic_auth` on one input and compares the decision, plus whether the
/// token store was read at all. The router and binary tests cover the wiring
/// around it (`state.auth`/`state.tokens` into the verifiers, the decision into
/// the response and the failure tracker).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod basic_decision_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests;

// ---------------------------------------------------------------------------
// OIDC Integration Tests — full middleware flow with mock JWKS server
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod oidc_integration_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod web_surface_gating_tests;

// ---------------------------------------------------------------------------
// Client address and lockout: the key the lockout and the limiters count by
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod client_address_tests;
