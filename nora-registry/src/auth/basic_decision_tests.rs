// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

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
fn decide(setup: Setup, encoded: &str, method: &Method, is_admin: bool) -> (BasicDecision, bool) {
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
fn row(setup: Setup, credentials: &str, method: Method, want: BasicDecision, read: bool) -> Row {
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

/// The lockout rules as a table, one row per point of the rule: what a
/// password attempt is answered and what it does to the counts, with the
/// account locked out or not.
#[test]
fn lockout_rule_table() {
    use super::{lockout_rule, LockoutCount};
    use LockoutCount::{Clear, Failure, Nothing};
    let alice = || ok("alice", Role::Write);
    let bob = || ok("bob", Role::Read);
    let forbidden = || BasicDecision::Forbidden("Read-only token");
    let rows: Vec<(
        &str,
        Option<u64>,
        BasicDecision,
        Option<&str>,
        BasicDecision,
        LockoutCount,
    )> = vec![
        (
            "a wrong password counts",
            None,
            wrong(),
            Some("alice"),
            wrong(),
            Failure,
        ),
        (
            "a header that does not decode counts nothing",
            None,
            malformed("Invalid credentials encoding"),
            Some("alice"),
            malformed("Invalid credentials encoding"),
            Nothing,
        ),
        (
            "a login clears its own username",
            None,
            alice(),
            Some("alice"),
            alice(),
            Clear,
        ),
        (
            "a token of another owner clears nothing",
            None,
            bob(),
            Some("alice"),
            bob(),
            Nothing,
        ),
        (
            "a 403 counts nothing",
            None,
            forbidden(),
            Some("alice"),
            forbidden(),
            Nothing,
        ),
        (
            "an outage counts nothing",
            None,
            unavailable(),
            Some("alice"),
            unavailable(),
            Nothing,
        ),
        (
            "no store counts nothing",
            None,
            BasicDecision::NotConfigured,
            Some("alice"),
            BasicDecision::NotConfigured,
            Nothing,
        ),
        (
            "a locked-out password is refused uncounted",
            Some(30),
            wrong(),
            Some("alice"),
            BasicDecision::LockedOut(30),
            Nothing,
        ),
        (
            "a locked-out header that does not decode is refused uncounted",
            Some(30),
            malformed("Invalid credentials format"),
            Some("alice"),
            BasicDecision::LockedOut(30),
            Nothing,
        ),
        (
            "a locked-out account without a store is refused",
            Some(30),
            BasicDecision::NotConfigured,
            Some("alice"),
            BasicDecision::LockedOut(30),
            Nothing,
        ),
        (
            "its own token is served under a lockout and clears it",
            Some(30),
            alice(),
            Some("alice"),
            alice(),
            Clear,
        ),
        (
            "another owner's token is served under a lockout",
            Some(30),
            bob(),
            Some("alice"),
            bob(),
            Nothing,
        ),
        (
            "a 403 under a lockout stays a 403",
            Some(30),
            forbidden(),
            Some("alice"),
            forbidden(),
            Nothing,
        ),
        (
            "an outage under a lockout stays an outage",
            Some(30),
            unavailable(),
            Some("alice"),
            unavailable(),
            Nothing,
        ),
        (
            "a login without a username clears nothing",
            None,
            alice(),
            None,
            alice(),
            Nothing,
        ),
    ];
    for (point, locked_out, checked, username, answer, count) in rows {
        assert_eq!(
            lockout_rule(locked_out, checked, username),
            (answer, count),
            "{point}"
        );
    }
}

/// The lockout counts change only through [`AuthFailureTracker::count`],
/// which applies what [`lockout_rule`] decided (white list): a route that
/// counted an attempt itself would skip the rule. Needles are built at run
/// time so this text does not match.
#[test]
fn the_lockout_counts_change_only_by_the_rule() {
    let needles = [
        [".record", "_failure("].concat(),
        [".record", "_success("].concat(),
    ];
    let mut found = std::collections::BTreeMap::new();
    for (file, source) in [
        ("auth/mod.rs", include_str!("mod.rs")),
        ("auth/token_routes.rs", include_str!("token_routes.rs")),
        ("ui/mod.rs", include_str!("../ui/mod.rs")),
        ("admin.rs", include_str!("../admin.rs")),
    ] {
        for (needle, functions) in crate::test_helpers::functions_containing(source, &needles) {
            for function in functions {
                found.insert((file, function), needle.clone());
            }
        }
    }
    assert_eq!(
        found.into_keys().collect::<Vec<_>>(),
        [("auth/mod.rs", "count".to_string())]
    );
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
