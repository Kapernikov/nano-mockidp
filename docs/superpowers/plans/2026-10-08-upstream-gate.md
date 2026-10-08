# Upstream Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An optional gate (off by default) that makes testers log in at a real upstream OIDC provider and pass a claim check before they reach nano-mockidp's persona login form.

**Architecture:** A Cargo feature `upstream` (default on) adds `src/upstream/` with three parts: `gate.rs` (signed cookie + claim check, pure), `client.rs` (discovery, JWKS, code exchange, ID-token checks via reqwest/rustls-ring) and `mod.rs` (the `Gate` that `/authorize` consults, plus the `/upstream/callback` handler). Config parsing is feature-independent; a binary without the feature refuses to start when `UPSTREAM_ISSUER` is set. With the gate on, `/token` only allows password/client_credentials for `CLIENTS`-configured clients with a secret.

**Tech Stack:** Rust, axum 0.8, tokio (current_thread), reqwest 0.12 (`rustls-tls-webpki-roots` = rustls + ring + bundled roots), hmac 0.12 + sha2 0.10, rsa 0.9.

**Spec:** `docs/superpowers/specs/2026-10-08-upstream-gate-design.md`

## Global Constraints

- With `UPSTREAM_ISSUER` unset, behaviour is unchanged: `tests/flow.rs` and `tests/offline.rs` must pass **without edits**.
- Feature `upstream` is in `default`; `cargo build --no-default-features` must build and `cargo test --no-default-features` must pass.
- No OpenSSL, no aws-lc: `cargo tree -i openssl-sys` and `cargo tree -i aws-lc-sys` must find nothing. TLS = rustls with the ring provider, roots from `webpki-roots`.
- Built without the feature and `UPSTREAM_ISSUER` set → startup error, never a silently open instance.
- Startup never contacts the upstream; discovery happens on first use and is cached only on success.
- Upstream `redirect_uri` is always `<ISSUER_URL>/upstream/callback` (from `ISSUER_URL`, also with `ISSUER_FROM_REQUEST_HOST=true`).
- Cookie: name `nano_mockidp_gate`, `HttpOnly; SameSite=Lax; Path=<issuer path or />; Max-Age=<UPSTREAM_SESSION_TTL>`, `Secure` iff `ISSUER_URL` is https. HMAC-SHA256 key random per process.
- `POST /authorize` without a valid gate cookie → 403 page, never a redirect.
- Defaults: `UPSTREAM_SCOPE=openid email profile` (`openid` added if missing), `UPSTREAM_SESSION_TTL=28800`.
- `UPSTREAM_SUB_TOKEN_CLAIM` unset → tokens identical to today. Set → claim applied after the typed claims at every issue (code and refresh), so it can't be forged and survives admin overrides.
- Rust style: match the surrounding code (doc comments on pub items, `unwrap_or_else(|p| p.into_inner())` for mutexes, `tracing` structured fields).
- Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Before every commit: `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings`.

## Review Focus

- Instance mounted under a path (`ISSUER_URL=https://host/mockidp`, as in fullstack-sota's chart): callback route, `redirect_uri`, return URL and cookie `Path` must all carry `/mockidp` → test `gate_under_a_mount_path` (Task 4).
- Upstream issuer configured with a trailing slash (Auth0 style `https://t.auth0.com/`): ID-token `iss` comparison must still match → test `issuer_trailing_slash_is_tolerated` (Task 3).
- Tester presses back/refresh on the callback URL: a replayed `state` gives a readable 400, not a crash or a second cookie → test `callback_state_is_single_use_and_checked` (Task 4).
- nano-mockidp restarted (new cookie key) or a cookie from another gated instance: must be refused on POST and sent upstream on GET → test `foreign_or_tampered_cookie_is_refused` (Task 4).
- Upstream down when a tester arrives: 502 page with the reason, server keeps running → test `upstream_unreachable_is_502` (Task 4).

---

### Task 1: Feature flag, dependencies, config parsing, startup refusal

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/config.rs`
- Modify: `src/state.rs`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `crate::config::UpstreamConfig` (fields below) and `Config.upstream: Option<UpstreamConfig>`. Later tasks read `issuer`, `client_id`, `client_secret`, `scope`, `require_claim`, `session_ttl`, `sub_token_claim`, `ca_path`.

- [ ] **Step 1: Write the failing config tests**

Append to the `tests` module in `src/config.rs`:

```rust
    #[test]
    fn upstream_off_by_default() {
        assert!(cfg(&[]).unwrap().upstream.is_none());
    }

    #[test]
    fn upstream_config() {
        let u = cfg(&[
            ("UPSTREAM_ISSUER", "https://idp.example/realms/t/"),
            ("UPSTREAM_CLIENT_ID", "gate"),
            ("UPSTREAM_SCOPE", "email groups"),
            ("UPSTREAM_REQUIRE_CLAIM", "realm_access.roles=tester"),
            ("UPSTREAM_SUB_TOKEN_CLAIM", "upstream_sub"),
            ("UPSTREAM_SESSION_TTL", "60"),
        ])
        .unwrap()
        .upstream
        .unwrap();
        assert_eq!(u.issuer, "https://idp.example/realms/t");
        assert_eq!(u.client_id, "gate");
        assert!(u.client_secret.is_none());
        assert_eq!(u.scope, "openid email groups");
        assert_eq!(
            u.require_claim,
            Some(("realm_access.roles".to_string(), "tester".to_string()))
        );
        assert_eq!(u.session_ttl, 60);
        assert_eq!(u.sub_token_claim.as_deref(), Some("upstream_sub"));

        let u = cfg(&[
            ("UPSTREAM_ISSUER", "https://idp.example"),
            ("UPSTREAM_CLIENT_ID", "gate"),
            ("UPSTREAM_CLIENT_SECRET", "s"),
        ])
        .unwrap()
        .upstream
        .unwrap();
        assert_eq!(u.scope, "openid email profile");
        assert_eq!(u.session_ttl, 28_800);
        assert_eq!(u.client_secret.as_deref(), Some("s"));
        assert!(u.require_claim.is_none());
        assert!(u.sub_token_claim.is_none());
    }

    #[test]
    fn upstream_config_errors() {
        let base = [
            ("UPSTREAM_ISSUER", "https://idp.example"),
            ("UPSTREAM_CLIENT_ID", "gate"),
        ];
        let with = |k: &'static str, v: &'static str| {
            let mut e = base.to_vec();
            e.push((k, v));
            cfg(&e)
        };
        assert!(cfg(&[("UPSTREAM_ISSUER", "https://idp.example")])
            .unwrap_err()
            .contains("UPSTREAM_CLIENT_ID"));
        assert!(cfg(&[("UPSTREAM_ISSUER", "not a url"), ("UPSTREAM_CLIENT_ID", "g")]).is_err());
        for bad in ["groups", "=testers", "groups="] {
            assert!(with("UPSTREAM_REQUIRE_CLAIM", bad).is_err(), "{bad}");
        }
        for reserved in ["sub", "iss", "aud", "exp"] {
            assert!(with("UPSTREAM_SUB_TOKEN_CLAIM", reserved).is_err(), "{reserved}");
        }
        assert!(with("UPSTREAM_SESSION_TTL", "abc").is_err());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --lib config::tests`
Expected: compile error, `no field upstream on type Config`.

- [ ] **Step 3: Add `UpstreamConfig` and parsing**

In `src/config.rs`, after `ClientConfig`:

```rust
/// The upstream IdP gate (`UPSTREAM_*`). Present iff `UPSTREAM_ISSUER` is set.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamConfig {
    /// Issuer URL without trailing slash; ID-token `iss` is compared ignoring a trailing slash.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Always contains `openid`.
    pub scope: String,
    /// `UPSTREAM_REQUIRE_CLAIM` as (dotted path, value).
    pub require_claim: Option<(String, String)>,
    /// Seconds a gate cookie is valid.
    pub session_ttl: u64,
    /// Claim that carries the upstream `sub` in issued tokens.
    pub sub_token_claim: Option<String>,
    /// Extra PEM CA bundle for upstream TLS.
    pub ca_path: Option<PathBuf>,
}

/// Claims `UPSTREAM_SUB_TOKEN_CLAIM` may not name: they identify the persona or the token.
const RESERVED_CLAIMS: &[&str] = &[
    "sub", "iss", "aud", "azp", "exp", "iat", "jti", "nonce", "auth_time",
];

fn parse_upstream<'a>(
    get: impl Fn(&str) -> Option<&'a str>,
) -> Result<Option<UpstreamConfig>, String> {
    let Some(issuer) = get("UPSTREAM_ISSUER") else {
        return Ok(None);
    };
    let issuer = issuer.trim().trim_end_matches('/').to_string();
    parse_url("UPSTREAM_ISSUER", &issuer)?;
    let client_id = get("UPSTREAM_CLIENT_ID")
        .map(|s| s.trim().to_string())
        .ok_or("UPSTREAM_CLIENT_ID is required when UPSTREAM_ISSUER is set")?;
    let mut scope = get("UPSTREAM_SCOPE")
        .unwrap_or("openid email profile")
        .trim()
        .to_string();
    if !scope.split_whitespace().any(|s| s == "openid") {
        scope = format!("openid {scope}");
    }
    let require_claim = match get("UPSTREAM_REQUIRE_CLAIM") {
        None => None,
        Some(v) => match v.trim().split_once('=') {
            Some((path, value)) if !path.trim().is_empty() && !value.trim().is_empty() => {
                Some((path.trim().to_string(), value.trim().to_string()))
            }
            _ => {
                return Err(format!(
                    "UPSTREAM_REQUIRE_CLAIM: expected path=value, got {v:?}"
                ))
            }
        },
    };
    let session_ttl = match get("UPSTREAM_SESSION_TTL") {
        Some(v) => parse_u64("UPSTREAM_SESSION_TTL", v)?,
        None => 28_800,
    };
    let sub_token_claim = match get("UPSTREAM_SUB_TOKEN_CLAIM").map(str::trim) {
        Some(c) if RESERVED_CLAIMS.contains(&c) => {
            return Err(format!(
                "UPSTREAM_SUB_TOKEN_CLAIM: {c:?} is reserved, pick another name"
            ))
        }
        c => c.map(str::to_string),
    };
    Ok(Some(UpstreamConfig {
        issuer,
        client_id,
        client_secret: get("UPSTREAM_CLIENT_SECRET").map(|s| s.trim().to_string()),
        scope,
        require_claim,
        session_ttl,
        sub_token_claim,
        ca_path: get("UPSTREAM_CA_PATH").map(PathBuf::from),
    }))
}
```

Add to `struct Config` (after `default_claims`):

```rust
    /// Upstream IdP gate; None → off.
    pub upstream: Option<UpstreamConfig>,
```

In `from_map`, before `Ok(Config {`: `let upstream = parse_upstream(get)?;` and add `upstream,` to the struct literal. (`get` is a non-capturing-by-move closure over `m`, so passing it by value is fine; if the borrow checker complains, pass `&get` and change the parameter to `get: &impl Fn(&str) -> Option<&'a str>`.)

- [ ] **Step 4: Run config tests**

Run: `cargo test --lib config::tests`
Expected: PASS.

- [ ] **Step 5: Feature flag and dependencies**

In `Cargo.toml` add before `[dependencies]`:

```toml
[features]
default = ["upstream"]
# Upstream IdP gate: pulls in an HTTPS client (rustls + ring, bundled roots; no OpenSSL).
upstream = ["dep:reqwest", "dep:hmac"]
```

Add to `[dependencies]`:

```toml
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls-webpki-roots", "json"], optional = true }
hmac = { version = "0.12", optional = true }
```

(The existing `[dev-dependencies]` reqwest entry stays as is.)

- [ ] **Step 6: Refuse to start without the feature — failing test**

Append to `src/state.rs`:

```rust
#[cfg(all(test, not(feature = "upstream")))]
mod tests {
    use super::*;

    #[test]
    fn upstream_needs_the_feature() {
        let m = [
            ("UPSTREAM_ISSUER", "https://idp.example"),
            ("UPSTREAM_CLIENT_ID", "gate"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let err = AppState::new(Config::from_map(&m).unwrap()).err().unwrap();
        assert!(err.contains("without the `upstream` feature"), "{err}");
    }
}
```

Run: `cargo test --no-default-features --lib state::tests`
Expected: FAIL (`AppState::new` succeeds → `unwrap` on `None`).

- [ ] **Step 7: Implement the refusal**

At the top of `AppState::new` in `src/state.rs`:

```rust
        #[cfg(not(feature = "upstream"))]
        if config.upstream.is_some() {
            return Err(
                "UPSTREAM_ISSUER is set but this binary was built without the `upstream` feature"
                    .into(),
            );
        }
```

Run: `cargo test --no-default-features --lib state::tests` → PASS. Then `cargo test` and `cargo test --no-default-features` → all PASS.

- [ ] **Step 8: CI and dependency checks**

In `.github/workflows/ci.yml`, job `test`, after `- run: cargo test` add:

```yaml
      - run: cargo clippy --all-targets --no-default-features -- -D warnings
      - run: cargo test --no-default-features
      - name: no OpenSSL / aws-lc (musl static build)
        run: "! cargo tree -i openssl-sys && ! cargo tree -i aws-lc-sys"
```

Run locally: `! cargo tree -i openssl-sys && ! cargo tree -i aws-lc-sys && echo clean`
Expected: two "did not match any packages" errors, then `clean`.

- [ ] **Step 9: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add Cargo.toml Cargo.lock src/config.rs src/state.rs .github/workflows/ci.yml
git commit -m "feat(upstream): feature flag, UPSTREAM_* config, refuse without feature

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Gate cookie and claim check (pure)

**Files:**
- Create: `src/upstream/mod.rs`
- Create: `src/upstream/gate.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing from Task 1 besides the `hmac` dependency.
- Produces (in `crate::upstream::gate`):
  - `pub const COOKIE_NAME: &str = "nano_mockidp_gate"`
  - `pub struct GateSession { pub sub: String, pub email: Option<String>, pub exp: u64 }` (Serialize, Deserialize, Debug, Clone, PartialEq, Eq)
  - `pub struct GateKey` with `GateKey::random() -> GateKey`, `seal(&self, &GateSession) -> String`, `open(&self, value: &str, now: u64) -> Option<GateSession>`
  - `pub fn cookie_value(headers: &HeaderMap) -> Option<&str>`
  - `pub fn set_cookie(value: &str, path: &str, max_age: u64, secure: bool) -> String`
  - `pub fn claim_at<'a>(claims: &'a Claims, path: &str) -> Option<&'a Value>`
  - `pub fn claim_allows(claims: &Claims, path: &str, value: &str) -> bool`

- [ ] **Step 1: Module skeleton**

`src/upstream/mod.rs`:

```rust
//! Optional gate: testers log in at an upstream OIDC provider before they may pick a persona.

pub mod gate;
```

In `src/lib.rs` after `pub mod token;`:

```rust
#[cfg(feature = "upstream")]
pub mod upstream;
```

- [ ] **Step 2: Write the failing tests**

`src/upstream/gate.rs` (tests first; the implementation goes above them in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session(exp: u64) -> GateSession {
        GateSession {
            sub: "frank".into(),
            email: Some("f@x".into()),
            exp,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = GateKey::random();
        let v = k.seal(&session(100));
        assert_eq!(k.open(&v, 99), Some(session(100)));
    }

    #[test]
    fn open_rejects_expired_tampered_and_foreign() {
        let k = GateKey::random();
        let v = k.seal(&session(100));
        assert_eq!(k.open(&v, 100), None, "expired at exp");
        assert_eq!(GateKey::random().open(&v, 0), None, "other key (restart)");
        let (_, tag) = v.split_once('.').unwrap();
        let forged = format!(
            "{}.{tag}",
            URL_SAFE_NO_PAD.encode(br#"{"sub":"admin","exp":99999999999}"#)
        );
        assert_eq!(k.open(&forged, 0), None, "payload swapped");
        assert_eq!(k.open(&format!("{v}x"), 0), None, "tag changed");
        assert_eq!(k.open("garbage", 0), None);
        assert_eq!(k.open("a.b", 0), None);
    }

    #[test]
    fn cookie_value_finds_ours() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            "a=1; nano_mockidp_gate=abc.def; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&h), Some("abc.def"));
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, "a=1".parse().unwrap());
        h.append(header::COOKIE, "nano_mockidp_gate=x.y".parse().unwrap());
        assert_eq!(cookie_value(&h), Some("x.y"));
        assert_eq!(cookie_value(&HeaderMap::new()), None);
    }

    #[test]
    fn set_cookie_attributes() {
        assert_eq!(
            set_cookie("v", "/oidc", 60, true),
            "nano_mockidp_gate=v; Path=/oidc; Max-Age=60; HttpOnly; SameSite=Lax; Secure"
        );
        assert!(!set_cookie("v", "/", 60, false).contains("Secure"));
    }

    #[test]
    fn claim_check() {
        let c: Claims = serde_json::from_value(json!({
            "groups": ["devs", "testers"],
            "tier": "gold",
            "verified": true,
            "level": 3,
            "realm_access": {"roles": ["tester"]}
        }))
        .unwrap();
        assert!(claim_allows(&c, "groups", "testers"));
        assert!(!claim_allows(&c, "groups", "admins"));
        assert!(claim_allows(&c, "tier", "gold"));
        assert!(claim_allows(&c, "verified", "true"));
        assert!(claim_allows(&c, "level", "3"));
        assert!(claim_allows(&c, "realm_access.roles", "tester"));
        assert!(!claim_allows(&c, "realm_access.missing", "tester"));
        assert!(!claim_allows(&c, "missing", "x"));
        assert!(!claim_allows(&c, "realm_access", "tester"), "objects never match");
        assert_eq!(claim_at(&c, "realm_access.roles"), Some(&json!(["tester"])));
    }
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test --lib upstream::gate`
Expected: compile errors (`GateKey`, `cookie_value`, … not found).

- [ ] **Step 4: Implement**

Top of `src/upstream/gate.rs`:

```rust
//! Gate cookie and access check: pure functions, no I/O.

use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

use crate::store::Claims;

pub const COOKIE_NAME: &str = "nano_mockidp_gate";

/// Who passed the gate, and until when (unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSession {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub exp: u64,
}

/// HMAC key for gate cookies. Random per process: a restart sends testers upstream again.
pub struct GateKey([u8; 32]);

impl GateKey {
    pub fn random() -> GateKey {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        GateKey(k)
    }

    fn mac(&self) -> Hmac<Sha256> {
        Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts any key length")
    }

    /// `base64url(json) "." base64url(hmac)`.
    pub fn seal(&self, s: &GateSession) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(s).expect("json"));
        let mut mac = self.mac();
        mac.update(payload.as_bytes());
        let tag = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{payload}.{tag}")
    }

    /// The session in a cookie value, if we signed it and it hasn't expired at `now`.
    pub fn open(&self, value: &str, now: u64) -> Option<GateSession> {
        let (payload, tag) = value.split_once('.')?;
        let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
        let mut mac = self.mac();
        mac.update(payload.as_bytes());
        mac.verify_slice(&tag).ok()?;
        let s: GateSession =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        (s.exp > now).then_some(s)
    }
}

/// Our cookie's value from the request's `Cookie` headers.
pub fn cookie_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE_NAME)
        .map(|(_, v)| v)
}

/// `Set-Cookie` header value for a sealed session.
pub fn set_cookie(value: &str, path: &str, max_age: u64, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{COOKIE_NAME}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
    )
}

/// The claim at a dotted `path` (`realm_access.roles` descends into objects).
pub fn claim_at<'a>(claims: &'a Claims, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let first = claims.get(parts.next()?)?;
    parts.try_fold(first, |v, p| v.get(p))
}

/// `UPSTREAM_REQUIRE_CLAIM`: the claim at `path` equals `value`, or contains it if it is an
/// array. Numbers and booleans compare by their JSON text; objects never match.
pub fn claim_allows(claims: &Claims, path: &str, value: &str) -> bool {
    let matches = |v: &Value| match v {
        Value::String(s) => s == value,
        Value::Number(_) | Value::Bool(_) => v.to_string() == value,
        _ => false,
    };
    match claim_at(claims, path) {
        Some(Value::Array(a)) => a.iter().any(matches),
        Some(v) => matches(v),
        None => false,
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test --lib upstream::gate` → PASS. `cargo clippy --all-targets -- -D warnings` → clean (add `#[allow(dead_code)]` nowhere; everything is `pub`).

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add src/lib.rs src/upstream
git commit -m "feat(upstream): signed gate cookie and claim check

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Upstream OIDC client (discovery, JWKS, code exchange, ID-token checks)

**Files:**
- Modify: `src/token.rs` (split out signature verification)
- Create: `src/upstream/client.rs`
- Modify: `src/upstream/mod.rs`
- Create: `tests/upstream_client.rs`

**Interfaces:**
- Consumes: `UpstreamConfig` (Task 1).
- Produces:
  - `crate::token::jws_header(token: &str) -> Result<Value, String>`
  - `crate::token::verify_signature(verifier: &rsa::pkcs1v15::VerifyingKey<Sha256>, token: &str) -> Result<Claims, String>` (RS256 + signature + payload; no `exp`/`iss` checks)
  - `crate::upstream::Upstream` with:
    - `pub fn new(cfg: UpstreamConfig) -> Result<Upstream, String>`
    - `pub cfg: UpstreamConfig`
    - `pub async fn authorize_url(&self, redirect_uri: &str, state: &str, nonce: &str, code_challenge: &str) -> Result<String, String>`
    - `pub async fn exchange(&self, code: &str, redirect_uri: &str, code_verifier: &str) -> Result<String, String>` (returns the `id_token`)
    - `pub async fn verify_id_token(&self, id_token: &str, nonce: &str) -> Result<Claims, String>`

- [ ] **Step 1: Refactor `token.rs` verification (behaviour-preserving)**

In `src/token.rs`, replace `verify_inner`'s body up to and including the `claims` object match with a call to two new pub functions:

```rust
use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;

/// The decoded JOSE header of a compact JWS.
pub fn jws_header(token: &str) -> Result<Value, String> {
    let h = token.split('.').next().unwrap_or_default();
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(h)
            .map_err(|e| format!("bad header encoding: {e}"))?,
    )
    .map_err(|e| format!("bad header json: {e}"))
}

/// Check that `token` is an RS256 compact JWS signed by `verifier`; returns its claims.
/// `exp`, `iss` and `aud` are the caller's business.
pub fn verify_signature(
    verifier: &RsaVerifyingKey<Sha256>,
    token: &str,
) -> Result<Claims, String> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("token is not a compact JWS (expected 3 segments)".into());
    };
    if jws_header(token)?.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err("unsupported alg (expected RS256)".into());
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|e| format!("bad signature encoding: {e}"))?;
    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("bad signature: {e}"))?;
    verifier
        .verify(&token.as_bytes()[..h.len() + 1 + p.len()], &signature)
        .map_err(|_| "invalid signature".to_string())?;
    match serde_json::from_slice::<Value>(
        &URL_SAFE_NO_PAD
            .decode(p)
            .map_err(|e| format!("bad payload encoding: {e}"))?,
    )
    .map_err(|e| format!("bad payload json: {e}"))?
    {
        Value::Object(m) => Ok(m),
        _ => Err("claims are not an object".into()),
    }
}
```

and `verify_inner` becomes:

```rust
fn verify_inner(
    key: &SigningKey,
    issuer: IssuerCheck<'_>,
    token: &str,
    check_exp: bool,
) -> Result<Claims, String> {
    let claims = verify_signature(&key.verifier, token)?;
    // … the existing exp / iss checks, unchanged …
}
```

Run: `cargo test` → all PASS (pure refactor; `token::tests::issue_and_verify_roundtrip` covers it).

- [ ] **Step 2: Write the failing unit tests in `client.rs`**

Create `src/upstream/client.rs` with this test module at the bottom (implementation in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use crate::token::Issuer;

    #[test]
    fn jwks_keys_verify_our_own_tokens() {
        let k = SigningKey::from_seed("up");
        let keys = parse_jwks(&k.jwks());
        let verifier = keys.get(&k.kid).expect("kid from jwks");
        let set = Issuer {
            key: &k,
            issuer: "i",
            access_ttl: 60,
            id_ttl: 60,
            default_claims: &Claims::new(),
        }
        .issue(crate::token::IssueParams {
            client_id: "c".into(),
            audience: None,
            scope: None,
            nonce: None,
            claims: Claims::new(),
            auth_time: 0,
            expires_in: None,
            with_id_token: false,
        });
        assert_eq!(
            verify_signature(verifier, &set.access_token).unwrap()["sub"],
            "c"
        );
    }

    #[test]
    fn jwks_skips_non_rsa_and_encryption_keys() {
        let jwks = serde_json::json!({"keys": [
            {"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"}
        ]});
        assert!(parse_jwks(&jwks).is_empty());
    }

    #[test]
    fn unreadable_ca_bundle_is_a_config_error() {
        let cfg = UpstreamConfig {
            issuer: "https://idp.example".into(),
            client_id: "c".into(),
            client_secret: None,
            scope: "openid".into(),
            require_claim: None,
            session_ttl: 60,
            sub_token_claim: None,
            ca_path: Some("/nonexistent/ca.pem".into()),
        };
        assert!(Upstream::new(cfg).err().unwrap().contains("UPSTREAM_CA_PATH"));
    }
}
```

In `src/upstream/mod.rs` add `pub mod client;` and `pub use client::Upstream;`.

- [ ] **Step 3: Write the failing integration tests**

Create `tests/upstream_client.rs`:

```rust
#![cfg(feature = "upstream")]
mod common;

use std::collections::HashMap;

use common::*;
use nano_mockidp::upstream::Upstream;
use nano_mockidp::Config;
use serde_json::{json, Value};

fn upstream(issuer: &str, client_id: &str) -> Upstream {
    let m: HashMap<String, String> = [
        ("UPSTREAM_ISSUER", issuer),
        ("UPSTREAM_CLIENT_ID", client_id),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    Upstream::new(Config::from_map(&m).unwrap().upstream.unwrap()).unwrap()
}

/// An ID token from `a` for `client_id` via the password grant (no nonce).
async fn password_id_token(a: &TestServer, client_id: &str) -> String {
    let r: Value = a
        .client
        .post(a.url("/token"))
        .form(&[
            ("grant_type", "password"),
            ("client_id", client_id),
            ("username", "frank"),
            ("password", "x"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    r["id_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn code_exchange_and_id_token() {
    let a = spawn(&[]).await;
    let up = upstream(&a.issuer, "gate");
    let (verifier, challenge) = pkce_pair();
    let url = up
        .authorize_url("http://gated/cb", "st", "n1", &challenge)
        .await
        .unwrap();
    assert!(url.starts_with(&a.url("/authorize?")), "{url}");
    let r = a
        .client
        .post(&url)
        .form(&[("username", "frank"), ("claims", r#"{"groups":["testers"]}"#)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    let loc = r.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(query_param(&loc, "state").as_deref(), Some("st"));
    let code = query_param(&loc, "code").unwrap();

    let id = up.exchange(&code, "http://gated/cb", &verifier).await.unwrap();
    let claims = up.verify_id_token(&id, "n1").await.unwrap();
    assert_eq!(claims["sub"], "frank");
    assert_eq!(claims["groups"], json!(["testers"]));
    assert!(up
        .verify_id_token(&id, "other")
        .await
        .unwrap_err()
        .contains("nonce"));
}

#[tokio::test]
async fn id_token_for_another_client_is_rejected() {
    let a = spawn(&[]).await;
    let up = upstream(&a.issuer, "gate");
    let id = password_id_token(&a, "someone-else").await;
    assert!(up.verify_id_token(&id, "n").await.unwrap_err().contains("aud"));
}

#[tokio::test]
async fn id_token_from_another_issuer_is_rejected() {
    // same key on both, so only the iss check can tell them apart
    let a1 = spawn(&[("SIGNING_KEY_SEED", "shared")]).await;
    let a2 = spawn(&[("SIGNING_KEY_SEED", "shared")]).await;
    let up = upstream(&a1.issuer, "gate");
    let id = password_id_token(&a2, "gate").await;
    assert!(up.verify_id_token(&id, "n").await.unwrap_err().contains("iss"));
}

#[tokio::test]
async fn issuer_trailing_slash_is_tolerated() {
    let a = spawn(&[]).await;
    let up = upstream(&format!("{}/", a.issuer), "gate");
    let id = password_id_token(&a, "gate").await;
    // passes iss and aud; fails only on the nonce the password grant doesn't set
    assert!(up.verify_id_token(&id, "n").await.unwrap_err().contains("nonce"));
}

#[tokio::test]
async fn unreachable_upstream_is_an_error_not_a_panic() {
    let up = upstream("http://127.0.0.1:9", "gate");
    let err = up.authorize_url("http://x/cb", "s", "n", "c").await.unwrap_err();
    assert!(err.contains("openid-configuration"), "{err}");
}
```

Run: `cargo test --test upstream_client` and `cargo test --lib upstream::client`
Expected: compile errors (`Upstream::new`, `parse_jwks` … not found).

- [ ] **Step 4: Implement `client.rs`**

Above the test module in `src/upstream/client.rs`:

```rust
//! The upstream OIDC provider: discovery, JWKS, code exchange and ID-token checks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::VerifyingKey;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

use crate::config::UpstreamConfig;
use crate::store::{now_secs, Claims};
use crate::token::{jws_header, verify_signature};

/// Clock skew tolerated on the upstream ID token's `exp`.
const LEEWAY: u64 = 60;

#[derive(Debug, Deserialize)]
struct Metadata {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

pub struct Upstream {
    pub cfg: UpstreamConfig,
    http: reqwest::Client,
    /// Discovery, cached after the first success.
    meta: Mutex<Option<Arc<Metadata>>>,
    /// JWKS RSA keys by `kid` ("" when the JWK has none).
    keys: Mutex<HashMap<String, VerifyingKey<Sha256>>>,
}

impl Upstream {
    /// Builds the HTTP client; does not contact the upstream.
    pub fn new(cfg: UpstreamConfig) -> Result<Upstream, String> {
        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &cfg.ca_path {
            let pem = std::fs::read(path).map_err(|e| {
                format!("UPSTREAM_CA_PATH: cannot read {}: {e}", path.display())
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| format!("UPSTREAM_CA_PATH: {e}"))?;
            if certs.is_empty() {
                return Err(format!(
                    "UPSTREAM_CA_PATH: no certificates in {}",
                    path.display()
                ));
            }
            for c in certs {
                b = b.add_root_certificate(c);
            }
        }
        let http = b
            .build()
            .map_err(|e| format!("upstream HTTP client: {e}"))?;
        Ok(Upstream {
            cfg,
            http,
            meta: Mutex::new(None),
            keys: Mutex::new(HashMap::new()),
        })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, String> {
        let r = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        if !r.status().is_success() {
            return Err(format!("GET {url}: HTTP {}", r.status()));
        }
        r.json().await.map_err(|e| format!("GET {url}: {e}"))
    }

    /// Discovery, fetched on first use; a failure is retried on the next call.
    async fn metadata(&self) -> Result<Arc<Metadata>, String> {
        let cached = self.meta.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(m) = cached {
            return Ok(m);
        }
        let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
        let m: Arc<Metadata> = Arc::new(self.get_json(&url).await?);
        *self.meta.lock().unwrap_or_else(|p| p.into_inner()) = Some(m.clone());
        Ok(m)
    }

    /// Where to send the browser to log in upstream.
    pub async fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: &str,
    ) -> Result<String, String> {
        let m = self.metadata().await?;
        let mut url = url::Url::parse(&m.authorization_endpoint)
            .map_err(|e| format!("upstream authorization_endpoint: {e}"))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &self.cfg.scope)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Redeem `code` at the upstream token endpoint; returns the `id_token`.
    pub async fn exchange(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<String, String> {
        let m = self.metadata().await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ];
        let mut req = self.http.post(&m.token_endpoint);
        match &self.cfg.client_secret {
            Some(secret) => req = req.basic_auth(&self.cfg.client_id, Some(secret)),
            None => form.push(("client_id", self.cfg.client_id.as_str())),
        }
        let r = req
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("POST {}: {e}", m.token_endpoint))?;
        let status = r.status();
        let body: Value = r
            .json()
            .await
            .map_err(|e| format!("upstream token response: {e}"))?;
        if !status.is_success() {
            return Err(format!("upstream token endpoint HTTP {status}: {body}"));
        }
        body.get("id_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "upstream token response has no id_token".to_string())
    }

    /// RS256 signature against the upstream JWKS, then `iss`, `aud`, `exp` and `nonce`.
    pub async fn verify_id_token(&self, id_token: &str, nonce: &str) -> Result<Claims, String> {
        let kid = jws_header(id_token)?
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_string);
        let key = self.key(kid.as_deref()).await?;
        let claims = verify_signature(&key, id_token)?;
        let iss = claims.get("iss").and_then(Value::as_str).unwrap_or_default();
        if iss.trim_end_matches('/') != self.cfg.issuer {
            return Err(format!(
                "id_token iss {iss:?} is not {:?}",
                self.cfg.issuer
            ));
        }
        let client_id = self.cfg.client_id.as_str();
        let aud_ok = match claims.get("aud") {
            Some(Value::String(a)) => a == client_id,
            Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(client_id)),
            _ => false,
        };
        if !aud_ok {
            return Err(format!("id_token aud does not contain {client_id:?}"));
        }
        let exp = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or("id_token has no exp")?;
        if exp + LEEWAY <= now_secs() {
            return Err("id_token expired".into());
        }
        if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
            return Err("id_token nonce mismatch".into());
        }
        Ok(claims)
    }

    /// The JWKS key for `kid`. An unknown `kid` refetches the JWKS once (key rotation).
    async fn key(&self, kid: Option<&str>) -> Result<VerifyingKey<Sha256>, String> {
        if let Some(k) = self.cached_key(kid) {
            return Ok(k);
        }
        let m = self.metadata().await?;
        let jwks: Value = self.get_json(&m.jwks_uri).await?;
        *self.keys.lock().unwrap_or_else(|p| p.into_inner()) = parse_jwks(&jwks);
        self.cached_key(kid)
            .ok_or_else(|| format!("no RS256 key {kid:?} in the upstream JWKS"))
    }

    fn cached_key(&self, kid: Option<&str>) -> Option<VerifyingKey<Sha256>> {
        let keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        match kid {
            Some(k) => keys.get(k).cloned(),
            None if keys.len() == 1 => keys.values().next().cloned(),
            None => None,
        }
    }
}

/// RSA signing keys of a JWKS by `kid`.
fn parse_jwks(jwks: &Value) -> HashMap<String, VerifyingKey<Sha256>> {
    let b64 = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
    };
    jwks.get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|k| k.get("kty").and_then(Value::as_str) == Some("RSA"))
        .filter(|k| {
            k.get("use")
                .and_then(Value::as_str)
                .is_none_or(|u| u == "sig")
        })
        .filter_map(|k| {
            let n = BigUint::from_bytes_be(&b64(k.get("n"))?);
            let e = BigUint::from_bytes_be(&b64(k.get("e"))?);
            let public = RsaPublicKey::new(n, e).ok()?;
            let kid = k
                .get("kid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            Some((kid, VerifyingKey::<Sha256>::new(public)))
        })
        .collect()
}
```

Notes for the implementer:
- `jwks_skips_non_rsa_and_encryption_keys`: the `enc` key must be filtered by `use` before `RsaPublicKey::new` (which would reject the tiny modulus anyway).
- The `Mutex` guards are never held across `.await` (handler futures must be `Send`).

- [ ] **Step 5: Run tests**

Run: `cargo test --lib upstream && cargo test --test upstream_client`
Expected: PASS. Then `cargo test` (everything) → PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/token.rs src/upstream tests/upstream_client.rs
git commit -m "feat(upstream): OIDC client for discovery, code exchange, id_token checks

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Wire the gate into `/authorize` and `/upstream/callback`; upstream claim in tokens

**Files:**
- Modify: `src/store.rs` (UpstreamLogin, `upstream_pending`, `upstream_sub` on Code/Refresh entries)
- Modify: `src/upstream/mod.rs` (`Gate`, `callback`)
- Modify: `src/state.rs` (`gate` field)
- Modify: `src/routes/mod.rs` (callback route)
- Modify: `src/routes/authorize.rs` (gate checks; `error_page` → `pub`)
- Modify: `src/routes/token.rs` (`with_upstream_claim`, carry `upstream_sub`)
- Modify: `tests/common/mod.rs` (`spawn_at`)
- Create: `tests/upstream.rs`

**Interfaces:**
- Consumes: `GateKey`, `GateSession`, `cookie_value`, `set_cookie`, `claim_at`, `claim_allows` (Task 2); `Upstream` (Task 3); `UpstreamConfig` (Task 1).
- Produces:
  - `crate::store::UpstreamLogin { pub nonce: String, pub verifier: String, pub return_to: String }`, `Store.upstream_pending: HashMap<String, Expiring<UpstreamLogin>>`, `Store::take_upstream_login(&mut self, state: &str) -> Option<UpstreamLogin>`
  - `CodeEntry.upstream_sub: Option<String>`, `RefreshEntry.upstream_sub: Option<String>`
  - `crate::upstream::Gate` with `new(&Config) -> Result<Option<Gate>, String>`, `session(&self, &HeaderMap) -> Option<GateSession>`, `async start_login(&self, &AppState, return_to: String) -> Response`; `crate::upstream::callback` axum handler
  - `AppState.gate: Option<Gate>` (only with the feature)
  - `crate::routes::authorize::error_page(msg: &str) -> String` (now `pub`)
  - tests: `common::spawn_at(path: &str, env: &[(&str, &str)]) -> TestServer`

- [ ] **Step 1: Test helper for path-mounted servers**

In `tests/common/mod.rs`, rename the body of `spawn` into `spawn_at` and make `spawn` delegate:

```rust
/// Start the server in-process on an ephemeral port. `env` overrides config values.
/// Unless `ISSUER_URL` is given, it is set to `http://127.0.0.1:<port>`.
pub async fn spawn(env: &[(&str, &str)]) -> TestServer {
    spawn_at("", env).await
}

/// Like [`spawn`], with the default `ISSUER_URL` mounted at `path` (e.g. "/mockidp").
pub async fn spawn_at(path: &str, env: &[(&str, &str)]) -> TestServer {
    // … the former body of `spawn`, with:
    map.entry("ISSUER_URL".into())
        .or_insert_with(|| format!("{root}{path}"));
    // … rest unchanged …
}
```

- [ ] **Step 2: Write the failing integration tests**

Create `tests/upstream.rs`:

```rust
#![cfg(feature = "upstream")]
mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

const CB: &str = "http://app.example/cb";
const TESTERS: &str = r#"{"groups":["testers"]}"#;
const SCOPE: &str = "openid offline_access";

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn authz_url(s: &TestServer) -> String {
    format!(
        "{}?response_type=code&client_id=app&redirect_uri={}&state=st1&scope={}&nonce=n1",
        s.url("/authorize"),
        urlenc(CB),
        urlenc(SCOPE)
    )
}

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_string()
}

/// A = plain nano-mockidp playing the upstream; B = gated by A, mounted at `path`.
async fn pair(path: &str, extra: &[(&str, &str)]) -> (TestServer, TestServer) {
    let a = spawn(&[]).await;
    let issuer = a.issuer.clone();
    let mut env = vec![
        ("UPSTREAM_ISSUER", issuer.as_str()),
        ("UPSTREAM_CLIENT_ID", "gate"),
        ("UPSTREAM_REQUIRE_CLAIM", "groups=testers"),
    ];
    env.extend_from_slice(extra);
    let b = spawn_at(path, &env).await;
    (a, b)
}

/// Start at B, log in at A as `realfrank` with `claims`; returns B's callback URL.
async fn upstream_login(a: &TestServer, b: &TestServer, claims: &str) -> String {
    let r = b.client.get(authz_url(b)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let to_a = location(&r);
    assert!(to_a.starts_with(&a.url("/authorize?")), "{to_a}");
    assert_eq!(
        query_param(&to_a, "redirect_uri").unwrap(),
        b.url("/upstream/callback")
    );
    let r = a
        .client
        .post(&to_a)
        .form(&[("username", "realfrank"), ("claims", claims)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    location(&r)
}

/// Pass B's gate as a tester; returns the `Cookie` header value.
async fn pass_gate(a: &TestServer, b: &TestServer) -> String {
    let to_cb = upstream_login(a, b, TESTERS).await;
    let r = b.client.get(&to_cb).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    assert_eq!(
        format!("{}{}", b.root, location(&r)),
        authz_url(b),
        "back to the original authorize request"
    );
    let set = r.headers()["set-cookie"].to_str().unwrap();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Lax"), "{set}");
    assert!(!set.contains("Secure"), "http issuer: no Secure");
    set.split(';').next().unwrap().to_string()
}

/// Log in at B as persona `alice` with the gate cookie and redeem the code.
async fn persona_tokens(b: &TestServer, cookie: &str, claims: &str) -> Value {
    let r = b
        .client
        .post(authz_url(b))
        .header("cookie", cookie)
        .form(&[("username", "alice"), ("claims", claims)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let code = query_param(&location(&r), "code").expect("code");
    b.client
        .post(b.url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", CB),
            ("client_id", "app"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn refresh(b: &TestServer, rt: &str) -> reqwest::Response {
    b.client
        .post(b.url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", "app"),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn gated_login_then_personas_as_today() {
    let (a, b) = pair("", &[]).await;
    let cookie = pass_gate(&a, &b).await;
    let r = b
        .client
        .get(authz_url(&b))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "login page behind the gate");

    let t = persona_tokens(&b, &cookie, r#"{"roles":["admin"]}"#).await;
    let (_, at) = decode_jwt_unverified(t["access_token"].as_str().unwrap());
    assert_eq!(at["sub"], "alice");
    assert_eq!(at["roles"], json!(["admin"]));
    assert!(at.get("upstream_sub").is_none(), "no audit claim unless configured");

    let rt = t["refresh_token"].as_str().unwrap();
    let i: Value = b
        .client
        .post(b.url("/introspect"))
        .form(&[("token", rt)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(i["refresh_token_type"], "offline");
    assert_eq!(refresh(&b, rt).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn upstream_sub_claim_is_set_and_cannot_be_forged() {
    let (a, b) = pair(
        "",
        &[("UPSTREAM_SUB_TOKEN_CLAIM", "upstream_sub"), ("ADMIN_TOKEN", "adm")],
    )
    .await;
    let cookie = pass_gate(&a, &b).await;
    let t = persona_tokens(&b, &cookie, r#"{"upstream_sub":"forged"}"#).await;
    let (_, at) = decode_jwt_unverified(t["access_token"].as_str().unwrap());
    assert_eq!(at["sub"], "alice");
    assert_eq!(at["upstream_sub"], "realfrank");
    let (_, id) = decode_jwt_unverified(t["id_token"].as_str().unwrap());
    assert_eq!(id["upstream_sub"], "realfrank");

    // an admin override replaces the login claims; the upstream claim survives refresh
    let r = b
        .client
        .put(b.url("/admin/subjects/alice"))
        .bearer_auth("adm")
        .json(&json!({"claims": {"roles": ["viewer"]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r: Value = refresh(&b, t["refresh_token"].as_str().unwrap())
        .await
        .json()
        .await
        .unwrap();
    let (_, at) = decode_jwt_unverified(r["access_token"].as_str().unwrap());
    assert_eq!(at["roles"], json!(["viewer"]));
    assert_eq!(at["upstream_sub"], "realfrank");
}

#[tokio::test]
async fn upstream_user_without_required_claim_is_denied() {
    let (a, b) = pair("", &[]).await;
    let to_cb = upstream_login(&a, &b, r#"{"groups":["devs"]}"#).await;
    let r = b.client.get(&to_cb).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(r.headers().get("set-cookie").is_none());
    assert!(r.text().await.unwrap().contains("groups=testers"));
}

#[tokio::test]
async fn post_without_cookie_is_forbidden_not_redirected() {
    let (_a, b) = pair("", &[]).await;
    let r = b
        .client
        .post(authz_url(&b))
        .form(&[("username", "alice")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn foreign_or_tampered_cookie_is_refused() {
    let (a, b) = pair("", &[]).await;
    let cookie = pass_gate(&a, &b).await;
    // another gated instance (= a restart: new cookie key)
    let issuer = a.issuer.clone();
    let b2 = spawn(&[
        ("UPSTREAM_ISSUER", issuer.as_str()),
        ("UPSTREAM_CLIENT_ID", "gate"),
    ])
    .await;
    for (server, c) in [(&b2, cookie.clone()), (&b, format!("{cookie}x"))] {
        let r = server
            .client
            .post(authz_url(server))
            .header("cookie", &c)
            .form(&[("username", "alice")])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "POST with {c}");
        let r = server
            .client
            .get(authz_url(server))
            .header("cookie", &c)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FOUND, "GET with {c}");
        assert!(location(&r).starts_with(&a.url("/authorize?")));
    }
}

#[tokio::test]
async fn callback_state_is_single_use_and_checked() {
    let (a, b) = pair("", &[]).await;
    let to_cb = upstream_login(&a, &b, TESTERS).await;
    assert_eq!(b.client.get(&to_cb).send().await.unwrap().status(), StatusCode::FOUND);
    let r = b.client.get(&to_cb).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "replayed callback");
    assert!(r.text().await.unwrap().contains("start again"));
    let r = b
        .client
        .get(b.url("/upstream/callback?state=nope&code=x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upstream_error_is_shown() {
    let (_a, b) = pair("", &[]).await;
    let r = b.client.get(authz_url(&b)).send().await.unwrap();
    let st = query_param(&location(&r), "state").unwrap();
    let r = b
        .client
        .get(format!(
            "{}?state={st}&error=access_denied&error_description=nope",
            b.url("/upstream/callback")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(r.text().await.unwrap().contains("access_denied"));
}

#[tokio::test]
async fn upstream_unreachable_is_502() {
    let s = spawn(&[
        ("UPSTREAM_ISSUER", "http://127.0.0.1:9"),
        ("UPSTREAM_CLIENT_ID", "gate"),
    ])
    .await;
    let r = s.client.get(authz_url(&s)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    // the server is still fine
    let r = s.client.get(s.url("/health")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn gate_under_a_mount_path() {
    let (a, b) = pair("/mockidp", &[]).await;
    assert!(b.url("/upstream/callback").contains("/mockidp/upstream/callback"));
    let to_cb = upstream_login(&a, &b, TESTERS).await;
    let r = b.client.get(&to_cb).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    assert!(location(&r).starts_with("/mockidp/authorize?"));
    let set = r.headers()["set-cookie"].to_str().unwrap();
    assert!(set.contains("Path=/mockidp;"), "{set}");
    let cookie = set.split(';').next().unwrap().to_string();
    let t = persona_tokens(&b, &cookie, "{}").await;
    assert!(t["access_token"].is_string());
}

#[tokio::test]
async fn no_callback_route_without_gate() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .get(s.url("/upstream/callback?state=x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}
```

Run: `cargo test --test upstream`
Expected: FAIL (GET `/authorize` returns 200 instead of 302, etc.).

- [ ] **Step 3: Store changes**

In `src/store.rs`:

```rust
/// A browser on its way through the upstream login, keyed by the upstream `state`.
#[derive(Debug, Clone)]
pub struct UpstreamLogin {
    pub nonce: String,
    /// PKCE verifier for the upstream code exchange.
    pub verifier: String,
    /// Path + query of the original `/authorize` request, to return to.
    pub return_to: String,
}
```

- `CodeEntry`: add `/// Upstream `sub` of the tester who passed the gate.` `pub upstream_sub: Option<String>,`
- `RefreshEntry`: add the same field with the same doc comment.
- `Store`: add `pub upstream_pending: HashMap<String, Expiring<UpstreamLogin>>,`; in `sweep` add `self.upstream_pending.retain(|_, e| !e.is_expired(now));`; add

```rust
    pub fn take_upstream_login(&mut self, state: &str) -> Option<UpstreamLogin> {
        let e = self.upstream_pending.remove(state)?;
        (!e.is_expired(SystemTime::now())).then_some(e.value)
    }
```

- Update every `CodeEntry { … }` / `RefreshEntry { … }` literal to include `upstream_sub: None` (store tests, `token.rs` password grant) — `cargo build --all-targets` lists them.

- [ ] **Step 4: `Gate` and the callback**

Replace `src/upstream/mod.rs` with:

```rust
//! Optional gate: testers log in at an upstream OIDC provider before they may pick a persona.

pub mod client;
pub mod gate;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use client::Upstream;
pub use gate::{GateKey, GateSession};

use crate::config::Config;
use crate::routes::authorize::{error_page, found};
use crate::state::{AppState, SharedState};
use crate::store::{now_secs, random_token, Claims, Expiring, UpstreamLogin};

/// How long a browser may take for the upstream login.
const LOGIN_TTL: u64 = 600;

pub struct Gate {
    pub upstream: Upstream,
    pub key: GateKey,
    /// `<ISSUER_URL>/upstream/callback`: the one redirect URI registered at the upstream.
    pub redirect_uri: String,
    cookie_path: String,
    secure: bool,
}

impl Gate {
    /// The gate for `config`, or None when `UPSTREAM_ISSUER` is unset.
    pub fn new(config: &Config) -> Result<Option<Gate>, String> {
        let Some(up) = &config.upstream else {
            return Ok(None);
        };
        Ok(Some(Gate {
            upstream: Upstream::new(up.clone())?,
            key: GateKey::random(),
            redirect_uri: format!("{}/upstream/callback", config.issuer()),
            cookie_path: if config.issuer_path.is_empty() {
                "/".into()
            } else {
                config.issuer_path.clone()
            },
            secure: config.issuer_url.scheme() == "https",
        }))
    }

    /// The gate session of a request, if it carries a valid, unexpired cookie.
    pub fn session(&self, headers: &HeaderMap) -> Option<GateSession> {
        self.key.open(gate::cookie_value(headers)?, now_secs())
    }

    /// Send the browser to the upstream login; it comes back to `return_to` (path + query).
    pub async fn start_login(&self, state: &AppState, return_to: String) -> Response {
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let login_state = random_token();
        let nonce = random_token();
        match self
            .upstream
            .authorize_url(&self.redirect_uri, &login_state, &nonce, &challenge)
            .await
        {
            Ok(url) => {
                state.store().upstream_pending.insert(
                    login_state,
                    Expiring::new(
                        UpstreamLogin {
                            nonce,
                            verifier,
                            return_to,
                        },
                        LOGIN_TTL,
                    ),
                );
                found(&url)
            }
            Err(e) => {
                tracing::error!("upstream gate: {e}");
                page(
                    StatusCode::BAD_GATEWAY,
                    &format!("cannot reach the upstream identity provider: {e}"),
                )
            }
        }
    }
}

fn page(status: StatusCode, msg: &str) -> Response {
    (status, Html(error_page(msg))).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

async fn redeem(gate: &Gate, code: &str, login: &UpstreamLogin) -> Result<Claims, String> {
    let id_token = gate
        .upstream
        .exchange(code, &gate.redirect_uri, &login.verifier)
        .await?;
    gate.upstream.verify_id_token(&id_token, &login.nonce).await
}

/// `GET /upstream/callback`: finish the upstream login, check access, set the gate cookie.
pub async fn callback(State(state): State<SharedState>, Query(q): Query<CallbackQuery>) -> Response {
    let Some(gate) = &state.gate else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let login = q
        .state
        .as_deref()
        .and_then(|s| state.store().take_upstream_login(s));
    let Some(login) = login else {
        return page(
            StatusCode::BAD_REQUEST,
            "unknown or expired login state: start again from the application",
        );
    };
    if let Some(err) = &q.error {
        return page(
            StatusCode::FORBIDDEN,
            &format!(
                "upstream login failed: {err} {}",
                q.error_description.as_deref().unwrap_or_default()
            ),
        );
    }
    let Some(code) = q.code.as_deref().filter(|c| !c.is_empty()) else {
        return page(StatusCode::BAD_REQUEST, "missing code from the upstream");
    };
    let claims = match redeem(gate, code, &login).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("upstream login failed: {e}");
            return page(StatusCode::BAD_GATEWAY, &format!("upstream login failed: {e}"));
        }
    };
    let Some(sub) = claims.get("sub").and_then(Value::as_str).map(str::to_string) else {
        return page(StatusCode::BAD_GATEWAY, "upstream id_token has no sub");
    };
    let email = claims.get("email").and_then(Value::as_str).map(str::to_string);
    if let Some((path, value)) = &gate.upstream.cfg.require_claim {
        if !gate::claim_allows(&claims, path, value) {
            tracing::warn!(
                upstream_sub = %sub,
                email = ?email,
                claim = %path,
                seen = ?gate::claim_at(&claims, path),
                "upstream login denied"
            );
            return page(
                StatusCode::FORBIDDEN,
                &format!(
                    "upstream user {} is not allowed here (needs {path}={value})",
                    email.as_deref().unwrap_or(&sub)
                ),
            );
        }
    }
    tracing::info!(upstream_sub = %sub, email = ?email, "upstream login allowed");
    let ttl = gate.upstream.cfg.session_ttl;
    let cookie = gate.key.seal(&GateSession {
        sub,
        email,
        exp: now_secs() + ttl,
    });
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, login.return_to),
            (
                header::SET_COOKIE,
                gate::set_cookie(&cookie, &gate.cookie_path, ttl, gate.secure),
            ),
        ],
    )
        .into_response()
}
```

In `src/routes/authorize.rs` make `error_page` `pub fn error_page`. `src/routes/mod.rs` declares `mod authorize;` privately — change it to `pub mod authorize;` so `crate::routes::authorize::{error_page, found}` resolves.

- [ ] **Step 5: State and router**

`src/state.rs`: add field

```rust
    /// Upstream IdP gate; None when `UPSTREAM_ISSUER` is unset.
    #[cfg(feature = "upstream")]
    pub gate: Option<crate::upstream::Gate>,
```

and in `new`, before building the struct: `#[cfg(feature = "upstream")] let gate = crate::upstream::Gate::new(&config)?;`, plus `#[cfg(feature = "upstream")] gate,` in the literal.

`src/routes/mod.rs`, after the admin merge:

```rust
    #[cfg(feature = "upstream")]
    let oidc = if state.gate.is_some() {
        oidc.route("/upstream/callback", get(crate::upstream::callback))
    } else {
        oidc
    };
```

- [ ] **Step 6: Gate checks in `/authorize`**

`get`: add `headers: HeaderMap` (from `axum::http::HeaderMap`) as an extractor parameter, and after `validate` succeeds (before inserting into `pending`):

```rust
    #[cfg(feature = "upstream")]
    if let Some(gate) = &state.gate {
        if gate.session(&headers).is_none() {
            let query = raw.as_deref().map(|q| format!("?{q}")).unwrap_or_default();
            let return_to = format!("{}/authorize{query}", state.config.issuer_path);
            return gate.start_login(&state, return_to).await;
        }
    }
```

`post`: add `headers: HeaderMap` before `Form(form)` (Form must stay last). At the very top, before `validate`:

```rust
    // Behind the upstream gate, only browsers that passed it may log in as a persona.
    #[allow(unused_mut)]
    let mut upstream_sub: Option<String> = None;
    #[cfg(feature = "upstream")]
    if let Some(gate) = &state.gate {
        match gate.session(&headers) {
            Some(s) => upstream_sub = Some(s.sub),
            None => {
                return AuthzError::Page(
                    StatusCode::FORBIDDEN,
                    "not signed in at the upstream identity provider: reload the login page".into(),
                )
                .into_response()
            }
        }
    }
```

Replace the `let entry = CodeEntry { … };` block at the end of `post` with:

```rust
    if let Some(up) = &upstream_sub {
        tracing::info!(
            upstream_sub = %up,
            sub = ?sub_of(&claims),
            client_id = %req.client_id,
            "persona login behind the upstream gate"
        );
    }
    let entry = CodeEntry {
        req,
        claims,
        auth_time: now_secs(),
        expires_in,
        upstream_sub,
    };
```

Without the feature `headers` is unused in both handlers: put
`#[cfg_attr(not(feature = "upstream"), allow(unused_variables))]` on `get` and `post`.

- [ ] **Step 7: Upstream claim at issue time**

In `src/routes/token.rs`:

```rust
/// `UPSTREAM_SUB_TOKEN_CLAIM`: the gate's upstream `sub`, set over whatever was typed at login.
fn with_upstream_claim(state: &SharedState, mut claims: Claims, upstream_sub: Option<&str>) -> Claims {
    let name = state
        .config
        .upstream
        .as_ref()
        .and_then(|u| u.sub_token_claim.as_deref());
    if let (Some(name), Some(sub)) = (name, upstream_sub) {
        claims.insert(name.into(), json!(sub));
    }
    claims
}
```

- `authorization_code`: `claims: with_upstream_claim(&state, entry.claims.clone(), entry.upstream_sub.as_deref()),` in `IssueParams`; `upstream_sub: entry.upstream_sub.clone(),` in the new `RefreshEntry` (keep `claims: entry.claims` — the login snapshot without the claim; it's re-applied at every issue).
- `refresh_token`: `claims: with_upstream_claim(&state, claims, entry.upstream_sub.as_deref()),` (the existing `RefreshEntry { audience, ..entry }` carries `upstream_sub` over).
- `password`: `upstream_sub: None` in its `RefreshEntry`.

- [ ] **Step 8: Run tests**

Run: `cargo test --test upstream` → PASS. Then `cargo test`, `cargo test --no-default-features`, `cargo clippy --all-targets -- -D warnings`, `cargo clippy --all-targets --no-default-features -- -D warnings` → all clean. `git diff --stat tests/flow.rs tests/offline.rs` → empty.

- [ ] **Step 9: Commit**

```bash
cargo fmt --all
git add src tests
git commit -m "feat(upstream): gate /authorize behind an upstream OIDC login

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Close the back doors on `/token`

**Files:**
- Modify: `src/error.rs`
- Modify: `src/routes/token.rs`
- Modify: `tests/upstream.rs`

**Interfaces:**
- Consumes: `Config.upstream`, `Config.clients`, `client_credentials()` (existing in `token.rs`).
- Produces: `OAuthError::unauthorized_client(msg)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/upstream.rs`:

```rust
/// Gated, upstream never contacted (token grants don't need it).
async fn gated_offline() -> TestServer {
    spawn(&[
        ("UPSTREAM_ISSUER", "http://127.0.0.1:9"),
        ("UPSTREAM_CLIENT_ID", "gate"),
        (
            "CLIENTS",
            r#"[{"client_id":"ci","client_secret":"s3cret"},{"client_id":"public"}]"#,
        ),
    ])
    .await
}

async fn grant(s: &TestServer, grant: &str, client_id: &str, secret: Option<&str>) -> (StatusCode, Value) {
    let mut form = vec![
        ("grant_type", grant),
        ("client_id", client_id),
        ("username", "alice"),
        ("password", "x"),
    ];
    if let Some(sec) = secret {
        form.push(("client_secret", sec));
    }
    let r = s.client.post(s.url("/token")).form(&form).send().await.unwrap();
    (r.status(), r.json().await.unwrap())
}

#[tokio::test]
async fn browserless_grants_need_a_configured_client_with_secret() {
    let s = gated_offline().await;
    let reg: Value = s
        .client
        .post(s.url("/register"))
        .json(&json!({"redirect_uris": ["http://x/cb"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let (dyn_id, dyn_secret) = (
        reg["client_id"].as_str().unwrap().to_string(),
        reg["client_secret"].as_str().unwrap().to_string(),
    );
    for g in ["password", "client_credentials"] {
        for (id, secret) in [
            ("app", None),
            ("public", None),
            ("ci", None),
            ("ci", Some("wrong")),
            (dyn_id.as_str(), Some(dyn_secret.as_str())),
        ] {
            let (status, body) = grant(&s, g, id, secret).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{g} {id} {secret:?}");
            assert_eq!(body["error"], "unauthorized_client", "{g} {id}");
        }
        let (status, _) = grant(&s, g, "ci", Some("s3cret")).await;
        assert_eq!(status, StatusCode::OK, "{g} with the configured secret");
    }
    // HTTP Basic works too
    let r = s
        .client
        .post(s.url("/token"))
        .basic_auth("ci", Some("s3cret"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}
```

Run: `cargo test --test upstream browserless` → FAIL (200 for `app`).

- [ ] **Step 2: Implement**

`src/error.rs`, in `impl OAuthError`:

```rust
    pub fn unauthorized_client(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unauthorized_client", msg)
    }
```

`src/routes/token.rs`:

```rust
/// With the upstream gate on, the browser-less user grants (password, client_credentials)
/// are only for clients configured in `CLIENTS` with a secret, and the secret must match.
/// Dynamically registered clients don't count: anyone can register one.
fn ensure_trusted_client(
    state: &SharedState,
    headers: &HeaderMap,
    form: &TokenForm,
) -> Result<(), OAuthError> {
    if state.config.upstream.is_none() {
        return Ok(());
    }
    let (id, secret) = client_credentials(
        headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    );
    let trusted = state.config.clients.iter().any(|c| {
        Some(&c.client_id) == id.as_ref() && c.client_secret.is_some() && c.client_secret == secret
    });
    if trusted {
        return Ok(());
    }
    tracing::warn!(client_id = ?id, grant = ?form.grant_type, "grant refused by the upstream gate");
    Err(OAuthError::unauthorized_client(
        "behind the upstream gate this grant needs a client from CLIENTS with its client_secret",
    ))
}
```

Call `ensure_trusted_client(&state, &headers, &form)?;` as the first line of the `Some("password")` and `Some("client_credentials")` arms.

- [ ] **Step 3: Run tests**

Run: `cargo test` and `cargo test --no-default-features` → PASS (flow.rs's ungated password/client_credentials tests prove the gate-off path is unchanged).

- [ ] **Step 4: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/error.rs src/routes/token.rs tests/upstream.rs
git commit -m "feat(upstream): browserless grants need a configured client behind the gate

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Startup logging, smoke test, README, musl build check

**Files:**
- Modify: `src/main.rs`
- Modify: `scripts/smoke.sh`
- Modify: `README.md`

**Interfaces:**
- Consumes: `Config.upstream`, `nano_mockidp::keys::KeySource`.

- [ ] **Step 1: Startup log and seed warning**

In `src/main.rs`, after the `"nano-mockidp starting"` log:

```rust
    if let Some(up) = &state.config.upstream {
        tracing::info!(
            upstream = %up.issuer,
            client_id = %up.client_id,
            require_claim = ?up.require_claim,
            "upstream gate on"
        );
        if state.key.source == nano_mockidp::keys::KeySource::Seed {
            tracing::warn!(
                "upstream gate is on but the signing key comes from SIGNING_KEY_SEED: anyone \
                 who guesses the seed can mint tokens without passing the gate; use \
                 SIGNING_KEY_PEM or SIGNING_KEY_PATH on public instances"
            );
        }
    }
```

Check: `UPSTREAM_ISSUER=https://idp.example UPSTREAM_CLIENT_ID=x SIGNING_KEY_SEED=s cargo run` logs both lines and keeps running (Ctrl-C). `cargo run --no-default-features` with the same env exits 2 with the "built without the `upstream` feature" error.

- [ ] **Step 2: Smoke section**

In `scripts/smoke.sh`:
- Near the top (after `set -euo pipefail`): `ROOT=$(cd "$(dirname "$0")/.." && pwd)`, and replace the existing `cd "$(dirname "$0")/.."` with `cd "$ROOT"`.
- Add to the header comment: `#   UPSTREAM_SMOKE=1  also test the upstream gate with two local binaries (ports SMOKE_PORT+1, +2)`.
- Insert before the final `echo` / pass-fail lines:

```bash
# ---------- upstream gate (UPSTREAM_SMOKE=1; two local binaries) ----------
if [[ "${UPSTREAM_SMOKE:-}" == 1 ]]; then
  echo "upstream gate"
  cd "$ROOT"
  cargo build --release --quiet
  UP_PORT=$(( ${SMOKE_PORT:-18089} + 1 )); GATED_PORT=$(( ${SMOKE_PORT:-18089} + 2 ))
  UP="http://127.0.0.1:$UP_PORT"; GATED="http://127.0.0.1:$GATED_PORT"
  PORT=$UP_PORT ISSUER_URL=$UP LOG_LEVEL=warn ./target/release/nano-mockidp &
  UP_PID=$!
  PORT=$GATED_PORT ISSUER_URL=$GATED LOG_LEVEL=warn UPSTREAM_ISSUER=$UP UPSTREAM_CLIENT_ID=gate \
    UPSTREAM_REQUIRE_CLAIM=groups=testers UPSTREAM_SUB_TOKEN_CLAIM=upstream_sub \
    ./target/release/nano-mockidp &
  GATED_PID=$!
  trap 'kill ${SERVER_PID:-} $UP_PID $GATED_PID 2>/dev/null' EXIT
  for u in "$UP" "$GATED"; do
    for _ in $(seq 50); do curl -sf "$u/health" >/dev/null && break; sleep 0.1; done
  done
  JAR=$(mktemp)
  uri() { jq -rn --arg v "$1" '$v|@uri'; }
  AUTHZ="$GATED/authorize?response_type=code&client_id=smoke&state=s&scope=$(uri 'openid offline_access')&redirect_uri=$(uri "$REDIRECT_URI")"

  to_up=$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTHZ")
  check "no gate cookie → upstream login" "${to_up%%\?*}" "$UP/authorize"
  to_cb=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$to_up" \
    --data-urlencode username=realfrank --data-urlencode 'claims={"groups":["testers"]}')
  check "upstream returns to the callback" "${to_cb%%\?*}" "$GATED/upstream/callback"
  check "callback → 302" "$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" "$to_cb")" 302
  check "gate cookie set" "$(grep -c nano_mockidp_gate "$JAR")" 1
  check "login page behind the gate" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$AUTHZ")" 200

  loc=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$JAR" -X POST "$AUTHZ" \
    --data-urlencode username=alice --data-urlencode 'claims={"upstream_sub":"forged"}')
  code=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$loc")
  BODY=$(curl -s -X POST "$GATED/token" -d grant_type=authorization_code -d client_id=smoke \
    -d "code=$code" --data-urlencode "redirect_uri=$REDIRECT_URI")
  AT=$(jq -r .access_token <<<"$BODY"); RT=$(jq -r .refresh_token <<<"$BODY")
  check "persona sub" "$(jwt_claim "$AT" .sub)" '"alice"'
  check "upstream_sub from the gate, not the form" "$(jwt_claim "$AT" .upstream_sub)" '"realfrank"'
  check "gated refresh works" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATED/token" \
    -d grant_type=refresh_token -d client_id=smoke --data-urlencode "refresh_token=$RT")" 200

  check "POST without cookie → 403" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$AUTHZ" \
    --data-urlencode username=alice)" 403
  to_up=$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTHZ")
  to_cb=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$to_up" \
    --data-urlencode username=intruder --data-urlencode 'claims={"groups":["devs"]}')
  check "upstream user without the group → 403" "$(curl -s -o /dev/null -w '%{http_code}' "$to_cb")" 403
  check "password grant behind the gate → unauthorized_client" "$(curl -s -X POST "$GATED/token" \
    -d grant_type=password -d client_id=smoke -d username=alice -d password=x | jq -r .error)" unauthorized_client
  rm -f "$JAR"
fi
```

Run: `UPSTREAM_SMOKE=1 scripts/smoke.sh`
Expected: all lines `ok`, final `smoke test passed`. Also run plain `scripts/smoke.sh` → passes, upstream section skipped.

- [ ] **Step 3: README**

In `README.md`:
- Feature list: add `- Optional **upstream IdP gate** (`UPSTREAM_ISSUER`): testers log in at a real OIDC provider before picking a persona — for test environments on the open internet`.
- Change the line "Never expose it publicly." to "Never expose it publicly — unless behind the [upstream gate](#gating-with-an-upstream-idp)."
- New section before `## Strict mode`:

````markdown
## Gating with an upstream IdP

For a test environment on the internet: before the persona form, testers log in at a real
OpenID Connect provider (Entra ID, Google, Keycloak, …) and must pass a claim check. After that,
everything works as without the gate: any username, any claims. The upstream identity never
becomes the token's `sub`.

```sh
docker run --rm -p 8080:8080 \
  -e ISSUER_URL=https://mockidp.test.example \
  -e SIGNING_KEY_PEM="$(cat key.pem)" \
  -e UPSTREAM_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0 \
  -e UPSTREAM_CLIENT_ID=<app id> -e UPSTREAM_CLIENT_SECRET=<secret> \
  -e UPSTREAM_REQUIRE_CLAIM=groups=<tester group id> \
  ghcr.io/kapernikov/nano-mockidp:latest
```

Register `<ISSUER_URL>/upstream/callback` as the redirect URI at the upstream.

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM_ISSUER` | – | Upstream issuer URL. Setting it turns the gate on. |
| `UPSTREAM_CLIENT_ID` | – | Required with the gate. |
| `UPSTREAM_CLIENT_SECRET` | – | Sent with HTTP Basic. Unset → public client with PKCE. |
| `UPSTREAM_SCOPE` | `openid email profile` | `openid` is added if missing. |
| `UPSTREAM_REQUIRE_CLAIM` | – | `path=value`: the upstream ID-token claim at `path` (dots descend, e.g. `realm_access.roles=tester`) must equal `value` or, if an array, contain it. Unset → any upstream user. |
| `UPSTREAM_SESSION_TTL` | `28800` | Seconds before a tester goes through the upstream again. |
| `UPSTREAM_SUB_TOKEN_CLAIM` | – | Claim name that carries the tester's upstream `sub` in every token (e.g. `upstream_sub`). Can't be overridden from the form. |
| `UPSTREAM_CA_PATH` | – | Extra PEM CA bundle for the upstream (private CA). |

With the gate on:

| | |
|---|---|
| `GET /authorize` | needs the gate cookie, else redirect to the upstream |
| `POST /authorize` | needs the gate cookie, else 403 |
| `password`, `client_credentials` grants | only for a `CLIENTS` entry with a `client_secret`, secret checked (clients from `/register` don't count) |
| everything else | unchanged: refresh (online/offline), revoke, logout, introspect, userinfo, admin |

**Use a secret signing key** (`SIGNING_KEY_PEM` / `SIGNING_KEY_PATH`): with a guessable
`SIGNING_KEY_SEED` anyone can sign their own tokens and skip the gate. Startup warns about this.

The gate cookie's key is random per start: after a restart testers pass the upstream again.
Without a bypass for robots, run e2e suites against an ungated instance.

The gate is a Cargo feature (`upstream`, on by default, ~TLS client via rustls + ring, no
OpenSSL). `cargo build --release --no-default-features` builds the smaller binary without it;
that binary refuses to start when `UPSTREAM_ISSUER` is set.
````

- Development section: add `UPSTREAM_SMOKE=1 scripts/smoke.sh   # also the upstream gate, with two local binaries`.

- [ ] **Step 4: musl / image check**

Run (whichever is available):
- `cargo zigbuild --release --target x86_64-unknown-linux-musl` → builds; then
- `docker build -t nano-mockidp:gate . && docker images nano-mockidp:gate` → note the image size; and
  `docker run --rm -e UPSTREAM_ISSUER=https://accounts.google.com -e UPSTREAM_CLIENT_ID=x -p 18080:8080 nano-mockidp:gate` in one shell, `curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' 'http://localhost:18080/authorize?response_type=code&client_id=a&redirect_uri=http://x/cb'` in another → `302 https://accounts.google.com/o/oauth2/v2/auth?...` (proves HTTPS discovery with bundled roots in the `FROM scratch` image).

Report the image size in the task summary.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/main.rs scripts/smoke.sh README.md
git commit -m "docs+smoke: upstream gate (README section, UPSTREAM_SMOKE, seed warning)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
