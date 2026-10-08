//! Optional gate: testers log in at an upstream OIDC provider before they may pick a persona.

pub mod client;
pub mod gate;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use client::Upstream;
pub use gate::{GateKey, GateSession, PendingLogin};

use crate::config::Config;
use crate::routes::authorize::{error_page, found};
use crate::state::SharedState;
use crate::store::{now_secs, random_token, Claims};

/// How long a browser may take for the upstream login (pre-login cookie lifetime).
const LOGIN_TTL: u64 = 600;
/// Longest `/authorize` path + query carried through the upstream login in the cookie.
const MAX_RETURN_TO: usize = 2048;

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
        self.key
            .open(gate::cookie_value(headers, gate::COOKIE_NAME)?, now_secs())
    }

    fn set_cookie(&self, name: &str, value: &str, max_age: u64) -> String {
        gate::set_cookie(name, value, &self.cookie_path, max_age, self.secure)
    }

    /// Send the browser to the upstream login; it comes back to `return_to` (path + query).
    /// The login lives in a sealed pre-login cookie: nothing is stored server side.
    pub async fn start_login(&self, return_to: String) -> Response {
        if return_to.len() > MAX_RETURN_TO {
            return page(StatusCode::URI_TOO_LONG, "authorization request too long");
        }
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
                let name =
                    gate::login_cookie_name(&login_state).expect("random_token is base64url");
                let sealed = self.key.seal(&PendingLogin {
                    state: login_state,
                    nonce,
                    verifier,
                    return_to,
                    exp: now_secs() + LOGIN_TTL,
                });
                let mut r = found(&url);
                add_set_cookie(&mut r, &self.set_cookie(&name, &sealed, LOGIN_TTL));
                r
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

fn add_set_cookie(r: &mut Response, cookie: &str) {
    let v = HeaderValue::from_str(cookie).expect("cookie names and values are base64url");
    r.headers_mut().append(header::SET_COOKIE, v);
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

async fn redeem(gate: &Gate, code: &str, login: &PendingLogin) -> Result<Claims, String> {
    let id_token = gate
        .upstream
        .exchange(code, &gate.redirect_uri, &login.verifier)
        .await?;
    gate.upstream.verify_id_token(&id_token, &login.nonce).await
}

fn unknown_state() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "unknown or expired login state: start again from the application \
         (the login must finish in the same browser, on the ISSUER_URL host)",
    )
}

/// `GET /upstream/callback`: finish the upstream login, check access, set the gate cookie.
/// Only the browser holding the pre-login cookie for `state` can finish; the cookie is
/// cleared on every outcome.
pub async fn callback(
    State(state): State<SharedState>,
    Query(q): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(gate) = &state.gate else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(st) = q.state.as_deref() else {
        return unknown_state();
    };
    let Some(name) = gate::login_cookie_name(st) else {
        return unknown_state();
    };
    let Some(value) = gate::cookie_value(&headers, &name) else {
        return unknown_state();
    };
    let login = gate
        .key
        .open::<PendingLogin>(value, now_secs())
        .filter(|l| l.state == st);
    let mut r = match login {
        Some(login) => finish(gate, &q, login).await,
        None => unknown_state(),
    };
    add_set_cookie(&mut r, &gate.set_cookie(&name, "", 0));
    r
}

/// The callback once the pre-login cookie checked out.
async fn finish(gate: &Gate, q: &CallbackQuery, login: PendingLogin) -> Response {
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
            return page(
                StatusCode::BAD_GATEWAY,
                &format!("upstream login failed: {e}"),
            );
        }
    };
    let Some(sub) = claims
        .get("sub")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return page(StatusCode::BAD_GATEWAY, "upstream id_token has no sub");
    };
    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_string);
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
    let mut r = found(&login.return_to);
    add_set_cookie(&mut r, &gate.set_cookie(gate::COOKIE_NAME, &cookie, ttl));
    r
}
