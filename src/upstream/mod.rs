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
pub async fn callback(
    State(state): State<SharedState>,
    Query(q): Query<CallbackQuery>,
) -> Response {
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
