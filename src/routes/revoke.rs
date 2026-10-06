use axum::extract::State;
use axum::http::header::{self, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use serde_json::Value;

use crate::error::OAuthError;
use crate::state::SharedState;
use crate::token::verify_allow_expired;

use super::token::authenticate_client;

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: Option<String>,
    /// Accepted but not needed: both token kinds are recognised on their own.
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// RFC 7009 token revocation. Refresh tokens are dropped; access/ID tokens (JWTs) have their
/// `jti` remembered until `exp`, so `/introspect` and `/userinfo` treat them as inactive.
/// Unknown tokens get 200, as the RFC requires.
pub async fn handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Result<Response, OAuthError> {
    let client_id = authenticate_client(
        &state,
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )?;
    let Some(token) = form.token.as_deref().filter(|s| !s.is_empty()) else {
        return Err(OAuthError::invalid_request("token is required"));
    };
    let other_client = || OAuthError::invalid_request("token was issued to a different client");

    let mut store = state.store();
    if let Some(e) = store.refresh.get(token) {
        if e.value.client_id != client_id {
            return Err(other_client());
        }
        store.refresh.remove(token);
    } else if let Ok(claims) = verify_allow_expired(&state.key, state.issuer_check(), token) {
        if claims.get("azp").and_then(Value::as_str) != Some(client_id.as_str()) {
            return Err(other_client());
        }
        if let (Some(jti), Some(exp)) = (
            claims.get("jti").and_then(Value::as_str),
            claims.get("exp").and_then(Value::as_u64),
        ) {
            store.revoked_jti.insert(jti.to_string(), exp);
        }
    }
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        "",
    )
        .into_response())
}
