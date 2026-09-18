use axum::extract::State;
use axum::http::header::HeaderMap;
use axum::Form;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::OAuthError;
use crate::state::SharedState;
use crate::token::verify;

use super::token::authenticate_client;

#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
    pub token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub async fn handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> Result<axum::Json<Value>, OAuthError> {
    // RFC 7662 requires the caller to authenticate; enforce only in strict mode.
    if state.config.strict {
        authenticate_client(
            &state,
            &headers,
            form.client_id.as_deref(),
            form.client_secret.as_deref(),
        )?;
    }
    let Some(token) = form.token.as_deref().filter(|s| !s.is_empty()) else {
        return Err(OAuthError::invalid_request("token is required"));
    };

    if let Ok(mut claims) = verify(&state.key, state.issuer_check(), token) {
        claims.insert("active".into(), json!(true));
        claims.insert("token_type".into(), json!("Bearer"));
        if let Some(aud) = claims.get("aud").cloned() {
            claims.insert("client_id".into(), aud);
        }
        return Ok(axum::Json(Value::Object(claims)));
    }

    let store = state.store();
    if let Some(e) = store.peek_refresh(token) {
        let exp = e
            .expires_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        return Ok(axum::Json(json!({
            "active": true,
            "token_type": "refresh_token",
            "client_id": e.value.client_id,
            "sub": e.value.claims.get("sub"),
            "scope": e.value.scope,
            "exp": exp,
        })));
    }
    Ok(axum::Json(json!({ "active": false })))
}
