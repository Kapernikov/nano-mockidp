use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use crate::state::SharedState;
use crate::store::sub_of;
use crate::token::verify_allow_expired;

use super::authorize::found;

#[derive(Debug, Deserialize)]
pub struct EndSessionQuery {
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub id_token_hint: Option<String>,
}

fn bad_request(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(format!(
            "<!doctype html><title>nano-mockidp</title><p>{}</p>",
            msg.replace('&', "&amp;").replace('<', "&lt;")
        )),
    )
        .into_response()
}

/// RP-initiated logout. With an `id_token_hint` (expired is fine), the refresh tokens of
/// that `sub` issued to that client (`azp`) are revoked.
pub async fn handler(
    State(state): State<SharedState>,
    Query(q): Query<EndSessionQuery>,
) -> Response {
    if let Some(hint) = q.id_token_hint.as_deref().filter(|s| !s.is_empty()) {
        let claims = match verify_allow_expired(&state.key, state.issuer_check(), hint) {
            Ok(c) => c,
            Err(e) => return bad_request(&format!("invalid id_token_hint: {e}")),
        };
        let client = claims
            .get("azp")
            .or_else(|| claims.get("aud"))
            .and_then(Value::as_str);
        if let (Some(sub), Some(client)) = (sub_of(&claims), client) {
            let n = state.store().revoke_refresh_for(sub, Some(client));
            tracing::debug!(
                sub,
                client,
                revoked = n,
                "end_session revoked refresh tokens"
            );
        }
    }
    match q.post_logout_redirect_uri.as_deref().filter(|s| !s.is_empty()) {
        Some(uri) => match url::Url::parse(uri) {
            Ok(mut url) => {
                if let Some(s) = &q.state {
                    url.query_pairs_mut().append_pair("state", s);
                }
                found(url.as_str())
            }
            Err(_) => bad_request("invalid post_logout_redirect_uri"),
        },
        None => Html(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>nano-mockidp</title>\
             <style>body{font-family:system-ui,sans-serif;max-width:640px;margin:60px auto;color:#222}h1{color:#ba2415;font-size:20px}</style></head>\
             <body><h1>Logged out</h1><p>You can close this page.</p></body></html>",
        )
        .into_response(),
    }
}
