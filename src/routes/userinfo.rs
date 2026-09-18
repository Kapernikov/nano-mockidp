use axum::extract::State;
use axum::http::header::{self, HeaderMap};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::state::SharedState;
use crate::token::verify;

const STRIP: &[&str] = &["exp", "iat", "jti", "at_hash", "nonce", "azp", "scope"];

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            format!(
                "Bearer error=\"invalid_token\", error_description=\"{}\"",
                msg.replace('"', "'")
            ),
        )],
    )
        .into_response()
}

pub async fn handler(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return unauthorized("missing bearer token");
    };
    match verify(&state.key, state.issuer_check(), token) {
        Ok(mut claims) => {
            for k in STRIP {
                claims.remove(*k);
            }
            axum::Json(Value::Object(claims)).into_response()
        }
        Err(e) => unauthorized(&e),
    }
}
