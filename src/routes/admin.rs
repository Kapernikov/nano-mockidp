//! Runtime subject management, so tests can change a user's claims or remove them while
//! refresh tokens are outstanding. Mounted only when `ADMIN_TOKEN` is set.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;
use crate::store::{Claims, Store, Subject};

use super::userinfo::bearer;

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SubjectBody {
    #[serde(default)]
    pub claims: Option<Claims>,
    #[serde(default)]
    pub disabled: bool,
}

/// Constant-time comparison, so the admin token can't be guessed byte by byte.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn require_admin(State(state): State<SharedState>, req: Request, next: Next) -> Response {
    let expected = state.config.admin_token.as_deref().unwrap_or_default();
    match bearer(req.headers()) {
        Some(t) if !expected.is_empty() && same(t.as_bytes(), expected.as_bytes()) => {
            next.run(req).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Bearer realm=\"nano-mockidp-admin\"")],
            Json(json!({"error": "unauthorized"})),
        )
            .into_response(),
    }
}

fn view(store: &Store, sub: &str) -> Value {
    let s = store.subjects.get(sub).cloned().unwrap_or_default();
    json!({
        "sub": sub,
        "claims": s.claims,
        "disabled": s.disabled,
        "refresh_tokens": store.count_refresh_for(sub),
    })
}

pub async fn list(State(state): State<SharedState>) -> Json<Value> {
    let store = state.store();
    let mut subs: Vec<&String> = store.subjects.keys().collect();
    subs.sort();
    Json(Value::Array(
        subs.into_iter().map(|s| view(&store, s)).collect(),
    ))
}

pub async fn get(State(state): State<SharedState>, Path(sub): Path<String>) -> Json<Value> {
    Json(view(&state.store(), &sub))
}

/// Replace the subject's state. `claims` (if given) replace the login-time claims on the
/// next refresh; `sub` is always the path value.
pub async fn put(
    State(state): State<SharedState>,
    Path(sub): Path<String>,
    Json(body): Json<SubjectBody>,
) -> Json<Value> {
    let claims = body.claims.map(|mut c| {
        c.insert("sub".into(), json!(sub));
        c
    });
    let mut store = state.store();
    store.subjects.insert(
        sub.clone(),
        Subject {
            claims,
            disabled: body.disabled,
        },
    );
    Json(view(&store, &sub))
}

/// Forget the subject's state and revoke all its refresh tokens.
pub async fn delete(State(state): State<SharedState>, Path(sub): Path<String>) -> Json<Value> {
    let mut store = state.store();
    store.subjects.remove(&sub);
    let revoked = store.revoke_refresh_for(&sub, None);
    Json(json!({ "sub": sub, "revoked_refresh_tokens": revoked }))
}
