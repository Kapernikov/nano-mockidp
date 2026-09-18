use axum::extract::{Form, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::login::load_login_page;
use crate::state::SharedState;
use crate::store::{now_secs, random_token, AuthRequest, Claims, CodeEntry, Expiring};

const PENDING_TTL: u64 = 600;
const CODE_TTL: u64 = 300;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: Option<String>,
    pub claims: Option<String>,
    pub expires_in: Option<String>,
}

/// Errors before we trust the redirect_uri are rendered as HTML; afterwards as OAuth redirects.
enum AuthzError {
    Page(StatusCode, String),
    Redirect {
        redirect_uri: String,
        error: &'static str,
        description: String,
        state: Option<String>,
    },
}

impl IntoResponse for AuthzError {
    fn into_response(self) -> Response {
        match self {
            AuthzError::Page(status, msg) => (status, Html(error_page(&msg))).into_response(),
            AuthzError::Redirect {
                redirect_uri,
                error,
                description,
                state,
            } => {
                let mut url = url::Url::parse(&redirect_uri).expect("validated");
                {
                    let mut q = url.query_pairs_mut();
                    q.append_pair("error", error);
                    q.append_pair("error_description", &description);
                    if let Some(s) = state {
                        q.append_pair("state", &s);
                    }
                }
                found(url.as_str())
            }
        }
    }
}

fn error_page(msg: &str) -> String {
    let escaped = msg
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>nano-mockidp error</title>\
         <style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:60px auto;padding:0 16px;color:#222}}\
         h1{{color:#ba2415;font-size:20px}}pre{{background:#ececec;padding:12px;white-space:pre-wrap}}</style></head>\
         <body><h1>Authorization request error</h1><pre>{escaped}</pre></body></html>"
    )
}

/// Validate an authorization request. Returns the request to store on success.
fn validate(state: &SharedState, q: &AuthorizeQuery) -> Result<AuthRequest, AuthzError> {
    let client_id = q
        .client_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AuthzError::Page(StatusCode::BAD_REQUEST, "missing client_id".into()))?;
    let redirect_uri = q
        .redirect_uri
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AuthzError::Page(StatusCode::BAD_REQUEST, "missing redirect_uri".into()))?;
    if url::Url::parse(redirect_uri).is_err() {
        return Err(AuthzError::Page(
            StatusCode::BAD_REQUEST,
            format!("redirect_uri is not a valid absolute URL: {redirect_uri}"),
        ));
    }

    let mut public_client = false;
    if state.config.strict {
        let store = state.store();
        let client = store.clients.get(client_id).ok_or_else(|| {
            AuthzError::Page(
                StatusCode::BAD_REQUEST,
                format!("unknown client_id: {client_id}"),
            )
        })?;
        let registered = client.redirect_uris.as_deref().unwrap_or(&[]);
        if !registered.iter().any(|u| u == redirect_uri) {
            return Err(AuthzError::Page(
                StatusCode::BAD_REQUEST,
                format!("redirect_uri not registered for client {client_id}: {redirect_uri}"),
            ));
        }
        public_client = client.client_secret.is_none();
    }

    let redirect_err = |error: &'static str, description: String| AuthzError::Redirect {
        redirect_uri: redirect_uri.to_string(),
        error,
        description,
        state: q.state.clone(),
    };

    if q.response_type.as_deref() != Some("code") {
        return Err(redirect_err(
            "unsupported_response_type",
            "only response_type=code is supported".into(),
        ));
    }
    if let Some(m) = q.code_challenge_method.as_deref() {
        if m != "S256" {
            return Err(redirect_err(
                "invalid_request",
                format!("only code_challenge_method=S256 is supported, got {m}"),
            ));
        }
    }
    if q.code_challenge.is_some() && q.code_challenge_method.is_none() {
        return Err(redirect_err(
            "invalid_request",
            "code_challenge_method=S256 is required when code_challenge is given".into(),
        ));
    }
    if state.config.strict && public_client && q.code_challenge.is_none() {
        return Err(redirect_err(
            "invalid_request",
            "PKCE (code_challenge) is required for public clients in strict mode".into(),
        ));
    }

    Ok(AuthRequest {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        state: q.state.clone(),
        scope: q.scope.clone(),
        nonce: q.nonce.clone(),
        code_challenge: q.code_challenge.clone(),
    })
}

pub async fn get(State(state): State<SharedState>, Query(q): Query<AuthorizeQuery>) -> Response {
    let req = match validate(&state, &q) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    state
        .store()
        .pending
        .insert(random_token(), Expiring::new(req, PENDING_TTL));
    match load_login_page(&state.config) {
        Ok(html) => ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(error_page(&format!(
                "cannot read login page {}: {e}",
                state
                    .config
                    .login_page_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            ))),
        )
            .into_response(),
    }
}

pub async fn post(
    State(state): State<SharedState>,
    Query(q): Query<AuthorizeQuery>,
    Form(form): Form<LoginForm>,
) -> Response {
    let req = match validate(&state, &q) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    let mut claims: Claims = match form
        .claims
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => Claims::new(),
        Some(raw) => match serde_json::from_str::<Value>(raw) {
            Ok(Value::Object(m)) => m,
            Ok(_) => {
                return AuthzError::Page(
                    StatusCode::BAD_REQUEST,
                    "claims must be a JSON object".into(),
                )
                .into_response()
            }
            Err(e) => {
                return AuthzError::Page(
                    StatusCode::BAD_REQUEST,
                    format!("claims is not valid JSON: {e}"),
                )
                .into_response()
            }
        },
    };
    let username = form
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if !claims.contains_key("sub") {
        match username {
            Some(u) => {
                claims.insert("sub".into(), json!(u));
            }
            None => {
                return AuthzError::Page(
                    StatusCode::BAD_REQUEST,
                    "username is required (or a `sub` claim)".into(),
                )
                .into_response()
            }
        }
    }
    let expires_in = match form
        .expires_in
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(v) => match v.parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => {
                return AuthzError::Page(
                    StatusCode::BAD_REQUEST,
                    format!("expires_in must be an integer, got {v}"),
                )
                .into_response()
            }
        },
    };

    let code = random_token();
    let mut location = url::Url::parse(&req.redirect_uri).expect("validated");
    {
        let mut qp = location.query_pairs_mut();
        qp.append_pair("code", &code);
        if let Some(s) = &req.state {
            qp.append_pair("state", s);
        }
    }
    let entry = CodeEntry {
        req,
        claims,
        auth_time: now_secs(),
        expires_in,
    };
    state
        .store()
        .codes
        .insert(code, Expiring::new(entry, CODE_TTL));
    found(location.as_str())
}

/// 302 Found redirect (OAuth convention; axum's `Redirect::to` uses 303).
pub fn found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}
