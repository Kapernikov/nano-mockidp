use axum::extract::State;
use axum::http::header::{self, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Form;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::error::OAuthError;
use crate::state::SharedState;
use crate::store::{now_secs, random_token, Claims, Expiring, RefreshEntry};
use crate::token::{pkce_verify, IssueParams, TokenSet};
use crate::urls::RequestBase;

#[derive(Debug, Deserialize, Default)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub audience: Option<String>,
}

/// Credentials from HTTP Basic (preferred) or the form body.
pub fn client_credentials(
    headers: &HeaderMap,
    form_id: Option<&str>,
    form_secret: Option<&str>,
) -> (Option<String>, Option<String>) {
    if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(b64) = v.strip_prefix("Basic ") {
            if let Ok(bytes) = STANDARD.decode(b64.trim()) {
                if let Ok(s) = String::from_utf8(bytes) {
                    let (id, secret) = s.split_once(':').unwrap_or((&s, ""));
                    let dec = |x: &str| {
                        url::form_urlencoded::parse(x.as_bytes())
                            .next()
                            .map(|(k, _)| k.into_owned())
                            .unwrap_or_default()
                    };
                    return (Some(dec(id)), Some(dec(secret)).filter(|s| !s.is_empty()));
                }
            }
        }
    }
    (
        form_id.map(str::to_string).filter(|s| !s.is_empty()),
        form_secret.map(str::to_string).filter(|s| !s.is_empty()),
    )
}

/// Resolve and (in strict mode) authenticate the client. Returns the client_id.
pub fn authenticate_client(
    state: &SharedState,
    headers: &HeaderMap,
    form_id: Option<&str>,
    form_secret: Option<&str>,
) -> Result<String, OAuthError> {
    let (id, secret) = client_credentials(headers, form_id, form_secret);
    let client_id = id.ok_or_else(|| OAuthError::invalid_client("client_id is required"))?;
    if state.config.strict {
        let store = state.store();
        let client = store
            .clients
            .get(&client_id)
            .ok_or_else(|| OAuthError::invalid_client(format!("unknown client: {client_id}")))?;
        if let Some(expected) = &client.client_secret {
            if secret.as_deref() != Some(expected.as_str()) {
                return Err(OAuthError::invalid_client("invalid client_secret"));
            }
        }
    }
    Ok(client_id)
}

fn token_response(set: TokenSet, refresh: Option<String>, scope: Option<&str>) -> Response {
    let mut body = Map::new();
    body.insert("access_token".into(), json!(set.access_token));
    body.insert("token_type".into(), json!("Bearer"));
    body.insert("expires_in".into(), json!(set.expires_in));
    if let Some(s) = scope {
        body.insert("scope".into(), json!(s));
    }
    if let Some(id) = set.id_token {
        body.insert("id_token".into(), json!(id));
    }
    if let Some(r) = refresh {
        body.insert("refresh_token".into(), json!(r));
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(Value::Object(body)),
    )
        .into_response()
}

fn new_refresh(state: &SharedState, entry: RefreshEntry) -> String {
    let token = random_token();
    state.store().refresh.insert(
        token.clone(),
        Expiring::new(entry, state.config.refresh_token_ttl),
    );
    token
}

pub async fn handler(
    State(state): State<SharedState>,
    RequestBase(base): RequestBase,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Response, OAuthError> {
    let issuer = state.issuer_for(&base);
    let client_id = authenticate_client(
        &state,
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )?;

    match form.grant_type.as_deref() {
        Some("authorization_code") => {
            let code = form
                .code
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
            let entry = state.store().take_code(code).ok_or_else(|| {
                OAuthError::invalid_grant("unknown, expired or already used code")
            })?;
            if entry.req.client_id != client_id {
                return Err(OAuthError::invalid_grant(
                    "code was issued to a different client",
                ));
            }
            match form.redirect_uri.as_deref() {
                Some(u) if u == entry.req.redirect_uri => {}
                Some(_) => {
                    return Err(OAuthError::invalid_grant(
                        "redirect_uri does not match the authorization request",
                    ))
                }
                None => return Err(OAuthError::invalid_request("redirect_uri is required")),
            }
            if let Some(challenge) = &entry.req.code_challenge {
                let verifier = form
                    .code_verifier
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        OAuthError::invalid_request("code_verifier is required (PKCE)")
                    })?;
                if !pkce_verify(verifier, challenge) {
                    return Err(OAuthError::invalid_grant("PKCE verification failed"));
                }
            }
            let set = state.token_issuer(&issuer).issue(IssueParams {
                client_id: client_id.clone(),
                scope: entry.req.scope.clone(),
                nonce: entry.req.nonce.clone(),
                claims: entry.claims.clone(),
                auth_time: entry.auth_time,
                expires_in: entry.expires_in,
                with_id_token: true,
            });
            let refresh = new_refresh(
                &state,
                RefreshEntry {
                    client_id,
                    scope: entry.req.scope.clone(),
                    claims: entry.claims,
                    auth_time: entry.auth_time,
                    expires_in: entry.expires_in,
                },
            );
            Ok(token_response(
                set,
                Some(refresh),
                entry.req.scope.as_deref(),
            ))
        }
        Some("refresh_token") => {
            let token = form
                .refresh_token
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
            let entry = state.store().take_refresh(token).ok_or_else(|| {
                OAuthError::invalid_grant("unknown, expired or rotated refresh token")
            })?;
            if entry.client_id != client_id {
                return Err(OAuthError::invalid_grant(
                    "refresh token was issued to a different client",
                ));
            }
            let set = state.token_issuer(&issuer).issue(IssueParams {
                client_id: client_id.clone(),
                scope: entry.scope.clone(),
                nonce: None,
                claims: entry.claims.clone(),
                auth_time: entry.auth_time,
                expires_in: entry.expires_in,
                with_id_token: true,
            });
            let scope = entry.scope.clone();
            let refresh = new_refresh(&state, entry);
            Ok(token_response(set, Some(refresh), scope.as_deref()))
        }
        Some("client_credentials") => {
            let mut claims = Claims::new();
            claims.insert("sub".into(), json!(client_id));
            if let Some(aud) = form.audience.as_deref().filter(|s| !s.is_empty()) {
                claims.insert("aud".into(), json!(aud));
            }
            let set = state.token_issuer(&issuer).issue(IssueParams {
                client_id,
                scope: form.scope.clone(),
                nonce: None,
                claims,
                auth_time: now_secs(),
                expires_in: None,
                with_id_token: false,
            });
            Ok(token_response(set, None, form.scope.as_deref()))
        }
        Some(_) => Err(OAuthError::unsupported_grant_type()),
        None => Err(OAuthError::invalid_request("grant_type is required")),
    }
}
