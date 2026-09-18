use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::SharedState;
use crate::urls::{Endpoints, RequestBase};

pub async fn handler(
    State(state): State<SharedState>,
    RequestBase(base): RequestBase,
) -> Json<Value> {
    let e = Endpoints::resolve(&state.config, Some(&base));
    Json(json!({
        "issuer": e.issuer,
        "authorization_endpoint": e.authorization,
        "token_endpoint": e.token,
        "jwks_uri": e.jwks,
        "userinfo_endpoint": e.userinfo,
        "introspection_endpoint": e.introspection,
        "end_session_endpoint": e.end_session,
        "registration_endpoint": e.registration,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "name"],
    }))
}
