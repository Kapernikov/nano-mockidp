use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Map, Value};

use crate::error::OAuthError;
use crate::state::SharedState;
use crate::store::{now_secs, random_token, Client};

pub async fn handler(
    State(state): State<SharedState>,
    body: Option<axum::Json<Value>>,
) -> Result<Response, OAuthError> {
    let mut meta: Map<String, Value> = match body {
        Some(axum::Json(Value::Object(m))) => m,
        Some(_) => return Err(OAuthError::invalid_request("body must be a JSON object")),
        None => Map::new(),
    };

    let redirect_uris: Option<Vec<String>> = meta.get("redirect_uris").and_then(|v| {
        v.as_array().map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
    });
    let auth_method = meta
        .get("token_endpoint_auth_method")
        .and_then(|v| v.as_str())
        .unwrap_or("client_secret_basic")
        .to_string();

    let client_id = random_token();
    let client_secret = (auth_method != "none").then(random_token);

    state.store().clients.insert(
        client_id.clone(),
        Client {
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            redirect_uris: redirect_uris.clone(),
        },
    );

    meta.insert("client_id".into(), json!(client_id));
    meta.insert("client_id_issued_at".into(), json!(now_secs()));
    if let Some(s) = &client_secret {
        meta.insert("client_secret".into(), json!(s));
        meta.insert("client_secret_expires_at".into(), json!(0));
    }
    meta.insert("token_endpoint_auth_method".into(), json!(auth_method));
    meta.entry("redirect_uris")
        .or_insert_with(|| json!(redirect_uris.unwrap_or_default()));
    meta.entry("grant_types")
        .or_insert_with(|| json!(["authorization_code", "refresh_token"]));
    meta.insert("response_types".into(), json!(["code"]));

    Ok((StatusCode::CREATED, axum::Json(Value::Object(meta))).into_response())
}
