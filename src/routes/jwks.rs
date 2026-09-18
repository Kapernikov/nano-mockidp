use axum::extract::State;
use axum::Json;
use serde_json::Value;

use crate::state::SharedState;

pub async fn handler(State(state): State<SharedState>) -> Json<Value> {
    Json(state.key.jwks())
}
