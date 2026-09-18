mod authorize;
mod discovery;
mod health;
mod jwks;

use axum::http::{HeaderValue, Method};
use axum::routing::get;
use axum::Router;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::SharedState;

pub fn router(state: SharedState) -> Router {
    let oidc = Router::new()
        .route("/.well-known/openid-configuration", get(discovery::handler))
        .route("/jwks", get(jwks::handler))
        .route("/authorize", get(authorize::get).post(authorize::post))
        .route("/health", get(health::handler));

    let path = state.config.issuer_path.clone();
    let app = if path.is_empty() {
        oidc
    } else {
        Router::new()
            .nest(&path, oidc)
            .route("/health", get(health::handler))
    };

    app.layer(cors(&state.config.cors_allowed_origins))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn cors(origins: &[String]) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);
    if origins.iter().any(|o| o == "*") {
        layer.allow_origin(Any)
    } else {
        let list: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse::<HeaderValue>().ok())
            .collect();
        layer.allow_origin(AllowOrigin::list(list))
    }
}
