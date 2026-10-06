mod admin;
mod authorize;
mod discovery;
mod health;
mod introspect;
mod jwks;
mod register;
mod revoke;
mod session;
mod token;
mod userinfo;

use axum::http::{HeaderValue, Method};
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::SharedState;

pub fn router(state: SharedState) -> Router {
    let oidc = Router::new()
        .route("/.well-known/openid-configuration", get(discovery::handler))
        .route("/jwks", get(jwks::handler))
        .route("/authorize", get(authorize::get).post(authorize::post))
        .route("/token", post(token::handler))
        .route("/userinfo", get(userinfo::handler).post(userinfo::handler))
        .route("/introspect", post(introspect::handler))
        .route("/revoke", post(revoke::handler))
        .route("/end_session", get(session::handler))
        .route("/register", post(register::handler))
        .route("/health", get(health::handler));
    let oidc = if state.config.admin_token.is_some() {
        oidc.merge(admin_routes(state.clone()))
    } else {
        oidc
    };

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

fn admin_routes(state: SharedState) -> Router<SharedState> {
    Router::new()
        .route("/admin/subjects", get(admin::list))
        .route(
            "/admin/subjects/{sub}",
            get(admin::get).put(admin::put).delete(admin::delete),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            admin::require_admin,
        ))
}

fn cors(origins: &[String]) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
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
