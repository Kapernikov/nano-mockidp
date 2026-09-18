use nano_mockidp::{build, spawn_sweeper, Config};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.log_level))
        .init();
    let port = config.port;
    let (state, router) = match build(config) {
        Ok(x) => x,
        Err(e) => {
            tracing::error!("startup error: {e}");
            std::process::exit(2);
        }
    };
    tracing::info!(
        kid = %state.key.kid,
        key_source = %state.key.source,
        issuer = %state.issuer(),
        strict = state.config.strict,
        "nano-mockidp starting"
    );
    spawn_sweeper(state.clone());
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind port {port}: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(port, "listening");
    if let Err(e) = axum::serve(listener, router).await {
        tracing::error!("server error: {e}");
    }
}
