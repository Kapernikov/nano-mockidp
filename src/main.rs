use nano_mockidp::{build, spawn_sweeper, Config};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

// A mock IdP has no use for a thread per core; one thread keeps the footprint minimal.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    // `Targets` understands the usual `info,tower_http=debug` syntax without pulling in regex.
    let filter: Targets = match config.log_level.parse() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("LOG_LEVEL: invalid filter {:?}: {e}", config.log_level);
            std::process::exit(2);
        }
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(false))
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
