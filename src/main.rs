mod config;
mod keys;

use config::Config;
use keys::SigningKey;
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
    let key = match SigningKey::load(&config) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("signing key error: {e}");
            std::process::exit(2);
        }
    };
    tracing::info!(kid = %key.kid, source = %key.source, issuer = %config.issuer(), "nano-mockidp starting");
    tracing::info!(port = config.port, "listening");
}
