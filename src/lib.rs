pub mod config;
pub mod error;
pub mod keys;
pub mod login;
pub mod routes;
pub mod state;
pub mod store;
pub mod token;
pub mod urls;

pub use config::Config;
pub use state::{AppState, SharedState};

/// Build the shared state and the axum router from a config.
pub fn build(config: Config) -> Result<(SharedState, axum::Router), String> {
    let state = std::sync::Arc::new(AppState::new(config)?);
    let router = routes::router(state.clone());
    Ok((state, router))
}

/// Spawn the periodic sweep of expired store entries.
pub fn spawn_sweeper(state: SharedState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            state.store().sweep(std::time::SystemTime::now());
        }
    });
}
