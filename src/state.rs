use std::sync::{Arc, Mutex, MutexGuard};

use crate::config::Config;
use crate::keys::SigningKey;
use crate::store::{Client, Store};
use crate::token::Issuer;

pub struct AppState {
    pub config: Config,
    pub key: SigningKey,
    pub store: Mutex<Store>,
    issuer_str: String,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(config: Config) -> Result<AppState, String> {
        let key = SigningKey::load(&config)?;
        let mut store = Store::default();
        for c in &config.clients {
            store.clients.insert(
                c.client_id.clone(),
                Client {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    redirect_uris: c.redirect_uris.clone(),
                },
            );
        }
        let issuer_str = config.issuer();
        Ok(AppState {
            config,
            key,
            store: Mutex::new(store),
            issuer_str,
        })
    }

    pub fn store(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn issuer(&self) -> &str {
        &self.issuer_str
    }

    pub fn token_issuer(&self) -> Issuer<'_> {
        Issuer {
            key: &self.key,
            issuer: &self.issuer_str,
            access_ttl: self.config.access_token_ttl,
            id_ttl: self.config.id_token_ttl,
        }
    }
}
