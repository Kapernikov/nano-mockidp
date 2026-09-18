use std::sync::{Arc, Mutex, MutexGuard};

use crate::config::Config;
use crate::keys::SigningKey;
use crate::store::{Client, Store};
use crate::token::{Issuer, IssuerCheck};
use crate::urls;

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

    /// The issuer to put in tokens for a request arriving at `request_base`.
    pub fn issuer_for(&self, request_base: &str) -> String {
        urls::issuer_for(&self.config, Some(request_base))
    }

    /// How incoming tokens' `iss` must be checked.
    pub fn issuer_check(&self) -> IssuerCheck<'_> {
        if self.config.issuer_from_request_host {
            IssuerCheck::PathOnly(&self.config.issuer_path)
        } else {
            IssuerCheck::Exact(&self.issuer_str)
        }
    }

    pub fn token_issuer<'a>(&'a self, issuer: &'a str) -> Issuer<'a> {
        Issuer {
            key: &self.key,
            issuer,
            access_ttl: self.config.access_token_ttl,
            id_ttl: self.config.id_token_ttl,
        }
    }
}
