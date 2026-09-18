use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde_json::{Map, Value};

pub type Claims = Map<String, Value>;

#[derive(Debug, Clone)]
pub struct Expiring<T> {
    pub value: T,
    pub expires_at: SystemTime,
}

impl<T> Expiring<T> {
    pub fn new(value: T, ttl_secs: u64) -> Self {
        Expiring {
            value,
            expires_at: SystemTime::now() + Duration::from_secs(ttl_secs),
        }
    }
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CodeEntry {
    pub req: AuthRequest,
    pub claims: Claims,
    pub auth_time: u64,
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RefreshEntry {
    pub client_id: String,
    pub scope: Option<String>,
    pub claims: Claims,
    pub auth_time: u64,
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
}

#[derive(Default)]
pub struct Store {
    pub pending: HashMap<String, Expiring<AuthRequest>>,
    pub codes: HashMap<String, Expiring<CodeEntry>>,
    pub refresh: HashMap<String, Expiring<RefreshEntry>>,
    pub clients: HashMap<String, Client>,
}

impl Store {
    pub fn sweep(&mut self, now: SystemTime) {
        self.pending.retain(|_, e| !e.is_expired(now));
        self.codes.retain(|_, e| !e.is_expired(now));
        self.refresh.retain(|_, e| !e.is_expired(now));
    }

    /// Remove and return an entry if present and not expired.
    pub fn take_code(&mut self, code: &str) -> Option<CodeEntry> {
        let e = self.codes.remove(code)?;
        (!e.is_expired(SystemTime::now())).then_some(e.value)
    }

    pub fn take_refresh(&mut self, token: &str) -> Option<RefreshEntry> {
        let e = self.refresh.remove(token)?;
        (!e.is_expired(SystemTime::now())).then_some(e.value)
    }

    pub fn peek_refresh(&self, token: &str) -> Option<&Expiring<RefreshEntry>> {
        self.refresh
            .get(token)
            .filter(|e| !e.is_expired(SystemTime::now()))
    }
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> AuthRequest {
        AuthRequest {
            client_id: "c".into(),
            redirect_uri: "http://x/cb".into(),
            state: None,
            scope: None,
            nonce: None,
            code_challenge: None,
        }
    }

    #[test]
    fn sweep_removes_expired() {
        let mut s = Store::default();
        s.pending.insert("a".into(), Expiring::new(req(), 0));
        s.pending.insert("b".into(), Expiring::new(req(), 100));
        s.sweep(SystemTime::now() + Duration::from_secs(1));
        assert!(!s.pending.contains_key("a"));
        assert!(s.pending.contains_key("b"));
    }

    #[test]
    fn take_code_is_single_use() {
        let mut s = Store::default();
        let entry = CodeEntry {
            req: req(),
            claims: Claims::new(),
            auth_time: 0,
            expires_in: None,
        };
        s.codes.insert("code".into(), Expiring::new(entry, 60));
        assert!(s.take_code("code").is_some());
        assert!(s.take_code("code").is_none());
    }

    #[test]
    fn random_token_is_43_chars_urlsafe() {
        let t = random_token();
        assert_eq!(t.len(), 43);
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(t, random_token());
    }
}
