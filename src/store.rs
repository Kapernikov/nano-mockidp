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
    /// RFC 8707 `resource` values given on /authorize.
    pub resources: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CodeEntry {
    pub req: AuthRequest,
    pub claims: Claims,
    pub auth_time: u64,
    pub expires_in: Option<u64>,
    /// Upstream `sub` of the tester who passed the gate.
    pub upstream_sub: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshEntry {
    pub client_id: String,
    pub scope: Option<String>,
    /// Audience the original grant resolved to (None = client_id).
    pub audience: Option<Value>,
    pub claims: Claims,
    pub auth_time: u64,
    pub expires_in: Option<u64>,
    /// Granted with `offline_access`: survives logout (`end_session`), like Keycloak.
    pub offline: bool,
    /// Upstream `sub` of the tester who passed the gate.
    pub upstream_sub: Option<String>,
}

impl RefreshEntry {
    pub fn kind(&self) -> &'static str {
        if self.offline {
            "offline"
        } else {
            "online"
        }
    }
}

/// A browser on its way through the upstream login, keyed by the upstream `state`.
#[derive(Debug, Clone)]
pub struct UpstreamLogin {
    pub nonce: String,
    /// PKCE verifier for the upstream code exchange.
    pub verifier: String,
    /// Path + query of the original `/authorize` request, to return to.
    pub return_to: String,
}

/// Runtime state for a `sub`, set via `/admin/subjects/{sub}`.
#[derive(Debug, Clone, Default)]
pub struct Subject {
    /// Replaces the login-time claims on refresh. None → use the login snapshot.
    pub claims: Option<Claims>,
    /// Disabled subjects cannot log in, refresh, or pass introspection/userinfo.
    pub disabled: bool,
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
    pub upstream_pending: HashMap<String, Expiring<UpstreamLogin>>,
    pub clients: HashMap<String, Client>,
    pub subjects: HashMap<String, Subject>,
    /// `jti` of revoked access/ID tokens → their `exp` (unix seconds).
    pub revoked_jti: HashMap<String, u64>,
}

impl Store {
    pub fn sweep(&mut self, now: SystemTime) {
        self.pending.retain(|_, e| !e.is_expired(now));
        self.codes.retain(|_, e| !e.is_expired(now));
        self.refresh.retain(|_, e| !e.is_expired(now));
        self.upstream_pending.retain(|_, e| !e.is_expired(now));
        let secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.revoked_jti.retain(|_, exp| *exp > secs);
    }

    /// Remove and return an entry if present and not expired.
    pub fn take_code(&mut self, code: &str) -> Option<CodeEntry> {
        let e = self.codes.remove(code)?;
        (!e.is_expired(SystemTime::now())).then_some(e.value)
    }

    pub fn take_upstream_login(&mut self, state: &str) -> Option<UpstreamLogin> {
        let e = self.upstream_pending.remove(state)?;
        (!e.is_expired(SystemTime::now())).then_some(e.value)
    }

    pub fn take_refresh(&mut self, token: &str) -> Option<RefreshEntry> {
        let e = self.refresh.remove(token)?;
        (!e.is_expired(SystemTime::now())).then_some(e.value)
    }

    pub fn is_disabled(&self, sub: &str) -> bool {
        self.subjects.get(sub).is_some_and(|s| s.disabled)
    }

    /// True if `claims` belong to a disabled subject or carry a revoked `jti`.
    pub fn is_blocked(&self, claims: &Claims) -> bool {
        sub_of(claims).is_some_and(|s| self.is_disabled(s))
            || claims
                .get("jti")
                .and_then(Value::as_str)
                .is_some_and(|j| self.revoked_jti.contains_key(j))
    }

    /// Drop the refresh tokens of `sub`, optionally only those of `client_id` and/or only
    /// online ones. Returns how many were removed.
    pub fn revoke_refresh_for(
        &mut self,
        sub: &str,
        client_id: Option<&str>,
        online_only: bool,
    ) -> usize {
        let before = self.refresh.len();
        self.refresh.retain(|_, e| {
            !(sub_of(&e.value.claims) == Some(sub)
                && client_id.is_none_or(|c| c == e.value.client_id)
                && !(online_only && e.value.offline))
        });
        before - self.refresh.len()
    }

    /// Live refresh tokens of `sub` as (online, offline).
    pub fn count_refresh_for(&self, sub: &str) -> (usize, usize) {
        let now = SystemTime::now();
        self.refresh
            .values()
            .filter(|e| !e.is_expired(now) && sub_of(&e.value.claims) == Some(sub))
            .fold((0, 0), |(on, off), e| {
                if e.value.offline {
                    (on, off + 1)
                } else {
                    (on + 1, off)
                }
            })
    }

    pub fn peek_refresh(&self, token: &str) -> Option<&Expiring<RefreshEntry>> {
        self.refresh
            .get(token)
            .filter(|e| !e.is_expired(SystemTime::now()))
    }
}

pub fn sub_of(claims: &Claims) -> Option<&str> {
    claims.get("sub").and_then(Value::as_str)
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
            resources: Vec::new(),
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
            upstream_sub: None,
        };
        s.codes.insert("code".into(), Expiring::new(entry, 60));
        assert!(s.take_code("code").is_some());
        assert!(s.take_code("code").is_none());
    }

    fn refresh_for(sub: &str, client: &str, offline: bool) -> Expiring<RefreshEntry> {
        let mut claims = Claims::new();
        claims.insert("sub".into(), Value::from(sub));
        Expiring::new(
            RefreshEntry {
                client_id: client.into(),
                scope: None,
                audience: None,
                claims,
                auth_time: 0,
                expires_in: None,
                offline,
                upstream_sub: None,
            },
            60,
        )
    }

    #[test]
    fn revoke_refresh_for_filters_by_sub_and_client() {
        let mut s = Store::default();
        s.refresh
            .insert("1".into(), refresh_for("alice", "a", false));
        s.refresh
            .insert("2".into(), refresh_for("alice", "b", false));
        s.refresh.insert("3".into(), refresh_for("bob", "a", false));
        s.refresh
            .insert("4".into(), refresh_for("alice", "a", true));
        assert_eq!(s.count_refresh_for("alice"), (2, 1));
        assert_eq!(s.revoke_refresh_for("alice", Some("a"), true), 1);
        assert!(s.refresh.contains_key("2"));
        assert!(
            s.refresh.contains_key("4"),
            "offline survives online-only revocation"
        );
        assert_eq!(s.revoke_refresh_for("alice", None, false), 2);
        assert_eq!(s.refresh.len(), 1);
        assert!(s.refresh.contains_key("3"));
    }

    #[test]
    fn is_blocked_by_disabled_sub_or_revoked_jti() {
        let mut s = Store::default();
        let mut c = Claims::new();
        c.insert("sub".into(), Value::from("alice"));
        c.insert("jti".into(), Value::from("j1"));
        assert!(!s.is_blocked(&c));
        s.revoked_jti.insert("j1".into(), u64::MAX);
        assert!(s.is_blocked(&c));
        s.revoked_jti.clear();
        s.subjects.insert(
            "alice".into(),
            Subject {
                claims: None,
                disabled: true,
            },
        );
        assert!(s.is_blocked(&c));
    }

    #[test]
    fn random_token_is_43_chars_urlsafe() {
        let t = random_token();
        assert_eq!(t.len(), 43);
        assert!(t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(t, random_token());
    }
}
