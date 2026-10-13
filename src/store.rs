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
    /// Login session id, minted when the login form is submitted.
    pub sid: String,
    pub expires_in: Option<u64>,
    /// Upstream `sub` of the tester who passed the gate.
    pub upstream_sub: Option<String>,
    /// Upstream `email` of that tester, if the upstream gave one.
    pub upstream_email: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshEntry {
    pub client_id: String,
    pub scope: Option<String>,
    /// Audience the original grant resolved to (None = client_id).
    pub audience: Option<Value>,
    pub claims: Claims,
    pub auth_time: u64,
    /// Login session id (`sid`); kept across rotation. `end_session` ends one sid.
    pub sid: String,
    pub expires_in: Option<u64>,
    /// Granted with `offline_access`: survives logout (`end_session`), like Keycloak.
    pub offline: bool,
    /// Upstream `sub` of the tester who passed the gate.
    pub upstream_sub: Option<String>,
    /// Upstream `email` of that tester, if the upstream gave one.
    pub upstream_email: Option<String>,
    /// When this token (and the tokens issued with it) was minted, unix seconds.
    pub issued_at: u64,
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

/// One live login (`sid`), as listed by `/admin/sessions`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Session {
    pub sid: String,
    /// Persona `sub`.
    pub sub: Option<String>,
    pub client_id: String,
    pub upstream_sub: Option<String>,
    pub upstream_email: Option<String>,
    pub auth_time: u64,
    /// Last time tokens were issued for this login (code exchange or refresh).
    pub last_issued_at: u64,
    /// When the login's last refresh token expires, unless refreshed again.
    pub expires_at: u64,
    pub offline: bool,
    pub refresh_tokens: usize,
}

#[derive(Default)]
pub struct Store {
    pub pending: HashMap<String, Expiring<AuthRequest>>,
    pub codes: HashMap<String, Expiring<CodeEntry>>,
    pub refresh: HashMap<String, Expiring<RefreshEntry>>,
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

    /// Drop the online refresh tokens of one login session (`sid`) of `client_id`.
    pub fn revoke_session(&mut self, sid: &str, client_id: &str) -> usize {
        let before = self.refresh.len();
        self.refresh.retain(|_, e| {
            !(e.value.sid == sid && e.value.client_id == client_id && !e.value.offline)
        });
        before - self.refresh.len()
    }

    /// Drop every refresh token, online and offline, of one login session (`sid`).
    pub fn revoke_sid(&mut self, sid: &str) -> usize {
        let before = self.refresh.len();
        self.refresh.retain(|_, e| e.value.sid != sid);
        before - self.refresh.len()
    }

    /// Live logins: the live refresh tokens grouped by `sid`, most recently active first.
    pub fn sessions(&self) -> Vec<Session> {
        let now = SystemTime::now();
        let mut by_sid: HashMap<&str, Session> = HashMap::new();
        for e in self.refresh.values().filter(|e| !e.is_expired(now)) {
            let r = &e.value;
            let expires_at = unix_secs(e.expires_at);
            let s = by_sid.entry(&r.sid).or_insert_with(|| Session {
                sid: r.sid.clone(),
                sub: sub_of(&r.claims).map(str::to_string),
                client_id: r.client_id.clone(),
                upstream_sub: r.upstream_sub.clone(),
                upstream_email: r.upstream_email.clone(),
                auth_time: r.auth_time,
                last_issued_at: r.issued_at,
                expires_at,
                offline: r.offline,
                refresh_tokens: 0,
            });
            s.last_issued_at = s.last_issued_at.max(r.issued_at);
            s.expires_at = s.expires_at.max(expires_at);
            s.offline |= r.offline;
            s.refresh_tokens += 1;
        }
        let mut v: Vec<Session> = by_sid.into_values().collect();
        v.sort_by(|a, b| {
            b.last_issued_at
                .cmp(&a.last_issued_at)
                .then(a.sid.cmp(&b.sid))
        });
        v
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
    unix_secs(SystemTime::now())
}

pub fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
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
            sid: "s".into(),
            expires_in: None,
            upstream_sub: None,
            upstream_email: None,
        };
        s.codes.insert("code".into(), Expiring::new(entry, 60));
        assert!(s.take_code("code").is_some());
        assert!(s.take_code("code").is_none());
    }

    fn refresh_for(sub: &str, client: &str, offline: bool) -> Expiring<RefreshEntry> {
        refresh_in(sub, client, offline, "s")
    }

    fn refresh_in(sub: &str, client: &str, offline: bool, sid: &str) -> Expiring<RefreshEntry> {
        let mut claims = Claims::new();
        claims.insert("sub".into(), Value::from(sub));
        Expiring::new(
            RefreshEntry {
                client_id: client.into(),
                scope: None,
                audience: None,
                claims,
                auth_time: 0,
                sid: sid.into(),
                expires_in: None,
                offline,
                upstream_sub: None,
                upstream_email: None,
                issued_at: 0,
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
    fn revoke_session_filters_by_sid_and_client() {
        let mut s = Store::default();
        s.refresh
            .insert("1".into(), refresh_in("alice", "a", false, "s1"));
        s.refresh
            .insert("2".into(), refresh_in("alice", "a", false, "s2"));
        s.refresh
            .insert("3".into(), refresh_in("alice", "b", false, "s1"));
        s.refresh
            .insert("4".into(), refresh_in("alice", "a", true, "s1"));
        assert_eq!(s.revoke_session("s1", "a"), 1);
        assert!(!s.refresh.contains_key("1"));
        assert_eq!(s.refresh.len(), 3);
    }

    #[test]
    fn sessions_group_by_sid_and_revoke_sid_drops_all() {
        let mut s = Store::default();
        s.refresh
            .insert("1".into(), refresh_in("alice", "a", false, "s1"));
        let mut t = refresh_in("alice", "a", true, "s1");
        t.value.issued_at = 50;
        t.value.upstream_email = Some("frank@x".into());
        s.refresh.insert("2".into(), t);
        let mut t = refresh_in("bob", "b", false, "s2");
        t.value.issued_at = 10;
        s.refresh.insert("3".into(), t);
        s.refresh.insert(
            "4".into(),
            Expiring::new(refresh_in("eve", "a", false, "s3").value, 0),
        );
        let v = s.sessions();
        assert_eq!(v.len(), 2, "expired s3 not listed");
        assert_eq!(v[0].sid, "s1");
        assert_eq!(v[0].refresh_tokens, 2);
        assert!(v[0].offline);
        assert_eq!(v[0].last_issued_at, 50);
        assert_eq!(v[1].sub.as_deref(), Some("bob"));
        assert_eq!(s.revoke_sid("s1"), 2, "online and offline");
        assert_eq!(s.revoke_sid("s1"), 0);
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
