//! Gate cookie and access check: pure functions, no I/O.

use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

use crate::store::Claims;

pub const COOKIE_NAME: &str = "nano_mockidp_gate";

/// Who passed the gate, and until when (unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSession {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub exp: u64,
}

/// HMAC key for gate cookies. Random per process: a restart sends testers upstream again.
pub struct GateKey([u8; 32]);

impl GateKey {
    pub fn random() -> GateKey {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        GateKey(k)
    }

    fn mac(&self) -> Hmac<Sha256> {
        Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts any key length")
    }

    /// `base64url(json) "." base64url(hmac)`.
    pub fn seal(&self, s: &GateSession) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(s).expect("json"));
        let mut mac = self.mac();
        mac.update(payload.as_bytes());
        let tag = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{payload}.{tag}")
    }

    /// The session in a cookie value, if we signed it and it hasn't expired at `now`.
    pub fn open(&self, value: &str, now: u64) -> Option<GateSession> {
        let (payload, tag) = value.split_once('.')?;
        let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
        let mut mac = self.mac();
        mac.update(payload.as_bytes());
        mac.verify_slice(&tag).ok()?;
        let s: GateSession = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        (s.exp > now).then_some(s)
    }
}

/// Our cookie's value from the request's `Cookie` headers.
pub fn cookie_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE_NAME)
        .map(|(_, v)| v)
}

/// `Set-Cookie` header value for a sealed session.
pub fn set_cookie(value: &str, path: &str, max_age: u64, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{COOKIE_NAME}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
}

/// The claim at a dotted `path` (`realm_access.roles` descends into objects).
pub fn claim_at<'a>(claims: &'a Claims, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let first = claims.get(parts.next()?)?;
    parts.try_fold(first, |v, p| v.get(p))
}

/// `UPSTREAM_REQUIRE_CLAIM`: the claim at `path` equals `value`, or contains it if it is an
/// array. Numbers and booleans compare by their JSON text; objects never match.
pub fn claim_allows(claims: &Claims, path: &str, value: &str) -> bool {
    // Numbers and booleans are compared by their JSON text, as documented above.
    #[allow(clippy::cmp_owned)]
    let matches = |v: &Value| match v {
        Value::String(s) => s == value,
        Value::Number(_) | Value::Bool(_) => v.to_string() == value,
        _ => false,
    };
    match claim_at(claims, path) {
        Some(Value::Array(a)) => a.iter().any(matches),
        Some(v) => matches(v),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session(exp: u64) -> GateSession {
        GateSession {
            sub: "frank".into(),
            email: Some("f@x".into()),
            exp,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = GateKey::random();
        let v = k.seal(&session(100));
        assert_eq!(k.open(&v, 99), Some(session(100)));
    }

    #[test]
    fn open_rejects_expired_tampered_and_foreign() {
        let k = GateKey::random();
        let v = k.seal(&session(100));
        assert_eq!(k.open(&v, 100), None, "expired at exp");
        assert_eq!(GateKey::random().open(&v, 0), None, "other key (restart)");
        let (_, tag) = v.split_once('.').unwrap();
        let forged = format!(
            "{}.{tag}",
            URL_SAFE_NO_PAD.encode(br#"{"sub":"admin","exp":99999999999}"#)
        );
        assert_eq!(k.open(&forged, 0), None, "payload swapped");
        assert_eq!(k.open(&format!("{v}x"), 0), None, "tag changed");
        assert_eq!(k.open("garbage", 0), None);
        assert_eq!(k.open("a.b", 0), None);
    }

    #[test]
    fn cookie_value_finds_ours() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            "a=1; nano_mockidp_gate=abc.def; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&h), Some("abc.def"));
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, "a=1".parse().unwrap());
        h.append(header::COOKIE, "nano_mockidp_gate=x.y".parse().unwrap());
        assert_eq!(cookie_value(&h), Some("x.y"));
        assert_eq!(cookie_value(&HeaderMap::new()), None);
    }

    #[test]
    fn set_cookie_attributes() {
        assert_eq!(
            set_cookie("v", "/oidc", 60, true),
            "nano_mockidp_gate=v; Path=/oidc; Max-Age=60; HttpOnly; SameSite=Lax; Secure"
        );
        assert!(!set_cookie("v", "/", 60, false).contains("Secure"));
    }

    #[test]
    fn claim_check() {
        let c: Claims = serde_json::from_value(json!({
            "groups": ["devs", "testers"],
            "tier": "gold",
            "verified": true,
            "level": 3,
            "realm_access": {"roles": ["tester"]}
        }))
        .unwrap();
        assert!(claim_allows(&c, "groups", "testers"));
        assert!(!claim_allows(&c, "groups", "admins"));
        assert!(claim_allows(&c, "tier", "gold"));
        assert!(claim_allows(&c, "verified", "true"));
        assert!(claim_allows(&c, "level", "3"));
        assert!(claim_allows(&c, "realm_access.roles", "tester"));
        assert!(!claim_allows(&c, "realm_access.missing", "tester"));
        assert!(!claim_allows(&c, "missing", "x"));
        assert!(
            !claim_allows(&c, "realm_access", "tester"),
            "objects never match"
        );
        assert_eq!(claim_at(&c, "realm_access.roles"), Some(&json!(["tester"])));
    }
}
