//! Gate cookie and access check: pure functions, no I/O.

use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

use crate::store::Claims;

pub const COOKIE_NAME: &str = "nano_mockidp_gate";
/// Pre-login cookies are named this plus the first 12 characters of the upstream `state`.
pub const LOGIN_COOKIE_PREFIX: &str = "nano_mockidp_login_";

/// A payload sealed into a cookie by [`GateKey`].
pub trait Sealed: Serialize + DeserializeOwned {
    /// Mixed into the MAC, so a value sealed as one kind never opens as another.
    const KIND: &'static [u8];
    /// Expiry, unix seconds.
    fn exp(&self) -> u64;
}

/// Who passed the gate, and until when (unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSession {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub exp: u64,
}

impl Sealed for GateSession {
    const KIND: &'static [u8] = b"gate";
    fn exp(&self) -> u64 {
        self.exp
    }
}

/// A browser on its way through the upstream login (the pre-login cookie).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLogin {
    /// Upstream `state`; the callback's must equal it.
    pub state: String,
    pub nonce: String,
    /// PKCE verifier for the upstream code exchange.
    pub verifier: String,
    /// Path + query of the original `/authorize` request, to return to.
    pub return_to: String,
    pub exp: u64,
}

impl Sealed for PendingLogin {
    const KIND: &'static [u8] = b"login";
    fn exp(&self) -> u64 {
        self.exp
    }
}

/// HMAC key for gate cookies. Random per process: a restart sends testers upstream again.
pub struct GateKey([u8; 32]);

impl GateKey {
    pub fn random() -> GateKey {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        GateKey(k)
    }

    /// HMAC over `kind "\0" payload`.
    fn mac<T: Sealed>(&self, payload: &str) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(T::KIND);
        mac.update(b"\0");
        mac.update(payload.as_bytes());
        mac
    }

    /// `base64url(json) "." base64url(hmac)`.
    pub fn seal<T: Sealed>(&self, v: &T) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).expect("json"));
        let tag = URL_SAFE_NO_PAD.encode(self.mac::<T>(&payload).finalize().into_bytes());
        format!("{payload}.{tag}")
    }

    /// The `T` in a cookie value, if we sealed it as a `T` and it hasn't expired at `now`.
    pub fn open<T: Sealed>(&self, value: &str, now: u64) -> Option<T> {
        let (payload, tag) = value.split_once('.')?;
        let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
        self.mac::<T>(payload).verify_slice(&tag).ok()?;
        let v: T = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        (v.exp() > now).then_some(v)
    }
}

/// The pre-login cookie's name for an upstream `state`; None unless `state` is base64url
/// (ours always is), so a crafted `state` cannot shape a cookie name.
pub fn login_cookie_name(state: &str) -> Option<String> {
    let ok = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    (!state.is_empty() && state.chars().all(ok))
        .then(|| format!("{LOGIN_COOKIE_PREFIX}{}", &state[..state.len().min(12)]))
}

/// The value of cookie `name` from the request's `Cookie` headers.
pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// `Set-Cookie` header value for cookie `name` (`max_age` 0 clears it).
pub fn set_cookie(name: &str, value: &str, path: &str, max_age: u64, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
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
        let open = |k: &GateKey, v: &str, now| k.open::<GateSession>(v, now);
        assert_eq!(open(&k, &v, 100), None, "expired at exp");
        assert_eq!(open(&GateKey::random(), &v, 0), None, "other key (restart)");
        let (_, tag) = v.split_once('.').unwrap();
        let forged = format!(
            "{}.{tag}",
            URL_SAFE_NO_PAD.encode(br#"{"sub":"admin","exp":99999999999}"#)
        );
        assert_eq!(open(&k, &forged, 0), None, "payload swapped");
        assert_eq!(open(&k, &format!("{v}x"), 0), None, "tag changed");
        assert_eq!(open(&k, "garbage", 0), None);
        assert_eq!(open(&k, "a.b", 0), None);
    }

    fn pending(exp: u64) -> PendingLogin {
        PendingLogin {
            state: "st".into(),
            nonce: "n".into(),
            verifier: "v".into(),
            return_to: "/authorize?x=1".into(),
            exp,
        }
    }

    #[test]
    fn login_and_gate_cookies_are_not_interchangeable() {
        let k = GateKey::random();
        let login = k.seal(&pending(100));
        assert_eq!(k.open(&login, 0), Some(pending(100)));
        assert_eq!(k.open::<GateSession>(&login, 0), None, "login as gate");
        let gate = k.seal(&session(100));
        assert_eq!(k.open::<PendingLogin>(&gate, 0), None, "gate as login");
        assert_eq!(k.open::<PendingLogin>(&login, 100), None, "expired");
    }

    #[test]
    fn login_cookie_names() {
        assert_eq!(
            login_cookie_name("abcdefghijklmnop").as_deref(),
            Some("nano_mockidp_login_abcdefghijkl")
        );
        assert_eq!(
            login_cookie_name("a-_1").as_deref(),
            Some("nano_mockidp_login_a-_1")
        );
        assert_eq!(login_cookie_name(""), None);
        assert_eq!(login_cookie_name("a;Domain=x"), None);
        assert_eq!(login_cookie_name("é"), None);
    }

    #[test]
    fn cookie_value_finds_ours() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            "a=1; nano_mockidp_gate=abc.def; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&h, COOKIE_NAME), Some("abc.def"));
        assert_eq!(cookie_value(&h, "b"), Some("2"));
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, "a=1".parse().unwrap());
        h.append(header::COOKIE, "nano_mockidp_gate=x.y".parse().unwrap());
        assert_eq!(cookie_value(&h, COOKIE_NAME), Some("x.y"));
        assert_eq!(cookie_value(&HeaderMap::new(), COOKIE_NAME), None);
    }

    #[test]
    fn set_cookie_attributes() {
        assert_eq!(
            set_cookie(COOKIE_NAME, "v", "/oidc", 60, true),
            "nano_mockidp_gate=v; Path=/oidc; Max-Age=60; HttpOnly; SameSite=Lax; Secure"
        );
        assert!(!set_cookie(COOKIE_NAME, "v", "/", 60, false).contains("Secure"));
        assert_eq!(
            set_cookie("nano_mockidp_login_x", "", "/", 0, false),
            "nano_mockidp_login_x=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        );
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
