use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, Header, Validation};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::keys::SigningKey;
use crate::store::{now_secs, random_token, Claims};

pub struct Issuer<'a> {
    pub key: &'a SigningKey,
    pub issuer: &'a str,
    pub access_ttl: u64,
    pub id_ttl: u64,
}

pub struct IssueParams {
    pub client_id: String,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub claims: Claims,
    pub auth_time: u64,
    pub expires_in: Option<u64>,
    pub with_id_token: bool,
}

pub struct TokenSet {
    pub access_token: String,
    pub id_token: Option<String>,
    pub expires_in: u64,
}

/// Claims the user may not override.
const PROTECTED: &[&str] = &["iss", "exp", "iat", "jti"];

/// Merge user-supplied claims over the base claims. User wins except for PROTECTED keys.
pub fn merge_claims(mut base: Claims, user: Claims) -> Claims {
    for (k, v) in user {
        if PROTECTED.contains(&k.as_str()) {
            continue;
        }
        base.insert(k, v);
    }
    base
}

pub fn pkce_verify(verifier: &str, challenge: &str) -> bool {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == challenge
}

fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

impl<'a> Issuer<'a> {
    pub fn issue(&self, p: IssueParams) -> TokenSet {
        let now = now_secs();
        let access_ttl = p.expires_in.unwrap_or(self.access_ttl);
        let id_ttl = p.expires_in.unwrap_or(self.id_ttl);

        let mut base = Claims::new();
        base.insert("sub".into(), json!(p.client_id));
        base.insert("aud".into(), json!(p.client_id));
        base.insert("azp".into(), json!(p.client_id));
        base.insert("auth_time".into(), json!(p.auth_time));
        if let Some(scope) = &p.scope {
            base.insert("scope".into(), json!(scope));
        }
        let mut common = merge_claims(base, p.claims);
        common.insert("iss".into(), json!(self.issuer));
        common.insert("iat".into(), json!(now));

        let mut access = common.clone();
        access.insert("exp".into(), json!(now + access_ttl));
        access.insert("jti".into(), json!(random_token()));
        let access_token = self.sign(&access, "at+jwt");

        let id_token = p.with_id_token.then(|| {
            let mut id = common;
            id.insert("exp".into(), json!(now + id_ttl));
            id.insert("jti".into(), json!(random_token()));
            id.insert("at_hash".into(), json!(at_hash(&access_token)));
            if let Some(nonce) = &p.nonce {
                id.insert("nonce".into(), json!(nonce));
            }
            self.sign(&id, "JWT")
        });

        TokenSet {
            access_token,
            id_token,
            expires_in: access_ttl,
        }
    }

    fn sign(&self, claims: &Claims, typ: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key.kid.clone());
        header.typ = Some(typ.to_string());
        jsonwebtoken::encode(&header, &Value::Object(claims.clone()), &self.key.encoding)
            .expect("jwt sign")
    }
}

/// How to check the `iss` claim when verifying a token.
#[derive(Debug, Clone, Copy)]
pub enum IssuerCheck<'a> {
    /// `iss` must equal this string.
    Exact(&'a str),
    /// `iss` may have any scheme/host, but its path must equal this issuer path
    /// (used with `ISSUER_FROM_REQUEST_HOST`).
    PathOnly(&'a str),
}

/// Verify signature, `exp` and `iss` of a token issued by this server. Returns the claims.
pub fn verify(key: &SigningKey, issuer: IssuerCheck<'_>, token: &str) -> Result<Claims, String> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.leeway = 0;
    match issuer {
        IssuerCheck::Exact(iss) => validation.set_issuer(&[iss]),
        IssuerCheck::PathOnly(_) => {
            validation.required_spec_claims.remove("iss");
        }
    }
    let data = jsonwebtoken::decode::<Value>(token, &key.decoding, &validation)
        .map_err(|e| e.to_string())?;
    let claims = match data.claims {
        Value::Object(m) => m,
        _ => return Err("claims are not an object".into()),
    };
    if let IssuerCheck::PathOnly(path) = issuer {
        let iss = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or("missing iss claim")?;
        let url = url::Url::parse(iss).map_err(|e| format!("iss is not a URL: {e}"))?;
        if url.path().trim_end_matches('/') != path {
            return Err(format!(
                "iss path {:?} does not match issuer path {path:?}",
                url.path()
            ));
        }
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_seed("test")
    }

    fn decode_unverified(token: &str) -> (Value, Value) {
        let parts: Vec<&str> = token.split('.').collect();
        let h = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let c = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        (h, c)
    }

    #[test]
    fn pkce_known_vector() {
        assert!(pkce_verify(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_verify(
            "wrong",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn merge_precedence() {
        let mut base = Claims::new();
        base.insert("sub".into(), json!("client"));
        base.insert("aud".into(), json!("client"));
        let mut user = Claims::new();
        user.insert("sub".into(), json!("alice"));
        user.insert("iss".into(), json!("evil"));
        user.insert("email".into(), json!("a@b"));
        let m = merge_claims(base, user);
        assert_eq!(m["sub"], "alice");
        assert_eq!(m["aud"], "client");
        assert_eq!(m["email"], "a@b");
        assert!(!m.contains_key("iss"));
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let k = key();
        let iss = Issuer {
            key: &k,
            issuer: "http://issuer/oidc",
            access_ttl: 100,
            id_ttl: 200,
        };
        let mut claims = Claims::new();
        claims.insert("sub".into(), json!("alice"));
        claims.insert("email".into(), json!("a@b"));
        let set = iss.issue(IssueParams {
            client_id: "app".into(),
            scope: Some("openid".into()),
            nonce: Some("n1".into()),
            claims,
            auth_time: 42,
            expires_in: None,
            with_id_token: true,
        });
        let access = verify(
            &k,
            IssuerCheck::Exact("http://issuer/oidc"),
            &set.access_token,
        )
        .unwrap();
        assert_eq!(access["iss"], "http://issuer/oidc");
        assert_eq!(access["sub"], "alice");
        assert_eq!(access["aud"], "app");
        assert_eq!(access["azp"], "app");
        assert_eq!(access["email"], "a@b");
        assert_eq!(access["auth_time"], 42);
        assert_eq!(access["scope"], "openid");
        assert!(!access.contains_key("nonce"));
        assert_eq!(set.expires_in, 100);

        let (h, _) = decode_unverified(&set.access_token);
        assert_eq!(h["typ"], "at+jwt");
        assert_eq!(h["kid"], k.kid);

        let id = set.id_token.unwrap();
        let idc = verify(&k, IssuerCheck::Exact("http://issuer/oidc"), &id).unwrap();
        assert_eq!(idc["nonce"], "n1");
        assert_eq!(idc["at_hash"], at_hash(&set.access_token));
        let (h, _) = decode_unverified(&id);
        assert_eq!(h["typ"], "JWT");

        assert!(verify(&k, IssuerCheck::Exact("http://other"), &set.access_token).is_err());
        assert!(verify(
            &SigningKey::from_seed("other"),
            IssuerCheck::Exact("http://issuer/oidc"),
            &set.access_token
        )
        .is_err());
        // path-only: any host with the same path is fine, other path is not
        assert!(verify(&k, IssuerCheck::PathOnly("/oidc"), &set.access_token).is_ok());
        assert!(verify(&k, IssuerCheck::PathOnly("/other"), &set.access_token).is_err());
        assert!(verify(&k, IssuerCheck::PathOnly(""), &set.access_token).is_err());
    }

    #[test]
    fn no_id_token_when_disabled() {
        let k = key();
        let iss = Issuer {
            key: &k,
            issuer: "i",
            access_ttl: 10,
            id_ttl: 10,
        };
        let set = iss.issue(IssueParams {
            client_id: "app".into(),
            scope: None,
            nonce: None,
            claims: Claims::new(),
            auth_time: 0,
            expires_in: Some(5),
            with_id_token: false,
        });
        assert!(set.id_token.is_none());
        assert_eq!(set.expires_in, 5);
    }
}
