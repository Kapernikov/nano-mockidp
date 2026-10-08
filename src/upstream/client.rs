//! The upstream OIDC provider: discovery, JWKS, code exchange and ID-token checks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::VerifyingKey;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

use crate::config::UpstreamConfig;
use crate::store::{now_secs, Claims};
use crate::token::{jws_header, verify_signature};

/// Clock skew tolerated on the upstream ID token's `exp`.
const LEEWAY: u64 = 60;

#[derive(Debug, Deserialize)]
struct Metadata {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

pub struct Upstream {
    pub cfg: UpstreamConfig,
    http: reqwest::Client,
    /// Discovery, cached after the first success.
    meta: Mutex<Option<Arc<Metadata>>>,
    /// JWKS RSA keys by `kid` ("" when the JWK has none).
    keys: Mutex<HashMap<String, VerifyingKey<Sha256>>>,
}

impl Upstream {
    /// Builds the HTTP client; does not contact the upstream.
    pub fn new(cfg: UpstreamConfig) -> Result<Upstream, String> {
        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &cfg.ca_path {
            let pem = std::fs::read(path)
                .map_err(|e| format!("UPSTREAM_CA_PATH: cannot read {}: {e}", path.display()))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| format!("UPSTREAM_CA_PATH: {e}"))?;
            if certs.is_empty() {
                return Err(format!(
                    "UPSTREAM_CA_PATH: no certificates in {}",
                    path.display()
                ));
            }
            for c in certs {
                b = b.add_root_certificate(c);
            }
        }
        let http = b
            .build()
            .map_err(|e| format!("upstream HTTP client: {e}"))?;
        Ok(Upstream {
            cfg,
            http,
            meta: Mutex::new(None),
            keys: Mutex::new(HashMap::new()),
        })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, String> {
        let r = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        if !r.status().is_success() {
            return Err(format!("GET {url}: HTTP {}", r.status()));
        }
        r.json().await.map_err(|e| format!("GET {url}: {e}"))
    }

    /// Discovery, fetched on first use; a failure is retried on the next call.
    async fn metadata(&self) -> Result<Arc<Metadata>, String> {
        let cached = self.meta.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(m) = cached {
            return Ok(m);
        }
        let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
        let m: Arc<Metadata> = Arc::new(self.get_json(&url).await?);
        *self.meta.lock().unwrap_or_else(|p| p.into_inner()) = Some(m.clone());
        Ok(m)
    }

    /// Where to send the browser to log in upstream.
    pub async fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: &str,
    ) -> Result<String, String> {
        let m = self.metadata().await?;
        let mut url = url::Url::parse(&m.authorization_endpoint)
            .map_err(|e| format!("upstream authorization_endpoint: {e}"))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &self.cfg.scope)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Redeem `code` at the upstream token endpoint; returns the `id_token`.
    pub async fn exchange(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<String, String> {
        let m = self.metadata().await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ];
        let mut req = self.http.post(&m.token_endpoint);
        match &self.cfg.client_secret {
            Some(secret) => req = req.basic_auth(&self.cfg.client_id, Some(secret)),
            None => form.push(("client_id", self.cfg.client_id.as_str())),
        }
        let r = req
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("POST {}: {e}", m.token_endpoint))?;
        let status = r.status();
        let body: Value = r
            .json()
            .await
            .map_err(|e| format!("upstream token response: {e}"))?;
        if !status.is_success() {
            return Err(format!("upstream token endpoint HTTP {status}: {body}"));
        }
        body.get("id_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "upstream token response has no id_token".to_string())
    }

    /// RS256 signature against the upstream JWKS, then `iss`, `aud`, `exp` and `nonce`.
    pub async fn verify_id_token(&self, id_token: &str, nonce: &str) -> Result<Claims, String> {
        let kid = jws_header(id_token)?
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_string);
        let key = self.key(kid.as_deref()).await?;
        let claims = verify_signature(&key, id_token)?;
        let iss = claims
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if iss.trim_end_matches('/') != self.cfg.issuer {
            return Err(format!("id_token iss {iss:?} is not {:?}", self.cfg.issuer));
        }
        let client_id = self.cfg.client_id.as_str();
        let aud_ok = match claims.get("aud") {
            Some(Value::String(a)) => a == client_id,
            Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(client_id)),
            _ => false,
        };
        if !aud_ok {
            return Err(format!("id_token aud does not contain {client_id:?}"));
        }
        let exp = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or("id_token has no exp")?;
        if exp + LEEWAY <= now_secs() {
            return Err("id_token expired".into());
        }
        if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
            return Err("id_token nonce mismatch".into());
        }
        Ok(claims)
    }

    /// The JWKS key for `kid`. An unknown `kid` refetches the JWKS once (key rotation).
    async fn key(&self, kid: Option<&str>) -> Result<VerifyingKey<Sha256>, String> {
        if let Some(k) = self.cached_key(kid) {
            return Ok(k);
        }
        let m = self.metadata().await?;
        let jwks: Value = self.get_json(&m.jwks_uri).await?;
        *self.keys.lock().unwrap_or_else(|p| p.into_inner()) = parse_jwks(&jwks);
        self.cached_key(kid)
            .ok_or_else(|| format!("no RS256 key {kid:?} in the upstream JWKS"))
    }

    fn cached_key(&self, kid: Option<&str>) -> Option<VerifyingKey<Sha256>> {
        let keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        match kid {
            Some(k) => keys.get(k).cloned(),
            None if keys.len() == 1 => keys.values().next().cloned(),
            None => None,
        }
    }
}

/// RSA signing keys of a JWKS by `kid`.
fn parse_jwks(jwks: &Value) -> HashMap<String, VerifyingKey<Sha256>> {
    let b64 = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
    };
    jwks.get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|k| k.get("kty").and_then(Value::as_str) == Some("RSA"))
        .filter(|k| {
            k.get("use")
                .and_then(Value::as_str)
                .is_none_or(|u| u == "sig")
        })
        .filter_map(|k| {
            let n = BigUint::from_bytes_be(&b64(k.get("n"))?);
            let e = BigUint::from_bytes_be(&b64(k.get("e"))?);
            let public = RsaPublicKey::new(n, e).ok()?;
            let kid = k
                .get("kid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            Some((kid, VerifyingKey::<Sha256>::new(public)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use crate::token::Issuer;

    #[test]
    fn jwks_keys_verify_our_own_tokens() {
        let k = SigningKey::from_seed("up");
        let keys = parse_jwks(&k.jwks());
        let verifier = keys.get(&k.kid).expect("kid from jwks");
        let set = Issuer {
            key: &k,
            issuer: "i",
            access_ttl: 60,
            id_ttl: 60,
            default_claims: &Claims::new(),
        }
        .issue(crate::token::IssueParams {
            client_id: "c".into(),
            audience: None,
            scope: None,
            nonce: None,
            claims: Claims::new(),
            auth_time: 0,
            expires_in: None,
            with_id_token: false,
        });
        assert_eq!(
            verify_signature(verifier, &set.access_token).unwrap()["sub"],
            "c"
        );
    }

    #[test]
    fn jwks_skips_non_rsa_and_encryption_keys() {
        let jwks = serde_json::json!({"keys": [
            {"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"}
        ]});
        assert!(parse_jwks(&jwks).is_empty());
    }

    #[test]
    fn unreadable_ca_bundle_is_a_config_error() {
        let cfg = UpstreamConfig {
            issuer: "https://idp.example".into(),
            client_id: "c".into(),
            client_secret: None,
            scope: "openid".into(),
            require_claim: None,
            session_ttl: 60,
            sub_token_claim: None,
            ca_path: Some("/nonexistent/ca.pem".into()),
        };
        assert!(Upstream::new(cfg)
            .err()
            .unwrap()
            .contains("UPSTREAM_CA_PATH"));
    }
}
