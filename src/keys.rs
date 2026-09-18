use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::SeedableRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Random,
    Seed,
    Pem,
}

impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::Random => write!(f, "random"),
            KeySource::Seed => write!(f, "seed"),
            KeySource::Pem => write!(f, "pem"),
        }
    }
}

pub struct SigningKey {
    pub kid: String,
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    pub jwk: serde_json::Value,
    pub source: KeySource,
    private_pem: String,
}

const BITS: usize = 2048;

impl SigningKey {
    pub fn load(cfg: &Config) -> Result<SigningKey, String> {
        if let Some(path) = &cfg.signing_key_path {
            let pem = std::fs::read_to_string(path)
                .map_err(|e| format!("SIGNING_KEY_PATH: cannot read {}: {e}", path.display()))?;
            return SigningKey::from_pem(&pem);
        }
        if let Some(pem) = &cfg.signing_key_pem {
            return SigningKey::from_pem(pem);
        }
        if let Some(seed) = &cfg.signing_key_seed {
            return Ok(SigningKey::from_seed(seed));
        }
        Ok(SigningKey::random())
    }

    pub fn random() -> SigningKey {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), BITS).expect("rsa keygen");
        SigningKey::from_private(key, KeySource::Random)
    }

    pub fn from_seed(seed: &str) -> SigningKey {
        let seed_bytes: [u8; 32] = Sha256::digest(seed.as_bytes()).into();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed_bytes);
        let key = RsaPrivateKey::new(&mut rng, BITS).expect("rsa keygen");
        SigningKey::from_private(key, KeySource::Seed)
    }

    pub fn from_pem(pem: &str) -> Result<SigningKey, String> {
        let key = RsaPrivateKey::from_pkcs1_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
            .map_err(|e| format!("invalid RSA private key PEM: {e}"))?;
        Ok(SigningKey::from_private(key, KeySource::Pem))
    }

    fn from_private(key: RsaPrivateKey, source: KeySource) -> SigningKey {
        let private_pem = key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("pem encode")
            .to_string();
        let public = key.to_public_key();
        let der = public.to_public_key_der().expect("der encode");
        let digest = Sha256::digest(der.as_bytes());
        let kid: String = digest.iter().map(|b| format!("{b:02x}")).collect::<String>()[..16].to_string();
        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let encoding = EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("encoding key");
        let decoding = DecodingKey::from_rsa_components(&n, &e).expect("decoding key");
        let jwk = serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e,
        });
        SigningKey {
            kid,
            encoding,
            decoding,
            jwk,
            source,
            private_pem,
        }
    }

    pub fn to_pem(&self) -> &str {
        &self.private_pem
    }

    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({ "keys": [self.jwk] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_deterministic() {
        assert_eq!(SigningKey::from_seed("a").kid, SigningKey::from_seed("a").kid);
        assert_ne!(SigningKey::from_seed("a").kid, SigningKey::from_seed("b").kid);
    }

    #[test]
    fn random_differs() {
        assert_ne!(SigningKey::random().kid, SigningKey::random().kid);
    }

    #[test]
    fn pem_roundtrip() {
        let a = SigningKey::from_seed("a");
        let b = SigningKey::from_pem(a.to_pem()).unwrap();
        assert_eq!(a.kid, b.kid);
        assert_eq!(b.source, KeySource::Pem);
    }

    #[test]
    fn jwk_shape() {
        let k = SigningKey::from_seed("x");
        assert_eq!(k.jwk["kty"], "RSA");
        assert_eq!(k.jwk["alg"], "RS256");
        assert_eq!(k.jwk["use"], "sig");
        assert_eq!(k.jwk["kid"], k.kid);
        assert!(k.jwk["n"].as_str().unwrap().len() > 300);
        assert_eq!(k.jwk["e"], "AQAB");
        assert_eq!(k.jwks()["keys"].as_array().unwrap().len(), 1);
    }
}
