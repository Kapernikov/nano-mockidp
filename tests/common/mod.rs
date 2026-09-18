#![allow(dead_code)]
use std::collections::HashMap;

use nano_mockidp::{build, Config};

pub struct TestServer {
    /// `http://127.0.0.1:port` — the root of the server.
    pub root: String,
    /// root + issuer path — where the OIDC endpoints live.
    pub base: String,
    /// The configured ISSUER_URL (value of `iss`).
    pub issuer: String,
    pub client: reqwest::Client,
}

/// Start the server in-process on an ephemeral port. `env` overrides config values.
/// Unless `ISSUER_URL` is given, it is set to `http://127.0.0.1:<port>`.
pub async fn spawn(env: &[(&str, &str)]) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = format!("http://127.0.0.1:{port}");
    let mut map: HashMap<String, String> =
        env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    map.entry("ISSUER_URL".into()).or_insert_with(|| root.clone());
    let config = Config::from_map(&map).unwrap();
    let issuer = config.issuer();
    let base = format!("{root}{}", config.issuer_path);
    let (_state, router) = build(config).unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    TestServer {
        root,
        base,
        issuer,
        client,
    }
}

impl TestServer {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

/// Extract a query parameter from a Location header value.
pub fn query_param(location: &str, name: &str) -> Option<String> {
    let url = url::Url::parse(location).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

pub fn pkce_pair() -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub fn decode_jwt_unverified(token: &str) -> (serde_json::Value, serde_json::Value) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "not a JWT: {token}");
    let h = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let c = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    (h, c)
}
