#![cfg(feature = "upstream")]
mod common;

use std::collections::HashMap;

use common::*;
use nano_mockidp::upstream::Upstream;
use nano_mockidp::Config;
use serde_json::{json, Value};

fn upstream(issuer: &str, client_id: &str) -> Upstream {
    let m: HashMap<String, String> = [
        ("UPSTREAM_ISSUER", issuer),
        ("UPSTREAM_CLIENT_ID", client_id),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    Upstream::new(Config::from_map(&m).unwrap().upstream.unwrap()).unwrap()
}

/// An ID token from `a` for `client_id` via the password grant (no nonce).
async fn password_id_token(a: &TestServer, client_id: &str) -> String {
    let r: Value = a
        .client
        .post(a.url("/token"))
        .form(&[
            ("grant_type", "password"),
            ("client_id", client_id),
            ("username", "frank"),
            ("password", "x"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    r["id_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn code_exchange_and_id_token() {
    let a = spawn(&[]).await;
    let up = upstream(&a.issuer, "gate");
    let (verifier, challenge) = pkce_pair();
    let url = up
        .authorize_url("http://gated/cb", "st", "n1", &challenge)
        .await
        .unwrap();
    assert!(url.starts_with(&a.url("/authorize?")), "{url}");
    let r = a
        .client
        .post(&url)
        .form(&[
            ("username", "frank"),
            ("claims", r#"{"groups":["testers"]}"#),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    let loc = r.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(query_param(&loc, "state").as_deref(), Some("st"));
    let code = query_param(&loc, "code").unwrap();

    let id = up
        .exchange(&code, "http://gated/cb", &verifier)
        .await
        .unwrap();
    let claims = up.verify_id_token(&id, "n1").await.unwrap();
    assert_eq!(claims["sub"], "frank");
    assert_eq!(claims["groups"], json!(["testers"]));
    assert!(up
        .verify_id_token(&id, "other")
        .await
        .unwrap_err()
        .contains("nonce"));
}

#[tokio::test]
async fn id_token_for_another_client_is_rejected() {
    let a = spawn(&[]).await;
    let up = upstream(&a.issuer, "gate");
    let id = password_id_token(&a, "someone-else").await;
    assert!(up
        .verify_id_token(&id, "n")
        .await
        .unwrap_err()
        .contains("aud"));
}

#[tokio::test]
async fn id_token_from_another_issuer_is_rejected() {
    // same key on both, so only the iss check can tell them apart
    let a1 = spawn(&[("SIGNING_KEY_SEED", "shared")]).await;
    let a2 = spawn(&[("SIGNING_KEY_SEED", "shared")]).await;
    let up = upstream(&a1.issuer, "gate");
    let id = password_id_token(&a2, "gate").await;
    assert!(up
        .verify_id_token(&id, "n")
        .await
        .unwrap_err()
        .contains("iss"));
}

#[tokio::test]
async fn issuer_trailing_slash_is_tolerated() {
    let a = spawn(&[]).await;
    let up = upstream(&format!("{}/", a.issuer), "gate");
    let id = password_id_token(&a, "gate").await;
    // passes iss and aud; fails only on the nonce the password grant doesn't set
    assert!(up
        .verify_id_token(&id, "n")
        .await
        .unwrap_err()
        .contains("nonce"));
}

#[tokio::test]
async fn unreachable_upstream_is_an_error_not_a_panic() {
    let up = upstream("http://127.0.0.1:9", "gate");
    let err = up
        .authorize_url("http://x/cb", "s", "n", "c")
        .await
        .unwrap_err();
    assert!(err.contains("openid-configuration"), "{err}");
}
