mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::Value;

const CB: &str = "http://app.example/cb";

fn authz_url(s: &TestServer, extra: &str) -> String {
    format!(
        "{}?response_type=code&client_id=app&redirect_uri={}&state=st1&scope=openid%20email&nonce=n1{extra}",
        s.url("/authorize"),
        urlenc(CB)
    )
}

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ---------- discovery / jwks / health ----------

#[tokio::test]
async fn discovery_shape() {
    let s = spawn(&[]).await;
    let d: Value = s
        .client
        .get(s.url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(d["response_types_supported"], serde_json::json!(["code"]));
    assert_eq!(d["code_challenge_methods_supported"], serde_json::json!(["S256"]));
    assert_eq!(d["issuer"], s.issuer);
    assert_eq!(d["token_endpoint"], format!("{}/token", s.base));
    assert_eq!(d["authorization_endpoint"], format!("{}/authorize", s.issuer));
    assert!(d["grant_types_supported"]
        .as_array()
        .unwrap()
        .contains(&Value::from("refresh_token")));
}

#[tokio::test]
async fn discovery_host_derivation() {
    let s = spawn(&[("ISSUER_URL", "http://public.example/oidc")]).await;
    let d: Value = s
        .client
        .get(s.url("/.well-known/openid-configuration"))
        .header("Host", "backend:9")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(d["issuer"], "http://public.example/oidc");
    assert_eq!(d["authorization_endpoint"], "http://public.example/oidc/authorize");
    assert_eq!(d["end_session_endpoint"], "http://public.example/oidc/end_session");
    assert_eq!(d["jwks_uri"], "http://backend:9/oidc/jwks");
    assert_eq!(d["token_endpoint"], "http://backend:9/oidc/token");

    // forwarded headers win over Host
    let d: Value = s
        .client
        .get(s.url("/.well-known/openid-configuration"))
        .header("X-Forwarded-Proto", "https")
        .header("X-Forwarded-Host", "idp.test")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(d["jwks_uri"], "https://idp.test/oidc/jwks");
}

#[tokio::test]
async fn jwks_has_key() {
    let s = spawn(&[("SIGNING_KEY_SEED", "abc")]).await;
    let j: Value = s.client.get(s.url("/jwks")).send().await.unwrap().json().await.unwrap();
    let keys = j["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "RSA");
    assert!(keys[0]["kid"].as_str().unwrap().len() == 16);
}

#[tokio::test]
async fn health_root_and_under_path() {
    let s = spawn(&[("ISSUER_URL", "http://localhost/oidc")]).await;
    assert_eq!(
        s.client.get(format!("{}/health", s.root)).send().await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(s.client.get(s.url("/health")).send().await.unwrap().status(), StatusCode::OK);
    // no double-mounting: unknown path 404
    assert_eq!(
        s.client.get(format!("{}/jwks", s.root)).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

// ---------- authorize ----------

#[tokio::test]
async fn authorize_get_renders_login() {
    let s = spawn(&[]).await;
    let r = s.client.get(authz_url(&s, "")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.text().await.unwrap();
    assert!(body.contains("name=\"username\""));
    assert!(body.contains("name=\"claims\""));
    assert!(body.contains("Kapernikov"));
    assert!(body.contains("method=\"post\""));
}

#[tokio::test]
async fn authorize_get_rejects_wrong_response_type() {
    let s = spawn(&[]).await;
    let u = authz_url(&s, "").replace("response_type=code", "response_type=token");
    let r = s.client.get(u).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let loc = r.headers()["location"].to_str().unwrap();
    assert!(loc.starts_with(CB));
    assert_eq!(query_param(loc, "error").unwrap(), "unsupported_response_type");
    assert_eq!(query_param(loc, "state").unwrap(), "st1");
}

#[tokio::test]
async fn authorize_get_missing_client_id_is_400_html() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .get(format!("{}?response_type=code&redirect_uri={}", s.url("/authorize"), urlenc(CB)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(r.text().await.unwrap().contains("client_id"));
}

#[tokio::test]
async fn authorize_rejects_plain_pkce_method() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .get(authz_url(&s, "&code_challenge=x&code_challenge_method=plain"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let loc = r.headers()["location"].to_str().unwrap();
    assert_eq!(query_param(loc, "error").unwrap(), "invalid_request");
}

#[tokio::test]
async fn authorize_post_issues_code() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .post(authz_url(&s, ""))
        .form(&[("username", "alice"), ("claims", r#"{"email":"a@b"}"#)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let loc = r.headers()["location"].to_str().unwrap();
    assert!(loc.starts_with(CB));
    assert!(query_param(loc, "code").unwrap().len() > 20);
    assert_eq!(query_param(loc, "state").unwrap(), "st1");
}

#[tokio::test]
async fn authorize_post_bad_claims_json() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .post(authz_url(&s, ""))
        .form(&[("username", "alice"), ("claims", "{not json")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = s
        .client
        .post(authz_url(&s, ""))
        .form(&[("username", ""), ("claims", "{}")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn custom_login_page() {
    let dir = std::env::temp_dir().join(format!("nano-mockidp-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("login.html");
    std::fs::write(&path, "<form method=post><input name=username></form><!--custom-->").unwrap();
    let s = spawn(&[("LOGIN_PAGE_PATH", path.to_str().unwrap())]).await;
    let body = s.client.get(authz_url(&s, "")).send().await.unwrap().text().await.unwrap();
    assert!(body.contains("<!--custom-->"));
    assert!(!body.contains("Kapernikov"));
    // edited while running → picked up
    std::fs::write(&path, "<!--v2-->").unwrap();
    let body = s.client.get(authz_url(&s, "")).send().await.unwrap().text().await.unwrap();
    assert!(body.contains("<!--v2-->"));
    std::fs::remove_dir_all(&dir).ok();
}
