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
    assert_eq!(
        d["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(d["issuer"], s.issuer);
    assert_eq!(d["token_endpoint"], format!("{}/token", s.base));
    assert_eq!(
        d["authorization_endpoint"],
        format!("{}/authorize", s.issuer)
    );
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
    assert_eq!(
        d["authorization_endpoint"],
        "http://public.example/oidc/authorize"
    );
    assert_eq!(
        d["end_session_endpoint"],
        "http://public.example/oidc/end_session"
    );
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
    let j: Value = s
        .client
        .get(s.url("/jwks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys = j["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "RSA");
    assert!(keys[0]["kid"].as_str().unwrap().len() == 16);
}

#[tokio::test]
async fn health_root_and_under_path() {
    let s = spawn(&[("ISSUER_URL", "http://localhost/oidc")]).await;
    assert_eq!(
        s.client
            .get(format!("{}/health", s.root))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        s.client
            .get(s.url("/health"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    // no double-mounting: unknown path 404
    assert_eq!(
        s.client
            .get(format!("{}/jwks", s.root))
            .send()
            .await
            .unwrap()
            .status(),
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
    assert_eq!(
        query_param(loc, "error").unwrap(),
        "unsupported_response_type"
    );
    assert_eq!(query_param(loc, "state").unwrap(), "st1");
}

#[tokio::test]
async fn authorize_get_missing_client_id_is_400_html() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .get(format!(
            "{}?response_type=code&redirect_uri={}",
            s.url("/authorize"),
            urlenc(CB)
        ))
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
        .get(authz_url(
            &s,
            "&code_challenge=x&code_challenge_method=plain",
        ))
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
    std::fs::write(
        &path,
        "<form method=post><input name=username></form><!--custom-->",
    )
    .unwrap();
    let s = spawn(&[("LOGIN_PAGE_PATH", path.to_str().unwrap())]).await;
    let body = s
        .client
        .get(authz_url(&s, ""))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<!--custom-->"));
    assert!(!body.contains("Kapernikov"));
    // edited while running → picked up
    std::fs::write(&path, "<!--v2-->").unwrap();
    let body = s
        .client
        .get(authz_url(&s, ""))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<!--v2-->"));
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- token flows ----------

/// Run GET+POST authorize and return the code.
async fn get_code(s: &TestServer, extra: &str, form: &[(&str, &str)]) -> String {
    let r = s
        .client
        .post(authz_url(s, extra))
        .form(form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND, "{}", r.text().await.unwrap());
    let loc = r.headers()["location"].to_str().unwrap();
    query_param(loc, "code").expect("code in redirect")
}

async fn post_token(s: &TestServer, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let r = s
        .client
        .post(s.url("/token"))
        .form(form)
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap())
}

async fn login_and_exchange(s: &TestServer) -> Value {
    let (verifier, challenge) = pkce_pair();
    let code = get_code(
        s,
        &format!("&code_challenge={challenge}&code_challenge_method=S256"),
        &[
            ("username", "alice"),
            ("claims", r#"{"email":"a@b","roles":["admin"]}"#),
        ],
    )
    .await;
    let (status, body) = post_token(
        s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "app"),
            ("client_secret", "whatever"),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn full_pkce_flow() {
    let s = spawn(&[("SIGNING_KEY_SEED", "flow")]).await;
    let body = login_and_exchange(&s).await;
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(body["scope"], "openid email");
    assert!(body["refresh_token"].as_str().unwrap().len() > 20);

    // verify id_token against JWKS
    let jwks: Value = s
        .client
        .get(s.url("/jwks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let k = &jwks["keys"][0];
    let (h, _) = decode_jwt_unverified(body["id_token"].as_str().unwrap());
    assert_eq!(h["kid"], k["kid"]);
    assert_eq!(h["alg"], "RS256");
    let dk = jsonwebtoken::DecodingKey::from_rsa_components(
        k["n"].as_str().unwrap(),
        k["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    v.set_audience(&["app"]);
    v.set_issuer(&[&s.issuer]);
    let id = jsonwebtoken::decode::<Value>(body["id_token"].as_str().unwrap(), &dk, &v)
        .unwrap()
        .claims;
    assert_eq!(id["iss"], s.issuer);
    assert_eq!(id["sub"], "alice");
    assert_eq!(id["aud"], "app");
    assert_eq!(id["nonce"], "n1");
    assert_eq!(id["email"], "a@b");
    assert_eq!(id["roles"], serde_json::json!(["admin"]));
    assert!(id["at_hash"].is_string());
    assert!(id["auth_time"].is_u64());

    let access = jsonwebtoken::decode::<Value>(body["access_token"].as_str().unwrap(), &dk, &v)
        .unwrap()
        .claims;
    assert_eq!(access["sub"], "alice");
    assert_eq!(access["email"], "a@b");
    let (h, _) = decode_jwt_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(h["typ"], "at+jwt");
}

#[tokio::test]
async fn claims_override_sub_and_expires_in() {
    let s = spawn(&[]).await;
    let code = get_code(
        &s,
        "",
        &[
            ("username", "alice"),
            ("claims", r#"{"sub":"bob"}"#),
            ("expires_in", "42"),
        ],
    )
    .await;
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "app"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["expires_in"], 42);
    let (_, c) = decode_jwt_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(c["sub"], "bob");
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 42);
}

#[tokio::test]
async fn wrong_verifier_rejected() {
    let s = spawn(&[]).await;
    let (_, challenge) = pkce_pair();
    let code = get_code(
        &s,
        &format!("&code_challenge={challenge}&code_challenge_method=S256"),
        &[("username", "a")],
    )
    .await;
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "app"),
            ("code_verifier", "nope"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn missing_verifier_rejected() {
    let s = spawn(&[]).await;
    let (_, challenge) = pkce_pair();
    let code = get_code(
        &s,
        &format!("&code_challenge={challenge}&code_challenge_method=S256"),
        &[("username", "a")],
    )
    .await;
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "app"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn code_reuse_rejected() {
    let s = spawn(&[]).await;
    let code = get_code(&s, "", &[("username", "a")]).await;
    let f = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", CB),
        ("client_id", "app"),
    ];
    assert_eq!(post_token(&s, &f).await.0, StatusCode::OK);
    let (status, body) = post_token(&s, &f).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn redirect_uri_and_client_mismatch_rejected() {
    let s = spawn(&[]).await;
    let code = get_code(&s, "", &[("username", "a")]).await;
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://other/cb"),
            ("client_id", "app"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    let code = get_code(&s, "", &[("username", "a")]).await;
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "other-app"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_rotates_and_preserves_claims() {
    let s = spawn(&[]).await;
    let first = login_and_exchange(&s).await;
    let rt = first["refresh_token"].as_str().unwrap();
    let (status, second) = post_token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", "app"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_ne!(second["refresh_token"], first["refresh_token"]);
    assert_ne!(second["access_token"], first["access_token"]);
    assert!(second["id_token"].is_string());
    let (_, c) = decode_jwt_unverified(second["access_token"].as_str().unwrap());
    assert_eq!(c["email"], "a@b");
    assert_eq!(c["sub"], "alice");
    assert_eq!(c["aud"], "app");
    // old refresh token rejected
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", "app"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    // new one works
    let rt2 = second["refresh_token"].as_str().unwrap();
    let (status, _) = post_token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt2),
            ("client_id", "app"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn client_credentials() {
    let s = spawn(&[]).await;
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "svc"),
            ("client_secret", "x"),
            ("scope", "read"),
            ("audience", "api"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["id_token"].is_null());
    assert!(body["refresh_token"].is_null());
    let (_, c) = decode_jwt_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(c["sub"], "svc");
    assert_eq!(c["aud"], "api");
    assert_eq!(c["scope"], "read");
}

#[tokio::test]
async fn basic_auth_accepted() {
    let s = spawn(&[]).await;
    let code = get_code(&s, "", &[("username", "a")]).await;
    let r = s
        .client
        .post(s.url("/token"))
        .basic_auth("app", Some("secret"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", CB),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn unsupported_grant_and_missing_client() {
    let s = spawn(&[]).await;
    let (status, body) = post_token(&s, &[("grant_type", "password"), ("client_id", "app")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported_grant_type");
    let (status, body) = post_token(&s, &[("grant_type", "client_credentials")]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
}

// ---------- strict mode ----------

#[tokio::test]
async fn strict_mode() {
    let s = spawn(&[
        ("STRICT", "true"),
        ("CLIENTS", r#"[{"client_id":"app","client_secret":"s3cret","redirect_uris":["http://app.example/cb"]}]"#),
    ])
    .await;

    // unknown client → 400 html
    let u = authz_url(&s, "").replace("client_id=app", "client_id=nope");
    assert_eq!(
        s.client.get(u).send().await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    // unregistered redirect → 400 html
    let u = authz_url(&s, "").replace(&urlenc(CB), &urlenc("http://evil/cb"));
    assert_eq!(
        s.client.get(u).send().await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    // valid request renders login
    assert_eq!(
        s.client
            .get(authz_url(&s, ""))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // wrong secret on token → 401
    let code = get_code(&s, "", &[("username", "a")]).await;
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "app"),
            ("client_secret", "wrong"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");

    // correct secret works
    let code = get_code(&s, "", &[("username", "a")]).await;
    let (status, _) = post_token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "app"),
            ("client_secret", "s3cret"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // DCR public client: PKCE required, then full flow works
    let reg: Value = s
        .client
        .post(s.url("/register"))
        .json(&serde_json::json!({"redirect_uris":["http://spa/cb"],"token_endpoint_auth_method":"none","client_name":"spa"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cid = reg["client_id"].as_str().unwrap();
    assert!(reg["client_secret"].is_null());
    let base = format!(
        "{}?response_type=code&client_id={cid}&redirect_uri={}&state=x",
        s.url("/authorize"),
        urlenc("http://spa/cb")
    );
    // no PKCE → redirect error
    let r = s.client.get(&base).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    assert_eq!(
        query_param(r.headers()["location"].to_str().unwrap(), "error").unwrap(),
        "invalid_request"
    );
    // with PKCE
    let (verifier, challenge) = pkce_pair();
    let r = s
        .client
        .post(format!(
            "{base}&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .form(&[("username", "spa-user")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let code = query_param(r.headers()["location"].to_str().unwrap(), "code").unwrap();
    let (status, body) = post_token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://spa/cb"),
            ("client_id", cid),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// ---------- userinfo / introspect / end_session / register ----------

#[tokio::test]
async fn userinfo() {
    let s = spawn(&[]).await;
    let body = login_and_exchange(&s).await;
    let at = body["access_token"].as_str().unwrap();
    let r = s
        .client
        .get(s.url("/userinfo"))
        .bearer_auth(at)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let u: Value = r.json().await.unwrap();
    assert_eq!(u["sub"], "alice");
    assert_eq!(u["email"], "a@b");
    assert!(u["exp"].is_null());
    assert!(u["jti"].is_null());
    // POST works too
    assert_eq!(
        s.client
            .post(s.url("/userinfo"))
            .bearer_auth(at)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    // bad token
    let r = s
        .client
        .get(s.url("/userinfo"))
        .bearer_auth("garbage")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(r.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .contains("invalid_token"));
    assert_eq!(
        s.client
            .get(s.url("/userinfo"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn introspect() {
    let s = spawn(&[]).await;
    let body = login_and_exchange(&s).await;
    let at = body["access_token"].as_str().unwrap();
    let i: Value = s
        .client
        .post(s.url("/introspect"))
        .form(&[("token", at)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(i["active"], true);
    assert_eq!(i["sub"], "alice");
    assert_eq!(i["client_id"], "app");
    let i: Value = s
        .client
        .post(s.url("/introspect"))
        .form(&[("token", "garbage")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(i, serde_json::json!({"active": false}));
    let rt = body["refresh_token"].as_str().unwrap();
    let i: Value = s
        .client
        .post(s.url("/introspect"))
        .form(&[("token", rt)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(i["active"], true);
    assert_eq!(i["client_id"], "app");
    assert_eq!(i["sub"], "alice");
    assert_eq!(i["token_type"], "refresh_token");
}

#[tokio::test]
async fn end_session() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .get(format!(
            "{}?post_logout_redirect_uri={}&state=zz",
            s.url("/end_session"),
            urlenc("http://app/bye")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let loc = r.headers()["location"].to_str().unwrap();
    assert!(loc.starts_with("http://app/bye"));
    assert_eq!(query_param(loc, "state").unwrap(), "zz");
    let r = s.client.get(s.url("/end_session")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("Logged out"));
}

#[tokio::test]
async fn register() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .post(s.url("/register"))
        .json(&serde_json::json!({"redirect_uris":["http://a/cb"],"client_name":"thing"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let reg: Value = r.json().await.unwrap();
    assert!(reg["client_id"].as_str().unwrap().len() > 20);
    assert!(reg["client_secret"].as_str().unwrap().len() > 20);
    assert_eq!(reg["client_secret_expires_at"], 0);
    assert_eq!(reg["client_name"], "thing");
    assert_eq!(reg["redirect_uris"], serde_json::json!(["http://a/cb"]));
    assert_eq!(reg["response_types"], serde_json::json!(["code"]));
    assert_eq!(reg["token_endpoint_auth_method"], "client_secret_basic");
    // empty body allowed
    let r = s.client.post(s.url("/register")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
}
