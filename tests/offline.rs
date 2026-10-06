//! offline_access, revocation, admin subjects, end_session revocation.
mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

const CB: &str = "http://app.example/cb";
const ADMIN: &str = "admin-secret";

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn post_form(s: &TestServer, path: &str, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let r = s.client.post(s.url(path)).form(form).send().await.unwrap();
    let status = r.status();
    let text = r.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Log in through the form with `scope` and exchange the code.
async fn login(s: &TestServer, scope: &str, claims: &str) -> (StatusCode, Value) {
    let url = format!(
        "{}?response_type=code&client_id=app&redirect_uri={}&state=st&scope={}",
        s.url("/authorize"),
        urlenc(CB),
        urlenc(scope)
    );
    let r = s
        .client
        .post(url)
        .form(&[("username", "alice"), ("claims", claims)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let loc = r.headers()["location"].to_str().unwrap().to_string();
    let Some(code) = query_param(&loc, "code") else {
        return (StatusCode::FOUND, json!({ "redirect": loc }));
    };
    post_form(
        s,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "app"),
        ],
    )
    .await
}

async fn refresh(s: &TestServer, rt: &str) -> (StatusCode, Value) {
    post_form(
        s,
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", "app"),
        ],
    )
    .await
}

async fn introspect(s: &TestServer, token: &str) -> Value {
    post_form(s, "/introspect", &[("token", token)]).await.1
}

fn admin(s: &TestServer, method: reqwest::Method, sub: &str) -> reqwest::RequestBuilder {
    s.client
        .request(method, s.url(&format!("/admin/subjects/{sub}")))
        .bearer_auth(ADMIN)
}

// ---------- (a) offline_access ----------

#[tokio::test]
async fn refresh_token_type_follows_offline_access() {
    let s = spawn(&[]).await;
    let (st, body) = login(&s, "openid", "").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let online = body["refresh_token"]
        .as_str()
        .expect("online refresh token");
    let i = introspect(&s, online).await;
    assert_eq!(i["refresh_token_type"], "online", "{i}");

    let (_, body) = login(&s, "openid offline_access", "").await;
    let offline = body["refresh_token"]
        .as_str()
        .expect("offline refresh token");
    assert_eq!(
        introspect(&s, offline).await["refresh_token_type"],
        "offline"
    );

    // rotation keeps the type
    let (st, body) = refresh(&s, offline).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let rotated = body["refresh_token"].as_str().unwrap();
    assert_eq!(
        introspect(&s, rotated).await["refresh_token_type"],
        "offline"
    );

    // password grant follows the same rule
    for (scope, kind) in [("openid", "online"), ("openid offline_access", "offline")] {
        let (_, body) = post_form(
            &s,
            "/token",
            &[
                ("grant_type", "password"),
                ("client_id", "app"),
                ("username", "bob"),
                ("scope", scope),
            ],
        )
        .await;
        let rt = body["refresh_token"].as_str().unwrap();
        assert_eq!(introspect(&s, rt).await["refresh_token_type"], kind);
    }
}

// ---------- (b) /revoke ----------

#[tokio::test]
async fn revoke_refresh_token() {
    let s = spawn(&[]).await;
    let (_, body) = login(&s, "openid offline_access", "").await;
    let rt = body["refresh_token"].as_str().unwrap();

    // another client may not revoke it
    let (st, err) = post_form(&s, "/revoke", &[("token", rt), ("client_id", "other")]).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(introspect(&s, rt).await["active"], true);

    let (st, _) = post_form(
        &s,
        "/revoke",
        &[
            ("token", rt),
            ("token_type_hint", "refresh_token"),
            ("client_id", "app"),
        ],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(introspect(&s, rt).await["active"], false);
    let (st, err) = refresh(&s, rt).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_grant");

    // unknown tokens: 200 per RFC 7009
    let (st, _) = post_form(&s, "/revoke", &[("token", "nope"), ("client_id", "app")]).await;
    assert_eq!(st, StatusCode::OK);
    // client auth is required, as on /token
    let (st, err) = post_form(&s, "/revoke", &[("token", "nope")]).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{err}");
}

#[tokio::test]
async fn revoke_access_token_shows_in_introspect_and_userinfo() {
    let s = spawn(&[]).await;
    let (_, body) = login(&s, "openid", "").await;
    let at = body["access_token"].as_str().unwrap();
    assert_eq!(introspect(&s, at).await["active"], true);
    let (st, _) = post_form(&s, "/revoke", &[("token", at), ("client_id", "app")]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(introspect(&s, at).await, json!({ "active": false }));
    let r = s
        .client
        .get(s.url("/userinfo"))
        .bearer_auth(at)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_checks_secret_in_strict_mode() {
    let s = spawn(&[
        ("STRICT", "true"),
        (
            "CLIENTS",
            r#"[{"client_id":"app","client_secret":"s","redirect_uris":["http://app.example/cb"]}]"#,
        ),
    ])
    .await;
    let (st, _) = post_form(
        &s,
        "/revoke",
        &[
            ("token", "x"),
            ("client_id", "app"),
            ("client_secret", "bad"),
        ],
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = post_form(
        &s,
        "/revoke",
        &[("token", "x"), ("client_id", "app"), ("client_secret", "s")],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn discovery_advertises_revocation() {
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
    assert_eq!(d["revocation_endpoint"], s.url("/revoke"));
    assert!(d["scopes_supported"]
        .as_array()
        .unwrap()
        .contains(&json!("offline_access")));
}

// ---------- (c) admin subjects ----------

#[tokio::test]
async fn admin_not_mounted_without_token() {
    let s = spawn(&[]).await;
    let r = admin(&s, reqwest::Method::GET, "alice")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_requires_bearer() {
    let s = spawn(&[("ADMIN_TOKEN", ADMIN)]).await;
    let url = s.url("/admin/subjects/alice");
    let r = s.client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = s
        .client
        .get(&url)
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = admin(&s, reqwest::Method::GET, "alice")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    assert_eq!(
        v,
        json!({
            "sub": "alice",
            "claims": null,
            "disabled": false,
            "refresh_tokens": {"online": 0, "offline": 0}
        })
    );
}

#[tokio::test]
async fn refresh_reflects_current_claims() {
    let s = spawn(&[("ADMIN_TOKEN", ADMIN)]).await;
    let (_, body) = login(&s, "openid offline_access", r#"{"roles":["admin"]}"#).await;
    let rt = body["refresh_token"].as_str().unwrap().to_string();

    let v: Value = admin(&s, reqwest::Method::PUT, "alice")
        .json(&json!({"claims": {"roles": ["viewer"], "sub": "mallory"}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["refresh_tokens"], json!({"online": 0, "offline": 1}));
    assert_eq!(v["claims"]["sub"], "alice", "path sub wins");

    let (st, body) = refresh(&s, &rt).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let (_, c) = decode_jwt_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(c["roles"], json!(["viewer"]));
    assert_eq!(c["sub"], "alice");
    let (_, c) = decode_jwt_unverified(body["id_token"].as_str().unwrap());
    assert_eq!(c["roles"], json!(["viewer"]));

    // dropping the override (PUT without claims) falls back to the login snapshot
    admin(&s, reqwest::Method::PUT, "alice")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let (_, body) = refresh(&s, body["refresh_token"].as_str().unwrap()).await;
    let (_, c) = decode_jwt_unverified(body["access_token"].as_str().unwrap());
    assert_eq!(c["roles"], json!(["admin"]));
}

#[tokio::test]
async fn disabled_subject_cannot_refresh_or_login() {
    let s = spawn(&[("ADMIN_TOKEN", ADMIN)]).await;
    let (_, body) = login(&s, "openid offline_access", "").await;
    let rt = body["refresh_token"].as_str().unwrap().to_string();
    let at = body["access_token"].as_str().unwrap().to_string();

    let r = admin(&s, reqwest::Method::PUT, "alice")
        .json(&json!({"disabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let (st, err) = refresh(&s, &rt).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_grant");
    assert_eq!(introspect(&s, &rt).await["active"], false);
    assert_eq!(introspect(&s, &at).await["active"], false);

    // login is refused with access_denied
    let (_, body) = login(&s, "openid", "").await;
    let loc = body["redirect"].as_str().expect("error redirect");
    assert_eq!(query_param(loc, "error").unwrap(), "access_denied");
    let (st, err) = post_form(
        &s,
        "/token",
        &[
            ("grant_type", "password"),
            ("client_id", "app"),
            ("username", "alice"),
        ],
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_grant");

    // re-enabling restores the (unconsumed) refresh token
    admin(&s, reqwest::Method::PUT, "alice")
        .json(&json!({"disabled": false}))
        .send()
        .await
        .unwrap();
    let (st, body) = refresh(&s, &rt).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn delete_subject_revokes_refresh_tokens() {
    let s = spawn(&[("ADMIN_TOKEN", ADMIN)]).await;
    let (_, a) = login(&s, "openid", "").await;
    let (_, b) = login(&s, "openid offline_access", "").await;
    let r: Value = admin(&s, reqwest::Method::DELETE, "alice")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["revoked_refresh_tokens"], 2);
    for body in [a, b] {
        let (st, err) = refresh(&s, body["refresh_token"].as_str().unwrap()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(err["error"], "invalid_grant");
    }
    let list: Value = s
        .client
        .get(s.url("/admin/subjects"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list, json!([]));
}

// ---------- (d) end_session ----------

#[tokio::test]
async fn end_session_revokes_only_online_refresh_tokens_of_that_client() {
    let s = spawn(&[]).await;
    let (_, body) = login(&s, "openid", "").await;
    let online = body["refresh_token"].as_str().unwrap().to_string();
    let id = body["id_token"].as_str().unwrap().to_string();
    let (_, body) = login(&s, "openid offline_access", "").await;
    let offline = body["refresh_token"].as_str().unwrap().to_string();
    // another client's online refresh token for the same user survives
    let (_, other) = post_form(
        &s,
        "/token",
        &[
            ("grant_type", "password"),
            ("client_id", "worker"),
            ("username", "alice"),
        ],
    )
    .await;
    let other_rt = other["refresh_token"].as_str().unwrap();

    let r = s
        .client
        .get(format!(
            "{}?id_token_hint={id}&post_logout_redirect_uri={}",
            s.url("/end_session"),
            urlenc("http://app/bye")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);

    let (st, err) = refresh(&s, &online).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_grant");
    assert_eq!(introspect(&s, other_rt).await["active"], true);
    let (st, body) = refresh(&s, &offline).await;
    assert_eq!(st, StatusCode::OK, "offline token survives logout: {body}");
}

#[tokio::test]
async fn end_session_rejects_forged_hint() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .get(format!("{}?id_token_hint=a.b.c", s.url("/end_session")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}
