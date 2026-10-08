#![cfg(feature = "upstream")]
mod common;

use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

const CB: &str = "http://app.example/cb";
const TESTERS: &str = r#"{"groups":["testers"]}"#;
const SCOPE: &str = "openid offline_access";

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn authz_url(s: &TestServer) -> String {
    authz_url_with_state(s, "st1")
}

fn authz_url_with_state(s: &TestServer, state: &str) -> String {
    format!(
        "{}?response_type=code&client_id=app&redirect_uri={}&state={state}&scope={}&nonce=n1",
        s.url("/authorize"),
        urlenc(CB),
        urlenc(SCOPE)
    )
}

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_string()
}

/// The `Set-Cookie` header of `r` for a cookie whose name starts with `prefix`.
fn set_cookie(r: &reqwest::Response, prefix: &str) -> Option<String> {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .find(|v| v.starts_with(prefix))
}

/// `name=value` of a `Set-Cookie` header.
fn pair_of(set: &str) -> String {
    set.split(';').next().unwrap().to_string()
}

const LOGIN_PREFIX: &str = "nano_mockidp_login_";
const GATE_PREFIX: &str = "nano_mockidp_gate=";

/// A = plain nano-mockidp playing the upstream; B = gated by A, mounted at `path`.
async fn pair(path: &str, extra: &[(&str, &str)]) -> (TestServer, TestServer) {
    let a = spawn(&[]).await;
    let issuer = a.issuer.clone();
    let mut env = vec![
        ("UPSTREAM_ISSUER", issuer.as_str()),
        ("UPSTREAM_CLIENT_ID", "gate"),
        ("UPSTREAM_REQUIRE_CLAIM", "groups=testers"),
    ];
    env.extend_from_slice(extra);
    let b = spawn_at(path, &env).await;
    (a, b)
}

/// GET `authz` at B without a gate cookie: returns (redirect to A, login cookie `name=value`).
async fn start_at_b(a: &TestServer, b: &TestServer, authz: &str) -> (String, String) {
    let r = b.client.get(authz).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let to_a = location(&r);
    assert!(to_a.starts_with(&a.url("/authorize?")), "{to_a}");
    assert_eq!(
        query_param(&to_a, "redirect_uri").unwrap(),
        b.url("/upstream/callback")
    );
    let set = set_cookie(&r, LOGIN_PREFIX).expect("login cookie");
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Lax") && set.contains("Max-Age=600"),
        "{set}"
    );
    let st = query_param(&to_a, "state").unwrap();
    let cookie = pair_of(&set);
    assert!(
        cookie.starts_with(&format!("{LOGIN_PREFIX}{}=", &st[..12])),
        "{cookie}"
    );
    (to_a, cookie)
}

/// Log in at A as `realfrank` with `claims`; returns B's callback URL.
async fn login_at_a(a: &TestServer, to_a: &str, claims: &str) -> String {
    let r = a
        .client
        .post(to_a)
        .form(&[("username", "realfrank"), ("claims", claims)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    location(&r)
}

/// Start at B, log in at A as `realfrank` with `claims`; returns (B's callback URL, login cookie).
async fn upstream_login(a: &TestServer, b: &TestServer, claims: &str) -> (String, String) {
    let (to_a, cookie) = start_at_b(a, b, &authz_url(b)).await;
    (login_at_a(a, &to_a, claims).await, cookie)
}

async fn get_with(s: &TestServer, url: &str, cookie: &str) -> reqwest::Response {
    s.client
        .get(url)
        .header("cookie", cookie)
        .send()
        .await
        .unwrap()
}

/// The callback response clears the login cookie.
fn assert_login_cleared(r: &reqwest::Response) {
    let set = set_cookie(r, LOGIN_PREFIX).expect("login cookie cleared");
    assert!(set.contains("Max-Age=0"), "{set}");
}

/// Pass B's gate as a tester; returns the gate cookie `name=value`.
async fn pass_gate(a: &TestServer, b: &TestServer) -> String {
    let (to_cb, login) = upstream_login(a, b, TESTERS).await;
    let r = get_with(b, &to_cb, &login).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    assert_eq!(
        format!("{}{}", b.root, location(&r)),
        authz_url(b),
        "back to the original authorize request"
    );
    assert_login_cleared(&r);
    let set = set_cookie(&r, GATE_PREFIX).expect("gate cookie");
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Lax"),
        "{set}"
    );
    assert!(!set.contains("Secure"), "http issuer: no Secure");
    pair_of(&set)
}

/// Log in at B as persona `alice` with the gate cookie and redeem the code.
async fn persona_tokens(b: &TestServer, cookie: &str, claims: &str) -> Value {
    let r = b
        .client
        .post(authz_url(b))
        .header("cookie", cookie)
        .form(&[("username", "alice"), ("claims", claims)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    let code = query_param(&location(&r), "code").expect("code");
    b.client
        .post(b.url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", CB),
            ("client_id", "app"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn refresh(b: &TestServer, rt: &str) -> reqwest::Response {
    b.client
        .post(b.url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", "app"),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn gated_login_then_personas_as_today() {
    let (a, b) = pair("", &[]).await;
    let cookie = pass_gate(&a, &b).await;
    let r = b
        .client
        .get(authz_url(&b))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "login page behind the gate");

    let t = persona_tokens(&b, &cookie, r#"{"roles":["admin"]}"#).await;
    let (_, at) = decode_jwt_unverified(t["access_token"].as_str().unwrap());
    assert_eq!(at["sub"], "alice");
    assert_eq!(at["roles"], json!(["admin"]));
    assert!(
        at.get("upstream_sub").is_none(),
        "no audit claim unless configured"
    );

    let rt = t["refresh_token"].as_str().unwrap();
    let i: Value = b
        .client
        .post(b.url("/introspect"))
        .form(&[("token", rt)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(i["refresh_token_type"], "offline");
    assert_eq!(refresh(&b, rt).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn upstream_sub_claim_is_set_and_cannot_be_forged() {
    let (a, b) = pair(
        "",
        &[
            ("UPSTREAM_SUB_TOKEN_CLAIM", "upstream_sub"),
            ("ADMIN_TOKEN", "adm"),
        ],
    )
    .await;
    let cookie = pass_gate(&a, &b).await;
    let t = persona_tokens(&b, &cookie, r#"{"upstream_sub":"forged"}"#).await;
    let (_, at) = decode_jwt_unverified(t["access_token"].as_str().unwrap());
    assert_eq!(at["sub"], "alice");
    assert_eq!(at["upstream_sub"], "realfrank");
    let (_, id) = decode_jwt_unverified(t["id_token"].as_str().unwrap());
    assert_eq!(id["upstream_sub"], "realfrank");

    // an admin override replaces the login claims; the upstream claim survives refresh
    let r = b
        .client
        .put(b.url("/admin/subjects/alice"))
        .bearer_auth("adm")
        .json(&json!({"claims": {"roles": ["viewer"]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r: Value = refresh(&b, t["refresh_token"].as_str().unwrap())
        .await
        .json()
        .await
        .unwrap();
    let (_, at) = decode_jwt_unverified(r["access_token"].as_str().unwrap());
    assert_eq!(at["roles"], json!(["viewer"]));
    assert_eq!(at["upstream_sub"], "realfrank");
}

#[tokio::test]
async fn upstream_user_without_required_claim_is_denied() {
    let (a, b) = pair("", &[]).await;
    let (to_cb, login) = upstream_login(&a, &b, r#"{"groups":["devs"]}"#).await;
    let r = get_with(&b, &to_cb, &login).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie(&r, GATE_PREFIX).is_none(), "no gate cookie");
    assert_login_cleared(&r);
    assert!(r.text().await.unwrap().contains("groups=testers"));
}

#[tokio::test]
async fn post_without_cookie_is_forbidden_not_redirected() {
    let (_a, b) = pair("", &[]).await;
    let r = b
        .client
        .post(authz_url(&b))
        .form(&[("username", "alice")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn foreign_or_tampered_cookie_is_refused() {
    let (a, b) = pair("", &[]).await;
    let cookie = pass_gate(&a, &b).await;
    // another gated instance (= a restart: new cookie key)
    let issuer = a.issuer.clone();
    let b2 = spawn(&[
        ("UPSTREAM_ISSUER", issuer.as_str()),
        ("UPSTREAM_CLIENT_ID", "gate"),
    ])
    .await;
    for (server, c) in [(&b2, cookie.clone()), (&b, format!("{cookie}x"))] {
        let r = server
            .client
            .post(authz_url(server))
            .header("cookie", &c)
            .form(&[("username", "alice")])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "POST with {c}");
        let r = server
            .client
            .get(authz_url(server))
            .header("cookie", &c)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FOUND, "GET with {c}");
        assert!(location(&r).starts_with(&a.url("/authorize?")));
    }
}

#[tokio::test]
async fn callback_state_is_single_use_and_checked() {
    let (a, b) = pair("", &[]).await;
    let (to_cb, login) = upstream_login(&a, &b, TESTERS).await;
    assert_eq!(
        get_with(&b, &to_cb, &login).await.status(),
        StatusCode::FOUND
    );
    // the browser dropped the (cleared) login cookie
    let r = b.client.get(&to_cb).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "replayed callback");
    assert!(r.text().await.unwrap().contains("start again"));
    // a replay that kept the old login cookie: the upstream code is single-use
    let r = get_with(&b, &to_cb, &login).await;
    assert_ne!(
        r.status(),
        StatusCode::FOUND,
        "replay with the login cookie"
    );
    assert!(
        set_cookie(&r, GATE_PREFIX).is_none(),
        "no second gate session"
    );
    let r = b
        .client
        .get(b.url("/upstream/callback?state=nope&code=x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_in_another_browser_is_refused() {
    let (a, b) = pair("", &[]).await;
    let (to_cb, _login) = upstream_login(&a, &b, TESTERS).await;
    let r = b.client.get(&to_cb).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookie(&r, GATE_PREFIX).is_none(), "no gate cookie");
    assert!(r.text().await.unwrap().contains("start again"));
}

#[tokio::test]
async fn login_cookie_is_not_a_gate_cookie() {
    let (a, b) = pair("", &[]).await;
    // a login cookie's value presented as the gate cookie
    let (_to_a, login) = start_at_b(&a, &b, &authz_url(&b)).await;
    let (_, value) = login.split_once('=').unwrap();
    let r = b
        .client
        .post(authz_url(&b))
        .header("cookie", format!("{GATE_PREFIX}{value}"))
        .form(&[("username", "alice")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // a gate cookie's value presented as the login cookie
    let gate = pass_gate(&a, &b).await;
    let (_, gate_value) = gate.split_once('=').unwrap();
    let (to_cb, login) = upstream_login(&a, &b, TESTERS).await;
    let (name, _) = login.split_once('=').unwrap();
    let r = get_with(&b, &to_cb, &format!("{name}={gate_value}")).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookie(&r, GATE_PREFIX).is_none(), "no gate cookie");
}

#[tokio::test]
async fn overlong_authorize_request_is_refused_before_upstream() {
    let s = spawn(&[
        ("UPSTREAM_ISSUER", "http://127.0.0.1:9"),
        ("UPSTREAM_CLIENT_ID", "gate"),
    ])
    .await;
    let url = format!("{}&pad={}", authz_url(&s), "x".repeat(3000));
    let r = s.client.get(url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::URI_TOO_LONG);
    assert!(r.headers().get("set-cookie").is_none());
    assert!(r.text().await.unwrap().contains("too long"));
}

#[tokio::test]
async fn parallel_logins_in_one_browser() {
    let (a, b) = pair("", &[]).await;
    let (url1, url2) = (
        authz_url_with_state(&b, "one"),
        authz_url_with_state(&b, "two"),
    );
    let (to_a1, c1) = start_at_b(&a, &b, &url1).await;
    let (to_a2, c2) = start_at_b(&a, &b, &url2).await;
    assert_ne!(
        c1.split_once('=').unwrap().0,
        c2.split_once('=').unwrap().0,
        "one login cookie per login"
    );
    let both = format!("{c1}; {c2}");
    for (to_a, url) in [(to_a2, url2), (to_a1, url1)] {
        let to_cb = login_at_a(&a, &to_a, TESTERS).await;
        let r = get_with(&b, &to_cb, &both).await;
        assert_eq!(r.status(), StatusCode::FOUND, "{url}");
        assert_eq!(format!("{}{}", b.root, location(&r)), url);
        assert!(set_cookie(&r, GATE_PREFIX).is_some());
    }
}

#[tokio::test]
async fn upstream_error_is_shown() {
    let (a, b) = pair("", &[]).await;
    let (to_a, login) = start_at_b(&a, &b, &authz_url(&b)).await;
    let st = query_param(&to_a, "state").unwrap();
    let url = format!(
        "{}?state={st}&error=access_denied&error_description=nope",
        b.url("/upstream/callback")
    );
    let r = get_with(&b, &url, &login).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_login_cleared(&r);
    assert!(r.text().await.unwrap().contains("access_denied"));
}

#[tokio::test]
async fn upstream_unreachable_is_502() {
    let s = spawn(&[
        ("UPSTREAM_ISSUER", "http://127.0.0.1:9"),
        ("UPSTREAM_CLIENT_ID", "gate"),
    ])
    .await;
    let r = s.client.get(authz_url(&s)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    // the server is still fine
    let r = s.client.get(s.url("/health")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn gate_under_a_mount_path() {
    let (a, b) = pair("/mockidp", &[]).await;
    assert!(b
        .url("/upstream/callback")
        .contains("/mockidp/upstream/callback"));
    let (to_cb, login) = upstream_login(&a, &b, TESTERS).await;
    let r = get_with(&b, &to_cb, &login).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    assert!(location(&r).starts_with("/mockidp/authorize?"));
    let set = set_cookie(&r, GATE_PREFIX).expect("gate cookie");
    assert!(set.contains("Path=/mockidp;"), "{set}");
    let login_set = set_cookie(&r, LOGIN_PREFIX).expect("login cookie cleared");
    assert!(login_set.contains("Path=/mockidp;"), "{login_set}");
    let cookie = pair_of(&set);
    let t = persona_tokens(&b, &cookie, "{}").await;
    assert!(t["access_token"].is_string());
}

#[tokio::test]
async fn no_callback_route_without_gate() {
    let s = spawn(&[]).await;
    let r = s
        .client
        .get(s.url("/upstream/callback?state=x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

/// Gated, upstream never contacted (token grants don't need it).
async fn gated_offline() -> TestServer {
    spawn(&[
        ("UPSTREAM_ISSUER", "http://127.0.0.1:9"),
        ("UPSTREAM_CLIENT_ID", "gate"),
        (
            "CLIENTS",
            r#"[{"client_id":"ci","client_secret":"s3cret"},{"client_id":"public"}]"#,
        ),
    ])
    .await
}

async fn grant(
    s: &TestServer,
    grant: &str,
    client_id: &str,
    secret: Option<&str>,
) -> (StatusCode, Value) {
    let mut form = vec![
        ("grant_type", grant),
        ("client_id", client_id),
        ("username", "alice"),
        ("password", "x"),
    ];
    if let Some(sec) = secret {
        form.push(("client_secret", sec));
    }
    let r = s
        .client
        .post(s.url("/token"))
        .form(&form)
        .send()
        .await
        .unwrap();
    (r.status(), r.json().await.unwrap())
}

#[tokio::test]
async fn browserless_grants_need_a_configured_client_with_secret() {
    let s = gated_offline().await;
    let reg: Value = s
        .client
        .post(s.url("/register"))
        .json(&json!({"redirect_uris": ["http://x/cb"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let (dyn_id, dyn_secret) = (
        reg["client_id"].as_str().unwrap().to_string(),
        reg["client_secret"].as_str().unwrap().to_string(),
    );
    for g in ["password", "client_credentials"] {
        for (id, secret) in [
            ("app", None),
            ("public", None),
            ("ci", None),
            ("ci", Some("wrong")),
            (dyn_id.as_str(), Some(dyn_secret.as_str())),
        ] {
            let (status, body) = grant(&s, g, id, secret).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{g} {id} {secret:?}");
            assert_eq!(body["error"], "unauthorized_client", "{g} {id}");
        }
        let (status, _) = grant(&s, g, "ci", Some("s3cret")).await;
        assert_eq!(status, StatusCode::OK, "{g} with the configured secret");
    }
    // HTTP Basic works too
    let r = s
        .client
        .post(s.url("/token"))
        .basic_auth("ci", Some("s3cret"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}
