use axum::extract::Query;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use super::authorize::found;

#[derive(Debug, Deserialize)]
pub struct EndSessionQuery {
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    #[allow(dead_code)]
    pub id_token_hint: Option<String>,
}

pub async fn handler(Query(q): Query<EndSessionQuery>) -> Response {
    match q.post_logout_redirect_uri.as_deref().filter(|s| !s.is_empty()) {
        Some(uri) => match url::Url::parse(uri) {
            Ok(mut url) => {
                if let Some(s) = &q.state {
                    url.query_pairs_mut().append_pair("state", s);
                }
                found(url.as_str())
            }
            Err(_) => (
                axum::http::StatusCode::BAD_REQUEST,
                Html("<!doctype html><title>nano-mockidp</title><p>invalid post_logout_redirect_uri</p>"),
            )
                .into_response(),
        },
        None => Html(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>nano-mockidp</title>\
             <style>body{font-family:system-ui,sans-serif;max-width:640px;margin:60px auto;color:#222}h1{color:#ba2415;font-size:20px}</style></head>\
             <body><h1>Logged out</h1><p>nano-mockidp keeps no session; you can close this page.</p></body></html>",
        )
        .into_response(),
    }
}
