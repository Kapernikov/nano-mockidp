use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub struct OAuthError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: String,
}

impl OAuthError {
    fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        OAuthError {
            status,
            error,
            description: description.into(),
        }
    }
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", msg)
    }
    pub fn invalid_client(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", msg)
    }
    pub fn invalid_grant(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", msg)
    }
    pub fn unsupported_grant_type() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "supported: authorization_code, refresh_token, client_credentials",
        )
    }
    pub fn server_error(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", msg)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = json!({ "error": self.error, "error_description": self.description });
        let mut resp = (self.status, axum::Json(body)).into_response();
        let h = resp.headers_mut();
        h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        h.insert(header::PRAGMA, "no-cache".parse().unwrap());
        if self.status == StatusCode::UNAUTHORIZED {
            h.insert(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"nano-mockidp\"".parse().unwrap(),
            );
        }
        resp
    }
}
