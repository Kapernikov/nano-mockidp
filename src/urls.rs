use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::config::Config;

/// `scheme://host[:port]` of the incoming request, honouring X-Forwarded-* headers.
#[derive(Debug, Clone)]
pub struct RequestBase(pub String);

impl<S: Send + Sync> FromRequestParts<S> for RequestBase {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let scheme = header("x-forwarded-proto").unwrap_or_else(|| "http".to_string());
        let forwarded_host = header("x-forwarded-host");
        let mut host = forwarded_host
            .clone()
            .or_else(|| header("host"))
            .unwrap_or_else(|| "localhost".to_string());
        // X-Forwarded-Host without a port + X-Forwarded-Port: append the port when non-default.
        if forwarded_host.is_some() && !host_has_port(&host) {
            if let Some(port) = header("x-forwarded-port") {
                let default = matches!(
                    (scheme.as_str(), port.as_str()),
                    ("http", "80") | ("https", "443")
                );
                if !default {
                    host = format!("{host}:{port}");
                }
            }
        }
        Ok(RequestBase(format!("{scheme}://{host}")))
    }
}

fn host_has_port(host: &str) -> bool {
    if let Some(end) = host.rfind(']') {
        // IPv6 literal: [::1]:8080
        return host[end..].contains(':');
    }
    host.contains(':')
}

/// The issuer for a given request: `ISSUER_URL`, or request base + issuer path when
/// `ISSUER_FROM_REQUEST_HOST` is on.
pub fn issuer_for(cfg: &Config, request_base: Option<&str>) -> String {
    match (cfg.issuer_from_request_host, request_base) {
        (true, Some(base)) => format!("{}{}", base.trim_end_matches('/'), cfg.issuer_path),
        _ => cfg.issuer(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization: String,
    pub end_session: String,
    pub token: String,
    pub jwks: String,
    pub userinfo: String,
    pub introspection: String,
    pub registration: String,
}

impl Endpoints {
    /// Browser-facing URLs always come from `ISSUER_URL`. Backend-facing URLs come from
    /// `INTERNAL_URL`, else the request base (if enabled), else `ISSUER_URL`.
    pub fn resolve(cfg: &Config, request_base: Option<&str>) -> Endpoints {
        let public = issuer_for(cfg, request_base);
        let path = &cfg.issuer_path;
        let internal = match (
            &cfg.internal_url,
            request_base,
            cfg.endpoints_from_request_host,
        ) {
            (Some(u), _, _) => u.as_str().trim_end_matches('/').to_string(),
            (None, Some(base), true) => format!("{}{}", base.trim_end_matches('/'), path),
            _ => public.clone(),
        };
        Endpoints {
            authorization: format!("{public}/authorize"),
            end_session: format!("{public}/end_session"),
            token: format!("{internal}/token"),
            jwks: format!("{internal}/jwks"),
            userinfo: format!("{internal}/userinfo"),
            introspection: format!("{internal}/introspect"),
            registration: format!("{internal}/register"),
            issuer: public,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Config {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_map(&m).unwrap()
    }

    #[test]
    fn default_no_request_base() {
        let e = Endpoints::resolve(&cfg(&[]), None);
        assert_eq!(e.issuer, "http://localhost:8080");
        assert_eq!(e.token, "http://localhost:8080/token");
    }

    #[test]
    fn request_base_drives_backend_urls_only() {
        let c = cfg(&[("ISSUER_URL", "http://public.example/oidc")]);
        let e = Endpoints::resolve(&c, Some("http://backend:9"));
        assert_eq!(e.issuer, "http://public.example/oidc");
        assert_eq!(e.authorization, "http://public.example/oidc/authorize");
        assert_eq!(e.end_session, "http://public.example/oidc/end_session");
        assert_eq!(e.jwks, "http://backend:9/oidc/jwks");
        assert_eq!(e.token, "http://backend:9/oidc/token");
        assert_eq!(e.userinfo, "http://backend:9/oidc/userinfo");
        assert_eq!(e.introspection, "http://backend:9/oidc/introspect");
        assert_eq!(e.registration, "http://backend:9/oidc/register");
    }

    #[test]
    fn derivation_disabled() {
        let c = cfg(&[
            ("ISSUER_URL", "http://public.example"),
            ("ENDPOINTS_FROM_REQUEST_HOST", "false"),
        ]);
        let e = Endpoints::resolve(&c, Some("http://backend:9"));
        assert_eq!(e.jwks, "http://public.example/jwks");
    }

    #[test]
    fn issuer_from_request_host_opt_in() {
        let c = cfg(&[
            ("ISSUER_URL", "http://localhost:4200/mock-oauth"),
            ("ISSUER_FROM_REQUEST_HOST", "true"),
        ]);
        let e = Endpoints::resolve(&c, Some("http://localhost:4253"));
        assert_eq!(e.issuer, "http://localhost:4253/mock-oauth");
        assert_eq!(
            e.authorization,
            "http://localhost:4253/mock-oauth/authorize"
        );
        assert_eq!(
            e.end_session,
            "http://localhost:4253/mock-oauth/end_session"
        );
        assert_eq!(e.token, "http://localhost:4253/mock-oauth/token");
        assert_eq!(issuer_for(&c, Some("https://x")), "https://x/mock-oauth");
        // without request base falls back to ISSUER_URL
        assert_eq!(issuer_for(&c, None), "http://localhost:4200/mock-oauth");
        // off by default
        let c = cfg(&[("ISSUER_URL", "http://localhost:4200/mock-oauth")]);
        assert_eq!(
            issuer_for(&c, Some("http://localhost:4253")),
            "http://localhost:4200/mock-oauth"
        );
    }

    #[test]
    fn host_port_detection() {
        assert!(host_has_port("a:1"));
        assert!(!host_has_port("a"));
        assert!(host_has_port("[::1]:8080"));
        assert!(!host_has_port("[::1]"));
    }

    #[test]
    fn internal_url_overrides() {
        let c = cfg(&[
            ("ISSUER_URL", "http://public.example/oidc"),
            ("INTERNAL_URL", "http://svc.ns.svc:8080/oidc/"),
        ]);
        let e = Endpoints::resolve(&c, Some("http://backend:9"));
        assert_eq!(e.jwks, "http://svc.ns.svc:8080/oidc/jwks");
        assert_eq!(e.authorization, "http://public.example/oidc/authorize");
    }
}
