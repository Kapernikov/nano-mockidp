use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    /// Public issuer URL, without trailing slash. Always used for `iss`.
    pub issuer_url: Url,
    /// Path component of `issuer_url` without trailing slash ("" for root).
    pub issuer_path: String,
    pub endpoints_from_request_host: bool,
    pub internal_url: Option<Url>,
    pub strict: bool,
    pub clients: Vec<ClientConfig>,
    pub login_page_path: Option<PathBuf>,
    pub access_token_ttl: u64,
    pub id_token_ttl: u64,
    pub refresh_token_ttl: u64,
    pub signing_key_seed: Option<String>,
    pub signing_key_pem: Option<String>,
    pub signing_key_path: Option<PathBuf>,
    pub cors_allowed_origins: Vec<String>,
    pub log_level: String,
}

fn parse_bool(v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => Err(format!("invalid boolean: {other}")),
    }
}

fn parse_url(name: &str, v: &str) -> Result<Url, String> {
    let trimmed = v.trim().trim_end_matches('/');
    let url = Url::parse(trimmed).map_err(|e| format!("{name}: invalid URL {v:?}: {e}"))?;
    if url.cannot_be_a_base() || url.host().is_none() {
        return Err(format!("{name}: URL must be absolute with a host: {v:?}"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{name}: URL must not contain query or fragment: {v:?}"));
    }
    Ok(url)
}

fn parse_u64(name: &str, v: &str) -> Result<u64, String> {
    v.trim()
        .parse::<u64>()
        .map_err(|e| format!("{name}: invalid integer {v:?}: {e}"))
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let map: HashMap<String, String> = std::env::vars().collect();
        Config::from_map(&map)
    }

    pub fn from_map(m: &HashMap<String, String>) -> Result<Config, String> {
        let get = |k: &str| m.get(k).map(|s| s.as_str()).filter(|s| !s.trim().is_empty());

        let port = match get("PORT") {
            Some(v) => v
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("PORT: invalid port {v:?}: {e}"))?,
            None => 8080,
        };
        let issuer_url = parse_url("ISSUER_URL", get("ISSUER_URL").unwrap_or("http://localhost:8080"))?;
        let issuer_path = issuer_url.path().trim_end_matches('/').to_string();
        let endpoints_from_request_host = match get("ENDPOINTS_FROM_REQUEST_HOST") {
            Some(v) => parse_bool(v).map_err(|e| format!("ENDPOINTS_FROM_REQUEST_HOST: {e}"))?,
            None => true,
        };
        let internal_url = match get("INTERNAL_URL") {
            Some(v) => Some(parse_url("INTERNAL_URL", v)?),
            None => None,
        };
        let strict = match get("STRICT") {
            Some(v) => parse_bool(v).map_err(|e| format!("STRICT: {e}"))?,
            None => false,
        };
        let clients: Vec<ClientConfig> = match get("CLIENTS") {
            Some(v) => serde_json::from_str(v).map_err(|e| format!("CLIENTS: invalid JSON: {e}"))?,
            None => Vec::new(),
        };
        let login_page_path = get("LOGIN_PAGE_PATH").map(PathBuf::from);
        let access_token_ttl = match get("ACCESS_TOKEN_TTL") {
            Some(v) => parse_u64("ACCESS_TOKEN_TTL", v)?,
            None => 3600,
        };
        let id_token_ttl = match get("ID_TOKEN_TTL") {
            Some(v) => parse_u64("ID_TOKEN_TTL", v)?,
            None => 3600,
        };
        let refresh_token_ttl = match get("REFRESH_TOKEN_TTL") {
            Some(v) => parse_u64("REFRESH_TOKEN_TTL", v)?,
            None => 2_592_000,
        };
        let cors_allowed_origins = match get("CORS_ALLOWED_ORIGINS") {
            Some(v) => v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => vec!["*".to_string()],
        };
        Ok(Config {
            port,
            issuer_url,
            issuer_path,
            endpoints_from_request_host,
            internal_url,
            strict,
            clients,
            login_page_path,
            access_token_ttl,
            id_token_ttl,
            refresh_token_ttl,
            signing_key_seed: get("SIGNING_KEY_SEED").map(str::to_string),
            signing_key_pem: get("SIGNING_KEY_PEM").map(str::to_string),
            signing_key_path: get("SIGNING_KEY_PATH").map(PathBuf::from),
            cors_allowed_origins,
            log_level: get("LOG_LEVEL").unwrap_or("info").to_string(),
        })
    }

    /// Issuer URL as a string without trailing slash.
    pub fn issuer(&self) -> String {
        self.issuer_url.as_str().trim_end_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, String> {
        let m = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Config::from_map(&m)
    }

    #[test]
    fn defaults() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.port, 8080);
        assert_eq!(c.issuer(), "http://localhost:8080");
        assert_eq!(c.issuer_path, "");
        assert!(c.endpoints_from_request_host);
        assert!(!c.strict);
        assert_eq!(c.access_token_ttl, 3600);
        assert_eq!(c.refresh_token_ttl, 2_592_000);
        assert_eq!(c.cors_allowed_origins, vec!["*"]);
        assert!(c.signing_key_seed.is_none());
    }

    #[test]
    fn issuer_with_path() {
        let c = cfg(&[("ISSUER_URL", "http://x:1/oidc/")]).unwrap();
        assert_eq!(c.issuer(), "http://x:1/oidc");
        assert_eq!(c.issuer_path, "/oidc");
    }

    #[test]
    fn clients_json() {
        let c = cfg(&[(
            "CLIENTS",
            r#"[{"client_id":"a","client_secret":"s","redirect_uris":["http://a/cb"]},{"client_id":"b"}]"#,
        )])
        .unwrap();
        assert_eq!(c.clients.len(), 2);
        assert_eq!(c.clients[0].client_secret.as_deref(), Some("s"));
        assert!(c.clients[1].client_secret.is_none());
    }

    #[test]
    fn cors_list() {
        let c = cfg(&[("CORS_ALLOWED_ORIGINS", "http://a, http://b")]).unwrap();
        assert_eq!(c.cors_allowed_origins, vec!["http://a", "http://b"]);
    }

    #[test]
    fn invalid_port() {
        assert!(cfg(&[("PORT", "abc")]).is_err());
    }

    #[test]
    fn bool_parsing() {
        assert!(cfg(&[("STRICT", "YES")]).unwrap().strict);
        assert!(!cfg(&[("ENDPOINTS_FROM_REQUEST_HOST", "0")]).unwrap().endpoints_from_request_host);
        assert!(cfg(&[("STRICT", "maybe")]).is_err());
    }
}
