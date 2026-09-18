use crate::config::Config;

pub const DEFAULT_LOGIN_PAGE: &str = include_str!("../static/login.html");

/// Returns the login page HTML: the custom file (re-read on every call) or the built-in page.
pub fn load_login_page(cfg: &Config) -> Result<String, std::io::Error> {
    match &cfg.login_page_path {
        Some(path) => std::fs::read_to_string(path),
        None => Ok(DEFAULT_LOGIN_PAGE.to_string()),
    }
}
