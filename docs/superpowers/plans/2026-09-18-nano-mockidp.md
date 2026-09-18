# nano-mockidp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lightweight Rust mock OIDC provider (auth code + PKCE S256, refresh, client_credentials, DCR, customizable login HTML), shipped as a `FROM scratch` image on ghcr.io whose tag follows the git release tag.

**Architecture:** Single axum binary. `AppState` = config + RSA signing key + `Mutex<Store>` (pending auth requests, codes, refresh tokens, DCR clients). All routes mounted under the path of `ISSUER_URL`. Discovery splits browser-facing URLs (fixed to `ISSUER_URL`) from backend-facing URLs (derived from request Host). Login page is plain HTML posting back to the same URL.

**Tech Stack:** Rust 2021, axum 0.8, tokio 1, jsonwebtoken 9, rsa 0.9, rand 0.8 + rand_chacha 0.3, sha2 0.10, serde/serde_json, tower-http 0.6 (cors, trace), base64 0.22, url 2, tracing. Tests: reqwest 0.12. Build: musl static, Docker multi-stage `FROM scratch`. CI: GitHub Actions → ghcr.io/kapernikov/nano-mockidp.

**Spec:** `docs/superpowers/specs/2026-09-18-nano-mockidp-design.md`

## Global Constraints

- All configuration via env vars named exactly as the spec table (`PORT`, `ISSUER_URL`, `ENDPOINTS_FROM_REQUEST_HOST`, `INTERNAL_URL`, `STRICT`, `CLIENTS`, `LOGIN_PAGE_PATH`, `ACCESS_TOKEN_TTL`, `ID_TOKEN_TTL`, `REFRESH_TOKEN_TTL`, `SIGNING_KEY_SEED`, `SIGNING_KEY_PEM`, `SIGNING_KEY_PATH`, `CORS_ALLOWED_ORIGINS`, `LOG_LEVEL`).
- Defaults: `PORT=8080`, `ISSUER_URL=http://localhost:8080`, `ENDPOINTS_FROM_REQUEST_HOST=true`, `STRICT=false`, TTLs `3600/3600/2592000`, `CORS_ALLOWED_ORIGINS=*`, `LOG_LEVEL=info`, signing key random unless seed/PEM given.
- `response_types_supported` must be exactly `["code"]`; only `S256` PKCE.
- `iss` is always `ISSUER_URL` regardless of request Host.
- Server never validates the Host header.
- Random ids/tokens: 32 random bytes, base64url no padding.
- Image tag = git tag (`v1.2.3` → `1.2.3`, plus `latest` on main); Cargo.toml version ignored.
- Git: branch `main`, remote `git@github.com:Kapernikov/nano-mockidp.git`. Commits end with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

---

## File Structure

```
Cargo.toml
src/main.rs         — entry: init tracing, Config::from_env, AppState::new, router, serve; spawn sweep task
src/config.rs       — Config struct + from_env(); ClientConfig
src/keys.rs         — SigningKey {kid, encoding, decoding, jwk}; load(&Config) → seed/PEM/random
src/store.rs        — Store maps with expiry; AuthRequest, CodeEntry, RefreshEntry, Client; sweep()
src/token.rs        — TokenSet issuance: build claims, sign access/id tokens, at_hash, verify(); pkce_verify()
src/urls.rs         — RequestBase extractor (scheme/host from Host + X-Forwarded-*), Endpoints resolution
src/login.rs        — DEFAULT_LOGIN_PAGE const (include_str!) + load_login_page(&Config)
src/error.rs        — OAuthError {error, description, status} → IntoResponse (JSON); redirect variant
src/routes/mod.rs   — router(state) mounting everything under issuer path + /health at root
src/routes/discovery.rs, jwks.rs, authorize.rs, token.rs, userinfo.rs, introspect.rs, register.rs, session.rs, health.rs
static/login.html   — default Kapernikov-branded login page (include_str!)
assets/kapernikov-logo.svg (already present; inlined into static/login.html)
tests/common/mod.rs — spawn_server(env overrides) → TestServer {base, client}
tests/flow.rs       — integration tests
Dockerfile, .dockerignore, .github/workflows/ci.yml, README.md, LICENSE (MIT)
examples/login.html, examples/docker-compose.yml
```

---

### Task 1: Project scaffold, config, keys

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/config.rs`, `src/keys.rs`, `.gitignore`

**Interfaces:**
- Produces: `Config { port: u16, issuer_url: Url, issuer_path: String /* "" or "/oidc" */, endpoints_from_request_host: bool, internal_url: Option<Url>, strict: bool, clients: Vec<ClientConfig>, login_page_path: Option<PathBuf>, access_token_ttl: u64, id_token_ttl: u64, refresh_token_ttl: u64, signing_key_seed: Option<String>, signing_key_pem: Option<String>, signing_key_path: Option<PathBuf>, cors_allowed_origins: Vec<String> /* ["*"] */, log_level: String }`, `Config::from_env() -> Result<Config, String>`, `Config::from_map(&HashMap<String,String>) -> Result<Config,String>`.
- `ClientConfig { client_id: String, client_secret: Option<String>, redirect_uris: Option<Vec<String>> }` (serde Deserialize).
- `SigningKey { kid: String, encoding: jsonwebtoken::EncodingKey, decoding: jsonwebtoken::DecodingKey, jwk: serde_json::Value, source: KeySource }`, `SigningKey::load(&Config) -> Result<SigningKey,String>`, `SigningKey::from_seed(&str)`, `SigningKey::from_pem(&str)`, `SigningKey::random()`.

- [ ] **Step 1: Cargo.toml + .gitignore**

```toml
[package]
name = "nano-mockidp"
version = "0.0.0"
edition = "2021"
license = "MIT"
description = "Lightweight mock OpenID Connect provider for dev and CI"

[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
jsonwebtoken = "9"
rsa = { version = "0.9", features = ["pem", "sha2"] }
rand = "0.8"
rand_chacha = "0.3"
sha2 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tower-http = { version = "0.6", features = ["cors", "trace"] }
base64 = "0.22"
url = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
reqwest = { version = "0.12", features = ["json"], default-features = false }

[profile.release]
lto = true
codegen-units = 1
strip = true
```

`.gitignore`: `/target`.

- [ ] **Step 2: Write failing unit tests in `src/config.rs` and `src/keys.rs`**

config tests: defaults from empty map; `ISSUER_URL=http://x:1/oidc/` → `issuer_path == "/oidc"`, issuer_url without trailing slash; `CLIENTS` JSON parsed; `CORS_ALLOWED_ORIGINS=a,b` → vec; invalid `PORT` → Err.

keys tests: `from_seed("a").kid == from_seed("a").kid`; `from_seed("a").kid != from_seed("b").kid`; `random().kid != random().kid`; `from_pem(&from_seed("a").to_pem()).kid == from_seed("a").kid` (add `to_pem()` helper for tests); jwk has `kty=RSA, alg=RS256, use=sig, kid, n, e`.

- [ ] **Step 3: Implement config.rs**

Parse env into `HashMap`, then `from_map`. Trim trailing `/` from issuer URL; `issuer_path` = url path with trailing slash removed, `"/"` → `""`. Booleans accept `true/1/yes` case-insensitive.

- [ ] **Step 4: Implement keys.rs**

Seeded: `Sha256(seed)` → `ChaCha20Rng::from_seed` → `RsaPrivateKey::new(&mut rng, 2048)`. Random: `RsaPrivateKey::new(&mut rand::thread_rng(), 2048)`. PEM: try `RsaPrivateKey::from_pkcs1_pem` then `from_pkcs8_pem`. kid = hex(sha256(public_key_der))[..16]. Encoding via `EncodingKey::from_rsa_pem(pkcs1_pem)`, decoding via `DecodingKey::from_rsa_components(n_b64url, e_b64url)`. jwk = `{kty, use:"sig", alg:"RS256", kid, n, e}`.

- [ ] **Step 5: main.rs minimal** — init tracing from `LOG_LEVEL`, load config + key, log kid + source, print "listening"; no routes yet. `cargo build` and `cargo test` pass.

- [ ] **Step 6: Commit** `feat: scaffold, config parsing, signing key loading`

---

### Task 2: Store, token issuance, PKCE, URLs, error type

**Files:**
- Create: `src/store.rs`, `src/token.rs`, `src/urls.rs`, `src/error.rs`, `src/state.rs`

**Interfaces:**
- `store.rs`: `Store { pending: HashMap<String, Expiring<AuthRequest>>, codes: HashMap<String, Expiring<CodeEntry>>, refresh: HashMap<String, Expiring<RefreshEntry>>, clients: HashMap<String, Client> }`. `Expiring<T> { value: T, expires_at: SystemTime }`. `AuthRequest { client_id, redirect_uri, state: Option, scope: Option, nonce: Option, code_challenge: Option }`. `CodeEntry { req: AuthRequest, claims: serde_json::Map<String, Value>, auth_time: u64, expires_in: Option<u64> }`. `RefreshEntry { client_id, scope: Option, claims, auth_time, expires_in: Option<u64> }`. `Client { client_id, client_secret: Option<String>, redirect_uris: Option<Vec<String>>, metadata: Value }`. `Store::sweep(now)`. `random_token() -> String`.
- `token.rs`: `pub struct Issuer<'a> { key: &SigningKey, issuer: &str, access_ttl: u64, id_ttl: u64 }`; `issue(&self, IssueParams) -> TokenSet`; `IssueParams { client_id, scope: Option<String>, nonce: Option<String>, claims: Map, auth_time: u64, expires_in: Option<u64>, with_id_token: bool }`; `TokenSet { access_token, id_token: Option<String>, expires_in: u64 }`; `verify(key, issuer, token) -> Result<Map, String>` (validates exp, iss; no aud); `pkce_verify(verifier, challenge) -> bool`; `merge_claims(base: Map, user: Map) -> Map` (user wins except `iss/exp/iat/jti`).
- `urls.rs`: `RequestBase(String)` axum `FromRequestParts` extractor producing `scheme://host` from `X-Forwarded-Proto`, `X-Forwarded-Host`, else `Host`, scheme default `http`. `Endpoints::resolve(cfg, request_base: Option<&str>) -> Endpoints { issuer, authorization, end_session, token, jwks, userinfo, introspection, registration }` following spec precedence.
- `error.rs`: `OAuthError { status: StatusCode, error: &'static str, description: String }` with ctors `invalid_request(msg)`, `invalid_client(msg)` (401 + `WWW-Authenticate: Basic`), `invalid_grant(msg)`, `unsupported_grant_type()`, `server_error(msg)`; `IntoResponse` → JSON `{error, error_description}` + `Cache-Control: no-store`.
- `state.rs`: `AppState { config: Config, key: SigningKey, store: Mutex<Store> }`, `type SharedState = Arc<AppState>`; `AppState::new(config) -> Result<Self,String>` also pre-loads `config.clients` into `store.clients`.

- [ ] **Step 1: Unit tests** — pkce_verify with known vector (verifier `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → challenge `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`); merge_claims precedence; Endpoints::resolve for: default, request base differs, `ENDPOINTS_FROM_REQUEST_HOST=false`, `INTERNAL_URL` set, issuer with path; token issue+verify roundtrip, `iss` equals issuer, id_token has `nonce` + `at_hash`, access header `typ=at+jwt`; store sweep removes expired.

- [ ] **Step 2: Implement** all five files.

Claims per spec: `iss, sub, aud(=client_id), azp, exp, iat, auth_time, jti, scope` + merged user claims; id token adds `nonce`, `at_hash` = base64url(sha256(access_token)[..16]). Header `kid`, `typ`.

- [ ] **Step 3: `cargo test` passes. Commit** `feat: store, token issuance, pkce, url resolution`

---

### Task 3: Routes — discovery, jwks, health, authorize (GET/POST), login page

**Files:**
- Create: `src/routes/mod.rs`, `discovery.rs`, `jwks.rs`, `health.rs`, `authorize.rs`, `src/login.rs`, `static/login.html`
- Modify: `src/main.rs` (serve router, spawn sweep every 60s)
- Test: `tests/common/mod.rs`, `tests/flow.rs`

**Interfaces:**
- `routes::router(state: SharedState) -> axum::Router` — nests under `config.issuer_path` (or root if empty); `/health` at root and under path; CORS layer from config; trace layer.
- `login::load_login_page(cfg) -> Result<String, std::io::Error>`; `login::DEFAULT_LOGIN_PAGE: &str = include_str!("../static/login.html")`.
- Test helper: `common::spawn(env: &[(&str,&str)]) -> TestServer { base: String /* http://127.0.0.1:port + issuer_path */, root: String, client: reqwest::Client /* redirect::Policy::none */ }`. Server started in-process via `tokio::spawn(axum::serve(listener, router))` on port 0; `Config::from_map` with `PORT` ignored; `ISSUER_URL` default for tests `http://localhost:{port}` unless overridden.

- [ ] **Step 1: Integration tests** in `tests/flow.rs`:
  - `discovery_shape`: GET `.well-known/openid-configuration` → `response_types_supported == ["code"]`, `code_challenge_methods_supported == ["S256"]`, `issuer == ISSUER_URL`, `token_endpoint` starts with request base.
  - `discovery_host_derivation`: spawn with `ISSUER_URL=http://public.example/oidc`; request with header `Host: backend:9`; assert `issuer == http://public.example/oidc`, `authorization_endpoint == http://public.example/oidc/authorize`, `jwks_uri == http://backend:9/oidc/jwks`.
  - `jwks_has_key`: one key with kid.
  - `authorize_get_renders_login`: GET authorize with params → 200, body contains `name="username"` and `Kapernikov`.
  - `authorize_get_rejects_wrong_response_type`: `response_type=token` → 302 to redirect_uri with `error=unsupported_response_type`.
  - `authorize_post_issues_code`: POST form `username=alice&claims={"email":"a@b"}` → 302 Location `redirect_uri?code=...&state=...`.
  - `authorize_post_bad_claims_json` → 400.
  - `custom_login_page`: write temp html, spawn with `LOGIN_PAGE_PATH`, GET authorize returns it verbatim.
  - `health`: root `/health` and under path both 200.

- [ ] **Step 2: Implement** discovery/jwks/health/authorize/login, `static/login.html` (Kapernikov: inline `assets/kapernikov-logo.svg`, palette vars from spec, fields `username`, `claims` textarea prefilled `{"email": "user@example.com", "name": "Test User"}`, `expires_in`, JS showing `client_id/scope/redirect_uri` from `location.search`; form `method="post"` no action).

Authorize GET validation order: parse query (`serde` struct with all optional); `client_id` + `redirect_uri` required else 400 HTML; strict: client exists + redirect_uri registered else 400 HTML; `response_type != code` → redirect error `unsupported_response_type`; `code_challenge_method` present and `!= S256` → redirect `invalid_request`; strict + public client + no challenge → redirect `invalid_request`. Then store pending (TTL 600s) and return login page.

Authorize POST: same validation; parse form `{username, claims, expires_in}`; claims: empty → `{}`, else `serde_json::from_str::<Map>` else 400 HTML; `sub` = claims.sub or username; neither → 400. Create code (TTL 300s). 302.

- [ ] **Step 3: Tests pass. Commit** `feat: discovery, jwks, authorize, default login page`

---

### Task 4: Token endpoint (all grants), userinfo, introspect, end_session, register

**Files:**
- Create: `src/routes/token.rs`, `userinfo.rs`, `introspect.rs`, `session.rs`, `register.rs`
- Modify: `src/routes/mod.rs`
- Test: `tests/flow.rs`

- [ ] **Step 1: Integration tests**:
  - `full_pkce_flow`: generate verifier, challenge; GET+POST authorize; POST token (`client_secret_post`) → 200 with access/id/refresh; decode id_token header kid == jwks kid; verify with `jsonwebtoken` against jwks n/e; `iss == ISSUER_URL`, `aud == client_id`, `nonce` echoed, `email == a@b`, `sub == alice`.
  - `wrong_verifier_rejected` → 400 `invalid_grant`.
  - `code_reuse_rejected`.
  - `redirect_uri_mismatch_rejected`.
  - `refresh_rotates`: refresh → new tokens, claims preserved (`email`), old refresh → `invalid_grant`.
  - `client_credentials`: `sub == client_id`, no id_token, no refresh_token.
  - `basic_auth_accepted`.
  - `strict_mode`: spawn `STRICT=true`, `CLIENTS=[{"client_id":"app","client_secret":"s","redirect_uris":["http://app/cb"]}]`; unknown client on authorize → 400; wrong redirect → 400; wrong secret on token → 401 `invalid_client`; DCR register then full flow with registered client works.
  - `userinfo`: bearer access → 200 JSON with `sub`,`email`, no `exp`; bad token → 401.
  - `introspect`: active true for access; `{"active":false}` for garbage; refresh token active with `client_id`.
  - `end_session`: with `post_logout_redirect_uri` → 302 with state; without → 200.
  - `register`: POST JSON → 201 with `client_id`, `client_secret`; with `token_endpoint_auth_method: none` → no secret.
  - `unsupported_grant` → 400.

- [ ] **Step 2: Implement.**

Token endpoint: body form (`grant_type`, `code`, `redirect_uri`, `code_verifier`, `refresh_token`, `client_id`, `client_secret`, `scope`, `audience`). Client auth: Basic header (percent-decoded) overrides body. Resolve `client_id` (required; from auth or body). Strict: client must exist in store; if client has secret, provided secret must match else `invalid_client`. Permissive: anything.

- authorization_code: pop code (remove regardless of outcome) → missing/expired `invalid_grant`; `entry.req.client_id != client_id` → `invalid_grant`; `redirect_uri` must be present and equal; if `code_challenge` set → `code_verifier` required and `pkce_verify` else `invalid_grant`. Issue tokens (`with_id_token: true`), create refresh token (TTL `REFRESH_TOKEN_TTL`) storing claims/auth_time/expires_in/scope.
- refresh_token: pop entry → `invalid_grant` if missing; `client_id` must match; issue tokens, new refresh token.
- client_credentials: claims `{sub: client_id}`; aud = `audience` or client_id (pass via claims override `aud`); `with_id_token: false`; no refresh.

Response JSON: `access_token, token_type:"Bearer", expires_in, scope?, id_token?, refresh_token?`; headers `Cache-Control: no-store`, `Pragma: no-cache`.

Userinfo: bearer from `Authorization` (GET or POST); `token::verify`; strip `exp iat jti at_hash nonce azp scope`; 401 + `WWW-Authenticate: Bearer error="invalid_token"` on failure.

Introspect: form `token`; try JWT verify → `{active:true, ...claims, token_type:"Bearer", client_id: aud}`; else lookup refresh store → `{active:true, sub, client_id, exp, token_type:"refresh_token"}`; else `{active:false}`.

End_session: query `post_logout_redirect_uri`, `state` → 302 or 200 HTML.

Register: JSON body (arbitrary Value); `client_id = random_token()`, `client_secret = random_token()` unless `token_endpoint_auth_method == "none"`; store Client with `redirect_uris`; respond 201 with input metadata merged + `client_id`, `client_secret?`, `client_id_issued_at`, `client_secret_expires_at: 0`, `token_endpoint_auth_method` (default `client_secret_basic`), `grant_types` default `["authorization_code","refresh_token"]`, `response_types: ["code"]`.

- [ ] **Step 3: Tests pass, `cargo clippy -D warnings`, `cargo fmt`. Commit** `feat: token, userinfo, introspect, end_session, register endpoints`

---

### Task 5: Dockerfile, CI, README, examples, first release

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `.github/workflows/ci.yml`, `README.md`, `LICENSE`, `examples/login.html`, `examples/docker-compose.yml`

- [ ] **Step 1: Dockerfile** — stage 1 `rust:1-alpine` (musl) with `apk add musl-dev`, cache deps, `cargo build --release --target x86_64-unknown-linux-musl` / arm64 via `TARGETPLATFORM` mapping; stage 2 `FROM scratch`, copy binary to `/nano-mockidp`, `USER 65534:65534`, `EXPOSE 8080`, `ENTRYPOINT ["/nano-mockidp"]`. Verify locally: `docker build -t nano-mockidp . && docker run --rm -p 8080:8080 nano-mockidp` → curl discovery.

- [ ] **Step 2: CI workflow** — triggers: push `main`, tags `v*`, PRs. Job `test`: checkout, `dtolnay/rust-toolchain@stable` with clippy+rustfmt, `Swatinem/rust-cache`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`. Job `image` (needs test, not on PR): `docker/setup-qemu-action`, `docker/setup-buildx-action`, `docker/login-action` ghcr with `GITHUB_TOKEN`, `docker/metadata-action` images `ghcr.io/${{ github.repository }}` tags: `type=semver,pattern={{version}}`, `type=semver,pattern={{major}}.{{minor}}`, `type=sha`, `type=raw,value=latest,enable={{is_default_branch}}`; `docker/build-push-action` platforms `linux/amd64,linux/arm64`, push, GHA cache. Permissions `contents: read, packages: write`. Job `release` on tags: `softprops/action-gh-release` with generated notes.

- [ ] **Step 3: README** — what/why, quick start (docker run), env var table (copy from spec), login page contract + example, public/internal URL explanation, endpoints list, docker-compose example, strict mode + DCR example, `SIGNING_KEY_SEED` note, comparison to navikt.

- [ ] **Step 4: examples/login.html** — custom page with per-project preset buttons filling the textarea. `examples/docker-compose.yml` — mockidp + LOGIN_PAGE_PATH mount.

- [ ] **Step 5: Commit** `feat: Dockerfile, CI, README, examples`. Push `main` (`gh repo create Kapernikov/nano-mockidp --public --source . --push` if repo does not exist yet, else `git push -u origin main`).

- [ ] **Step 6: Watch CI** `gh run watch`; fix failures; tag `v0.1.0`, push tag; watch; verify `docker pull ghcr.io/kapernikov/nano-mockidp:0.1.0` and run it. If package is private by default, make it public via `gh api -X PATCH /orgs/Kapernikov/packages/container/nano-mockidp/visibility` or note for the user.

---

## Self-review

- Spec coverage: config ✓(T1), keys/seed ✓(T1), URL rules ✓(T2/T3), all endpoints ✓(T3/T4), login page default+custom ✓(T3), branding ✓(T3), store/sweep ✓(T2/T3), claims ✓(T2), tests ✓, CI/release ✓(T5), examples ✓(T5).
- Names consistent: `SharedState`, `Store`, `Issuer::issue`, `token::verify`, `pkce_verify`, `Endpoints::resolve`, `RequestBase`, `random_token`, `load_login_page`.
