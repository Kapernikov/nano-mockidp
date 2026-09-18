# nano-mockidp — Design

Lightweight mock OpenID Connect provider for local development and CI. A drop-in
alternative to navikt/mock-oauth2-server with a fraction of the footprint: single
static Rust binary, `FROM scratch` container image, all configuration via
environment variables, optional bind-mount for a custom login page.

## Goals

- Authorization code flow with PKCE (S256), token refresh, client credentials.
- Discovery document with `response_types_supported: ["code"]`.
- Dynamic Client Registration (RFC 7591).
- Customizable HTML login form: server only cares about two form fields
  (`username`, `claims`). Project-specific presets live in the user's own HTML.
- Optional deterministic signing key (from a seed string) for relying parties
  that cache JWKS across IdP restarts.
- Solve the "browser sees `localhost`, backend sees `service-name`" problem in
  the IdP instead of in every relying party.

## Non-goals

- Persistence across restarts (state is in memory; a seeded key is available if
  a stable JWKS is wanted).
- TLS (terminated by ingress / not needed locally).
- Token revocation endpoint (RFC 7009).
- Multiple issuers per instance.
- Any real security: tokens are forgeable by design.

## Stack

Rust, `axum` + `tokio`, `rsa` for key generation, `jsonwebtoken` for RS256
sign/verify, `serde`/`serde_json`, `rand_chacha` for seeded key derivation,
`tower-http` for CORS + tracing. Binary built with musl target, image
`FROM scratch`, published to `ghcr.io/kapernikov/nano-mockidp` by GitHub Actions
(amd64 + arm64).

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listen port (binds `0.0.0.0`). |
| `ISSUER_URL` | `http://localhost:8080` | Public issuer. Value of the `iss` claim and of `issuer`, `authorization_endpoint`, `end_session_endpoint` in discovery. Its path component is the mount path for all routes (e.g. `http://localhost:8080/oidc` → routes under `/oidc/`). |
| `ISSUER_FROM_REQUEST_HOST` | `false` | Opt-in (added v0.2.0): `iss`, `issuer`, `authorization_endpoint`, `end_session_endpoint` derive from the request scheme/host + `ISSUER_URL` path. `/userinfo` and `/introspect` then verify only signature, `exp`, and that the `iss` path equals the issuer path. |
| `ENDPOINTS_FROM_REQUEST_HOST` | `true` | Build backend-facing endpoint URLs in discovery from the requesting `Host` (honouring `X-Forwarded-Proto`/`X-Forwarded-Host`). |
| `INTERNAL_URL` | unset | If set, backend-facing endpoints use this base URL instead (overrides host derivation). |
| `STRICT` | `false` | Strict mode: only known clients, redirect_uri must match, PKCE required for public clients, client_secret checked. Permissive mode accepts anything. |
| `CLIENTS` | `[]` | JSON array of `{"client_id","client_secret"?,"redirect_uris"?:[...]}` pre-registered clients. |
| `LOGIN_PAGE_PATH` | unset | Path to a custom login HTML file. Re-read on every request. |
| `ACCESS_TOKEN_TTL` | `3600` | Seconds. |
| `ID_TOKEN_TTL` | `3600` | Seconds. |
| `REFRESH_TOKEN_TTL` | `2592000` | Seconds (30 days). |
| `SIGNING_KEY_SEED` | unset | Any string → deterministic RSA-2048 key (same string ⇒ same key/`kid`). Unset ⇒ fresh random key each start. |
| `SIGNING_KEY_PEM` | unset | PKCS#1 or PKCS#8 PEM private key inline. Takes precedence over seed. |
| `SIGNING_KEY_PATH` | unset | Path to PEM file. Takes precedence over seed. |
| `CORS_ALLOWED_ORIGINS` | `*` | Comma-separated origins, or `*`. |
| `LOG_LEVEL` | `info` | `tracing` filter. |

Startup logs the `kid` and whether the key is random, seeded, or loaded from PEM.

### Deterministic key derivation

`seed_bytes = SHA-256(SIGNING_KEY_SEED)` → `ChaCha20Rng::from_seed(seed_bytes)` →
`RsaPrivateKey::new(&mut rng, 2048)`. `kid` = first 16 hex chars of
SHA-256 of the DER-encoded public key. Same seed ⇒ same key and same `kid` on
any machine and any version (the `rsa` crate's keygen is deterministic given
the RNG; a major `rsa` upgrade that changes the algorithm is a breaking change
and gets a major version bump).

## Public vs. internal URLs

Relying parties in docker-compose / k8s reach the IdP at one hostname
(`http://mockidp:8080`) while the browser reaches it at another
(`http://localhost:8080`). Both must agree on `iss`.

Rules:

1. `iss` claim and discovery `issuer` are **always** `ISSUER_URL`.
2. `authorization_endpoint` and `end_session_endpoint` are **always** derived
   from `ISSUER_URL` (the browser follows them).
3. `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, `introspection_endpoint`,
   `registration_endpoint` are derived, in order of precedence, from
   `INTERNAL_URL` if set; else the request's scheme/host (when
   `ENDPOINTS_FROM_REQUEST_HOST=true`); else `ISSUER_URL`. The path component is
   always taken from `ISSUER_URL`.
4. The server never validates `Host`; every endpoint works on any hostname.
5. Request host derivation: `X-Forwarded-Proto` (default `http`), `X-Forwarded-Host`
   (+ `:X-Forwarded-Port` when the forwarded host carries no port and the port is not the
   scheme default), else `Host`.
6. With `ISSUER_FROM_REQUEST_HOST=true`, rule 1 and 2 use the request host instead of
   `ISSUER_URL` (path unchanged). Needed when the browser-facing port is dynamic.

Result: a backend fetching discovery via the service hostname gets endpoints it
can reach and an `issuer` equal to what it configured; the browser gets
`localhost` endpoints. No URL rewriting on the client side.

## Endpoints

All paths are relative to the path component of `ISSUER_URL`.

### `GET /.well-known/openid-configuration`

```json
{
  "issuer": "...",
  "authorization_endpoint": ".../authorize",
  "token_endpoint": ".../token",
  "jwks_uri": ".../jwks",
  "userinfo_endpoint": ".../userinfo",
  "introspection_endpoint": ".../introspect",
  "end_session_endpoint": ".../end_session",
  "registration_endpoint": ".../register",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "name"]
}
```

### `GET /jwks`

`{"keys":[{kty:"RSA", use:"sig", alg:"RS256", kid, n, e}]}`.

### `GET /authorize`

Query: `response_type` (must be `code`), `client_id` (required),
`redirect_uri` (required), `state`, `scope`, `nonce`, `code_challenge`,
`code_challenge_method` (must be `S256` if present), `resource` (RFC 8707, may
repeat; stored with the request, added v0.3.0).

Strict mode additionally: client must exist; `redirect_uri` must be in the
client's registered list (exact match); `code_challenge` required when the
client has no secret.

On success: store a pending authorization request keyed by a random id (TTL 10
min) and render the login page with HTTP 200. The pending id is not exposed —
the form posts back to the same URL including the original query string, and
the server re-validates parameters on POST. This keeps custom HTML pages free
of templating.

On error: if `redirect_uri` is syntactically valid (and, in strict mode,
registered), 302 to it with `error`, `error_description`, `state`. Otherwise
400 with a plain HTML error page.

### `POST /authorize`

`application/x-www-form-urlencoded` body:

- `username` — becomes `sub`. Required unless `claims` contains `sub`.
- `claims` — optional JSON object, merged over the defaults; may override
  `sub`, `aud`, `email`, anything except `iss`, `exp`, `iat`, `jti`.
- `expires_in` — optional, overrides `ACCESS_TOKEN_TTL`/`ID_TOKEN_TTL` for
  tokens issued from this login (and later refreshes of it).

Query string: same as `GET /authorize`, re-validated.

Invalid `claims` JSON → 400 HTML with the error message (not a redirect: the
user is still on the login page and should fix their input).

On success: create an authorization code (random 32 bytes, base64url, TTL 5
min, single use) bound to `client_id`, `redirect_uri`, `code_challenge`,
`nonce`, `scope`, the merged claims and `auth_time`. 302 to
`redirect_uri?code=...&state=...`.

### `POST /token`

Client authentication: HTTP Basic, or `client_id`/`client_secret` in body, or
`client_id` only (public client). Permissive mode: any client id/secret passes.
Strict mode: client must exist and secret must match if the client has one.

Grants:

- `authorization_code`: `code`, `redirect_uri` (must equal the one bound to the
  code), `code_verifier` (required if the code carries a `code_challenge`;
  verified as `BASE64URL(SHA256(verifier)) == challenge`). `client_id` must
  match the code's. Code consumed on first use (success or failure).
- `refresh_token`: `refresh_token`. Must exist and be unexpired. Old token is
  deleted, new one issued (rotation). Tokens re-issued with the claims stored
  at login, fresh `iat`/`exp`/`jti`, same `auth_time`.
- `client_credentials`: no user. Claims: `sub = client_id`, `scope`. No id_token,
  no refresh token.

Audience (all grants, v0.3.0): `aud` = token-time `resource` value(s) (string or
array), else token-time `audience`, else authorize-time `resource`(s) (carried
into the refresh token), else `client_id`. `azp` is always `client_id`. An `aud`
in the user-typed claims overrides all of these.

Response (200, `Cache-Control: no-store`):

```json
{"access_token":"...","id_token":"...","refresh_token":"...","token_type":"Bearer","expires_in":3600,"scope":"openid profile"}
```

Errors: RFC 6749 §5.2 JSON (`invalid_request`, `invalid_client` (401),
`invalid_grant`, `unsupported_grant_type`).

### Token claims

Common to access and id token: `iss`, `sub`, `aud` (= `client_id`), `azp`
(= `client_id`), `exp`, `iat`, `auth_time`, `jti`, `scope`, plus user claims.
`id_token` additionally: `nonce` (if given), `at_hash`. Header: `alg: RS256`,
`kid`, `typ: JWT` (id token) / `typ: at+jwt` (access token).

Both tokens are JWTs signed with the same key so backends can verify access
tokens locally against the JWKS.

### `GET|POST /userinfo`

`Authorization: Bearer <access_token>`. Verifies signature and `exp`; returns
all claims of the token as JSON (minus `exp`, `iat`, `jti`, `at_hash`,
`nonce`, `azp`, `scope`). 401 with `WWW-Authenticate: Bearer error="invalid_token"`
on failure.

### `POST /introspect`

RFC 7662. Body `token` (+ optional client auth, ignored in permissive mode).
Returns `{"active": true, ...claims, "token_type":"Bearer"}` for a valid
access/id JWT, `{"active": false}` otherwise. Refresh tokens are also
introspectable: active if present in the store, with `sub`, `client_id`,
`exp`.

### `GET /end_session`

Query `post_logout_redirect_uri`, `state`, `id_token_hint` (ignored). If a
redirect URI is given → 302 to it (with `state`). Else 200 HTML "Logged out".
No server-side session exists, so nothing to invalidate.

### `POST /register`

RFC 7591. JSON body; honours `redirect_uris`, `client_name`,
`token_endpoint_auth_method`, `grant_types`, `scope`. Generates `client_id`
(random) and `client_secret` (random; omitted when
`token_endpoint_auth_method == "none"`). Stores the client in memory. Returns
201 with the registered metadata plus `client_id_issued_at`,
`client_secret_expires_at: 0`. Works in both modes; in strict mode this is the
runtime way to add clients.

### `GET /health`

200 `{"status":"ok"}`. Served at the root `/health` **and** under the issuer
path.

## Login page

### Default page

Embedded in the binary. No external assets. Kapernikov branding: inline
horizontal Kapernikov SVG logo (from the official logo pack), colour palette
from the Kapernikov theme (`--kpv-primary: #ba2415`, dark grey `#484847`,
medium grey `#818281`, light grey `#bfc0c0`, very light grey `#ececec`, beige
`#e2d7cd`), system sans-serif font stack. Contains:

- text input `username`
- textarea `claims` prefilled with `{"email": "user@example.com", "name": "Test User"}`
- number input `expires_in` (empty by default)
- submit button
- small JS: shows `client_id`, `scope`, `redirect_uri` from `location.search`
  for orientation.

### Custom page

`LOGIN_PAGE_PATH` points to any HTML file; the server serves it verbatim as
`text/html` on `GET /authorize`, re-reading it on each request (edit while
running). Contract:

- A `<form method="post">` with **no `action`** (or `action=""`) so it posts
  back to the same URL, preserving the OAuth query parameters.
- Fields named `username`, `claims` (optional), `expires_in` (optional).
- Anything else (preset buttons per project that fill the textarea, styling,
  JS) is up to the page.

If the file cannot be read → 500 with the OS error in the body.

## State

Single `AppState` behind `Arc`, containing the config, signing key, and a
`Mutex<Store>` with four maps: pending auth requests, authorization codes,
refresh tokens, registered clients. Each entry carries an expiry; a
background task sweeps expired entries every 60 s. All ids/tokens/secrets are
32 random bytes, base64url without padding.

## Code layout

```
src/
  main.rs          — parse config, build state, router, serve
  config.rs        — env parsing, defaults, validation
  keys.rs          — seed/PEM key loading, kid, JWKS document
  store.rs         — in-memory maps + sweep
  token.rs         — claims assembly, sign, verify, at_hash, PKCE check
  urls.rs          — public/internal endpoint URL resolution from request
  login.rs         — default page + custom page loading
  error.rs         — OAuth error type → HTTP response
  routes/
    mod.rs         — router assembly under issuer path
    discovery.rs, jwks.rs, authorize.rs, token.rs, userinfo.rs,
    introspect.rs, register.rs, session.rs, health.rs
tests/
  flow.rs          — integration tests against a live server
Dockerfile, .github/workflows/ci.yml, README.md, examples/login.html,
examples/docker-compose.yml
```

## Testing

Unit tests: PKCE verification, deterministic key derivation (same seed ⇒ same
`kid`; different seed ⇒ different), claims merge precedence, URL derivation
(host header, forwarded headers, `INTERNAL_URL`, disabled derivation).

Integration tests (`tests/flow.rs`): start the server on an ephemeral port
with a given config, drive it with `reqwest` (redirects disabled):

- discovery document shape, `response_types_supported == ["code"]`
- full code + PKCE flow → tokens verify against JWKS, `iss` == `ISSUER_URL`
- wrong `code_verifier` → `invalid_grant`; code reuse → `invalid_grant`
- refresh: new tokens, old refresh token rejected, claims preserved
- client_credentials
- strict mode: unknown client rejected, bad redirect_uri rejected, DCR-registered client accepted
- custom login page served verbatim, `claims` override `sub`
- discovery via different `Host` header → backend endpoints follow host, issuer does not
- userinfo, introspect, end_session

## CI / release

GitHub Actions on push to `main` and tags `v*`:

1. `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.
2. `docker buildx` multi-arch (linux/amd64, linux/arm64) → push
   `ghcr.io/kapernikov/nano-mockidp:<tag>`, `:sha-<short>`, and `:latest` on
   main. Image: multi-stage, musl static binary, `FROM scratch`, non-root user,
   `EXPOSE 8080`.

## Example usage

```yaml
services:
  mockidp:
    image: ghcr.io/kapernikov/nano-mockidp:latest
    ports: ["8080:8080"]
    environment:
      ISSUER_URL: http://localhost:8080
    volumes:
      - ./login.html:/login.html:ro
    # LOGIN_PAGE_PATH: /login.html
  backend:
    environment:
      AUTH_ISSUER: http://localhost:8080          # matches iss
      OIDC_DISCOVERY: http://mockidp:8080/.well-known/openid-configuration
```
