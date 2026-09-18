# nano-mockidp

A tiny mock OpenID Connect provider for local development and CI.
Drop-in alternative to [navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server),
written in Rust: a single static binary, a **~4 MB `FROM scratch` container image**, sub-second
startup, everything configured through environment variables.

- Authorization code flow with **PKCE (S256)**, `response_types_supported: ["code"]`
- **Refresh tokens** (rotating), **client_credentials**
- **Dynamic Client Registration** (RFC 7591)
- **Customizable HTML login form**: bring your own page with per-project test personas, or type
  claims into a textarea. Any username, any claims — the tokens contain what you enter.
- Discovery, JWKS, userinfo, introspection (RFC 7662), end_session
- Solves the *"browser sees `localhost`, backend sees `mockidp`"* problem inside the IdP
- Permissive by default; `STRICT=true` for real client/redirect/secret validation
- Optional deterministic signing key (`SIGNING_KEY_SEED`) so JWKS survives restarts

Not a real identity provider. Tokens are forgeable by design. Never expose it publicly.

## Quick start

```sh
docker run --rm -p 8080:8080 ghcr.io/kapernikov/nano-mockidp:latest
```

```sh
curl http://localhost:8080/.well-known/openid-configuration
```

Point your app at `http://localhost:8080` as issuer, use any `client_id`, and open the authorize URL
your app generates. You get the login page: enter a username, optionally edit the claims JSON, sign in.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listen port (binds `0.0.0.0`). |
| `ISSUER_URL` | `http://localhost:8080` | Public issuer URL. Value of the `iss` claim and of `issuer`, `authorization_endpoint`, `end_session_endpoint` in discovery. Its **path is the mount path** for all routes (`http://localhost:8080/oidc` → everything under `/oidc/`). |
| `ISSUER_FROM_REQUEST_HOST` | `false` | Opt-in: `iss`, `issuer`, `authorization_endpoint`, `end_session_endpoint` follow the requesting host too (like mock-oauth2-server). Path still comes from `ISSUER_URL`. `/userinfo` and `/introspect` then accept tokens from any host with that path. Use when the browser-facing port is not known in advance (devcontainer forwarded ports, one port per worktree). |
| `ENDPOINTS_FROM_REQUEST_HOST` | `true` | Derive backend-facing endpoint URLs in discovery from the requesting `Host` (honours `X-Forwarded-Proto` / `X-Forwarded-Host`). See below. |
| `INTERNAL_URL` | – | If set, backend-facing endpoints use this base URL instead of the request host. |
| `STRICT` | `false` | Strict mode: only known clients, `redirect_uri` must be registered, `client_secret` checked, PKCE required for public clients. |
| `CLIENTS` | `[]` | JSON array of pre-registered clients: `[{"client_id":"app","client_secret":"s","redirect_uris":["http://localhost:3000/cb"]}]`. |
| `LOGIN_PAGE_PATH` | – | Path to a custom login HTML file. Re-read on every request, so you can edit it live. |
| `ACCESS_TOKEN_TTL` | `3600` | Seconds. |
| `ID_TOKEN_TTL` | `3600` | Seconds. |
| `REFRESH_TOKEN_TTL` | `2592000` | Seconds (30 days). |
| `SIGNING_KEY_SEED` | – | Any string → deterministic RSA-2048 key (same string ⇒ same key and `kid`, on any machine). Unset ⇒ fresh random key on every start. |
| `SIGNING_KEY_PEM` | – | RSA private key (PKCS#1 or PKCS#8 PEM) inline. Takes precedence over the seed. |
| `SIGNING_KEY_PATH` | – | Path to a PEM file. Takes precedence over the seed. |
| `CORS_ALLOWED_ORIGINS` | `*` | Comma-separated list of origins, or `*`. |
| `LOG_LEVEL` | `info` | [`tracing`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) filter, e.g. `debug` or `tower_http=debug`. |

## The login page

### Default page

Built in, Kapernikov-branded, no external assets. Fields: **username** (becomes `sub`), a **claims**
textarea (JSON object merged into the tokens; may override `sub`, `aud`, anything except
`iss`/`exp`/`iat`/`jti`), and an optional **token lifetime** override.

### Your own page

Set `LOGIN_PAGE_PATH=/login.html` and mount any HTML file there. The server serves it verbatim on
`GET /authorize`. The only contract:

- a `<form method="post">` **without `action`** (so it posts back to the same URL and the OAuth
  query parameters survive),
- a field named `username`,
- optionally a field named `claims` (JSON object) and one named `expires_in` (seconds).

Everything else — preset buttons per project, tenants, roles, styling — is up to your HTML.
See [`examples/login.html`](examples/login.html). The page can read `client_id`, `scope`,
`redirect_uri` from `location.search` if it wants to show them.

## Public vs. internal URLs (docker-compose / k8s)

In compose the browser reaches the IdP at `http://localhost:8080` while your backend reaches it at
`http://mockidp:8080`. Both must agree on `iss`, but the backend cannot fetch `localhost` URLs.
nano-mockidp handles this so you don't have to rewrite URLs in the relying party:

1. `iss`, `issuer`, `authorization_endpoint`, `end_session_endpoint` are **always** `ISSUER_URL`
   (the browser-facing URL).
2. `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, `introspection_endpoint`,
   `registration_endpoint` are built from **whoever is asking**: the request `Host`
   (or `X-Forwarded-*`), with the path from `ISSUER_URL`. Override with `INTERNAL_URL`, or
   disable with `ENDPOINTS_FROM_REQUEST_HOST=false` to get fixed `ISSUER_URL`-based URLs.
3. The server never validates `Host`; every endpoint works on any hostname.
4. Request host = `X-Forwarded-Proto` + `X-Forwarded-Host` (+ `X-Forwarded-Port` when the
   forwarded host has none and the port is non-default), else `Host`.

If you *cannot* know the browser-facing URL in advance (e.g. VS Code forwards a random port and
the SPA computes the issuer from `window.location.origin`), set `ISSUER_FROM_REQUEST_HOST=true`:
the issuer then follows the request host exactly like mock-oauth2-server does, and token
verification on `/userinfo` / `/introspect` only checks signature, expiry and the issuer *path*.

So the backend fetches `http://mockidp:8080/.well-known/openid-configuration`, gets
`issuer = http://localhost:8080` (what it configured) and `jwks_uri = http://mockidp:8080/jwks`
(what it can reach). See [`examples/docker-compose.yml`](examples/docker-compose.yml).

## Endpoints

All relative to the path of `ISSUER_URL`.

| Path | Notes |
|---|---|
| `GET /.well-known/openid-configuration` | `response_types_supported: ["code"]`, `code_challenge_methods_supported: ["S256"]` |
| `GET /jwks` | One RS256 key |
| `GET /authorize` | Renders the login page. Params: `response_type=code`, `client_id`, `redirect_uri`, `state`, `scope`, `nonce`, `code_challenge`, `code_challenge_method=S256` |
| `POST /authorize` | Form post from the login page → `302 redirect_uri?code=…&state=…` |
| `POST /token` | Grants: `authorization_code` (+ `code_verifier`), `refresh_token` (rotating), `client_credentials`. Client auth: Basic, body, or none. `resource` (RFC 8707, repeatable) or `audience` sets `aud`. |
| `GET/POST /userinfo` | Bearer access token → claims |
| `POST /introspect` | RFC 7662; also works for refresh tokens |
| `GET /end_session` | Redirects to `post_logout_redirect_uri` (+`state`) or shows "Logged out" |
| `POST /register` | RFC 7591 dynamic client registration; returns `client_id`/`client_secret` |
| `GET /health` | Also at the server root |

**Audience (`aud`)**: defaults to the `client_id`. Pass `resource=<uri>` (RFC 8707, may repeat)
on `/authorize` and/or `/token` — or `audience=<value>` on `/token` — to set it instead
(string for one value, array for several; token-time values win over authorize-time ones;
refresh keeps the audience). `azp` is always the `client_id`. MCP clients do this out of the
box, so a self-registered MCP client can obtain a token your API accepts. An explicit `aud`
typed into the login claims overrides everything.

Access tokens and ID tokens are both RS256 JWTs with the same claims (`iss`, `sub`, `aud`, `azp`,
`exp`, `iat`, `auth_time`, `jti`, `scope` + whatever you typed); the ID token adds `nonce` and
`at_hash`. Backends can validate access tokens locally against `/jwks`.

## Strict mode

```sh
docker run --rm -p 8080:8080 \
  -e STRICT=true \
  -e CLIENTS='[{"client_id":"web","client_secret":"s3cret","redirect_uris":["http://localhost:3000/callback"]}]' \
  ghcr.io/kapernikov/nano-mockidp:latest
```

Unknown clients, unregistered redirect URIs and wrong secrets are rejected; public clients
(no secret) must use PKCE. Clients can also be added at runtime:

```sh
curl -s -X POST http://localhost:8080/register \
  -H 'content-type: application/json' \
  -d '{"redirect_uris":["http://localhost:5173/cb"],"token_endpoint_auth_method":"none"}'
```

## CI usage

```sh
docker run -d -p 8080:8080 -e SIGNING_KEY_SEED=ci ghcr.io/kapernikov/nano-mockidp:0.1.0
# machine token
curl -s -X POST http://localhost:8080/token -d grant_type=client_credentials -d client_id=ci -d client_secret=x
```

For browser-less user tokens, drive the login form with two requests:

```sh
AUTHZ='http://localhost:8080/authorize?response_type=code&client_id=app&redirect_uri=http://app/cb&state=x'
CODE=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$AUTHZ" \
  --data-urlencode username=alice --data-urlencode 'claims={"email":"alice@test","roles":["admin"]}' \
  | sed 's/.*code=\([^&]*\).*/\1/')
curl -s -X POST http://localhost:8080/token -d grant_type=authorization_code -d code=$CODE \
  -d redirect_uri=http://app/cb -d client_id=app
```

## Compared to navikt/mock-oauth2-server

| | nano-mockidp | mock-oauth2-server |
|---|---|---|
| Image | ~4 MB, `FROM scratch` | JVM, hundreds of MB |
| Startup | milliseconds | seconds |
| Config | env vars | env vars + JSON |
| Login page | any HTML, two form fields | Kotlin template / custom HTML |
| Issuers | one (mount path configurable) | many, path-based |
| Response types | `code` only | `code`, `token`, `id_token`… |
| Public/internal URL split | built in | – |

## Development

```sh
cargo test
cargo run     # http://localhost:8080
docker build -t nano-mockidp .
```

Releases: push a tag `vX.Y.Z`. CI builds `linux/amd64` + `linux/arm64` and publishes
`ghcr.io/kapernikov/nano-mockidp:X.Y.Z` (plus `X.Y`, `latest`). The git tag is the version;
`Cargo.toml`'s version is not used.

## License

MIT
