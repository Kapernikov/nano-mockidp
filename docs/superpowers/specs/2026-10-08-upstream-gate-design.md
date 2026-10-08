# Upstream gate — Design

Optional gate in front of the login form: before a tester may pick a persona, they must log in
at a real upstream OpenID Connect provider and pass an access check. After that, everything
works as today — any username, any claims. The upstream identity only decides *who may reach
the persona form*; it never becomes the token's `sub`.

Use case: a test environment reachable from the internet (e.g. a review deployment of
fullstack-sota) where outsiders must not get in, but testers still log in as arbitrary
personas.

```
browser → app → nano-mockidp GET /authorize
                  │ no valid gate cookie
                  ├─→ upstream /authorize (real login, MFA, …)
                  │     ← /upstream/callback?code&state
                  │   code → upstream /token, verify id_token, check claim
                  │   Set-Cookie: gate (signed, 8h)
                  ├─→ 302 back to the original /authorize URL
                  └─→ persona form as today → code → app
```

## Goals

- Off by default. With the gate off (or the binary built without the feature), behaviour is
  byte-for-byte what it is today, including online/offline refresh tokens.
- Generic OIDC upstream (Entra ID, Google, Keycloak, Authentik, GitLab, Auth0, …):
  discovery, authorization code + PKCE, RS256 ID token.
- One simple access check on an upstream ID-token claim.
- No path to a user token that bypasses the gate (see *Closing the back doors*).
- Testable end to end without external services: nano-mockidp is its own upstream.

## Non-goals

- Non-OIDC upstreams (GitHub OAuth2, SAML).
- A bypass secret for robots. Gated instances are for humans; e2e runs against ungated ones.
- Upstream logout / single logout. `end_session` does not touch the gate cookie.
- Signing algorithms other than RS256 for the upstream ID token.
- Separate internal/public URLs for the upstream (the upstream is reached at
  `UPSTREAM_ISSUER` by both browser and server).
- Persisting gate sessions across restarts.

## Build: Cargo feature `upstream`

- New feature `upstream`, **enabled by default**, so the published image includes it.
  `cargo build --no-default-features` gives the small binary without an HTTP client.
- HTTP client: `reqwest` 0.12 with `default-features = false`,
  features `["rustls-tls-webpki-roots", "json"]`: rustls with the **ring** provider, bundled
  Mozilla roots (the `FROM scratch` image has no CA store), **no OpenSSL, no aws-lc** → stays
  musl / cargo-zigbuild compatible.
- `hmac` crate for the gate cookie (sha2 is already a dependency).
- Built without the feature and `UPSTREAM_ISSUER` set → **startup error** (exit 2), never a
  silently open instance.
- CI: existing fmt/clippy/test run with default features; add
  `cargo clippy --no-default-features -- -D warnings` and `cargo build --no-default-features`.

## Configuration

The gate is on iff `UPSTREAM_ISSUER` is set.

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM_ISSUER` | – | Issuer URL of the upstream OIDC provider. Setting it turns the gate on. Discovery at `<issuer>/.well-known/openid-configuration`; ID token `iss` must equal it. |
| `UPSTREAM_CLIENT_ID` | – | Required when the gate is on. |
| `UPSTREAM_CLIENT_SECRET` | – | Sent with HTTP Basic at the upstream token endpoint. Unset → public client (PKCE only). |
| `UPSTREAM_SCOPE` | `openid email profile` | Scope requested upstream. `openid` is added if missing. |
| `UPSTREAM_REQUIRE_CLAIM` | – | `path=value`. The ID-token claim at `path` (dots descend into objects, e.g. `realm_access.roles`) must equal `value`, or contain it if it is an array. Unset → any user the upstream authenticates passes. |
| `UPSTREAM_SESSION_TTL` | `28800` | Seconds a gate cookie is valid (8h). |
| `UPSTREAM_SUB_TOKEN_CLAIM` | – | Name of a claim that carries the upstream `sub` in every token issued after a gated login, e.g. `upstream_sub`. Unset → tokens look exactly as today. |
| `UPSTREAM_CA_PATH` | – | Extra PEM CA bundle trusted for upstream calls (private-CA Keycloak). Added to the bundled roots. |

Validation at startup: `UPSTREAM_CLIENT_ID` required, `UPSTREAM_ISSUER` a valid absolute URL,
`UPSTREAM_REQUIRE_CLAIM` contains `=` with a non-empty path, `UPSTREAM_CA_PATH` readable PEM.
Startup does **not** contact the upstream (the container must start even if the upstream is
down); discovery happens on first use and is retried until it succeeds.

Startup warning when the gate is on and the signing key comes from `SIGNING_KEY_SEED`: a
guessable seed lets anyone derive the key and mint tokens without passing the gate. Use
`SIGNING_KEY_PEM` / `SIGNING_KEY_PATH` (or a long random seed) on public instances.

## Flow

### `GET /authorize`

1. Validate the authorization request exactly as today (errors unchanged).
2. Gate on, valid gate cookie → render the login page as today.
3. Gate on, no/invalid/expired cookie →
   - create an upstream login: `state`, `nonce`, PKCE verifier (all random), and the
     original request as *path + query* (relative, so the final redirect can't leave this host);
   - path + query longer than 2048 bytes → 414 error page, no upstream redirect;
   - seal it (same HMAC key as the gate cookie, different MAC label, so neither cookie opens
     as the other) into a pre-login cookie `nano_mockidp_login_<first 12 chars of state>`,
     `Max-Age=600`, same attributes as the gate cookie. Nothing is stored server side, and the
     login is bound to the browser that started it; per-`state` names let parallel logins run;
   - 302 to the upstream `authorization_endpoint` with `response_type=code`, `client_id`,
     `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`.

The upstream `redirect_uri` is always `<ISSUER_URL>/upstream/callback`, built from
`ISSUER_URL` even when `ISSUER_FROM_REQUEST_HOST=true`, because the upstream needs one fixed,
registered URI.

### `GET /upstream/callback` (route exists only when the gate is on)

1. Open the pre-login cookie named for `state`; its sealed `state` must equal the query's.
   Missing/invalid/expired/mismatched (e.g. callback opened in another browser) → 400 error
   page. Whenever the cookie was present, the response clears it (`Max-Age=0`); a replay
   that keeps the cookie fails at the upstream, whose code is single-use.
2. `error` from upstream → 403 error page showing `error` / `error_description`.
3. POST the upstream `token_endpoint`: `grant_type=authorization_code`, `code`,
   `redirect_uri`, `code_verifier`, client auth via Basic if a secret is configured, else
   `client_id` in the body.
4. Verify the `id_token`: RS256 signature with the upstream JWKS key matching `kid`
   (JWKS cached; refetched once on unknown `kid`), `iss == UPSTREAM_ISSUER`,
   `aud` equals or contains `UPSTREAM_CLIENT_ID`, `exp` in the future (60 s leeway),
   `nonce` matches.
5. Access check (`UPSTREAM_REQUIRE_CLAIM`). Fail → 403 page "upstream user X is not allowed",
   logged at `warn`.
6. Set the gate cookie and 302 to the stored original path + query.

Any upstream HTTP/parse failure → 502 error page, details logged.

### `POST /authorize`

Gate on and no valid gate cookie → 403 error page. Never a redirect: a POST without the
cookie is a script or a forged form, not a tester to send upstream.

With a valid cookie: as today. If `UPSTREAM_SUB_TOKEN_CLAIM` is set, that claim is set to the
cookie's upstream `sub` **after** merging the typed claims, so a tester cannot overwrite it.

### Gate cookie

- Name `nano_mockidp_gate`, value `base64url(payload) "." base64url(HMAC-SHA256)`.
  Payload: `{"sub": <upstream sub>, "email": <if present>, "exp": <unix seconds>}`.
- HMAC key: 32 random bytes per process start → a restart sends testers upstream again
  (the upstream session usually makes that a click-through).
- `HttpOnly; SameSite=Lax; Path=<issuer path or />; Max-Age=<UPSTREAM_SESSION_TTL>`,
  plus `Secure` when `ISSUER_URL` is `https`.
- `SameSite=Lax` is needed: the cookie is set on a top-level navigation back from the
  upstream and must be sent on top-level navigations from the app.

### Upstream `sub` on refresh

When `UPSTREAM_SUB_TOKEN_CLAIM` is set, the upstream `sub` is stored on the code entry and
the refresh entry (new field `upstream_sub: Option<String>`) and re-applied at every issue,
so it survives an admin claims override (`PUT /admin/subjects/{sub}`) and rotation.

## Closing the back doors

With the gate on, every way to a user token must pass it:

| Way in | Gate off | Gate on |
|---|---|---|
| `GET /authorize` | login page | gate cookie required, else upstream |
| `POST /authorize` | code | gate cookie required, else 403 |
| `grant_type=password` | any client | only a **`CLIENTS`-configured client with a secret**, secret checked; else `unauthorized_client` |
| `grant_type=client_credentials` | any client | same as password |
| `grant_type=authorization_code` | as today | as today (the code came from a gated login) |
| `grant_type=refresh_token` | as today | as today (online/offline, rotation, revocation unchanged) |
| `/register` | as today | as today — but dynamically registered clients **do not** count as configured clients above, otherwise anyone could register a client with a secret and reopen the door |
| `/introspect`, `/userinfo`, `/revoke`, `/end_session`, `/jwks`, discovery | as today | as today |
| `/admin/*` | `ADMIN_TOKEN` | `ADMIN_TOKEN` |

`STRICT` keeps its meaning and combines with the gate.

## Logging

- `info`: upstream login allowed — upstream `sub`, `email`.
- `warn`: upstream login denied (claim check) — upstream `sub`, `email`, the claim value seen.
- `info`: persona login behind the gate — upstream `sub`, persona `sub`, `client_id`.
- `warn`: refused password / client_credentials grant because of the gate.

## Code layout

- `src/upstream/mod.rs` (feature-gated): config struct, discovery + JWKS cache, the
  `/upstream/callback` handler, the upstream redirect, ID-token verification.
- `src/upstream/gate.rs`: cookie seal/open for both payloads (`GateSession`,
  `PendingLogin`), claim check (pure functions, unit tested).
- `src/token.rs`: split the JWS check so it verifies against any RSA public key
  (own signing key or an upstream JWK).
- `src/routes/authorize.rs`, `src/routes/token.rs`: gate checks behind a small
  `state.gate()` accessor that is `None` when the gate is off or the feature is absent.
- `src/store.rs`: `upstream_sub` on code/refresh entries (no pending-login store: the
  pre-login cookie carries it).
  "Configured client" means an entry of `Config.clients` (the `CLIENTS` env var), so clients
  from `/register` are excluded without extra bookkeeping.

## Testing

**Integration tests** (`tests/upstream.rs`): two in-process servers, A = plain nano-mockidp as
upstream, B = gated with `UPSTREAM_ISSUER=A`, `UPSTREAM_REQUIRE_CLAIM=groups=testers`.

- Happy path: B authorize → A → log in with `groups:["testers"]` → callback → cookie → persona
  `alice` → tokens with `sub=alice`; refresh and offline tokens work.
- `UPSTREAM_SUB_TOKEN_CLAIM`: claim present, can't be overwritten from the form, survives
  refresh and an admin claims override.
- Denied: upstream user without the group → 403, no cookie.
- `POST /authorize` without cookie → 403; with a tampered or expired cookie → 403.
- Callback with unknown/reused `state`, or without the pre-login cookie (another browser)
  → 400; a login cookie never passes as a gate cookie or vice versa; wrong `nonce` / wrong
  `iss` → rejected.
- Password and client_credentials: refused for unknown and dynamically registered clients,
  allowed for a configured client with the right secret.
- Gate off: the existing `tests/flow.rs` and `tests/offline.rs` stay unchanged and green.
- Config: gate on without client id → error; feature off + `UPSTREAM_ISSUER` → error.

**Smoke** (`scripts/smoke.sh`): new optional section `UPSTREAM_SMOKE=1` that starts two
release binaries (A on `SMOKE_PORT+1` as upstream, B gated) and walks the same flow with curl
and a cookie jar, plus the denied and no-cookie cases.

**Manual** (once, not automated): a real upstream (Keycloak or Entra) to confirm discovery,
TLS with bundled roots, and claim shapes.

## Documentation

README: a *Gating with an upstream IdP* section (use case, config table, the back-door table,
the signing-key warning, an Entra/Keycloak example), and the `--no-default-features` build.
