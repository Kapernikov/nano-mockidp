#!/usr/bin/env bash
# Smoke test: drives a nano-mockidp instance with curl through login, refresh, admin subject
# changes, revocation and logout.
#
#   scripts/smoke.sh                     # builds and starts a local release binary
#   BASE_URL=https://idp.example/oidc ADMIN_TOKEN=... scripts/smoke.sh   # existing instance
#
# Env (all optional):
#   BASE_URL       issuer URL of a running instance; unset → start one locally on SMOKE_PORT
#   SMOKE_PORT     port for the local instance (default 18089)
#   ADMIN_TOKEN    must match the instance's ADMIN_TOKEN (default when local: smoke-admin)
#   CLIENT_ID      default smoke (in STRICT mode it must be registered with REDIRECT_URI)
#   CLIENT_SECRET  sent if set
#   REDIRECT_URI   default http://localhost/cb
#
# Needs curl and jq. Uses a fresh random username, so it's safe against a shared instance.
set -euo pipefail

CLIENT_ID=${CLIENT_ID:-smoke}
CLIENT_SECRET=${CLIENT_SECRET:-}
REDIRECT_URI=${REDIRECT_URI:-http://localhost/cb}
USERNAME="smoke-$(date +%s)-$RANDOM"

fail=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
info() { printf '  \033[33m--\033[0m   %s\n' "$1"; }
check() { # check <description> <actual> <expected>
  if [[ "$2" == "$3" ]]; then pass "$1"; else bad "$1 (got: $2, want: $3)"; fi
}

# ---------- start a local instance if needed ----------
if [[ -z "${BASE_URL:-}" ]]; then
  cd "$(dirname "$0")/.."
  echo "building release binary..."
  cargo build --release --quiet
  PORT=${SMOKE_PORT:-18089}
  BASE_URL="http://127.0.0.1:$PORT"
  ADMIN_TOKEN=${ADMIN_TOKEN:-smoke-admin}
  PORT=$PORT ISSUER_URL=$BASE_URL ADMIN_TOKEN=$ADMIN_TOKEN REQUIRE_OFFLINE_ACCESS=true \
    LOG_LEVEL=warn ./target/release/nano-mockidp &
  SERVER_PID=$!
  trap 'kill $SERVER_PID 2>/dev/null' EXIT
  for _ in $(seq 50); do
    curl -sf "$BASE_URL/health" >/dev/null && break
    sleep 0.1
  done
fi
BASE_URL=${BASE_URL%/}
ADMIN_TOKEN=${ADMIN_TOKEN:-}
echo "target: $BASE_URL  user: $USERNAME  client: $CLIENT_ID"

# ---------- helpers ----------
client_auth=(-d "client_id=$CLIENT_ID")
[[ -n "$CLIENT_SECRET" ]] && client_auth+=(-d "client_secret=$CLIENT_SECRET")

req() { # req <method> <path> [curl args...]; sets STATUS and BODY
  local method=$1 path=$2; shift 2
  local out
  out=$(curl -s -w '\n%{http_code}' -X "$method" "$BASE_URL$path" "$@")
  STATUS=${out##*$'\n'}
  BODY=${out%$'\n'*}
}
token() { req POST /token "${client_auth[@]}" "$@"; }
admin() { local m=$1 sub=$2; shift 2; req "$m" "/admin/subjects/$sub" -H "Authorization: Bearer $ADMIN_TOKEN" "$@"; }
introspect_active() { req POST /introspect "${client_auth[@]}" --data-urlencode "token=$1"; jq -r .active <<<"$BODY"; }
jwt_claim() { # jwt_claim <jwt> <jq filter>
  local p
  p=$(cut -d. -f2 <<<"$1" | tr '_-' '/+')
  while (( ${#p} % 4 )); do p+='='; done
  base64 -d <<<"$p" 2>/dev/null | jq -c "$2"
}
refresh() { token -d grant_type=refresh_token --data-urlencode "refresh_token=$1"; }

# login <scope> <claims json> → sets BODY to the token response
login() {
  local authz="$BASE_URL/authorize?response_type=code&client_id=$CLIENT_ID&state=s"
  authz+="&redirect_uri=$(jq -rn --arg v "$REDIRECT_URI" '$v|@uri')&scope=$(jq -rn --arg v "$1" '$v|@uri')"
  local loc code
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$authz" \
    --data-urlencode "username=$USERNAME" --data-urlencode "claims=$2")
  code=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$loc")
  if [[ -z "$code" ]]; then STATUS=302; BODY="{\"redirect\":\"$loc\"}"; return; fi
  token -d grant_type=authorization_code -d "code=$code" --data-urlencode "redirect_uri=$REDIRECT_URI"
}

# ---------- discovery ----------
echo "discovery"
req GET /.well-known/openid-configuration
check "revocation_endpoint advertised" "$(jq -r '.revocation_endpoint | endswith("/revoke")' <<<"$BODY")" true
check "offline_access in scopes_supported" "$(jq -r '.scopes_supported | index("offline_access") != null' <<<"$BODY")" true

# ---------- offline_access ----------
echo "offline_access"
login "openid" '{"roles":["admin"]}'
check "login without offline_access" "$STATUS" 200
if [[ "$(jq -r 'has("refresh_token")' <<<"$BODY")" == true ]]; then
  info "refresh_token issued without offline_access (REQUIRE_OFFLINE_ACCESS is off)"
  # drop it so the admin checks below see exactly one refresh token
  req POST /revoke "${client_auth[@]}" --data-urlencode "token=$(jq -r .refresh_token <<<"$BODY")"
else
  pass "no refresh_token without offline_access (REQUIRE_OFFLINE_ACCESS is on)"
fi
login "openid offline_access" '{"roles":["admin"]}'
check "login with offline_access" "$STATUS" 200
RT=$(jq -r .refresh_token <<<"$BODY")
check "refresh_token issued" "$([[ $RT != null ]] && echo yes)" yes

# ---------- refresh rotation ----------
echo "refresh"
refresh "$RT"
check "refresh succeeds" "$STATUS" 200
OLD=$RT; RT=$(jq -r .refresh_token <<<"$BODY")
check "refresh token rotated" "$([[ $RT != "$OLD" && $RT != null ]] && echo yes)" yes
check "roles from login" "$(jwt_claim "$(jq -r .access_token <<<"$BODY")" .roles)" '["admin"]'
refresh "$OLD"
check "old refresh token rejected" "$(jq -r .error <<<"$BODY")" invalid_grant

# ---------- admin subjects ----------
if [[ -z "$ADMIN_TOKEN" ]]; then
  info "ADMIN_TOKEN not set: skipping admin subject checks"
else
  echo "admin subjects"
  req GET "/admin/subjects/$USERNAME"
  check "admin rejects missing bearer" "$STATUS" 401
  admin PUT "$USERNAME" -H 'content-type: application/json' -d '{"claims":{"roles":["viewer"]}}'
  check "PUT claims override" "$STATUS" 200
  check "subject reports 1 refresh token" "$(jq -r .refresh_tokens <<<"$BODY")" 1
  refresh "$RT"; RT=$(jq -r .refresh_token <<<"$BODY")
  check "refresh picks up new roles" "$(jwt_claim "$(jq -r .access_token <<<"$BODY")" .roles)" '["viewer"]'
  AT=$(jq -r .access_token <<<"$BODY")

  admin PUT "$USERNAME" -H 'content-type: application/json' -d '{"disabled":true}'
  check "PUT disabled" "$STATUS" 200
  refresh "$RT"
  check "disabled: refresh → invalid_grant" "$(jq -r .error <<<"$BODY")" invalid_grant
  check "disabled: refresh token inactive" "$(introspect_active "$RT")" false
  check "disabled: access token inactive" "$(introspect_active "$AT")" false
  login "openid offline_access" '{}'
  check "disabled: login → access_denied" "$(jq -r .redirect <<<"$BODY" | grep -o 'error=access_denied')" error=access_denied

  admin PUT "$USERNAME" -H 'content-type: application/json' -d '{"disabled":false}'
  refresh "$RT"
  check "re-enabled: refresh works again" "$STATUS" 200
  RT=$(jq -r .refresh_token <<<"$BODY")

  admin DELETE "$USERNAME"
  check "DELETE revoked 1 refresh token" "$(jq -r .revoked_refresh_tokens <<<"$BODY")" 1
  refresh "$RT"
  check "deleted: refresh → invalid_grant" "$(jq -r .error <<<"$BODY")" invalid_grant
fi

# ---------- /revoke ----------
echo "revoke"
login "openid offline_access" '{}'
RT=$(jq -r .refresh_token <<<"$BODY"); AT=$(jq -r .access_token <<<"$BODY")
req POST /revoke "${client_auth[@]}" --data-urlencode "token=$RT" -d token_type_hint=refresh_token
check "revoke refresh token" "$STATUS" 200
refresh "$RT"
check "revoked refresh → invalid_grant" "$(jq -r .error <<<"$BODY")" invalid_grant
req POST /revoke "${client_auth[@]}" --data-urlencode "token=$AT"
check "revoke access token" "$STATUS" 200
check "revoked access token inactive" "$(introspect_active "$AT")" false
req GET /userinfo -H "Authorization: Bearer $AT"
check "revoked access token → userinfo 401" "$STATUS" 401

# ---------- end_session ----------
echo "end_session"
login "openid offline_access" '{}'
RT=$(jq -r .refresh_token <<<"$BODY"); IDT=$(jq -r .id_token <<<"$BODY")
req GET "/end_session?id_token_hint=$IDT&post_logout_redirect_uri=$(jq -rn --arg v "$REDIRECT_URI" '$v|@uri')"
check "end_session redirects" "$STATUS" 302
refresh "$RT"
check "after logout: refresh → invalid_grant" "$(jq -r .error <<<"$BODY")" invalid_grant

echo
if (( fail )); then echo "SMOKE TEST FAILED"; exit 1; fi
echo "smoke test passed"
