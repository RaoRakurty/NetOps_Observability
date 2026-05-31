#!/usr/bin/env bash
# Authentication & identity test suite — exercises the full auth surface end to
# end against a running stack: login (good/bad), bearer enforcement, token
# refresh ROTATION + REUSE-DETECTION, logout revocation, API-key mint/use/revoke,
# per-key RATE LIMITING (429), and RBAC denial. Maps to the user's auth test
# matrix (user auth, tokens, API/curl, RBAC). SSO/SAML/LDAP and TACACS+ have
# their own procedures (see tests/README.md) since they need an external IdP.
#
# Requires an ADMIN login (creates a throwaway user + API keys, then cleans up).
# Usage:  NETOPS_USER=admin NETOPS_PASS=... tests/auth.sh
set -u
BASE="${NETOPS_BASE:-http://localhost:8000}"
USER="${NETOPS_USER:-admin}"
PASS="${NETOPS_PASS:-}"
PASS_N=0; FAIL_N=0
J() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }

ok()   { printf "  \033[32m✓\033[0m %s\n" "$1"; PASS_N=$((PASS_N+1)); }
bad()  { printf "  \033[31m✗\033[0m %s\n" "$1"; FAIL_N=$((FAIL_N+1)); }
# assert_code DESC EXPECTED ACTUAL
ac()   { if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 (got $3 want $2)"; fi; }

code() { # METHOD PATH [BEARER] [BODY] -> prints http_code
  local m="$1" p="$2" b="${3:-}" body="${4:-}"; local a=(-s -m15 -o /dev/null -w '%{http_code}' -X "$m")
  [ -n "$b" ] && a+=(-H "Authorization: Bearer $b")
  [ -n "$body" ] && a+=(-H 'Content-Type: application/json' -d "$body")
  curl "${a[@]}" "$BASE$p"
}
body() { # METHOD PATH [BEARER] [BODY] -> prints response body
  local m="$1" p="$2" b="${3:-}" body="${4:-}"; local a=(-s -m15 -X "$m")
  [ -n "$b" ] && a+=(-H "Authorization: Bearer $b")
  [ -n "$body" ] && a+=(-H 'Content-Type: application/json' -d "$body")
  curl "${a[@]}" "$BASE$p"
}

[ -z "$PASS" ] && { echo "set NETOPS_PASS (admin password)"; exit 2; }
echo "== NetOps auth suite ($BASE) =="

# 1) Login — negative then positive --------------------------------------------
echo "-- 1. user auth --"
ac "login rejects bad password" 401 "$(code POST /api/auth/login '' '{"username":"'"$USER"'","password":"definitely-wrong"}')"
LR=$(body POST /api/auth/login '' "{\"username\":\"$USER\",\"password\":\"$PASS\"}")
TOK=$(printf '%s' "$LR" | J "['token']"); RT=$(printf '%s' "$LR" | J "['refresh_token']")
[ -n "$TOK" ] && ok "login returns access + refresh token" || bad "login failed: $LR"
ac "expires_in present" "True" "$(printf '%s' "$LR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("expires_in",0)>0)')"

# 2) Bearer enforcement --------------------------------------------------------
echo "-- 2. bearer enforcement --"
ac "/api/auth/me with token" 200 "$(code GET /api/auth/me "$TOK")"
ac "/api/auth/me without token" 401 "$(code GET /api/auth/me '')"
ac "protected route w/ junk token" 401 "$(code GET /api/devices 'not.a.jwt')"

# 3) Token refresh: rotation + reuse detection ---------------------------------
echo "-- 3. token rotation + reuse detection --"
R1=$(body POST /api/auth/refresh '' "{\"refresh_token\":\"$RT\"}")
NT=$(printf '%s' "$R1" | J "['token']"); NRT=$(printf '%s' "$R1" | J "['refresh_token']")
[ -n "$NT" ] && [ "$NRT" != "$RT" ] && ok "refresh rotates (new access + new refresh)" || bad "refresh did not rotate: $R1"
ac "rotated access token works" 200 "$(code GET /api/auth/me "$NT")"
# Re-using the OLD refresh token must be detected and rejected (single-use).
ac "OLD refresh token reuse -> 401" 401 "$(code POST /api/auth/refresh '' "{\"refresh_token\":\"$RT\"}")"
# Reuse-detection revokes the lineage: the NEW refresh is now invalid too.
ac "lineage revoked after reuse -> 401" 401 "$(code POST /api/auth/refresh '' "{\"refresh_token\":\"$NRT\"}")"

# Fresh session for the rest.
LR=$(body POST /api/auth/login '' "{\"username\":\"$USER\",\"password\":\"$PASS\"}")
TOK=$(printf '%s' "$LR" | J "['token']"); RT=$(printf '%s' "$LR" | J "['refresh_token']")

# 4) Logout revokes refresh ----------------------------------------------------
echo "-- 4. logout --"
ac "logout ok" 200 "$(code POST /api/auth/logout '' "{\"refresh_token\":\"$RT\"}")"
ac "refresh after logout -> 401" 401 "$(code POST /api/auth/refresh '' "{\"refresh_token\":\"$RT\"}")"
LR=$(body POST /api/auth/login '' "{\"username\":\"$USER\",\"password\":\"$PASS\"}")
TOK=$(printf '%s' "$LR" | J "['token']")

# 5) API keys: mint -> use -> revoke ------------------------------------------
echo "-- 5. API keys (curl / machine clients) --"
KR=$(body POST /api/apikeys "$TOK" '{"label":"smoke-key","scopes":["read:metrics"]}')
SECRET=$(printf '%s' "$KR" | J "['secret']"); KID=$(printf '%s' "$KR" | J "['key']['id']")
[ -n "$SECRET" ] && ok "API key minted (shown once)" || bad "key mint failed: $KR"
ac "API key as Bearer works"   200 "$(code GET /api/devices "$SECRET")"
ac "API key as X-API-Key works" 200 "$(curl -s -m15 -o /dev/null -w '%{http_code}' -H "X-API-Key: $SECRET" "$BASE/api/devices")"
ac "revoke API key" 204 "$(code DELETE "/api/apikeys/$KID" "$TOK")"
ac "revoked key rejected -> 401" 401 "$(code GET /api/devices "$SECRET")"

# 6) Per-key rate limiting (429) ----------------------------------------------
echo "-- 6. per-key rate limit --"
KR=$(body POST /api/apikeys "$TOK" '{"label":"rl-key","scopes":["read:metrics"],"rate_limit_per_min":3}')
RLSEC=$(printf '%s' "$KR" | J "['secret']"); RLID=$(printf '%s' "$KR" | J "['key']['id']")
hit429=0
for i in 1 2 3 4 5 6; do
  c=$(code GET /api/devices "$RLSEC"); [ "$c" = "429" ] && hit429=1
done
[ "$hit429" = "1" ] && ok "key capped at 3/min returns 429 when exceeded" || bad "rate limit did not trigger 429"
code DELETE "/api/apikeys/$RLID" "$TOK" >/dev/null

# 7) RBAC denial ---------------------------------------------------------------
echo "-- 7. RBAC (least privilege) --"
RUSER="smoke_ro_$$"; RPASS="ReadOnlyPass123!"
MK=$(body POST /api/users "$TOK" "{\"username\":\"$RUSER\",\"password\":\"$RPASS\",\"role\":\"read-only\"}")
if printf '%s' "$MK" | grep -q "$RUSER"; then
  ok "created read-only user"
  RLR=$(body POST /api/auth/login '' "{\"username\":\"$RUSER\",\"password\":\"$RPASS\"}")
  ROTOK=$(printf '%s' "$RLR" | J "['token']")
  ac "read-only can view devices" 200 "$(code GET /api/devices "$ROTOK")"
  ac "read-only DENIED admin (GET /api/users)" 403 "$(code GET /api/users "$ROTOK")"
  ac "read-only DENIED key mint" 403 "$(code POST /api/apikeys "$ROTOK" '{"label":"x","scopes":[]}')"
  code DELETE "/api/users/$RUSER" "$TOK" >/dev/null  # cleanup
else
  bad "could not create read-only user (admin perms / cap?): $MK"
fi

echo
echo "== $PASS_N passed, $FAIL_N failed =="
[ "$FAIL_N" -eq 0 ]
