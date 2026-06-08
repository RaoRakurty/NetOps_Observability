package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// clientIP derives the caller's source IP: the first hop in X-Forwarded-For if
// present, else the host portion of RemoteAddr. Returns nil if unparseable.
func clientIP(r *http.Request) net.IP {
	if trustProxy() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

// trustProxy reports whether X-Forwarded-* headers may be trusted. Default FALSE:
// behind an untrusted hop a client can spoof these to forge source IPs and dodge
// per-tenant/IP rate limits, so we only honor them when TRUST_PROXY=true.
func trustProxy() bool { return os.Getenv("TRUST_PROXY") == "true" }

// auth.go — login + middleware.
//
// Tokens are JWTs signed with HS256 using the JWT_SECRET, carrying the username
// (sub), role, issued-at and expiry. Access tokens are short-lived; clients
// trade a rotating refresh token (see refresh.go) for a fresh one at
// /api/auth/refresh. Both lifetimes are env-configurable.

// durEnv parses a Go duration from env (e.g. "15m", "12h"), falling back to def.
func durEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// Token lifetimes are env-configurable but clamped to safe, standards-aligned
// bounds — see token_policy.go.
func accessTokenTTL() time.Duration {
	return boundedDurEnv("ACCESS_TOKEN_TTL", time.Hour, accessTTLMin, accessTTLMax, accessTTLRecommended)
}
func refreshTokenTTL() time.Duration {
	return boundedDurEnv("REFRESH_TOKEN_TTL", 7*24*time.Hour, refreshTTLMin, refreshTTLMax, refreshTTLRecommended)
}

type ctxKey int

const userCtxKey ctxKey = 0

// ---- handlers -------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token        string     `json:"token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresIn    int        `json:"expires_in"` // access token lifetime, seconds
	User         publicUser `json:"user"`
}

type publicUser struct {
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	Email       string    `json:"email,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Status      string    `json:"status,omitempty"`
	AuthSource  string    `json:"auth_source,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

func toPublic(u User) publicUser {
	return publicUser{
		Username:    u.Username,
		Role:        u.Role,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		TenantID:    u.TenantID,
		Status:      u.Status,
		AuthSource:  u.AuthSource,
		CreatedAt:   u.CreatedAt,
		LastLoginAt: u.LastLoginAt,
	}
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// SR-012: login is unauthenticated — bound its body tightly (credentials are
	// tiny). Pairs with the verifyPassword length cap (SR-013).
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, ok := s.users.Get(req.Username)
	if !ok || !verifyPassword(req.Password, user.PasswordHash) {
		// Generic message: don't leak whether the username exists.
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	// SR-029: opportunistically upgrade a hash stored at a weaker iteration count
	// to the current cost. Best-effort — never fail the login if rehash fails.
	if passwordNeedsRehash(user.PasswordHash) {
		if err := s.users.ChangePassword(user.Username, req.Password); err != nil {
			logWarn("auth", "password rehash-on-login failed", map[string]any{"user": user.Username, "err": err.Error()})
		}
	}
	ttl := accessTokenTTL()
	tok, err := signJWT(jwtClaims{
		Sub:    user.Username,
		Role:   user.Role,
		Tenant: user.TenantID,
		Iat:    time.Now().Unix(),
		Exp:    time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	refresh, err := s.refresh.Issue(user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.users.TouchLogin(user.Username)
	setOSDCookie(w, r, tok, ttl) // /search gate cookie (enforced for platform owner only)
	logInfo("auth", "login ok", map[string]any{"user": user.Username, "role": user.Role})
	writeJSON(w, http.StatusOK, loginResponse{
		Token: tok, RefreshToken: refresh, ExpiresIn: int(ttl.Seconds()), User: toPublic(user),
	})
}

// handleRefresh trades a valid (rotating) refresh token for a fresh access
// token + a new refresh token. Reachable without an access token.
func (s *server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	newRefresh, username, err := s.refresh.Rotate(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	user, ok := s.users.Get(username)
	if !ok || user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, errors.New("account unavailable"))
		return
	}
	ttl := accessTokenTTL()
	tok, err := signJWT(jwtClaims{
		Sub: user.Username, Role: user.Role, Tenant: user.TenantID,
		Iat: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Refresh the /search gate cookie too, so it tracks the rotating session and
	// covers principals that authenticated via SSO/LDAP/TACACS (they reach a fresh
	// access token through this path).
	setOSDCookie(w, r, tok, ttl)
	writeJSON(w, http.StatusOK, loginResponse{
		Token: tok, RefreshToken: newRefresh, ExpiresIn: int(ttl.Seconds()), User: toPublic(user),
	})
}

// handleConsoleGate (re)issues the embedded-console gate cookie for the current
// session, on demand. The embedded consoles (/netbox, /search) are loaded as raw
// browser iframes that don't pass through the SPA's Bearer/refresh path, so their
// gate cookie can go stale (short TTL) or be missing/old-path after a deploy. The
// SPA calls this (Bearer-authed) right before mounting an embedded console so the
// iframe always carries a fresh, correctly-pathed cookie. Platform-owner only.
func (s *server) handleConsoleGate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	if !isPlatformOwner(claims) { // identity check — ignore any view-as-tenant override
		writeError(w, http.StatusForbidden, errors.New("platform administrator access required"))
		return
	}
	// Re-sign a fresh session JWT for the cookie so it verifies at osd-gate
	// regardless of how the caller authenticated (session/SSO).
	ttl := accessTokenTTL()
	tok, err := signJWT(jwtClaims{
		Sub: claims.Sub, Role: claims.Role, Tenant: claims.Tenant,
		Iat: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	setOSDCookie(w, r, tok, ttl)
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout revokes the presented refresh token. Idempotent; reachable
// without a valid access token (the access token may already be expired).
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.RefreshToken != "" {
		s.refresh.Revoke(req.RefreshToken)
	}
	clearOSDCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	user, ok := s.users.Get(claims.Sub)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("user removed"))
		return
	}
	// platform_admin tells the SPA whether to surface infra-stack monitoring and
	// platform-wide administration — including the tenant "view as" switcher. This
	// is an IDENTITY question (is the caller the platform owner?), so it MUST use
	// isPlatformOwner, NOT principalTenant: the latter honors the view-as-tenant
	// override, which would flip platform_admin to false while scoped and hide the
	// very switcher needed to scope back (locking the owner into a tenant).
	owner := isPlatformOwner(claims)
	// Keep the embedded-console gate cookie fresh for the platform owner. /me is
	// hit on app load, so the bundled NetBox / Dashboards iframes always carry a
	// valid, correctly-pathed cookie without a separate round-trip (no 403 wall).
	if owner {
		if tok, err := signJWT(jwtClaims{
			Sub: claims.Sub, Role: claims.Role, Tenant: claims.Tenant,
			Iat: time.Now().Unix(), Exp: time.Now().Add(accessTokenTTL()).Unix(),
		}, jwtSecret()); err == nil {
			setOSDCookie(w, r, tok, accessTokenTTL())
		}
	}
	writeJSON(w, http.StatusOK, struct {
		publicUser
		PlatformAdmin bool `json:"platform_admin"`
	}{toPublic(user), owner})
}

// isLocalAccount reports whether an account's password is managed locally (so it
// can be changed in-app). Federated sources (oidc/saml/ldap/tacacs) are managed
// by the IdP. An empty source means a legacy/bootstrap local account.
func isLocalAccount(authSource string) bool {
	s := strings.ToLower(strings.TrimSpace(authSource))
	return s == "" || s == "local"
}

type changePasswordRequest struct {
	// Username is used only by the unauthenticated login-window flow to name the
	// account; an authenticated caller's account comes from its token instead.
	Username        string `json:"username,omitempty"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// handleChangePassword serves self-service password change in two modes:
//   - authenticated: the signed-in user changes its own password (account = token).
//   - unauthenticated: the login-window "Change password" form names the account
//     and proves ownership with the current password (this path is in publicPaths).
//
// Either way the change is server-authoritative: the current password must verify,
// the account must be local, and the new password must satisfy the Security Policy.
func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Identify the account. An authenticated caller can only change its own.
	username := ""
	authed := false
	if claims, ok := userFrom(r.Context()); ok {
		username, authed = claims.Sub, true
	} else {
		username = strings.TrimSpace(req.Username)
	}
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	// Generic credential error so the pre-auth path doesn't enumerate usernames;
	// the authed path keeps the clearer "current password incorrect".
	badCreds := errors.New("invalid username or password")
	if authed {
		badCreds = errors.New("current password incorrect")
	}
	user, ok := s.users.Get(username)
	if !ok {
		writeError(w, http.StatusUnauthorized, badCreds)
		return
	}
	// Only LOCAL accounts have a password we own. Federated accounts (oidc/saml/
	// ldap/tacacs) authenticate against the IdP and carry no usable local hash.
	if !isLocalAccount(user.AuthSource) {
		writeError(w, http.StatusBadRequest, errors.New("password is managed by your identity provider; change it there"))
		return
	}
	if !verifyPassword(req.CurrentPassword, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, badCreds)
		return
	}
	// Enforce the account's resolved Security Policy (length + complexity) before
	// the store's own floor — zero-trust, server-authoritative (#24 wiring).
	rules := s.callerPasswordRules(jwtClaims{Sub: user.Username, Role: user.Role, Tenant: user.TenantID})
	if err := validatePasswordAgainstPolicy(req.NewPassword, rules); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.users.ChangePassword(user.Username, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	logInfo("auth", "password changed", map[string]any{"user": user.Username, "pre_auth": !authed})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- middleware -----------------------------------------------------------

// publicPaths can be reached without a Bearer token.
var publicPaths = []string{
	"/admin/health",
	"/admin/version",
	"/api/auth/login",
	"/api/auth/refresh",
	"/api/auth/logout",
	"/api/auth/sso/config",
	"/api/auth/sso/login",
	"/api/auth/sso/callback",
	"/api/auth/methods",
	"/api/auth/ldap/login",
	"/api/auth/tacacs/login",
	"/api/auth/change-password", // self-service from the login window; names the account + verifies the current password (local accounts only)
	"/api/auth/osd-gate",        // cookie-authenticated nginx auth_request target; does its own authz
	"/metrics",
}

func (s *server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pass through CORS preflight unchanged.
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		for _, p := range publicPaths {
			if r.URL.Path == p {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Secure report/export links carry a signed, expiring token in the path and
		// do their own authorization in the view handler — no Bearer needed.
		if strings.HasPrefix(r.URL.Path, "/api/reports/view/") || strings.HasPrefix(r.URL.Path, "/api/exports/view/") {
			next.ServeHTTP(w, r)
			return
		}
		// ITSM inbound webhooks are called by external systems (no JWT). The
		// handler authenticates via the per-tenant path token + the provider's
		// signature (HMAC/replay) before touching any state — fail-closed.
		if strings.HasPrefix(r.URL.Path, "/api/integrations/webhook/") {
			next.ServeHTTP(w, r)
			return
		}
		// Anything outside /api/ and /admin/ (i.e. /metrics is the only
		// odd duck, already handled above) is fronted by the SPA / iframes
		// and doesn't go through this Go server.
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/admin/") {
			next.ServeHTTP(w, r)
			return
		}
		// /api/events is a WebSocket — the browser's WS API can't set the
		// Authorization header, so we accept ?token=<jwt> there.
		var token string
		// WebSocket routes accept ?token=<jwt> (browsers can't set Authorization on
		// a WS): the events hub and the device-SSH gateway (/api/devices/{id}/ssh).
		if r.URL.Path == "/api/events" ||
			(strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.HasSuffix(r.URL.Path, "/ssh")) {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			auth := r.Header.Get("Authorization")
			if h := r.Header.Get("X-API-Key"); h != "" && auth == "" {
				auth = "Bearer " + h
			}
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
				return
			}
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
		// Machine clients present an API key (ntk_…). Resolve it to a synthetic
		// principal carrying the key's tenant + scopes; the RBAC role is derived
		// from the scopes (see docs/API_ACCESS.md). Scope checks gate the
		// scope-protected endpoints (e.g. write:incidents).
		if strings.HasPrefix(token, keyPrefix) {
			k, ok := s.apiKeys.Verify(token)
			if !ok {
				writeError(w, http.StatusUnauthorized, errors.New("invalid or revoked API key"))
				return
			}
			// Source-IP allow-list (NetOps extension). Reject calls from outside
			// the key's permitted CIDRs without authenticating.
			if !k.sourceAllowed(clientIP(r)) {
				writeError(w, http.StatusForbidden, errors.New("source address not permitted for this API key"))
				return
			}
			// Per-key rate limit (fixed window / minute). 429 + Retry-After when
			// the key exceeds its cap; surfaced live in Administration → API Access.
			if ok, retry := s.apiKeys.Allow(k.ID, s.apiKeys.effectiveLimit(k)); !ok {
				w.Header().Set("Retry-After", intToString(retry))
				writeError(w, http.StatusTooManyRequests, errors.New("API key rate limit exceeded"))
				return
			}
			claims := jwtClaims{
				Sub:    "apikey:" + k.ID,
				Role:   roleFromScopes(k.Scopes),
				Tenant: k.TenantID,
				Scopes: k.Scopes,
			}
			ctx := context.WithValue(r.Context(), userCtxKey, s.withActingTenant(r, claims))
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Our own session tokens are HS256. Try that first (the common path).
		claims, err := verifyJWT(token, jwtSecret())
		if err == nil {
			ctx := context.WithValue(r.Context(), userCtxKey, s.withActingTenant(r, claims))
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Otherwise, if SSO is configured, accept a Keycloak-signed RS256 Bearer
		// (service accounts / direct API clients) verified against its JWKS.
		if op := s.oidcProvider(); op.ready() {
			if oc, verr := op.jwks.verifyRS256(token, op.issuer, op.clientID); verr == nil {
				ctx := context.WithValue(r.Context(), userCtxKey, s.withActingTenant(r, jwtClaims{
					Sub:    firstNonEmpty(oc.PreferredUsername, oc.Email, oc.Sub),
					Role:   op.roleFor(oc),
					Tenant: op.defaultTenant,
				}))
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		writeError(w, http.StatusUnauthorized, err)
	})
}

func userFrom(ctx context.Context) (jwtClaims, bool) {
	v := ctx.Value(userCtxKey)
	if v == nil {
		return jwtClaims{}, false
	}
	c, ok := v.(jwtClaims)
	return c, ok
}

// ---- OpenSearch Dashboards (/search) platform-owner gate (#35) -------------
//
// nginx proxies /search/ to OpenSearch Dashboards OUTSIDE this auth middleware
// (it's a browser-loaded iframe, not an XHR, so it can't carry the Bearer
// header). To keep that surface platform-owner-only — Dashboards runs with its
// security plugin off, so it has NO tenant isolation and would expose every
// tenant's logs — nginx auth_request's each /search request against
// handleOSDGate. The principal is carried in a short-lived httpOnly cookie
// scoped to Path=/search (set at login/refresh, cleared at logout), so it is
// only ever sent on /search requests and never reaches /api.
const osdCookieName = "netops_osd"

// secureCookies marks session cookies Secure (HTTPS-only) via explicit env
// override. Used as a fallback; cookieSecure also auto-detects HTTPS per request.
func secureCookies() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SECURE_COOKIES")), "true")
}

// cookieSecure decides the Secure flag for a session cookie (SR-030). It is set
// whenever the request arrived over HTTPS (direct TLS or X-Forwarded-Proto from
// the TLS edge), OR when SECURE_COOKIES=true forces it. This auto-protects the
// JWT-bearing cookie on HTTPS deployments without breaking the plain-HTTP default
// (a Secure cookie over HTTP is silently dropped by the browser).
func cookieSecure(r *http.Request) bool {
	if secureCookies() {
		return true
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// consoleGatePath is the cookie path for the embedded-console gate cookie. It
// must cover every same-origin console nginx guards with the auth_request gate —
// today /search (OpenSearch Dashboards) AND /netbox/ (the bundled Source of
// Truth, embedded in-app). Path="/" so one cookie reaches them all; the cookie
// is HttpOnly + SameSite=Lax and carries only the access token the gate verifies.
const consoleGatePath = "/"

// setOSDCookie issues/refreshes the embedded-console gate cookie carrying the
// caller's access token. SameSite=Lax is sufficient (the consoles are embedded
// same-origin). Lifetime tracks the access token.
func setOSDCookie(w http.ResponseWriter, r *http.Request, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     osdCookieName,
		Value:    token,
		Path:     consoleGatePath,
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// clearOSDCookie expires the gate cookie on logout (same attributes, MaxAge<0).
func clearOSDCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     osdCookieName,
		Value:    "",
		Path:     consoleGatePath,
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// handleOSDGate is the nginx auth_request target for the embedded consoles
// (/search, /netbox). It authenticates from the gate cookie (not a Bearer token)
// and authorizes ONLY the platform owner — a super-admin in the global tenant
// (principalTenant cross==true). 200 = allow, 401 = no/invalid session, 403 =
// authenticated but not platform owner. It is in publicPaths so the bearer-token
// middleware doesn't reject the cookie-only subrequest; the authz lives here.
//
// On allow it returns X-Netbox-User: the NetBox superuser name. nginx captures
// it (auth_request_set) and forwards it to NetBox as the REMOTE_AUTH header so
// the embedded Source of Truth auto-logs-in as that superuser — no NetBox login
// screen. Safe because the header is emitted ONLY after the platform-owner check
// passes, and nginx strips any client-supplied copy.
func (s *server) handleOSDGate(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(osdCookieName)
	if err != nil || c.Value == "" {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	claims, err := verifyJWT(c.Value, jwtSecret())
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("invalid or expired session"))
		return
	}
	if !isPlatformOwner(claims) { // identity check — ignore any view-as-tenant override
		writeError(w, http.StatusForbidden, errors.New("platform administrator access required"))
		return
	}
	w.Header().Set("X-Netbox-User", netboxRemoteUser())
	w.WriteHeader(http.StatusOK)
}

// netboxRemoteUser is the NetBox username the embedded console auto-logs-in as.
// It MUST match the bundled NetBox superuser (compose SUPERUSER_NAME) so NetBox's
// REMOTE_AUTH maps the request to that existing superuser rather than minting a
// permissionless auto-created user. Sourced from the same env compose feeds NetBox.
func netboxRemoteUser() string {
	if u := strings.TrimSpace(os.Getenv("NETBOX_SUPERUSER")); u != "" {
		return u
	}
	return "admin"
}

func jwtSecret() string {
	if v := os.Getenv("JWT_SECRET"); v != "" {
		return v
	}
	// Last-resort fallback so the API doesn't refuse to start without env.
	// install.py always sets JWT_SECRET; this branch only matters for
	// rogue runs (e.g. `go run main.go` directly). ensureSigningSecret() makes
	// boot fail-closed (SR-017) unless ALLOW_DEV_SECRETS=true, so reaching this
	// fallback at runtime means dev mode was explicitly opted into.
	return devFallbackSecret
}

// devFallbackSecret is the publicly-known signing secret used ONLY when no
// JWT_SECRET is configured AND dev mode was opted into (ALLOW_DEV_SECRETS=true).
const devFallbackSecret = "dev-only-do-not-use-in-production" // #nosec G101 -- intentionally public placeholder, not a real credential; ensureSigningSecret fails closed unless ALLOW_DEV_SECRETS=true

// ensureSigningSecret fails the process closed (SR-017) when no JWT_SECRET is
// set. The fallback secret is public, and it also keys report/export capability
// links (report_links.go), so running with it in any real deployment lets anyone
// forge sessions and signed links. install.py always sets JWT_SECRET; the only
// way to hit the fallback is an unconfigured run, which must be an explicit
// dev-only opt-in via ALLOW_DEV_SECRETS=true. Call this at startup.
func ensureSigningSecret() error {
	if strings.TrimSpace(os.Getenv("JWT_SECRET")) != "" {
		return nil
	}
	if os.Getenv("ALLOW_DEV_SECRETS") == "true" {
		logWarn("auth", "JWT_SECRET unset — using the publicly-known dev fallback (ALLOW_DEV_SECRETS=true). NEVER use this outside local dev: sessions and report/export links are forgeable.", nil)
		return nil
	}
	return errors.New("JWT_SECRET is not set — refusing to start with the publicly-known dev fallback secret (it also signs report/export links). Set JWT_SECRET, or set ALLOW_DEV_SECRETS=true for local development only")
}
