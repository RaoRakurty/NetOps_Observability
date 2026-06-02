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
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		if ip := net.ParseIP(first); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

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
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, ok := s.users.Get(req.Username)
	if !ok || !verifyPassword(req.Password, user.PasswordHash) {
		// Generic message: don't leak whether the username exists.
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
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
	setOSDCookie(w, tok, ttl) // /search gate cookie (enforced for platform owner only)
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
	setOSDCookie(w, tok, ttl)
	writeJSON(w, http.StatusOK, loginResponse{
		Token: tok, RefreshToken: newRefresh, ExpiresIn: int(ttl.Seconds()), User: toPublic(user),
	})
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
	clearOSDCookie(w)
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
	// platform-wide administration. It mirrors the backend's own cross-tenant
	// rule (principalTenant) so the UI never re-derives the policy itself.
	_, cross := principalTenant(claims)
	writeJSON(w, http.StatusOK, struct {
		publicUser
		PlatformAdmin bool `json:"platform_admin"`
	}{toPublic(user), cross})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, ok := s.users.Get(claims.Sub)
	if !ok || !verifyPassword(req.CurrentPassword, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, errors.New("current password incorrect"))
		return
	}
	if err := s.users.ChangePassword(user.Username, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	logInfo("auth", "password changed", map[string]any{"user": user.Username})
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
	"/api/auth/osd-gate", // cookie-authenticated nginx auth_request target; does its own authz
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
		// Secure report links carry a signed, expiring token in the path and do
		// their own authorization in handleReportView — no Bearer needed.
		if strings.HasPrefix(r.URL.Path, "/api/reports/view/") {
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
		if r.URL.Path == "/api/events" {
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
			ctx := context.WithValue(r.Context(), userCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Our own session tokens are HS256. Try that first (the common path).
		claims, err := verifyJWT(token, jwtSecret())
		if err == nil {
			ctx := context.WithValue(r.Context(), userCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Otherwise, if SSO is configured, accept a Keycloak-signed RS256 Bearer
		// (service accounts / direct API clients) verified against its JWKS.
		if op := s.oidcProvider(); op.ready() {
			if oc, verr := op.jwks.verifyRS256(token, op.issuer, op.clientID); verr == nil {
				ctx := context.WithValue(r.Context(), userCtxKey, jwtClaims{
					Sub:    firstNonEmpty(oc.PreferredUsername, oc.Email, oc.Sub),
					Role:   op.roleFor(oc),
					Tenant: op.defaultTenant,
				})
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

// secureCookies marks session cookies Secure (HTTPS-only). Off by default
// because the stack currently serves plain HTTP on :8000; flip SECURE_COOKIES=
// true once TLS (#18) terminates at nginx. A Secure cookie over plain HTTP is
// silently dropped by the browser, which would break the gate — hence opt-in.
func secureCookies() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SECURE_COOKIES")), "true")
}

// setOSDCookie issues/refreshes the /search gate cookie carrying the caller's
// access token. Path=/search confines it to the Dashboards route; SameSite=Lax
// is sufficient (the iframe is same-origin). Lifetime tracks the access token.
func setOSDCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     osdCookieName,
		Value:    token,
		Path:     "/search",
		HttpOnly: true,
		Secure:   secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// clearOSDCookie expires the gate cookie on logout (same attributes, MaxAge<0).
func clearOSDCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     osdCookieName,
		Value:    "",
		Path:     "/search",
		HttpOnly: true,
		Secure:   secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// handleOSDGate is the nginx auth_request target for /search. It authenticates
// from the gate cookie (not a Bearer token) and authorizes ONLY the platform
// owner — a super-admin in the global tenant (principalTenant cross==true).
// 200 = allow, 401 = no/invalid session, 403 = authenticated but not platform
// owner. It is in publicPaths so the bearer-token middleware doesn't reject the
// cookie-only subrequest; the authorization lives here.
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
	if _, cross := principalTenant(claims); !cross {
		writeError(w, http.StatusForbidden, errors.New("platform administrator access required"))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func jwtSecret() string {
	if v := os.Getenv("JWT_SECRET"); v != "" {
		return v
	}
	// Last-resort fallback so the API doesn't refuse to start without env.
	// install.py always sets JWT_SECRET; this branch only matters for
	// rogue runs (e.g. `go run main.go` directly).
	return "dev-only-do-not-use-in-production"
}
