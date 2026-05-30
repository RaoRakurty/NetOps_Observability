package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

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

func accessTokenTTL() time.Duration  { return durEnv("ACCESS_TOKEN_TTL", time.Hour) }
func refreshTokenTTL() time.Duration { return durEnv("REFRESH_TOKEN_TTL", 7*24*time.Hour) }

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
		Sub:  user.Username,
		Role: user.Role,
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(ttl).Unix(),
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
		Sub: user.Username, Role: user.Role,
		Iat: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
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
	writeJSON(w, http.StatusOK, toPublic(user))
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
		// principal scoped read-only by default (scope→level enforcement is a
		// follow-up; see docs/API_ACCESS.md).
		if strings.HasPrefix(token, keyPrefix) {
			k, ok := s.apiKeys.Verify(token)
			if !ok {
				writeError(w, http.StatusUnauthorized, errors.New("invalid or revoked API key"))
				return
			}
			claims := jwtClaims{Sub: "apikey:" + k.ID, Role: RoleReadOnly}
			ctx := context.WithValue(r.Context(), userCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		claims, err := verifyJWT(token, jwtSecret())
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
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

func jwtSecret() string {
	if v := os.Getenv("JWT_SECRET"); v != "" {
		return v
	}
	// Last-resort fallback so the API doesn't refuse to start without env.
	// install.py always sets JWT_SECRET; this branch only matters for
	// rogue runs (e.g. `go run main.go` directly).
	return "dev-only-do-not-use-in-production"
}
