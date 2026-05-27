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
// Tokens are JWTs signed with HS256 using the JWT_SECRET. Tokens carry
// the username (sub), role, issued-at, and expiry. The expiry is 24h
// from issue; clients re-login when it lapses.

const tokenTTL = 24 * time.Hour

type ctxKey int

const userCtxKey ctxKey = 0

// ---- handlers -------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string    `json:"token"`
	User  publicUser `json:"user"`
}

type publicUser struct {
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

func toPublic(u User) publicUser {
	return publicUser{Username: u.Username, Role: u.Role, LastLoginAt: u.LastLoginAt}
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
	tok, err := signJWT(jwtClaims{
		Sub:  user.Username,
		Role: user.Role,
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(tokenTTL).Unix(),
	}, jwtSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.users.TouchLogin(user.Username)
	logInfo("auth", "login ok", map[string]any{"user": user.Username, "role": user.Role})
	writeJSON(w, http.StatusOK, loginResponse{Token: tok, User: toPublic(user)})
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
	"/metrics",
}

func withAuth(next http.Handler) http.Handler {
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
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
				return
			}
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
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
