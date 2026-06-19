package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// token_policy.go — bounded, configurable token lifetimes.
//
// Limits are derived from current industry guidance:
//   - RFC 9700 (OAuth 2.0 Security Best Current Practice, Jan 2025): keep access
//     tokens short (5–15 min for sensitive APIs, 30–60 min general); refresh
//     tokens 7–30 days with single-use rotation + reuse detection.
//   - NIST SP 800-63B session management: AAL2 sessions reauthenticate at most
//     every 12 h (absolute) and after 30 min of inactivity; AAL1 ≤ 30 days.
//
// We expose the lifetimes via env (ACCESS_TOKEN_TTL / REFRESH_TOKEN_TTL) but
// CLAMP them into a safe [min,max] window so a typo or an over-eager operator
// can't mint a multi-year access token, and we log a warning when a value
// exceeds the recommended ceiling. Rotation + reuse-detection already live in
// refresh.go; HS256 (local) / RS256 (Keycloak) signing in password.go / jwks.go.
const (
	accessTTLMin         = 1 * time.Minute
	accessTTLMax         = 24 * time.Hour
	accessTTLRecommended = 1 * time.Hour // warn above this (RFC 9700 general API)

	refreshTTLMin         = 5 * time.Minute
	refreshTTLMax         = 90 * 24 * time.Hour
	refreshTTLRecommended = 30 * 24 * time.Hour // warn above this (RFC 9700 / NIST)
)

// clampDuration returns d bounded to [min,max] and whether it had to be clamped.
func clampDuration(d, min, max time.Duration) (time.Duration, bool) {
	if d < min {
		return min, true
	}
	if d > max {
		return max, true
	}
	return d, false
}

// boundedDurEnv parses a duration from env, applies [min,max] clamping, and logs
// when a value is clamped or exceeds the recommended ceiling. An empty/invalid
// value falls back to def (already within bounds).
func boundedDurEnv(key string, def, min, max, recommended time.Duration) time.Duration {
	d := durEnv(key, def)
	clamped, was := clampDuration(d, min, max)
	if was {
		log.Printf("token policy: %s=%s out of bounds [%s,%s]; clamped to %s", key, d, min, max, clamped)
	}
	if clamped > recommended {
		log.Printf("token policy: %s=%s exceeds the recommended maximum %s (RFC 9700 / NIST 800-63B) — shorten for AAL2 compliance", key, clamped, recommended)
	}
	return clamped
}

// ---------------------------------------------------------------------------
// Runtime-configurable token policy (admin UI)
// ---------------------------------------------------------------------------

// tokenPolicyConfig is the operator-tunable token lifetime policy.
type tokenPolicyConfig struct {
	AccessTTLSeconds  int `json:"access_ttl_seconds"`
	RefreshTTLSeconds int `json:"refresh_ttl_seconds"`
}

// tokenPolicyStore persists the policy via the kv store and pushes it into the
// live resolution paths: access TTL is read per-login through boundedDurEnv (so
// it updates the process env), and the refresh store's TTL is updated in place
// so changes take effect on the next issued token without a restart.
type tokenPolicyStore struct {
	mu      sync.Mutex
	path    string
	refresh *refreshStore
}

func newTokenPolicyStore(path string, refresh *refreshStore) *tokenPolicyStore {
	s := &tokenPolicyStore{path: path, refresh: refresh}
	s.load()
	return s
}

func (s *tokenPolicyStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var c tokenPolicyConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	s.apply(c)
}

// apply writes the config into the env (clamped/read by accessTokenTTL /
// refreshTokenTTL) and refreshes the refresh-store TTL.
func (s *tokenPolicyStore) apply(c tokenPolicyConfig) {
	if c.AccessTTLSeconds > 0 {
		if err := os.Setenv("ACCESS_TOKEN_TTL", (time.Duration(c.AccessTTLSeconds) * time.Second).String()); err != nil {
			log.Printf("token policy: set ACCESS_TOKEN_TTL: %v", err)
		}
	}
	if c.RefreshTTLSeconds > 0 {
		if err := os.Setenv("REFRESH_TOKEN_TTL", (time.Duration(c.RefreshTTLSeconds) * time.Second).String()); err != nil {
			log.Printf("token policy: set REFRESH_TOKEN_TTL: %v", err)
		}
		if s.refresh != nil {
			s.refresh.SetTTL(refreshTokenTTL())
		}
	}
}

// effective returns the current (clamped) lifetimes actually in force.
func (s *tokenPolicyStore) effective() tokenPolicyConfig {
	return tokenPolicyConfig{
		AccessTTLSeconds:  int(accessTokenTTL().Seconds()),
		RefreshTTLSeconds: int(refreshTokenTTL().Seconds()),
	}
}

// set validates (positive + clamped to the RFC/NIST bounds), persists, and
// applies the policy. Returns the effective (post-clamp) config.
func (s *tokenPolicyStore) set(c tokenPolicyConfig) (tokenPolicyConfig, error) {
	if c.AccessTTLSeconds <= 0 || c.RefreshTTLSeconds <= 0 {
		return tokenPolicyConfig{}, errors.New("token policy: access and refresh TTL must be positive seconds")
	}
	acc, _ := clampDuration(time.Duration(c.AccessTTLSeconds)*time.Second, accessTTLMin, accessTTLMax)
	ref, _ := clampDuration(time.Duration(c.RefreshTTLSeconds)*time.Second, refreshTTLMin, refreshTTLMax)
	c = tokenPolicyConfig{AccessTTLSeconds: int(acc.Seconds()), RefreshTTLSeconds: int(ref.Seconds())}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return tokenPolicyConfig{}, err
	}
	if err := kvSave(s.path, b); err != nil {
		return tokenPolicyConfig{}, err
	}
	s.apply(c)
	return s.effective(), nil
}

// handleTokenPolicy: GET/PUT /api/auth/token-policy (admin-gated). GET returns
// the effective lifetimes plus the [min,max,recommended] bounds so the UI can
// validate + show guidance; PUT clamps + persists.
func (s *server) handleTokenPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	bounds := map[string]any{
		"access_min_seconds":          int(accessTTLMin.Seconds()),
		"access_max_seconds":          int(accessTTLMax.Seconds()),
		"access_recommended_seconds":  int(accessTTLRecommended.Seconds()),
		"refresh_min_seconds":         int(refreshTTLMin.Seconds()),
		"refresh_max_seconds":         int(refreshTTLMax.Seconds()),
		"refresh_recommended_seconds": int(refreshTTLRecommended.Seconds()),
	}
	switch r.Method {
	case http.MethodGet:
		c := s.tokenPolicy.effective()
		writeJSON(w, http.StatusOK, map[string]any{
			"access_ttl_seconds":  c.AccessTTLSeconds,
			"refresh_ttl_seconds": c.RefreshTTLSeconds,
			"bounds":              bounds,
		})
	case http.MethodPut:
		var c tokenPolicyConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := s.tokenPolicy.set(c)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("auth", "token policy updated", map[string]any{"access_ttl_s": out.AccessTTLSeconds, "refresh_ttl_s": out.RefreshTTLSeconds})
		writeJSON(w, http.StatusOK, map[string]any{
			"access_ttl_seconds":  out.AccessTTLSeconds,
			"refresh_ttl_seconds": out.RefreshTTLSeconds,
			"bounds":              bounds,
		})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
