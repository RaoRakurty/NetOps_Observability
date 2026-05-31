package main

import (
	"log"
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
