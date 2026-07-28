// Package token is the auth-crypto boundary: the session/API token claims
// model and a minimal HS256 JWT signer/verifier implemented in pure stdlib.
//
// We never accept any algorithm other than HS256. We never trust the
// `alg` field in the header (a classic JWT pitfall — accepting "none"
// or letting clients downgrade to RS256-with-public-key-as-HMAC-secret
// has been a real exploit). The header is fixed at sign time and the
// verifier ignores it.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrInvalid is returned for every verification failure. Deliberately a single
// opaque error: the reason a token was rejected is never revealed to a caller.
var ErrInvalid = errors.New("invalid token")

// Claims is the platform's JWT claims set.
type Claims struct {
	Sub    string   `json:"sub"`
	Role   string   `json:"role"`
	Tenant string   `json:"tenant,omitempty"` // tenant id the principal is bound to
	Sid    string   `json:"sid,omitempty"`    // server-side session id (lifecycle source of truth)
	Scopes []string `json:"scopes,omitempty"` // API-key scopes (empty for human sessions)
	Iat    int64    `json:"iat"`
	Nbf    int64    `json:"nbf,omitempty"` // not-before; enforced by Verify (SR-024)
	Exp    int64    `json:"exp"`

	// ActingTenant is the platform owner's "view as tenant" override, set
	// server-side by withActingTenant from a request header — NEVER from the
	// token. SECURITY: the `json:"-"` tag is the control that enforces that.
	// Before this type crossed the package boundary the field was unexported,
	// which made it invisible to encoding/json; exporting it (required for use
	// from package main) would let a crafted token populate a platform-owner
	// tenant override unless (un)marshal is excluded. Do NOT remove the tag —
	// TestCraftedTokenCannotSetActingTenant pins the property. Empty means no
	// override (all-tenants view). See principalTenant in the integrator.
	ActingTenant string `json:"-"`
}

// HasScope reports whether the principal carries an API-key scope. Human
// sessions carry none, so they fall through to RBAC role checks instead.
func (c Claims) HasScope(want string) bool {
	for _, s := range c.Scopes {
		if s == want || s == "admin:*" {
			return true
		}
		// "read:*" satisfies any "read:<x>"; "write:*" any "write:<x>".
		if strings.HasSuffix(s, ":*") && strings.HasPrefix(want, strings.TrimSuffix(s, "*")) {
			return true
		}
	}
	return false
}

const jwtHeader = `{"alg":"HS256","typ":"JWT"}`

// Sign mints an HS256 JWT for the given claims.
func Sign(claims Claims, secret string) (string, error) {
	// SR-024: stamp iat/nbf even if a caller forgot, so every token Verify
	// sees can be time-validated.
	now := time.Now().Unix()
	if claims.Iat == 0 {
		claims.Iat = now
	}
	if claims.Nbf == 0 {
		claims.Nbf = claims.Iat
	}
	headerEnc := b64url([]byte(jwtHeader))
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsEnc := b64url(claimsBytes)
	signingInput := headerEnc + "." + claimsEnc
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signingInput))
	sig := b64url(h.Sum(nil))
	return signingInput + "." + sig, nil
}

// Verify checks an HS256 JWT's signature and time bounds and returns its
// claims. Every failure returns ErrInvalid.
func Verify(tok, secret string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalid
	}
	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signingInput))
	expected := b64url(h.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return Claims{}, ErrInvalid
	}
	claimsBytes, err := b64urlDecode(parts[1])
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var c Claims
	if err := json.Unmarshal(claimsBytes, &c); err != nil {
		return Claims{}, ErrInvalid
	}
	// SR-024: enforce time bounds with a small clock-skew allowance. exp (expiry),
	// nbf (not-before), and a future-dated iat are all rejected.
	const skew = 60 // seconds
	now := time.Now().Unix()
	if c.Exp != 0 && now > c.Exp {
		return Claims{}, ErrInvalid
	}
	if c.Nbf != 0 && now+skew < c.Nbf {
		return Claims{}, ErrInvalid
	}
	if c.Iat != 0 && now+skew < c.Iat {
		return Claims{}, ErrInvalid
	}
	return c, nil
}

func b64url(b []byte) string                { return base64.RawURLEncoding.EncodeToString(b) }
func b64urlDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
