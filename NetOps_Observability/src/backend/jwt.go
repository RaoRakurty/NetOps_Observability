package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Minimal HS256 JWT signer/verifier implemented in pure stdlib.
//
// We never accept any algorithm other than HS256. We never trust the
// `alg` field in the header (a classic JWT pitfall — accepting "none"
// or letting clients downgrade to RS256-with-public-key-as-HMAC-secret
// has been a real exploit). The header is fixed at sign time and the
// verifier ignores it.

const jwtHeader = `{"alg":"HS256","typ":"JWT"}`

func signJWT(claims jwtClaims, secret string) (string, error) {
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

func verifyJWT(token, secret string) (jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, errJWT
	}
	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signingInput))
	expected := b64url(h.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return jwtClaims{}, errJWT
	}
	claimsBytes, err := b64urlDecode(parts[1])
	if err != nil {
		return jwtClaims{}, errJWT
	}
	var c jwtClaims
	if err := json.Unmarshal(claimsBytes, &c); err != nil {
		return jwtClaims{}, errJWT
	}
	if c.Exp != 0 && time.Now().Unix() > c.Exp {
		return jwtClaims{}, errJWT
	}
	return c, nil
}

func b64url(b []byte) string             { return base64.RawURLEncoding.EncodeToString(b) }
func b64urlDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
