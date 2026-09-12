// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// workload_issuer.go — Wave 4 #13: platform-minted workload OIDC assertions.
//
// Until now every federated exchange (Azure Entra WIF client_assertion, GCP STS
// subject_token, AWS AssumeRoleWithWebIdentity) depended on an EXTERNALLY
// minted assertion projected into the environment (EnvWorkloadAssertionSource —
// the K8s/CI pattern). MintedWorkloadAssertionSource makes the platform its own
// OIDC issuer: the backend holds a vault-sealed RSA signing key and mints a
// short-lived RS256 assertion per exchange — iss = the platform issuer URL the
// customer's identity provider trusts, sub = the per-connector subject their
// trust policy names, aud = what the relying provider expects. The public half
// is served as JWKS + OIDC discovery by the backend (cloud_workload_issuer.go)
// so AWS/Azure/GCP can verify what we mint.
//
// stdlib-only (crypto/rsa, crypto/rand, crypto/sha256, encoding/json). The
// signing key NEVER leaves this process; assertions are short-lived (default
// 5m) and single-purpose (unique jti), per §9 idempotency/least-exposure.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// defaultWorkloadAssertionTTL bounds a minted assertion's validity. Providers
// only need it to survive the immediately following token exchange.
const defaultWorkloadAssertionTTL = 5 * time.Minute

// MintedWorkloadAssertionSource mints Correlix's own workload OIDC assertions
// with a platform signing key. Zero value is unusable — a nil Key returns
// ErrWorkloadAssertionMissing (the standard "not configured" deferral).
type MintedWorkloadAssertionSource struct {
	Key    *rsa.PrivateKey
	Kid    string           // JWKS key id (RSAJWKThumbprintKid of the public key)
	Issuer string           // public issuer URL customers federate against
	TTL    time.Duration    // assertion lifetime; 0 → defaultWorkloadAssertionTTL
	Now    func() time.Time // injectable clock; nil → time.Now UTC
}

// Assertion implements WorkloadAssertionSource.
func (m MintedWorkloadAssertionSource) Assertion(_ context.Context, audience, subject string) (string, error) {
	if m.Key == nil || strings.TrimSpace(m.Issuer) == "" {
		return "", ErrWorkloadAssertionMissing
	}
	aud, sub := strings.TrimSpace(audience), strings.TrimSpace(subject)
	if aud == "" {
		return "", &ExchangeError{Code: "request_invalid", Msg: "workload assertion audience missing"}
	}
	if sub == "" || strings.HasSuffix(sub, ":") { // ":" = WorkloadSubject default with an empty connector id
		return "", &ExchangeError{Code: "request_invalid", Msg: "workload assertion subject missing"}
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now()
	}
	ttl := m.TTL
	if ttl <= 0 {
		ttl = defaultWorkloadAssertionTTL
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("cloudconn: assertion jti: %w", err)
	}
	claims := map[string]any{
		"iss": strings.TrimSpace(m.Issuer),
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"nbf": now.Add(-30 * time.Second).Unix(), // small skew allowance
		"exp": now.Add(ttl).Unix(),
		"jti": hex.EncodeToString(jti),
	}
	return signRS256JWT(m.Key, m.Kid, claims)
}

// RSAJWKThumbprintKid computes the RFC 7638 JWK thumbprint (SHA-256,
// base64url) of an RSA public key — the stable, derivable kid the JWKS and
// every minted assertion header share.
func RSAJWKThumbprintKid(pub *rsa.PublicKey) string {
	// RFC 7638 §3: lexicographic required members, no whitespace.
	canon := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, b64BigInt(big.NewInt(int64(pub.E))), b64BigInt(pub.N))
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RSAPublicJWKS renders the JWKS document for the issuer's signing key —
// public material only, safe on an unauthenticated surface.
func RSAPublicJWKS(pub *rsa.PublicKey, kid string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   b64BigInt(pub.N),
			"e":   b64BigInt(big.NewInt(int64(pub.E))),
		}},
	})
}

func b64BigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// AdapterForWithAssertions is AdapterFor with every exchanger's assertion
// source replaced by src — the wiring the backend uses once the platform
// issuer is configured, so all federated paths mint instead of reading a
// projected token. Probe clients stay live, identical to AdapterFor.
// Resolution goes through the provider registry; a descriptor without the
// assertion hook falls back to its plain live adapter (no assertion minting,
// which that provider then simply does not use).
func AdapterForWithAssertions(p Provider, src WorkloadAssertionSource) CloudIdentityProvider {
	d, ok := providerRegistry[p]
	if !ok {
		return nil
	}
	if d.NewAdapterWithAssertions == nil {
		return d.NewAdapter()
	}
	return d.NewAdapterWithAssertions(src)
}
