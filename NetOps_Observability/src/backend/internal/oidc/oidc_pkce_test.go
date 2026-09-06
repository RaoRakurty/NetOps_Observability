// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/jwks"
)

// oidc_pkce_test.go — PKCE S256 + nonce + server-owned IdP aliases in the
// authorization request. The invariants: the verifier never appears in any
// URL, "plain" is structurally impossible, and kc_idp_hint only carries
// aliases the operator configured.

// RFC 7636 §4.1 unreserved set for code_verifier.
var pkceVerifierChars = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

func TestNewPKCEVerifierShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		v, c, err := NewPKCEVerifier()
		if err != nil {
			t.Fatalf("NewPKCEVerifier: %v", err)
		}
		if !pkceVerifierChars.MatchString(v) {
			t.Fatalf("verifier %q violates RFC 7636 length/charset", v)
		}
		sum := sha256.Sum256([]byte(v))
		if want := base64.RawURLEncoding.EncodeToString(sum[:]); c != want {
			t.Fatalf("challenge = %q, want S256(verifier) = %q", c, want)
		}
		if seen[v] {
			t.Fatalf("verifier %q repeated — not cryptographically random", v)
		}
		seen[v] = true
	}
}

func testProvider(t *testing.T, providers string) *Provider {
	t.Helper()
	p := NewProviderFromConfig(Config{
		Enabled:   true,
		Issuer:    "https://idp.example.test/realms/netops",
		ClientID:  "netops-api",
		Providers: providers,
	}, 10*time.Minute)
	p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:       p.Issuer(),
		AuthEndpoint: p.Issuer() + "/protocol/openid-connect/auth",
	})
	return p
}

func TestAuthorizeURLCarriesNoncePKCEAndHint(t *testing.T) {
	p := testProvider(t, "okta-saml:Okta:saml")
	v, challenge, err := NewPKCEVerifier()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	raw, err := p.AuthorizeURL("https://app.example.test/api/auth/sso/callback",
		"state-1", "nonce-1", challenge, "okta-saml")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type":         "code",
		"state":                 "state-1",
		"nonce":                 "nonce-1",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
		"kc_idp_hint":           "okta-saml",
		"client_id":             "netops-api",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope %q lacks openid", q.Get("scope"))
	}
	// The verifier must never ride in a URL; "plain" must never be offered.
	if strings.Contains(raw, v) {
		t.Error("authorize URL contains the PKCE verifier")
	}
	if strings.Contains(raw, "plain") {
		t.Error("authorize URL mentions the plain challenge method")
	}
}

func TestValidIDPOnlyAcceptsConfiguredAliases(t *testing.T) {
	p := testProvider(t, "okta-saml:Okta:saml,okta-oidc:Okta OIDC:oidc")
	for alias, want := range map[string]bool{
		"":           true, // realm default login page
		"okta-saml":  true,
		"okta-oidc":  true,
		"acme-okta":  false, // never configured — browser-invented
		"OKTA-SAML":  false, // exact match only
		"okta-saml ": false, // caller must trim; the provider does not guess
	} {
		if got := p.ValidIDP(alias); got != want {
			t.Errorf("ValidIDP(%q) = %v, want %v", alias, got, want)
		}
	}
	// With NO configured buttons the provider defaults to a single realm-default
	// entry with ID "" — every non-empty alias must be rejected.
	bare := testProvider(t, "")
	if !bare.ValidIDP("") {
		t.Error("realm default rejected on a bare provider")
	}
	if bare.ValidIDP("anything") {
		t.Error("bare provider accepted a browser-invented alias")
	}
}
