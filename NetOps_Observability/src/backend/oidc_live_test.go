// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"os"
	"testing"

	"netops/backend/internal/oidc"

	"time"
)

// TestOIDCLiveDuende validates the OIDC integration end-to-end against the
// public Duende demo IdentityServer (https://demo.duendesoftware.com), up to the
// token-verification layer: it builds the provider from config, confirms it is
// ready(), fetches the real OIDC discovery document, and loads the live JWKS
// signing keys. The full interactive code-exchange login needs a browser, so it
// is not covered here. Skipped unless NETOPS_OIDC_LIVE=1 (keeps the offline
// suite hermetic).
func TestOIDCLiveDuende(t *testing.T) {
	if os.Getenv("NETOPS_OIDC_LIVE") != "1" {
		t.Skip("set NETOPS_OIDC_LIVE=1 to run against demo.duendesoftware.com")
	}
	p := oidc.NewProviderFromConfig(oidcConfig{
		Enabled:  true,
		Issuer:   "https://demo.duendesoftware.com",
		ClientID: "interactive.public",
		Scopes:   "openid profile email",
	}, 10*time.Minute)
	if !p.Ready() {
		t.Fatalf("provider should be ready (enabled+issuer+clientID+jwks)")
	}
	disc, err := p.JWKS().Discovery()
	if err != nil {
		t.Fatalf("OIDC discovery against Duende failed: %v", err)
	}
	if disc.AuthEndpoint == "" || disc.TokenEndpoint == "" || disc.JWKSURI == "" {
		t.Fatalf("incomplete discovery doc: %+v", disc)
	}
	t.Logf("discovery OK: auth=%s token=%s jwks=%s", disc.AuthEndpoint, disc.TokenEndpoint, disc.JWKSURI)

	// Force a JWKS fetch and assert the live key set was retrieved.
	if err := p.JWKS().Refresh(); err != nil {
		t.Fatalf("live JWKS refresh failed: %v", err)
	}
	if p.JWKS().KeyCount() == 0 {
		t.Fatal("expected ≥1 signing key fetched from the live JWKS endpoint")
	}
	t.Logf("JWKS OK: %d live signing key(s) loaded", p.JWKS().KeyCount())
}
