// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// oidc_bearer_account_state_test.go — H2: the RS256 bearer path must honour the
// STORED account state, not just the IdP token. Before bearerPrincipal, the
// branch minted claims directly from the verified token: a DISABLED account
// kept API access for the token's lifetime, a tenant move/demotion recorded in
// the user store was ignored in favour of OIDC_DEFAULT_TENANT + the raw IdP
// role, tenant suspension never applied, and a bearer named like a LOCAL
// account acted as that account (the H1 collision, on the API surface).
//
// Reuses the bearerHarness from oidc_bearer_platform_owner_test.go (real
// withAuth + real RS256 verification against a test JWKS).

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/internal/jwks"
	"netops/backend/internal/oidc"
)

// bearerRequest runs the REAL withAuth middleware and returns the HTTP status
// alongside the claims that reached the handler (reached=false on refusal).
func bearerRequest(t *testing.T, h *bearerHarness, token string) (int, jwtClaims, bool) {
	t.Helper()
	var got jwtClaims
	var reached bool
	handler := h.s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, reached = userFrom(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/devices", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	return rec.Code, got, reached
}

// mintBearerClaims signs an RS256 token with the harness key from an arbitrary
// claim set (mintBearer's fixed shape isn't enough for the amr/azp cases).
func mintBearerClaims(t *testing.T, h *bearerHarness, claims map[string]any) string {
	t.Helper()
	b64 := func(v any) string {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(j)
	}
	signing := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": bearerKID}) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func baseBearerClaims(h *bearerHarness, sub string) map[string]any {
	return map[string]any{
		"iss": h.p.Issuer(), "aud": h.p.ClientID(), "sub": sub, "preferred_username": sub,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
	}
}

func TestOIDCBearerHonoursStoredAccountState(t *testing.T) {
	h := newBearerHarness(t, TenantGlobal)
	tok := h.mintBearer(t, "svc-2") // no admin roles → default read-only

	// First sight JIT-provisions through UpsertFederated, like the SSO callback.
	if st, _, reached := bearerRequest(t, h, tok); st != http.StatusOK || !reached {
		t.Fatalf("initial bearer: status %d reached=%v, want 200/true", st, reached)
	}
	u, ok := h.s.users.Get("svc-2")
	if !ok || u.AuthSource != "oidc" {
		t.Fatalf("bearer subject not provisioned as federated: %+v (ok=%v)", u, ok)
	}

	// Disabled account → 401 on the very next request, token still valid or not.
	if _, err := h.s.users.Update("svc-2", User{Status: "disabled"}); err != nil {
		t.Fatal(err)
	}
	if st, _, reached := bearerRequest(t, h, tok); st != http.StatusUnauthorized || reached {
		t.Fatalf("disabled account via bearer: status %d reached=%v, want 401/false", st, reached)
	}

	// Stored tenant is authoritative: a tenant move recorded in the user store
	// must be what the request acts as — not OIDC_DEFAULT_TENANT.
	if _, err := h.s.tenants.Create("Acme", "acme", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.users.Update("svc-2", User{Status: "active", TenantID: "acme"}); err != nil {
		t.Fatal(err)
	}
	st, claims, reached := bearerRequest(t, h, tok)
	if st != http.StatusOK || !reached {
		t.Fatalf("re-enabled bearer: status %d reached=%v, want 200/true", st, reached)
	}
	if claims.Tenant != "acme" {
		t.Errorf("bearer claims.Tenant = %q, want the STORED tenant %q", claims.Tenant, "acme")
	}

	// Suspended tenant → 403 (deny-by-default lifecycle applies to bearers too).
	if _, err := h.s.tenants.SetStatus("acme", TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	if st, _, reached := bearerRequest(t, h, tok); st != http.StatusForbidden || reached {
		t.Fatalf("suspended tenant via bearer: status %d reached=%v, want 403/false", st, reached)
	}
}

// A bearer whose subject names a LOCAL account must be refused — the API twin
// of the H1 interactive rule (an IdP identity must never act as a colliding
// local account; that bypasses its password and MFA enrollment).
func TestOIDCBearerRefusedForLocalAccount(t *testing.T) {
	h := newBearerHarness(t, TenantGlobal)
	before, ok := h.s.users.Get("admin") // seeded LOCAL bootstrap admin
	if !ok {
		t.Fatal("seeded admin missing")
	}
	st, _, reached := bearerRequest(t, h, h.mintBearer(t, "admin", "admin"))
	if st != http.StatusForbidden || reached {
		t.Fatalf("bearer as local admin: status %d reached=%v, want 403/false", st, reached)
	}
	after, _ := h.s.users.Get("admin")
	if after.Role != before.Role || after.AuthSource != before.AuthSource {
		t.Errorf("local admin mutated by refused bearer: %+v", after)
	}
}

// RequireMFA applies to USER bearers (no azp): the token must assert a second
// factor, as the SSO callback demands. Tokens carrying azp are service-account
// (client-credentials) grants and exempt — documented trade-off on
// bearerPrincipal.
func TestOIDCBearerRequireMFA(t *testing.T) {
	_, s := newTestServerState(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": bearerKID, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	}))
	t.Cleanup(jwksSrv.Close)
	p := oidc.NewProviderFromConfig(oidcConfig{
		Enabled: true, Issuer: "https://idp.example.test/realms/netops", ClientID: "netops-api",
		DefaultRole: RoleReadOnly, DefaultTenant: TenantGlobal, RequireMFA: true,
	}, 10*time.Minute)
	p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:        p.Issuer(),
		AuthEndpoint:  p.Issuer() + "/protocol/openid-connect/auth",
		TokenEndpoint: p.Issuer() + "/protocol/openid-connect/token",
		JWKSURI:       jwksSrv.URL,
	})
	s.oidc.Store(p)
	h := &bearerHarness{s: s, key: key, p: p}

	// User token (no azp), no second factor asserted → refused.
	if st, _, reached := bearerRequest(t, h, mintBearerClaims(t, h, baseBearerClaims(h, "human-1"))); st != http.StatusUnauthorized || reached {
		t.Fatalf("MFA-less user bearer: status %d reached=%v, want 401/false", st, reached)
	}
	// User token asserting a second factor (amr) → accepted.
	withAmr := baseBearerClaims(h, "human-1")
	withAmr["amr"] = []string{"pwd", "otp"}
	if st, _, reached := bearerRequest(t, h, mintBearerClaims(t, h, withAmr)); st != http.StatusOK || !reached {
		t.Fatalf("otp-asserting user bearer: status %d reached=%v, want 200/true", st, reached)
	}
	// Service-account token (azp present) → exempt from the MFA assertion.
	svc := baseBearerClaims(h, "svc-batch")
	svc["azp"] = "netops-api"
	if st, _, reached := bearerRequest(t, h, mintBearerClaims(t, h, svc)); st != http.StatusOK || !reached {
		t.Fatalf("service-account bearer: status %d reached=%v, want 200/true", st, reached)
	}
}
