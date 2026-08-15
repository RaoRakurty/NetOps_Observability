package backend

// oidc_bearer_platform_owner_test.go — SR-025 parity for the RS256 BEARER path.
//
// The interactive SSO callback gets the federated platform-owner guard for free:
// it provisions through users.UpsertFederated, which runs Deps.GuardRole
// (= guardFederatedRole). The bearer branch of withAuth mints jwtClaims DIRECTLY
// from the verified token and so had no guard at all — an IdP access token whose
// realm roles merely contain "admin" (one of the DEFAULT OIDC_ADMIN_ROLES values,
// oidc.go:132) mapped to super-admin on the GLOBAL tenant, i.e. cross-tenant
// platform-owner reach, with FEDERATION_ALLOW_PLATFORM_OWNER unset.
//
// These tests drive the real withAuth middleware with a real RS256 token against
// a real JWKS, and assert the claims that actually reach the handler.

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

// bearerHarness serves a JWKS and mints RS256 access tokens the real provider
// verifies, wired into a full test server.
type bearerHarness struct {
	s   *server
	key *rsa.PrivateKey
	p   *oidcProvider
}

const bearerKID = "bearer-kid"

func newBearerHarness(t *testing.T, defaultTenant string) *bearerHarness {
	t.Helper()
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
		DefaultRole: RoleReadOnly, DefaultTenant: defaultTenant,
		// AdminRoles deliberately left empty: the DEFAULT set is what ships, and
		// "admin" being in it is precisely what makes this reachable in the field.
	}, 10*time.Minute)
	p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:        p.Issuer(),
		AuthEndpoint:  p.Issuer() + "/protocol/openid-connect/auth",
		TokenEndpoint: p.Issuer() + "/protocol/openid-connect/token",
		JWKSURI:       jwksSrv.URL,
	})
	s.oidc.Store(p)
	return &bearerHarness{s: s, key: key, p: p}
}

// mintBearer signs an access token asserting `roles` as Keycloak realm roles.
func (h *bearerHarness) mintBearer(t *testing.T, sub string, roles ...string) string {
	t.Helper()
	b64 := func(v any) string {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(j)
	}
	claims := map[string]any{
		"iss": h.p.Issuer(), "aud": h.p.ClientID(), "sub": sub, "preferred_username": sub,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
		"realm_access": map[string]any{"roles": roles},
	}
	signing := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": bearerKID}) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// callWithBearer runs the REAL withAuth middleware and returns the claims that
// reached the handler (ok=false when the middleware refused the request).
func (h *bearerHarness) callWithBearer(t *testing.T, token string) (jwtClaims, bool) {
	t.Helper()
	var got jwtClaims
	var reached bool
	handler := h.s.withAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, reached = userFrom(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/devices", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(httptest.NewRecorder(), r)
	return got, reached
}

func TestOIDCBearerCannotSelfElevateToPlatformOwner(t *testing.T) {
	h := newBearerHarness(t, TenantGlobal)
	claims, ok := h.callWithBearer(t, h.mintBearer(t, "svc-1", "admin"))
	if !ok {
		t.Fatal("bearer was rejected outright; this test must exercise the ACCEPTED path")
	}
	// The IdP asserted a role the provider maps to super-admin, on the global
	// tenant, with FEDERATION_ALLOW_PLATFORM_OWNER unset → SR-025 downgrade.
	if claims.Role == RoleSuperAdmin {
		t.Errorf("bearer with IdP role %q became %s on tenant %q — federated platform-owner "+
			"self-elevation (SR-025); guardFederatedRole must gate the bearer path too",
			"admin", claims.Role, claims.Tenant)
	}
	if claims.Role != RoleReadOnly {
		t.Errorf("downgraded role = %q, want %q (guardFederatedRole's verdict)", claims.Role, RoleReadOnly)
	}
	if isPlatformOwner(claims) {
		t.Error("downgraded bearer principal still reads as platform owner")
	}
}

func TestOIDCBearerPlatformOwnerAllowedWhenOptedIn(t *testing.T) {
	// The guard is an opt-IN gate, not a ban: with the operator's explicit
	// FEDERATION_ALLOW_PLATFORM_OWNER the same token keeps super-admin.
	t.Setenv("FEDERATION_ALLOW_PLATFORM_OWNER", "true")
	h := newBearerHarness(t, TenantGlobal)
	claims, ok := h.callWithBearer(t, h.mintBearer(t, "svc-1", "admin"))
	if !ok {
		t.Fatal("bearer was rejected outright")
	}
	if claims.Role != RoleSuperAdmin {
		t.Errorf("opted-in federated platform owner = %q, want %q", claims.Role, RoleSuperAdmin)
	}
}

func TestOIDCBearerAdminInScopedTenantIsUntouched(t *testing.T) {
	// The guard bites ONLY on global-tenant super-admin. A tenant-scoped admin
	// is an ordinary tenant administrator and must not be collaterally downgraded.
	h := newBearerHarness(t, "acme")
	claims, ok := h.callWithBearer(t, h.mintBearer(t, "svc-1", "admin"))
	if !ok {
		t.Fatal("bearer was rejected outright")
	}
	if claims.Role != RoleSuperAdmin {
		t.Errorf("tenant-scoped admin = %q, want %q (guard must not over-reach)", claims.Role, RoleSuperAdmin)
	}
	if claims.Tenant != "acme" {
		t.Errorf("tenant = %q, want %q", claims.Tenant, "acme")
	}
	if isPlatformOwner(claims) {
		t.Error("a tenant-scoped super-admin must not be a platform owner")
	}
}
