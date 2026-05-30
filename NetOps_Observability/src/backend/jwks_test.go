package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// signRS256 mints a compact RS256 JWT for tests using the production base64url.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	body, _ := json.Marshal(claims)
	signingInput := b64url(hdr) + "." + b64url(body)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + b64url(sig)
}

// idpServer stands up a minimal OIDC discovery + JWKS endpoint for one RSA key.
func idpServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	srv := httptest.NewServer(mux)
	base = srv.URL

	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(key.E))
	// trim leading zero bytes from the exponent
	i := 0
	for i < len(eBytes)-1 && eBytes[i] == 0 {
		i++
	}
	jwkJSON := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(eBytes[i:]),
	}}}

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/auth",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkJSON)
	})
	return srv
}

func TestVerifyRS256RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "test-key-1"
	srv := idpServer(t, key, kid)
	defer srv.Close()

	c := newJWKSCache(srv.URL)
	tok := signRS256(t, key, kid, map[string]any{
		"sub": "u1", "iss": srv.URL, "aud": "netops",
		"preferred_username": "alice", "email": "alice@example.com",
		"exp":          time.Now().Add(time.Hour).Unix(),
		"realm_access": map[string]any{"roles": []string{"netops-admin"}},
	})
	claims, err := c.verifyRS256(tok, srv.URL, "netops")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.PreferredUsername != "alice" || claims.Email != "alice@example.com" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestVerifyRS256RejectsBadAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	const kid = "k"
	srv := idpServer(t, key, kid)
	defer srv.Close()
	c := newJWKSCache(srv.URL)
	tok := signRS256(t, key, kid, map[string]any{
		"sub": "u", "iss": srv.URL, "aud": "someone-else",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := c.verifyRS256(tok, srv.URL, "netops"); err == nil {
		t.Error("expected audience mismatch to be rejected")
	}
}

func TestVerifyRS256RejectsExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	const kid = "k"
	srv := idpServer(t, key, kid)
	defer srv.Close()
	c := newJWKSCache(srv.URL)
	tok := signRS256(t, key, kid, map[string]any{
		"sub": "u", "iss": srv.URL, "aud": "netops",
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	if _, err := c.verifyRS256(tok, srv.URL, "netops"); err == nil {
		t.Error("expected expired token to be rejected")
	}
}

func TestVerifyRS256RejectsWrongKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	const kid = "k"
	srv := idpServer(t, key, kid)
	defer srv.Close()
	c := newJWKSCache(srv.URL)
	// Signed with a key the JWKS doesn't publish.
	tok := signRS256(t, other, kid, map[string]any{
		"sub": "u", "iss": srv.URL, "aud": "netops",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := c.verifyRS256(tok, srv.URL, "netops"); err == nil {
		t.Error("expected signature from an unknown key to be rejected")
	}
}

func TestRoleFromScopes(t *testing.T) {
	cases := []struct {
		scopes []string
		want   string
	}{
		{[]string{"read:metrics"}, RoleReadOnly},
		{[]string{"read:*"}, RoleReadOnly},
		{[]string{"write:incidents"}, RoleOperator},
		{[]string{"admin:*"}, RoleSuperAdmin},
		{nil, RoleReadOnly},
	}
	for _, c := range cases {
		if got := roleFromScopes(c.scopes); got != c.want {
			t.Errorf("roleFromScopes(%v)=%s want %s", c.scopes, got, c.want)
		}
	}
}
