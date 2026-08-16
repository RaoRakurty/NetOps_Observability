package jwks

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// b64url is the compact-JWT base64url encoding (test-local shorthand).
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signRS256 mints a compact RS256 JWT for tests.
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

	c := New(srv.URL, 0)
	tok := signRS256(t, key, kid, map[string]any{
		"sub": "u1", "iss": srv.URL, "aud": "netops",
		"preferred_username": "alice", "email": "alice@example.com",
		"exp":          time.Now().Add(time.Hour).Unix(),
		"realm_access": map[string]any{"roles": []string{"netops-admin"}},
	})
	claims, err := c.VerifyRS256(tok, srv.URL, "netops")
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
	c := New(srv.URL, 0)
	tok := signRS256(t, key, kid, map[string]any{
		"sub": "u", "iss": srv.URL, "aud": "someone-else",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := c.VerifyRS256(tok, srv.URL, "netops"); err == nil {
		t.Error("expected audience mismatch to be rejected")
	}
}

func TestVerifyRS256RejectsExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	const kid = "k"
	srv := idpServer(t, key, kid)
	defer srv.Close()
	c := New(srv.URL, 0)
	tok := signRS256(t, key, kid, map[string]any{
		"sub": "u", "iss": srv.URL, "aud": "netops",
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	if _, err := c.VerifyRS256(tok, srv.URL, "netops"); err == nil {
		t.Error("expected expired token to be rejected")
	}
}

func TestVerifyRS256RejectsWrongKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	const kid = "k"
	srv := idpServer(t, key, kid)
	defer srv.Close()
	c := New(srv.URL, 0)
	// Signed with a key the JWKS doesn't publish.
	tok := signRS256(t, other, kid, map[string]any{
		"sub": "u", "iss": srv.URL, "aud": "netops",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := c.VerifyRS256(tok, srv.URL, "netops"); err == nil {
		t.Error("expected signature from an unknown key to be rejected")
	}
}

// ── H10: unknown-kid fetch amplification ─────────────────────────────────────

// countingIdP is idpServer plus an atomic counter on the JWKS endpoint, so a
// test can assert exactly how many outbound fetches a verification burst cost.
func countingIdP(t *testing.T, key *rsa.PrivateKey, kid string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var fetches atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	base := srv.URL

	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(key.E))
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
			"issuer": base, "authorization_endpoint": base + "/auth",
			"token_endpoint": base + "/token", "jwks_uri": base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(jwkJSON)
	})
	return srv, &fetches
}

// FAILING-FIRST (H10, 2026-08-15 review): every verification carrying an
// unknown kid used to trigger its own outbound JWKS fetch — no single-flight,
// no floor — so an UNAUTHENTICATED caller minting random kids relayed its
// whole request rate onto the IdP. N concurrent verifications with N distinct
// unknown kids must now cost AT MOST ONE fetch within the refresh floor.
func TestVerifyH10UnknownKidBurstCostsOneFetch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	srv, fetches := countingIdP(t, key, "real-kid")
	defer srv.Close()

	c := New(srv.URL, time.Hour)
	// Prime the cache (one legitimate fetch) with a valid token.
	good := signRS256(t, key, "real-kid", map[string]any{
		"sub": "u1", "iss": srv.URL, "aud": "netops", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := c.VerifyRS256(good, srv.URL, "netops"); err != nil {
		t.Fatalf("prime verify: %v", err)
	}
	baseline := fetches.Load()

	const n = 24
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := signRS256(t, key, fmt.Sprintf("spoofed-kid-%d", i), map[string]any{
				"sub": "u1", "iss": srv.URL, "aud": "netops", "exp": time.Now().Add(time.Hour).Unix(),
			})
			if _, err := c.VerifyRS256(tok, srv.URL, "netops"); err == nil {
				t.Errorf("token with unknown kid %d verified", i)
			}
		}(i)
	}
	wg.Wait()
	extra := fetches.Load() - baseline
	if extra > 1 {
		t.Fatalf("burst of %d unknown-kid verifications cost %d JWKS fetches, want <= 1 per %v", n, extra, minRefreshInterval)
	}
	// The good kid must still verify from cache — the guard refuses fetches,
	// not legitimate logins.
	if _, err := c.VerifyRS256(good, srv.URL, "netops"); err != nil {
		t.Fatalf("known-kid verify after burst: %v", err)
	}
}

// H10, precondition ordering: a token that is structurally invalid (expired,
// wrong issuer, garbage) must be refused BEFORE the key lookup, i.e. with zero
// outbound fetches even when its kid is unknown.
func TestVerifyH10StructuralRejectsBeforeAnyFetch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	srv, fetches := countingIdP(t, key, "real-kid")
	defer srv.Close()
	c := New(srv.URL, time.Hour)

	expired := signRS256(t, key, "unknown-kid", map[string]any{
		"sub": "u1", "iss": srv.URL, "aud": "netops", "exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := c.VerifyRS256(expired, srv.URL, "netops"); err == nil {
		t.Fatal("expired token verified")
	}
	wrongIss := signRS256(t, key, "unknown-kid", map[string]any{
		"sub": "u1", "iss": "https://evil.example", "aud": "netops", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := c.VerifyRS256(wrongIss, srv.URL, "netops"); err == nil {
		t.Fatal("wrong-issuer token verified")
	}
	if _, err := c.VerifyRS256("not-a-jwt", srv.URL, "netops"); err == nil {
		t.Fatal("garbage verified")
	}
	if got := fetches.Load(); got != 0 {
		t.Fatalf("structurally invalid tokens cost %d JWKS fetches, want 0", got)
	}
}
