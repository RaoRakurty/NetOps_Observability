package backend

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/jwks"
	"netops/backend/internal/oidc"
)

// oidc_pkce_nonce_test.go — the SSO hardening acceptance criteria at the
// handler level (#135 preconditions 0.4/0.5/0.6, re-landed for the "Okta
// dashboard launch" capability):
//   - the browser cannot invent a kc_idp_hint alias;
//   - every login issues state + nonce + PKCE S256 and persists a transaction;
//   - state is single-use at the callback (server-side, not just the cookie);
//   - the PKCE verifier reaches the token endpoint but never the browser;
//   - an ID token without OUR nonce is rejected, before any provisioning.
// The correct-nonce SUCCESS path is deliberately not simulated here — it needs
// the full user/session wiring and is exercised for real against the running
// stack (runbook cells 1/3/4).

func TestSSOLoginRejectsUnknownIDPAlias(t *testing.T) {
	s := testSSOServer(t, "https://idp.example.test/token")
	r := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/auth/sso/login?idp=acme-okta", nil)
	rec := httptest.NewRecorder()
	s.handleSSOLogin(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — a browser-invented alias must be refused", rec.Code)
	}
}

func TestSSOLoginIssuesNoncePKCEAndTransaction(t *testing.T) {
	s := testSSOServer(t, "https://idp.example.test/token")
	r := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/auth/sso/login", nil)
	rec := httptest.NewRecorder()
	s.handleSSOLogin(rec, r)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body %q)", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := loc.Query()
	state, nonce, challenge := q.Get("state"), q.Get("nonce"), q.Get("code_challenge")
	if state == "" || nonce == "" || challenge == "" {
		t.Fatalf("authorize URL missing state/nonce/code_challenge: %v", loc)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if ck := findCookie(t, rec, ssoStateCookie); ck.Value != state {
		t.Errorf("state cookie %q != state param %q", ck.Value, state)
	}
	// The transaction must exist, carry the SAME nonce the IdP will echo, and a
	// verifier whose S256 equals the challenge that went to the IdP.
	txn, ok := s.ssoTxns.Consume(state, time.Now())
	if !ok {
		t.Fatal("no server-side transaction persisted for the issued state")
	}
	if txn.Nonce != nonce {
		t.Error("transaction nonce differs from the nonce sent to the IdP")
	}
	sum := sha256.Sum256([]byte(txn.Verifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
		t.Error("stored verifier does not hash to the challenge sent to the IdP")
	}
	if strings.Contains(rec.Header().Get("Location"), txn.Verifier) {
		t.Error("PKCE verifier leaked into the authorize redirect")
	}
}

func TestSSOCallbackStateIsSingleUse(t *testing.T) {
	// Token endpoint refuses, so the FIRST callback fails after consuming the
	// transaction; the SECOND must die earlier, at the consumed state.
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer idp.Close()
	s := testSSOServer(t, idp.URL+"/token")
	if err := s.ssoTxns.Create("st1", "n1", "v1", time.Now()); err != nil {
		t.Fatalf("seed txn: %v", err)
	}
	do := func() string {
		r := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/auth/sso/callback?state=st1&code=xyz", nil)
		r.AddCookie(&http.Cookie{Name: ssoStateCookie, Value: "st1"})
		rec := httptest.NewRecorder()
		s.handleSSOCallback(rec, r)
		return rec.Header().Get("Location")
	}
	if first := do(); !strings.Contains(first, "token+exchange+failed") &&
		!strings.Contains(first, "token%20exchange%20failed") {
		t.Fatalf("first callback should reach the token exchange, got %q", first)
	}
	if second := do(); !strings.Contains(second, "invalid+SSO+state") &&
		!strings.Contains(second, "invalid%20SSO%20state") {
		t.Fatalf("replayed callback must fail at the consumed state, got %q", second)
	}
}

// --- RS256 test IdP ---------------------------------------------------------

func mintIDToken(t *testing.T, key *rsa.PrivateKey, kid, iss, aud, nonce string) string {
	t.Helper()
	b64 := func(v any) string {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(j)
	}
	claims := map[string]any{
		"iss": iss, "aud": aud, "sub": "user-1", "preferred_username": "user-1",
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	signing := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestSSOCallbackRejectsWrongOrMissingNonce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	const kid = "t1"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	}))
	defer jwksSrv.Close()

	for _, tc := range []struct {
		name, tokenNonce string
	}{
		{"wrong nonce", "not-the-one-we-sent"},
		{"missing nonce", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotVerifier string
			p := oidc.NewProviderFromConfig(oidcConfig{
				Enabled: true, Issuer: "https://idp.example.test/realms/netops", ClientID: "netops-api",
			}, 10*time.Minute)
			tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse token form: %v", err)
				}
				gotVerifier = r.PostForm.Get("code_verifier")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"id_token": mintIDToken(t, key, kid, p.Issuer(), p.ClientID(), tc.tokenNonce),
				})
			}))
			defer tokenSrv.Close()
			p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
				Issuer:        p.Issuer(),
				AuthEndpoint:  p.Issuer() + "/protocol/openid-connect/auth",
				TokenEndpoint: tokenSrv.URL,
				JWKSURI:       jwksSrv.URL,
			})
			s := &server{ssoTxns: newSSOTxnStore()}
			s.oidc.Store(p)
			if err := s.ssoTxns.Create("st1", "the-real-nonce", "verifier-1", time.Now()); err != nil {
				t.Fatalf("seed txn: %v", err)
			}
			r := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/auth/sso/callback?state=st1&code=xyz", nil)
			r.AddCookie(&http.Cookie{Name: ssoStateCookie, Value: "st1"})
			rec := httptest.NewRecorder()
			s.handleSSOCallback(rec, r)

			loc := rec.Header().Get("Location")
			if !strings.Contains(loc, "nonce+mismatch") && !strings.Contains(loc, "nonce%20mismatch") {
				t.Fatalf("callback with %s must fail on the nonce check, got %q", tc.name, loc)
			}
			// The nonce values themselves must not leak into the browser redirect.
			for _, secret := range []string{"the-real-nonce", "not-the-one-we-sent"} {
				if strings.Contains(loc, secret) {
					t.Errorf("redirect leaks nonce value %q", secret)
				}
			}
			// PKCE: the verifier reached the token endpoint from the transaction —
			// a signed, iss/aud-valid token still fails without our nonce, proving
			// the checks are independent.
			if gotVerifier != "verifier-1" {
				t.Errorf("code_verifier at token endpoint = %q, want the transaction's verifier", gotVerifier)
			}
		})
	}
}
