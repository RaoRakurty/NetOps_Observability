package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/jwks"
	"testing"
)

// oidc_state_cookie_test.go — the SSO state cookie is the CSRF defence for the
// whole Authorization Code flow: handleSSOCallback accepts a code ONLY when the
// ?state parameter matches this cookie. It shipped WITHOUT the Secure flag
// (2026-07-27 audit, SEC-LOW-2 upgraded), so on an HTTPS deployment the browser
// also sent it over any plaintext request to the same host — stealable off the
// wire, which is precisely the login-CSRF the state parameter exists to stop.
// The blanket gosec G124 exclusion, justified only in terms of the auth cookies,
// is what hid it.
//
// The rule under test: this cookie's Secure flag must equal cookieSecure(r) —
// the SAME per-request decision the session cookies make (SECURE_COOKIES=true,
// direct TLS, or X-Forwarded-Proto=https from the TLS edge). Equality in BOTH
// directions matters: unconditional Secure would silently break the plain-HTTP
// default (a browser drops a Secure cookie arriving over HTTP), which would fail
// every SSO login open with "invalid SSO state".

// testSSOServer builds a server whose OIDC provider is ready, with the IdP
// discovery pre-seeded so no network call is made. tokenEndpoint may point at a
// test IdP (or anywhere unreachable) — the login handler never calls it.
func testSSOServer(t *testing.T, tokenEndpoint string) *server {
	t.Helper()
	p := newOIDCProviderFromConfig(oidcConfig{
		Enabled:  true,
		Issuer:   "https://idp.example.test/realms/netops",
		ClientID: "netops-api",
	})
	if p.jwks == nil {
		t.Fatal("provider built without a JWKS cache — cannot exercise the SSO handlers")
	}
	p.jwks.SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:        p.issuer,
		AuthEndpoint:  p.issuer + "/protocol/openid-connect/auth",
		TokenEndpoint: tokenEndpoint,
		JWKSURI:       p.issuer + "/protocol/openid-connect/certs",
	})
	if !p.ready() {
		t.Fatal("test provider is not ready")
	}
	s := &server{}
	s.oidc.Store(p)
	return s
}

// findCookie returns the named cookie from a recorded response.
func findCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range (&http.Response{Header: rec.Header()}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q cookie in response headers %v", name, rec.Header())
	return nil
}

// ssoStateCookieCases drives the same request shapes cookieSecure() decides on.
func ssoStateCookieCases() []struct {
	name   string
	mutate func(*http.Request)
	env    map[string]string
	secure bool
} {
	return []struct {
		name   string
		mutate func(*http.Request)
		env    map[string]string
		secure bool
	}{
		{name: "plain http", mutate: func(*http.Request) {}, secure: false},
		{name: "direct TLS", mutate: func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, secure: true},
		{
			name:   "X-Forwarded-Proto https",
			mutate: func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") },
			secure: true,
		},
		{
			name:   "SECURE_COOKIES forced",
			mutate: func(*http.Request) {},
			env:    map[string]string{"SECURE_COOKIES": "true"},
			secure: true,
		},
	}
}

func TestSSOStateCookieCarriesSecureOnHTTPS(t *testing.T) {
	for _, tc := range ssoStateCookieCases() {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			s := testSSOServer(t, "https://idp.example.test/protocol/openid-connect/token")
			r := httptest.NewRequest(http.MethodGet, "http://netops.example.test/api/auth/sso/login", nil)
			tc.mutate(r)
			rec := httptest.NewRecorder()
			s.handleSSOLogin(rec, r)

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302 (body %q)", rec.Code, rec.Body.String())
			}
			ck := findCookie(t, rec, ssoStateCookie)
			if ck.Secure != tc.secure {
				t.Errorf("Secure = %v, want %v — the SSO state cookie must follow cookieSecure(r)", ck.Secure, tc.secure)
			}
			if ck.Secure != cookieSecure(r) {
				t.Errorf("Secure = %v but cookieSecure(r) = %v — the two decisions must not diverge", ck.Secure, cookieSecure(r))
			}
			// The rest of the hardening must survive alongside the new flag.
			if !ck.HttpOnly {
				t.Error("state cookie lost HttpOnly")
			}
			if ck.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax", ck.SameSite)
			}
			if ck.Path != "/api/auth/sso" {
				t.Errorf("Path = %q, want /api/auth/sso", ck.Path)
			}
			if ck.Value == "" {
				t.Error("state cookie carries no value — CSRF check would compare empty to empty")
			}
		})
	}
}

// The callback CLEARS the state cookie. A delete is just a Set with MaxAge<0, so
// it needs the same attributes: a browser rejects a Secure cookie that arrives
// over plain HTTP, and a mismatched clear leaves the single-use state cookie
// alive for its full 10 minutes.
func TestSSOStateClearCookieMatchesSecureSemantics(t *testing.T) {
	// A token endpoint that refuses immediately, so the callback fails fast AFTER
	// the clear-cookie has been written.
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer idp.Close()

	for _, https := range []bool{false, true} {
		name := "plain http"
		if https {
			name = "forwarded https"
		}
		t.Run(name, func(t *testing.T) {
			s := testSSOServer(t, idp.URL+"/token")
			r := httptest.NewRequest(http.MethodGet, "http://netops.example.test/api/auth/sso/callback?state=abc&code=xyz", nil)
			r.AddCookie(&http.Cookie{Name: ssoStateCookie, Value: "abc"})
			if https {
				r.Header.Set("X-Forwarded-Proto", "https")
			}
			rec := httptest.NewRecorder()
			s.handleSSOCallback(rec, r)

			ck := findCookie(t, rec, ssoStateCookie)
			if ck.MaxAge >= 0 {
				t.Fatalf("MaxAge = %d, want < 0 (the callback must expire the state cookie)", ck.MaxAge)
			}
			if ck.Secure != cookieSecure(r) {
				t.Errorf("clear-cookie Secure = %v, want %v (cookieSecure(r))", ck.Secure, cookieSecure(r))
			}
			if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/api/auth/sso" {
				t.Errorf("clear-cookie attributes drifted from the set-cookie: httpOnly=%v sameSite=%v path=%q",
					ck.HttpOnly, ck.SameSite, ck.Path)
			}
		})
	}
}
