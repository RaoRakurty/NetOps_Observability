package backend

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// oidc_bookmark_login_test.go — F3 (pass-3): the supported "Okta dashboard
// launch" is a Bookmark tile that navigates the full page straight to
// /api/auth/sso/login?idp=okta (docs/runbooks/okta-sso-setup.md). That path
// never runs the SPA's ssoLoginUrl(), so no fe_state is supplied and the M20
// sessionStorage nonce is never armed. Without a server-synthesized nonce the
// callback echoes no `state`, and the SPA (captureSSORedirect) discards the
// valid #token= as "not started from this tab" — the primary enterprise
// onboarding path was broken for every user.
//
// The fix keeps the M20 login-CSRF defence: on a fe_state-less entry the server
// mints a random nonce, carries it through the transaction as FEState (so the
// callback echoes it as `state` unchanged) AND mirrors it into a JS-readable,
// single-use cookie the SPA falls back to. A browser that never hit /sso/login
// has neither the sessionStorage nonce nor the cookie, so an attacker-delivered
// fragment is still refused.

// TestBookmarkLoginSynthesizesPendingNonceAndEchoesIt asserts that a login with
// NO fe_state query sets the netops_sso_pending cookie and stores the SAME value
// as the transaction FEState — i.e. exactly what handleSSOCallback echoes back
// as the fragment `state`, so the SPA's cookie fallback will match it.
func TestBookmarkLoginSynthesizesPendingNonceAndEchoesIt(t *testing.T) {
	s := testSSOServer(t, "https://idp.example.test/protocol/openid-connect/token")
	r := httptest.NewRequest(http.MethodGet, "http://netops.example.test/api/auth/sso/login?idp=", nil)
	rec := httptest.NewRecorder()
	s.handleSSOLogin(rec, r)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body %q)", rec.Code, rec.Body.String())
	}

	pending := findCookie(t, rec, ssoPendingCookie)
	if pending.Value == "" {
		t.Fatal("netops_sso_pending cookie carries no value — the SPA fallback would compare empty to empty")
	}
	// JS-readable (SPA must read it), Path=/ (bookmark returns to the SPA root),
	// Secure follows cookieSecure(r), SameSite Lax, short TTL.
	if pending.HttpOnly {
		t.Error("netops_sso_pending is HttpOnly — the SPA cannot read it to match the echoed state")
	}
	if pending.Path != "/" {
		t.Errorf("Path = %q, want / ", pending.Path)
	}
	if pending.Secure != cookieSecure(r) {
		t.Errorf("Secure = %v, want %v (cookieSecure(r))", pending.Secure, cookieSecure(r))
	}
	if pending.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", pending.SameSite)
	}
	if pending.MaxAge <= 0 || pending.MaxAge > 600 {
		t.Errorf("MaxAge = %d, want a short positive TTL (<=600)", pending.MaxAge)
	}

	// The transaction is keyed by the state cookie value; its FEState is what the
	// callback echoes. It MUST equal the pending cookie the SPA will read.
	stateCk := findCookie(t, rec, ssoStateCookie)
	txn, ok := s.ssoTxns.Consume(stateCk.Value, time.Now())
	if !ok {
		t.Fatal("no login transaction registered for the state cookie")
	}
	if txn.FEState != pending.Value {
		t.Errorf("txn.FEState = %q but netops_sso_pending = %q — the callback echo would not match the cookie",
			txn.FEState, pending.Value)
	}
}

// TestSPInitiatedLoginDoesNotSynthesizeCookie asserts the SP-initiated path is
// untouched: when the SPA supplies fe_state, the server carries THAT value and
// synthesizes no netops_sso_pending cookie (the sessionStorage nonce is the
// control, not a cookie).
func TestSPInitiatedLoginDoesNotSynthesizeCookie(t *testing.T) {
	s := testSSOServer(t, "https://idp.example.test/protocol/openid-connect/token")
	r := httptest.NewRequest(http.MethodGet, "http://netops.example.test/api/auth/sso/login?fe_state=spa-nonce-123", nil)
	rec := httptest.NewRecorder()
	s.handleSSOLogin(rec, r)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body %q)", rec.Code, rec.Body.String())
	}
	for _, c := range (&http.Response{Header: rec.Header()}).Cookies() {
		if c.Name == ssoPendingCookie {
			t.Fatalf("SP-initiated login set a %q cookie — the sessionStorage nonce is the control, not a cookie", ssoPendingCookie)
		}
	}

	stateCk := findCookie(t, rec, ssoStateCookie)
	txn, ok := s.ssoTxns.Consume(stateCk.Value, time.Now())
	if !ok {
		t.Fatal("no login transaction registered for the state cookie")
	}
	if txn.FEState != "spa-nonce-123" {
		t.Errorf("txn.FEState = %q, want the SPA-supplied fe_state (unchanged behaviour)", txn.FEState)
	}
}
