// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// sso_org_locator_test.go — the /org/{id} sign-in locator, end to end (tracker
// 279c).
//
// THE DEFECT. ssoLoginRedirectURI derived the redirect_uri from the
// CONNECTION's tenant and nothing else, so a browser that entered through
// /org/{org_id} — the immutable, rename-proof locator the admin page hands to
// an IdP team as callback_url_immutable — was sent to the IdP with the TENANT
// callback URL. Two things went wrong from there:
//
//   1. The IdP returned the browser to /t/{slug}/sso/{alias}/callback while the
//      signed candidate cookie said the flow started in the ORG realm. The
//      realm check compares Kind as well as ids, so every /org sign-in was
//      refused at its own callback with "This sign-in did not start at …".
//   2. If the IdP was registered with the immutable org URL instead, the code
//      exchange would echo a redirect_uri that never matched the authorization
//      request, and a real IdP rejects that exchange outright.
//
// Nothing caught either one, because no test drove the org locator through a
// login and the token-endpoint doubles in this package ignore redirect_uri
// entirely. The double below does not: it compares the exchange's redirect_uri
// against the one the authorization request carried and answers invalid_grant
// when they differ, exactly as an IdP does.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"netops/backend/internal/jwks"
)

// orgIdP is a fake IdP that behaves like a real one about redirect_uri: it
// remembers what the authorization request asked for and refuses an exchange
// that does not echo it.
type orgIdP struct {
	authRedirect string // redirect_uri from the last authorization request
	nonce        string // nonce from the last authorization request
	seenRedirect string // redirect_uri the exchange actually sent
	tokenSrv     *httptest.Server
	jwksSrv      *httptest.Server
}

func newOrgIdP(t *testing.T, f *signinFixture) *orgIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	const kid = "org-locator-kid"
	idp := &orgIdP{}
	idp.jwksSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	}))
	t.Cleanup(idp.jwksSrv.Close)

	p := f.s.oidcProvider()
	idp.tokenSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
		}
		idp.seenRedirect = r.PostForm.Get("redirect_uri")
		// THE CHECK THAT WAS MISSING. RFC 6749 §4.1.3: the exchange must repeat
		// the redirect_uri the authorization request used. A double that
		// shrugs at this is why a mismatched pair shipped.
		if idp.seenRedirect != idp.authRedirect {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "redirect_uri does not match the authorization request",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token": mintIDToken(t, key, kid, p.Issuer(), p.ClientID(), idp.nonce),
		})
	}))
	t.Cleanup(idp.tokenSrv.Close)

	p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:        p.Issuer(),
		AuthEndpoint:  p.Issuer() + "/protocol/openid-connect/auth",
		TokenEndpoint: idp.tokenSrv.URL,
		JWKSURI:       idp.jwksSrv.URL,
	})
	return idp
}

// startLogin runs the SP-initiated login with the supplied locator cookie and
// returns the authorization request the browser would follow, plus the state
// cookie it was given.
func (idp *orgIdP) startLogin(t *testing.T, f *signinFixture, alias string, locator *http.Cookie) (redirectURI, state string, stateCookie *http.Cookie) {
	t.Helper()
	cookies := []*http.Cookie{}
	if locator != nil {
		cookies = append(cookies, locator)
	}
	resp, b := getWith(t, f.srv, "/api/auth/sso/login?idp="+alias, cookies...)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("sso login: status %d: %s", resp.StatusCode, b)
	}
	auth, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	q := auth.Query()
	idp.authRedirect, idp.nonce = q.Get("redirect_uri"), q.Get("nonce")
	stateCookie = cookieNamed(resp, ssoStateCookie)
	if stateCookie == nil {
		t.Fatal("the login did not arm the SSO state cookie")
	}
	return idp.authRedirect, q.Get("state"), stateCookie
}

// TestOrgLocatorLoginUsesTheOrgCallback is the unit half: the redirect_uri
// handed to the IdP must name the realm the browser is actually in.
func TestOrgLocatorLoginUsesTheOrgCallback(t *testing.T) {
	f := newSigninFixture(t)
	idp := newOrgIdP(t, f)

	org := locatorFor(t, f.srv, "/org/"+f.orgA)
	got, _, _ := idp.startLogin(t, f, "acme-idp", org)
	want := f.srv.URL + "/org/" + f.orgA + "/sso/acme-idp/callback"
	if got != want {
		t.Fatalf("redirect_uri for an /org sign-in = %q, want %q — the IdP is being told to return the browser to a realm this flow did not start in", got, want)
	}

	// The tenant locator is unchanged: it still gets its own /t/{slug} callback.
	tenant := locatorFor(t, f.srv, "/t/"+f.slugA)
	got, _, _ = idp.startLogin(t, f, "acme-idp", tenant)
	if want := f.srv.URL + "/t/" + f.slugA + "/sso/acme-idp/callback"; got != want {
		t.Fatalf("redirect_uri for a /t sign-in = %q, want %q", got, want)
	}

	// No locator at all keeps the connection's own tenant callback, which is
	// what an IdP-initiated flow and every pre-locator deployment rely on.
	got, _, _ = idp.startLogin(t, f, "acme-idp", nil)
	if want := f.srv.URL + "/t/" + f.slugA + "/sso/acme-idp/callback"; got != want {
		t.Fatalf("redirect_uri with no locator = %q, want the connection's own %q", got, want)
	}
}

// TestOrgLocatorSignInCompletes is the end-to-end half, through the real router
// with an IdP that checks redirect_uri. It fails at the realm binding before
// the fix and at the token endpoint if the two URIs are ever allowed to drift
// apart again.
func TestOrgLocatorSignInCompletes(t *testing.T) {
	f := newSigninFixture(t)
	idp := newOrgIdP(t, f)

	org := locatorFor(t, f.srv, "/org/"+f.orgA)
	redirectURI, state, stateCookie := idp.startLogin(t, f, "acme-idp", org)

	cb, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("parse redirect_uri: %v", err)
	}
	resp, b := getWith(t, f.srv, cb.Path+"?code=xyz&state="+url.QueryEscape(state), org, stateCookie)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: status %d: %s", resp.StatusCode, b)
	}
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "sso_error") {
		t.Fatalf("an /org sign-in was refused: %s", loc)
	}
	if !strings.Contains(loc, "token=") {
		t.Fatalf("the /org sign-in minted no session: %s", loc)
	}
	// It lands back on the org locator, so the SPA returns to the URL the
	// customer was handed.
	if !strings.HasPrefix(loc, "/org/"+f.orgA+"#") {
		t.Errorf("post-login path = %q, want /org/%s", loc, f.orgA)
	}
	// And the exchange really did echo the authorization request's value: the
	// IdP would have answered invalid_grant otherwise.
	if idp.seenRedirect != redirectURI {
		t.Fatalf("exchange redirect_uri = %q, want the authorization request's %q", idp.seenRedirect, redirectURI)
	}
}
