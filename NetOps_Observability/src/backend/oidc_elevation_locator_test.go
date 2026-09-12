// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// oidc_elevation_locator_test.go — a per-tenant ELEVATION sign-in must come
// back to the tenant's own entry point (3.7-05).
//
// THE DEFECT. completeElevationSSO's success redirect used the provider's
// GENERIC post-login URL while the standing success (handleSSOCallback) and
// every refusal (ssoFail / ssoLocatorRefuse) had become locator-aware in the
// same change. An operator who signed in for just-in-time access through
// /t/{slug}/sso/{alias}/callback was dropped on "/" instead of "/t/{slug}" —
// the tenant's own door, with its own branding and its own deep-link
// restoration. The token fragment is consumed either way, so nothing leaks and
// nobody is signed into the wrong place; what is lost is the entry point the
// per-tenant feature exists to provide, and the elevation path was the one
// success path still building its redirect a second way.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// elevSSORoundTripAt is ssoRoundTrip with the CALLBACK served on a caller-chosen
// path. handleSSOCallback is invoked directly, exactly as ssoRoundTrip does, so
// the assertion is about where completeElevationSSO sends the browser and not
// about handleTenantSSO's separate realm gate (proved in tenant_signin_test.go).
func (h *elevHarness) elevSSORoundTripAt(t *testing.T, alias, subject, cbPath string, extra map[string]any) string {
	t.Helper()
	loginReq := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/auth/sso/login?idp="+url.QueryEscape(alias), nil)
	loginRec := httptest.NewRecorder()
	h.s.handleSSOLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusFound {
		t.Fatalf("sso login: status %d, want 302 (%s)", loginRec.Code, loginRec.Body.String())
	}
	authURL, err := url.Parse(loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	state, nonce := authURL.Query().Get("state"), authURL.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("authorize url carried no state/nonce: %s", authURL)
	}
	claims := map[string]any{
		"iss": h.p.Issuer(), "aud": h.p.ClientID(), "sub": subject, "preferred_username": subject,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce,
	}
	for k, v := range extra {
		claims[k] = v
	}
	h.claims = claims

	cbReq := httptest.NewRequest(http.MethodGet, "http://app.example.test"+cbPath+"?code=abc&state="+url.QueryEscape(state), nil)
	for _, c := range loginRec.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()
	h.s.handleSSOCallback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("sso callback: status %d, want 302 (%s)", cbRec.Code, cbRec.Body.String())
	}
	return cbRec.Header().Get("Location")
}

// splitRedirect separates the path a redirect lands on from its fragment.
func splitRedirect(loc string) (path, frag string) {
	if i := strings.IndexByte(loc, '#'); i >= 0 {
		return loc[:i], loc[i+1:]
	}
	return loc, ""
}

func TestElevationSignInReturnsToTheTenantsOwnEntryPoint(t *testing.T) {
	h := newElevHarness(t)
	admin := login(t, h.srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, h.srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	tn, ok := h.s.tenants.Get(tenantID)
	if !ok || tn.Slug == "" {
		t.Fatalf("tenant %q has no slug to sign in through: %+v ok=%v", tenantID, tn, ok)
	}
	// The account the elevation door reads. It lives IN that tenant, which is
	// what lets the per-tenant callback's realm check pass.
	h.seedFederatedUser(t, "acmeops", RoleReadOnly, tenantID)

	cbPath := "/t/" + tn.Slug + "/sso/elev/callback"
	loc := h.elevSSORoundTripAt(t, "elev", "acmeops", cbPath, map[string]any{
		"access_expires_at": time.Now().Add(5 * time.Minute).Unix(),
		"change_ticket":     "CHG-9001",
	})
	path, frag := splitRedirect(loc)

	vals, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatalf("parse callback fragment %q: %v", frag, err)
	}
	if vals.Get("token") == "" {
		t.Fatalf("the elevation sign-in did not complete: %s", vals.Get("sso_error"))
	}
	if vals.Get("elevated") != "1" {
		t.Errorf("the fragment does not mark the session elevated: %s", frag)
	}
	if want := "/t/" + tn.Slug; path != want {
		t.Fatalf("an elevation sign-in that started at %s landed on %q, want %q — the tenant's own "+
			"entry point, the same one the standing success and every refusal take", cbPath, path, want)
	}
}

// A GENERIC elevation sign-in must keep the provider's configured post-login
// URL: the locator awareness must not change what a deployment with no
// per-tenant URLs has always done.
func TestGenericElevationSignInKeepsTheConfiguredPostLoginURL(t *testing.T) {
	h := newElevHarness(t)
	h.seedFederatedUser(t, "opsuser", RoleReadOnly, TenantGlobal)
	loc := h.elevSSORoundTripAt(t, "elev", "opsuser", "/api/auth/sso/callback", map[string]any{
		"access_expires_at": time.Now().Add(5 * time.Minute).Unix(),
	})
	path, frag := splitRedirect(loc)
	if !strings.Contains(frag, "token=") {
		t.Fatalf("the generic elevation sign-in did not complete: %s", frag)
	}
	if want := h.p.PostLoginURL(); path != want {
		t.Fatalf("generic elevation post-login path = %q, want the configured %q", path, want)
	}
}
