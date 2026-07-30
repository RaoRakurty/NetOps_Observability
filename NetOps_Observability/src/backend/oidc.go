package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"netops/backend/internal/oidc"
)

// oidc.go — Single Sign-On via Keycloak (broker-and-reissue model).
//
// Keycloak is the AUTHENTICATION plane: it speaks OIDC, SAML 2.0 and LDAP/AD and
// brokers external IdPs (Okta, Azure AD, Google). The Go API is the
// AUTHORIZATION plane and never parses SAML/LDAP itself. The flow:
//
//	1. /api/auth/sso/login         → 302 to Keycloak's authorize endpoint
//	                                  (optionally with kc_idp_hint=<idp> so a
//	                                  SAML/LDAP IdP is selected directly)
//	2. user authenticates at Keycloak (OIDC, SAML, LDAP, MFA — all Keycloak's job)
//	3. /api/auth/sso/callback?code → we exchange the code, verify the ID token
//	                                  against Keycloak's JWKS (jwks.go), JIT-
//	                                  provision a local user, then mint OUR OWN
//	                                  session (HS256 access + rotating refresh).
//
// Re-issuing our own session keeps the hot-path middleware on a single
// verification path and means SAML/LDAP "just work" as Keycloak IdPs without a
// line of SAML in Go. See docs/IDENTITY_ACCESS.md.

// ssoProviderInfo describes a sign-in button for the UI / login page.
func (s *server) handleSSOConfig(w http.ResponseWriter, _ *http.Request) {
	p := s.oidcProvider()
	if !p.Ready() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "providers": []ssoProviderInfo{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "providers": p.Providers()})
}

const ssoStateCookie = "netops_sso_state"

// handleSSOLogin (public) starts the Authorization Code flow: set a CSRF state
// cookie and 302 to Keycloak. ?idp=<id> selects a federated IdP via kc_idp_hint.
func (s *server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	p := s.oidcProvider()
	if !p.Ready() {
		writeError(w, http.StatusNotFound, errors.New("sso not configured"))
		return
	}
	state, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Secure is decided per request by the SAME helper the session cookies use
	// (cookieSecure: SECURE_COOKIES=true, direct TLS, or X-Forwarded-Proto=https
	// from the TLS edge). This cookie is the CSRF defence for the whole SSO
	// callback — without Secure it was emitted in the clear on an HTTPS
	// deployment and became stealable off any plaintext request to the same
	// host, which is exactly the login-CSRF the state parameter exists to stop.
	http.SetCookie(w, &http.Cookie{
		Name:     ssoStateCookie,
		Value:    state,
		Path:     "/api/auth/sso",
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	authURL, err := p.AuthorizeURL(p.CallbackURL(r), state, strings.TrimSpace(r.URL.Query().Get("idp")))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleSSOCallback (public) completes the flow: validate state, exchange the
// code, verify the ID token, JIT-provision the user and re-issue our session.
func (s *server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	p := s.oidcProvider()
	if !p.Ready() {
		writeError(w, http.StatusNotFound, errors.New("sso not configured"))
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.ssoFail(w, r, e+": "+r.URL.Query().Get("error_description"))
		return
	}
	state := r.URL.Query().Get("state")
	ck, err := r.Cookie(ssoStateCookie)
	if err != nil || ck.Value == "" || ck.Value != state {
		s.ssoFail(w, r, "invalid SSO state")
		return
	}
	// Clear the state cookie. Same attributes as the one that was set (a delete
	// is just a Set with MaxAge<0, and a browser will reject a Secure cookie
	// arriving over plain HTTP) so the expiry lands on exactly the cookie above.
	http.SetCookie(w, &http.Cookie{
		Name:     ssoStateCookie,
		Value:    "",
		Path:     "/api/auth/sso",
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		s.ssoFail(w, r, "missing authorization code")
		return
	}
	idToken, err := p.Exchange(code, p.CallbackURL(r))
	if err != nil {
		s.ssoFail(w, r, "token exchange failed: "+err.Error())
		return
	}
	claims, err := p.VerifyIDToken(idToken)
	if err != nil {
		s.ssoFail(w, r, "id token rejected: "+err.Error())
		return
	}
	// Honor the IdP's MFA: when required, the token must assert a second factor
	// (amr/acr). We don't run MFA for SSO users — we verify the IdP did.
	if p.RequireMFA() && !p.MFASatisfied(claims) {
		logWarn("auth", "sso login rejected — MFA required but not asserted by IdP", map[string]any{"sub": claims.Sub, "amr": claims.Amr, "acr": claims.Acr})
		s.ssoFail(w, r, "multi-factor authentication is required — your identity provider did not confirm a second factor")
		return
	}

	username := firstNonEmpty(claims.PreferredUsername, claims.Email, claims.Sub)
	if username == "" {
		s.ssoFail(w, r, "id token carried no usable subject")
		return
	}
	role := p.RoleFor(claims)
	user, err := s.users.UpsertFederated(username, claims.Email, firstNonEmpty(claims.Name, username), role, "oidc", p.DefaultTenant())
	if err != nil {
		s.ssoFail(w, r, "provisioning failed: "+err.Error())
		return
	}
	s.logBindingSync(user, "oidc") // PBAC Phase A: mirror the provisioned identity
	if user.Status == "disabled" {
		s.ssoFail(w, r, "account disabled")
		return
	}

	// Open a server-side session (same lifecycle as every other login path) and
	// hand the SPA a fresh access token (with sid) + refresh token.
	access, refresh, err := s.mintSession(r, user)
	if err != nil {
		s.ssoFail(w, r, err.Error())
		return
	}
	s.users.TouchLogin(user.Username)
	logInfo("auth", "sso login ok", map[string]any{"user": user.Username, "role": user.Role, "src": "oidc"})

	// Hand the session to the SPA via the URL fragment (never logged, never sent
	// to the server). The SPA captures it on load (services/api.ts).
	frag := url.Values{}
	frag.Set("token", access)
	frag.Set("refresh", refresh)
	frag.Set("sso", "1")
	http.Redirect(w, r, p.PostLoginURL()+"#"+frag.Encode(), http.StatusFound)
}

func (s *server) ssoFail(w http.ResponseWriter, r *http.Request, msg string) {
	logInfo("auth", "sso login failed", map[string]any{"reason": msg})
	frag := url.Values{}
	frag.Set("sso_error", msg)
	http.Redirect(w, r, s.oidcProvider().PostLoginURL()+"#"+frag.Encode(), http.StatusFound)
}

// exchange trades an authorization code for tokens at Keycloak's token endpoint
// and returns the raw ID token.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// jwksTTL is how long signing keys are cached before a refresh. This is the IdP
// cert-rollover refresh interval (best practice: hours). We default to 10 minutes
// — well within range and more current than typical — and the cache also refreshes
// on an unknown-kid miss, so a rotation is picked up immediately regardless.
// Tunable via OIDC_JWKS_TTL_MIN (minutes); clamped to [1, 1440].
func jwksTTL() time.Duration {
	m := 10
	if v := os.Getenv("OIDC_JWKS_TTL_MIN"); v != "" {
		if n, err := parseIntStrict(v); err == nil && n >= 1 && n <= 1440 {
			m = n
		}
	}
	return time.Duration(m) * time.Minute
}

// mfaAmrMethods are amr values that indicate a SECOND factor was used (anything
// beyond a bare password). Broad on purpose to interop across IdPs (Okta, Entra,
// Keycloak, Auth0, Ping…). "pwd"/"password" alone is NOT MFA.

// newOIDCProvider builds the env-derived initial provider (the admin overlay
// rebuilds via the same package path).
func newOIDCProvider() *oidcProvider {
	return oidc.NewProviderFromConfig(newOIDCConfigFromEnv(), jwksTTL())
}

// The provider + config domain moved to internal/oidc (Phase-2 W4.4).
type (
	oidcProvider    = oidc.Provider
	oidcConfig      = oidc.Config
	ssoProviderInfo = oidc.ProviderInfo
)
