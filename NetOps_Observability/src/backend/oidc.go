package backend

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
	// The idp alias is forwarded to Keycloak as kc_idp_hint. Only aliases the
	// operator configured (OIDC_PROVIDERS / saved config) are accepted — the
	// browser never selects an IdP the server did not offer ("Okta dashboard
	// launch" hardening; the bookmark URL carries one of these aliases).
	idpHint := strings.TrimSpace(r.URL.Query().Get("idp"))
	if !p.ValidIDP(idpHint) {
		logWarn("auth", "sso login refused — unknown idp alias", map[string]any{"idp": idpHint})
		writeError(w, http.StatusNotFound, errors.New("unknown identity provider"))
		return
	}
	state, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	verifier, challenge, err := oidc.NewPKCEVerifier()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Server-side transaction: makes state single-use at the callback and keeps
	// the nonce + PKCE verifier out of the browser entirely.
	if err := s.ssoTxns.Create(state, nonce, verifier, time.Now()); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
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
	authURL, err := p.AuthorizeURL(p.CallbackURL(r), state, nonce, challenge, idpHint)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// #nosec G710 -- the redirect target is the IdP's DISCOVERED auth endpoint
	// (trusted operator config via oidc.Provider), never caller input; the only
	// caller-influenced parts (state, kc_idp_hint) are query-encoded parameters.
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

	// Atomically consume the server-side transaction: state becomes single-use
	// (a replayed callback dies here even with a stolen cookie), and the nonce +
	// PKCE verifier come back from server memory, never from the browser. The
	// browser-facing message stays identical to the cookie failure on purpose —
	// an attacker learns nothing about WHICH binding failed.
	txn, ok := s.ssoTxns.Consume(state, time.Now())
	if !ok {
		s.ssoFail(w, r, "invalid SSO state")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.ssoFail(w, r, "missing authorization code")
		return
	}
	idToken, err := p.Exchange(code, p.CallbackURL(r), txn.Verifier)
	if err != nil {
		s.ssoFail(w, r, "token exchange failed: "+err.Error())
		return
	}
	claims, err := p.VerifyIDToken(idToken)
	if err != nil {
		s.ssoFail(w, r, "id token rejected: "+err.Error())
		return
	}
	// OIDC Core §3.1.3.7 #11: the ID token must echo OUR nonce. A token without
	// it, or with someone else's, was not minted for this login. Values are
	// deliberately not logged.
	if claims.Nonce == "" || claims.Nonce != txn.Nonce {
		s.ssoFail(w, r, "id token rejected: nonce mismatch")
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
	// #146b parity: the account-state gates every login path owes (tenant
	// suspension + hard account-lifecycle denials) and the F-68 concurrent-
	// login policy — previously enforced only on the local paths, so an
	// expired account or a suspended tenant's users could still enter via SSO.
	if msg := s.federatedLoginBarrier(r, user); msg != "" {
		s.ssoFail(w, r, msg)
		return
	}
	if err := s.enforceConcurrentLoginDeny(r, user); err != nil {
		s.ssoFail(w, r, err.Error())
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

// The provider + config domain moved to internal/oidc (Phase-2 W4.4); the
// login-transaction store lives there too (#135 hardening).
type (
	oidcProvider    = oidc.Provider
	oidcConfig      = oidc.Config
	ssoProviderInfo = oidc.ProviderInfo
	ssoTxnStore     = oidc.TxnStore
)

func newSSOTxnStore() *ssoTxnStore { return oidc.NewTxnStore() }
