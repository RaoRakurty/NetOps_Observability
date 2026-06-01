package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
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
type ssoProviderInfo struct {
	ID   string `json:"id"`   // kc_idp_hint; "" = realm default (plain OIDC)
	Name string `json:"name"` // display label
	Kind string `json:"kind"` // oidc | saml | ldap
}

type oidcProvider struct {
	enabled       bool
	clientID      string
	clientSecret  string
	scopes        string
	issuer        string
	redirectURL   string // optional override; else derived from the request
	postLoginURL  string
	defaultRole   string
	defaultTenant string
	adminRoles    map[string]bool
	operatorRoles map[string]bool
	providers     []ssoProviderInfo

	jwks *jwksCache
}

func splitSet(csv string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(csv, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			m[p] = true
		}
	}
	return m
}

// parseProviders turns "id:Label:kind,id2:Label2:kind2" into the button list.
// A bare "id" defaults to kind=oidc and Label=id.
func parseProviders(csv string) []ssoProviderInfo {
	var out []ssoProviderInfo
	for _, raw := range strings.Split(csv, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, ":", 3)
		p := ssoProviderInfo{ID: strings.TrimSpace(parts[0]), Kind: "oidc"}
		p.Name = p.ID
		if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
			p.Name = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 && strings.TrimSpace(parts[2]) != "" {
			p.Kind = strings.ToLower(strings.TrimSpace(parts[2]))
		}
		out = append(out, p)
	}
	return out
}

// newOIDCProvider builds the SSO provider from the environment. It returns a
// disabled provider (enabled=false) when OIDC_ENABLED!=true so the rest of the
// app is unaffected — local accounts remain the always-available fallback.
//
// It is a thin wrapper over newOIDCProviderFromConfig(newOIDCConfigFromEnv()):
// the env vars define the initial config, and the runtime overlay (oidc_config.go,
// admin UI) rebuilds the provider from a stored oidcConfig with identical shape.
func newOIDCProvider() *oidcProvider {
	return newOIDCProviderFromConfig(newOIDCConfigFromEnv())
}

// newOIDCProviderFromConfig builds a live provider from an oidcConfig. The same
// path is used for the env-derived initial provider and for every admin-driven
// rebuild, so there is one construction path and no drift between the two.
func newOIDCProviderFromConfig(c oidcConfig) *oidcProvider {
	p := &oidcProvider{
		enabled:       c.Enabled,
		clientID:      strings.TrimSpace(c.ClientID),
		clientSecret:  c.ClientSecret,
		scopes:        firstNonEmpty(strings.TrimSpace(c.Scopes), "openid email profile"),
		issuer:        strings.TrimRight(strings.TrimSpace(c.Issuer), "/"),
		redirectURL:   strings.TrimSpace(c.RedirectURL),
		postLoginURL:  firstNonEmpty(strings.TrimSpace(c.PostLoginURL), "/"),
		defaultRole:   firstNonEmpty(strings.TrimSpace(c.DefaultRole), RoleReadOnly),
		defaultTenant: firstNonEmpty(strings.TrimSpace(c.DefaultTenant), TenantGlobal),
		adminRoles:    splitSet(firstNonEmpty(strings.TrimSpace(c.AdminRoles), "super-admin,admin,netops-admin")),
		operatorRoles: splitSet(firstNonEmpty(strings.TrimSpace(c.OperatorRoles), "operator,netops-operator")),
		providers:     parseProviders(c.Providers),
	}
	if p.enabled && p.issuer != "" {
		p.jwks = newJWKSCache(p.issuer)
	}
	// Always offer at least the realm-default OIDC button when enabled.
	if p.enabled && len(p.providers) == 0 {
		p.providers = []ssoProviderInfo{{ID: "", Name: "Single Sign-On", Kind: "oidc"}}
	}
	return p
}

func (p *oidcProvider) ready() bool {
	return p != nil && p.enabled && p.issuer != "" && p.clientID != "" && p.jwks != nil
}

// roleFor maps Keycloak realm roles / groups onto a NetOps built-in role.
func (p *oidcProvider) roleFor(c oidcClaims) string {
	names := append([]string{}, c.RealmAccess.Roles...)
	names = append(names, c.Groups...)
	for _, n := range names {
		if p.adminRoles[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(n, "/")))] {
			return RoleSuperAdmin
		}
	}
	for _, n := range names {
		if p.operatorRoles[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(n, "/")))] {
			return RoleOperator
		}
	}
	return p.defaultRole
}

func (p *oidcProvider) callbackURL(r *http.Request) string {
	if p.redirectURL != "" {
		return p.redirectURL
	}
	scheme := "http"
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		scheme = xf
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if xh := r.Header.Get("X-Forwarded-Host"); xh != "" {
		host = xh
	}
	return scheme + "://" + host + "/api/auth/sso/callback"
}

// ---- handlers --------------------------------------------------------------

// handleSSOConfig (public) tells the SPA whether SSO is on and which buttons to
// render. Never leaks the client secret.
func (s *server) handleSSOConfig(w http.ResponseWriter, _ *http.Request) {
	p := s.oidcProvider()
	if !p.ready() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "providers": []ssoProviderInfo{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "providers": p.providers})
}

const ssoStateCookie = "netops_sso_state"

// handleSSOLogin (public) starts the Authorization Code flow: set a CSRF state
// cookie and 302 to Keycloak. ?idp=<id> selects a federated IdP via kc_idp_hint.
func (s *server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	p := s.oidcProvider()
	if !p.ready() {
		writeError(w, http.StatusNotFound, errors.New("sso not configured"))
		return
	}
	disc, err := p.jwks.discovery()
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	state, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     ssoStateCookie,
		Value:    state,
		Path:     "/api/auth/sso",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	q := url.Values{}
	q.Set("client_id", p.clientID)
	q.Set("response_type", "code")
	q.Set("scope", p.scopes)
	q.Set("redirect_uri", p.callbackURL(r))
	q.Set("state", state)
	if idp := strings.TrimSpace(r.URL.Query().Get("idp")); idp != "" {
		q.Set("kc_idp_hint", idp)
	}
	http.Redirect(w, r, disc.AuthEndpoint+"?"+q.Encode(), http.StatusFound)
}

// handleSSOCallback (public) completes the flow: validate state, exchange the
// code, verify the ID token, JIT-provision the user and re-issue our session.
func (s *server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	p := s.oidcProvider()
	if !p.ready() {
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
	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{Name: ssoStateCookie, Path: "/api/auth/sso", MaxAge: -1})

	code := r.URL.Query().Get("code")
	if code == "" {
		s.ssoFail(w, r, "missing authorization code")
		return
	}
	idToken, err := p.exchange(code, p.callbackURL(r))
	if err != nil {
		s.ssoFail(w, r, "token exchange failed: "+err.Error())
		return
	}
	claims, err := p.jwks.verifyRS256(idToken, p.issuer, p.clientID)
	if err != nil {
		s.ssoFail(w, r, "id token rejected: "+err.Error())
		return
	}

	username := firstNonEmpty(claims.PreferredUsername, claims.Email, claims.Sub)
	if username == "" {
		s.ssoFail(w, r, "id token carried no usable subject")
		return
	}
	role := p.roleFor(claims)
	user, err := s.users.UpsertFederated(username, claims.Email, firstNonEmpty(claims.Name, username), role, "oidc", p.defaultTenant)
	if err != nil {
		s.ssoFail(w, r, "provisioning failed: "+err.Error())
		return
	}
	if user.Status == "disabled" {
		s.ssoFail(w, r, "account disabled")
		return
	}

	ttl := accessTokenTTL()
	access, err := signJWT(jwtClaims{
		Sub: user.Username, Role: user.Role, Tenant: user.TenantID,
		Iat: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		s.ssoFail(w, r, err.Error())
		return
	}
	refresh, err := s.refresh.Issue(user.Username)
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
	http.Redirect(w, r, p.postLoginURL+"#"+frag.Encode(), http.StatusFound)
}

func (s *server) ssoFail(w http.ResponseWriter, r *http.Request, msg string) {
	logInfo("auth", "sso login failed", map[string]any{"reason": msg})
	frag := url.Values{}
	frag.Set("sso_error", msg)
	http.Redirect(w, r, s.oidcProvider().postLoginURL+"#"+frag.Encode(), http.StatusFound)
}

// exchange trades an authorization code for tokens at Keycloak's token endpoint
// and returns the raw ID token.
func (p *oidcProvider) exchange(code, redirectURI string) (string, error) {
	disc, err := p.jwks.discovery()
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.clientID)
	if p.clientSecret == "" {
		// public client (PKCE-less here); client_id in body is enough
	}
	req, err := http.NewRequest(http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.clientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(p.clientID), url.QueryEscape(p.clientSecret))
	}
	resp, err := p.jwks.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", errors.New(strings.TrimSpace(string(body)))
	}
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	if tok.IDToken == "" {
		return "", errors.New("no id_token in token response")
	}
	return tok.IDToken, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
