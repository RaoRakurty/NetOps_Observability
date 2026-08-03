// Package oidc is the OIDC/SSO provider domain (Phase-2 W4.4, extracted from
// package main's oidc.go + oidc_config.go, the internal/ldap pattern): the
// provider model over the jwks verifier, MFA amr/acr satisfaction, realm-role
// mapping, the code exchange, provider-button parsing, and the config domain
// (Normalize/Validate/Public). The kv store, env constructors, state cookie
// and login/callback handlers stay in main.
package oidc

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netops/backend/internal/jwks"
)

// firstNonEmpty returns the first non-blank value (duplicated at the boundary).
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

type ProviderInfo struct {
	ID   string `json:"id"`   // kc_idp_hint; "" = realm default (plain OIDC)
	Name string `json:"name"` // display label
	Kind string `json:"kind"` // oidc | saml | ldap
}

type Provider struct {
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
	providers     []ProviderInfo
	requireMFA    bool
	mfaAcr        map[string]bool // acr values that count as MFA (IdP-specific)

	jwks  *jwks.Cache
	httpc *http.Client // token-exchange client (the JWKS cache keeps its own)
}

var mfaAmrMethods = map[string]bool{
	"mfa": true, "otp": true, "totp": true, "hwk": true, "swk": true, "sms": true,
	"tel": true, "phone": true, "phr": true, "phrh": true, "pin": true, "fpt": true,
	"face": true, "iris": true, "vbm": true, "kba": true, "webauthn": true, "u2f": true,
	"hotp": true, "mca": true, "sc": true, "wia": true,
}

// mfaSatisfied reports whether the IdP token asserts a second factor: an amr entry
// in mfaAmrMethods, or an acr value the operator listed as MFA. Used only when
// requireMFA is on.
func (p *Provider) MFASatisfied(c jwks.Claims) bool {
	for _, m := range c.Amr {
		if mfaAmrMethods[strings.ToLower(strings.TrimSpace(m))] {
			return true
		}
	}
	if p.mfaAcr != nil && c.Acr != "" && p.mfaAcr[strings.TrimSpace(c.Acr)] {
		return true
	}
	return false
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

// ParseProviders turns "id:Label:kind,id2:Label2:kind2" into the button list.
// A bare "id" defaults to kind=oidc and Label=id.
func ParseProviders(csv string) []ProviderInfo {
	var out []ProviderInfo
	for _, raw := range strings.Split(csv, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, ":", 3)
		p := ProviderInfo{ID: strings.TrimSpace(parts[0]), Kind: "oidc"}
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
// NewProviderFromConfig builds a live provider from an Config. The same
// path is used for the env-derived initial provider and for every admin-driven
// rebuild, so there is one construction path and no drift between the two.
func NewProviderFromConfig(c Config, jwksTTL time.Duration) *Provider {
	p := &Provider{
		enabled:       c.Enabled,
		clientID:      strings.TrimSpace(c.ClientID),
		clientSecret:  c.ClientSecret,
		scopes:        firstNonEmpty(strings.TrimSpace(c.Scopes), "openid email profile"),
		issuer:        strings.TrimRight(strings.TrimSpace(c.Issuer), "/"),
		redirectURL:   strings.TrimSpace(c.RedirectURL),
		postLoginURL:  firstNonEmpty(strings.TrimSpace(c.PostLoginURL), "/"),
		defaultRole:   firstNonEmpty(strings.TrimSpace(c.DefaultRole), "read-only"),
		defaultTenant: firstNonEmpty(strings.TrimSpace(c.DefaultTenant), "global"),
		adminRoles:    splitSet(firstNonEmpty(strings.TrimSpace(c.AdminRoles), "super-admin,admin,netops-admin")),
		operatorRoles: splitSet(firstNonEmpty(strings.TrimSpace(c.OperatorRoles), "operator,netops-operator")),
		providers:     ParseProviders(c.Providers),
		requireMFA:    c.RequireMFA,
		mfaAcr:        splitSet(strings.TrimSpace(c.MFAAcr)),
		httpc:         &http.Client{Timeout: 10 * time.Second},
	}
	if p.enabled && p.issuer != "" {
		p.jwks = jwks.New(p.issuer, jwksTTL)
	}
	// Always offer at least the realm-default OIDC button when enabled.
	if p.enabled && len(p.providers) == 0 {
		p.providers = []ProviderInfo{{ID: "", Name: "Single Sign-On", Kind: "oidc"}}
	}
	return p
}

// AuthorizeURL builds the IdP authorization redirect for the code flow:
// client/scope/redirect/state, the optional kc_idp_hint, and — when MFA is
// required — acr_values so the IdP steps up (enforcement still happens at the
// callback via MFASatisfied).
func (p *Provider) AuthorizeURL(redirectURI, state, idpHint string) (string, error) {
	disc, err := p.jwks.Discovery()
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("client_id", p.clientID)
	q.Set("response_type", "code")
	q.Set("scope", p.scopes)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	if idpHint != "" {
		q.Set("kc_idp_hint", idpHint)
	}
	if p.requireMFA && len(p.mfaAcr) > 0 {
		acrs := make([]string, 0, len(p.mfaAcr))
		for a := range p.mfaAcr {
			acrs = append(acrs, a)
		}
		q.Set("acr_values", strings.Join(acrs, " "))
	}
	return disc.AuthEndpoint + "?" + q.Encode(), nil
}

// VerifyIDToken verifies the exchanged ID token against the provider's JWKS.
func (p *Provider) VerifyIDToken(idToken string) (jwks.Claims, error) {
	return p.jwks.VerifyRS256(idToken, p.issuer, p.clientID)
}

// RequireMFA and PostLoginURL expose the callback-side policy facts.
func (p *Provider) RequireMFA() bool { return p.requireMFA }

// Issuer and ClientID expose the identity facts (diagnostics + tests).
func (p *Provider) Issuer() string   { return p.issuer }
func (p *Provider) ClientID() string { return p.clientID }

// JWKS exposes the verifier cache for live diagnostics (discovery, refresh,
// key counts) — read-side only.
func (p *Provider) JWKS() *jwks.Cache    { return p.jwks }
func (p *Provider) PostLoginURL() string { return p.postLoginURL }

// VerifyBearer verifies an RS256 bearer against the provider's JWKS with its
// issuer/audience — the service-account API path the auth middleware uses.
func (p *Provider) VerifyBearer(token string) (jwks.Claims, error) {
	return p.jwks.VerifyRS256(token, p.issuer, p.clientID)
}

// DefaultTenant and Providers expose the JIT/identity facts the auth
// middleware and the methods endpoint render.
func (p *Provider) DefaultTenant() string     { return p.defaultTenant }
func (p *Provider) Providers() []ProviderInfo { return p.providers }

func (p *Provider) Ready() bool {
	return p != nil && p.enabled && p.issuer != "" && p.clientID != "" && p.jwks != nil
}

// roleFor maps Keycloak realm roles / groups onto a NetOps built-in role.
func (p *Provider) RoleFor(c jwks.Claims) string {
	names := append([]string{}, c.RealmAccess.Roles...)
	names = append(names, c.Groups...)
	for _, n := range names {
		if p.adminRoles[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(n, "/")))] {
			return "super-admin"
		}
	}
	for _, n := range names {
		if p.operatorRoles[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(n, "/")))] {
			return "operator"
		}
	}
	return p.defaultRole
}

func (p *Provider) CallbackURL(r *http.Request) string {
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
func (p *Provider) Exchange(code, redirectURI string) (string, error) {
	disc, err := p.jwks.Discovery()
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.clientID)
	req, err := http.NewRequest(http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.clientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(p.clientID), url.QueryEscape(p.clientSecret))
	}
	resp, err := p.httpc.Do(req)
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

type Config struct {
	Enabled       bool   `json:"enabled"`
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret,omitempty"` // write-only: persisted to the kv store; never returned by public()
	Scopes        string `json:"scopes"`
	RedirectURL   string `json:"redirect_url"`
	PostLoginURL  string `json:"post_login_url"`
	DefaultRole   string `json:"default_role"`
	DefaultTenant string `json:"default_tenant"`
	AdminRoles    string `json:"admin_roles"`    // csv
	OperatorRoles string `json:"operator_roles"` // csv
	Providers     string `json:"providers"`      // OIDC_PROVIDERS csv: "id:Label:kind,..."
	// RequireMFA rejects an SSO sign-in unless the IdP's token asserts a second
	// factor (amr/acr) — i.e. we HONOR the IdP's MFA instead of trusting it blindly.
	RequireMFA bool   `json:"require_mfa"`
	MFAAcr     string `json:"mfa_acr,omitempty"` // csv of acr values that count as MFA (IdP-specific; optional)
}

// newOIDCConfigFromEnv reads the same env vars newOIDCProvider() reads today so
// the env-only resolution is preserved until an operator saves from the UI.
func (c *Config) Normalize() {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.Scopes = strings.TrimSpace(c.Scopes)
	if c.Scopes == "" {
		c.Scopes = "openid email profile"
	}
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	c.PostLoginURL = strings.TrimSpace(c.PostLoginURL)
	if c.PostLoginURL == "" {
		c.PostLoginURL = "/"
	}
	c.DefaultRole = strings.TrimSpace(c.DefaultRole)
	if c.DefaultRole == "" {
		c.DefaultRole = "read-only"
	}
	c.DefaultTenant = strings.TrimSpace(c.DefaultTenant)
	if c.DefaultTenant == "" {
		c.DefaultTenant = "global"
	}
	c.AdminRoles = strings.TrimSpace(c.AdminRoles)
	c.OperatorRoles = strings.TrimSpace(c.OperatorRoles)
	c.Providers = strings.TrimSpace(c.Providers)
}

// validate enforces the invariants required for an enabled OIDC provider.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Issuer == "" {
		return errors.New("oidc: issuer is required when enabled")
	}
	if c.ClientID == "" {
		return errors.New("oidc: client_id is required when enabled")
	}
	return nil
}

// PublicConfig is the redacted view returned by GET: the client secret is
// replaced by a boolean so the secret never leaves the server.
type PublicConfig struct {
	Enabled         bool   `json:"enabled"`
	Issuer          string `json:"issuer"`
	ClientID        string `json:"client_id"`
	ClientSecretSet bool   `json:"client_secret_set"`
	Scopes          string `json:"scopes"`
	RedirectURL     string `json:"redirect_url"`
	PostLoginURL    string `json:"post_login_url"`
	DefaultRole     string `json:"default_role"`
	DefaultTenant   string `json:"default_tenant"`
	AdminRoles      string `json:"admin_roles"`
	OperatorRoles   string `json:"operator_roles"`
	Providers       string `json:"providers"`
	RequireMFA      bool   `json:"require_mfa"`
	MFAAcr          string `json:"mfa_acr,omitempty"`
}

func (c Config) Public() PublicConfig {
	return PublicConfig{
		Enabled:         c.Enabled,
		Issuer:          c.Issuer,
		ClientID:        c.ClientID,
		ClientSecretSet: c.ClientSecret != "",
		Scopes:          c.Scopes,
		RedirectURL:     c.RedirectURL,
		PostLoginURL:    c.PostLoginURL,
		DefaultRole:     c.DefaultRole,
		DefaultTenant:   c.DefaultTenant,
		AdminRoles:      c.AdminRoles,
		OperatorRoles:   c.OperatorRoles,
		Providers:       c.Providers,
		RequireMFA:      c.RequireMFA,
		MFAAcr:          c.MFAAcr,
	}
}

// ConfigStore is the kv-backed overlay. It holds a back-reference to the
// server so set() can rebuild and atomically swap the live provider.

// NeverConfigured reports whether this record is the default blank shape rather
// than a decision anyone made: disabled, with no issuer and no client id.
//
// Persisting that blank is indistinguishable from never having configured SSO,
// so the caller treats it exactly like an absent key and falls back to the
// OIDC_* environment. Anything else — including a DISABLED record that carries
// an issuer — is a real stored choice and must keep overriding the environment.
func (c Config) NeverConfigured() bool {
	return !c.Enabled &&
		strings.TrimSpace(c.Issuer) == "" &&
		strings.TrimSpace(c.ClientID) == ""
}
