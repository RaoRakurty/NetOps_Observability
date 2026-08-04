package keycloak

// reconcile.go — the idempotent ensure-style operations (GET, then create or
// update) that project Correlix's desired SSO state into Keycloak. Each maps
// 1:1 onto a phase of the manual Okta runbook; together they replace it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"bytes"
)

// ManagedPrefix marks every IdP mapper this reconciler owns. Reconciliation
// deletes ManagedPrefix-named mappers that are no longer in desired state and
// never touches mappers an operator created by hand in the console.
const ManagedPrefix = "correlix-managed-"

// IdP is the desired identity-provider state, protocol-discriminated.
type IdP struct {
	Alias       string // immutable in Keycloak — part of the broker ACS URL
	DisplayName string
	Protocol    string // "saml" | "oidc"
	Enabled     bool

	// SAML — exactly one metadata source; EntityID must equal the public realm
	// URL (it is pinned on both sides; a mismatch is Okta's "Bad SAML request").
	MetadataURL    string
	MetadataXML    string
	SigningCertPEM string // optional override of the imported signing cert
	EntityID       string

	// OIDC — broker credentials + discovery.
	DiscoveryURL string
	ClientID     string
	ClientSecret string
}

// AttrMapping imports one IdP attribute/claim into a Keycloak user attribute.
type AttrMapping struct {
	IdPAttr  string // SAML attribute name / OIDC claim
	UserAttr string // Keycloak user attribute (email, firstName, lastName, …)
}

// RoleMapping grants a realm role when the groups attribute/claim carries a
// value (the advanced-role-idp-mapper shape from runbook Phase 5).
type RoleMapping struct {
	GroupsAttr string // SAML attribute / OIDC claim holding group membership
	Value      string // group value to match
	Role       string // realm role to grant
}

// EnsureRealm creates the realm when absent (enabled, display name "Correlix").
func (c *Client) EnsureRealm(ctx context.Context, realm string) error {
	_, err := c.call(ctx, "get realm", http.MethodGet, "/admin/realms/"+url.PathEscape(realm), nil, nil)
	if err == nil {
		return nil
	}
	if !IsNotFound(err) {
		return fmt.Errorf("ensure realm: %w", err)
	}
	_, err = c.call(ctx, "create realm", http.MethodPost, "/admin/realms", map[string]any{
		"realm":       realm,
		"enabled":     true,
		"displayName": "Correlix",
	}, nil)
	if err != nil {
		return fmt.Errorf("ensure realm: %w", err)
	}
	return nil
}

// EnsureClient creates or updates the confidential OIDC relying-party client
// and returns its secret. Update touches only the fields we own (redirect
// URIs, web origins, confidentiality, enablement) on the fetched representation
// so console-side settings we do not manage survive.
func (c *Client) EnsureClient(ctx context.Context, realm, clientID string, redirectURIs, webOrigins []string) (string, error) {
	base := "/admin/realms/" + url.PathEscape(realm) + "/clients"
	var found []map[string]any
	if _, err := c.call(ctx, "list clients", http.MethodGet, base+"?clientId="+url.QueryEscape(clientID), nil, &found); err != nil {
		return "", fmt.Errorf("ensure client: %w", err)
	}
	if len(found) == 0 {
		rep := map[string]any{
			"clientId":                  clientID,
			"protocol":                  "openid-connect",
			"enabled":                   true,
			"publicClient":              false, // confidential — client authentication on
			"standardFlowEnabled":       true,
			"directAccessGrantsEnabled": false,
			"serviceAccountsEnabled":    false,
			"redirectUris":              redirectURIs,
			"webOrigins":                webOrigins,
		}
		if _, err := c.call(ctx, "create client", http.MethodPost, base, rep, nil); err != nil {
			return "", fmt.Errorf("ensure client: %w", err)
		}
		if _, err := c.call(ctx, "list clients", http.MethodGet, base+"?clientId="+url.QueryEscape(clientID), nil, &found); err != nil {
			return "", fmt.Errorf("ensure client: %w", err)
		}
		if len(found) == 0 {
			return "", errors.New("ensure client: created client not found on re-read")
		}
	} else {
		rep := found[0]
		rep["enabled"] = true
		rep["publicClient"] = false
		rep["standardFlowEnabled"] = true
		rep["redirectUris"] = redirectURIs
		rep["webOrigins"] = webOrigins
		id, _ := rep["id"].(string)
		if _, err := c.call(ctx, "update client", http.MethodPut, base+"/"+url.PathEscape(id), rep, nil); err != nil {
			return "", fmt.Errorf("ensure client: %w", err)
		}
	}
	id, _ := found[0]["id"].(string)
	if id == "" {
		return "", errors.New("ensure client: client representation has no id")
	}
	var secret struct {
		Value string `json:"value"`
	}
	if _, err := c.call(ctx, "get client secret", http.MethodGet, base+"/"+url.PathEscape(id)+"/client-secret", nil, &secret); err != nil {
		return "", fmt.Errorf("ensure client: %w", err)
	}
	if secret.Value == "" {
		// A confidential client without a generated secret yet — mint one.
		if _, err := c.call(ctx, "generate client secret", http.MethodPost, base+"/"+url.PathEscape(id)+"/client-secret", nil, &secret); err != nil {
			return "", fmt.Errorf("ensure client: %w", err)
		}
	}
	return secret.Value, nil
}

// protocolMapper is the slice of the client-scope/mapper representation we act on.
type protocolMapper struct {
	ID             string            `json:"id,omitempty"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol,omitempty"`
	ProtocolMapper string            `json:"protocolMapper,omitempty"`
	Config         map[string]string `json:"config"`
}

// EnsureRolesInIDToken flips the invisible-role trap (runbook Phase 5): the
// built-in "roles" client scope's "realm roles" protocol mapper defaults to
// access-token-only, while Correlix reads realm_access.roles from the ID
// token — so every federated user silently landed read-only. Set
// "id.token.claim":"true" (keeping the access token) once per realm.
func (c *Client) EnsureRolesInIDToken(ctx context.Context, realm string) error {
	base := "/admin/realms/" + url.PathEscape(realm) + "/client-scopes"
	var scopes []struct {
		ID              string           `json:"id"`
		Name            string           `json:"name"`
		ProtocolMappers []protocolMapper `json:"protocolMappers"`
	}
	if _, err := c.call(ctx, "list client scopes", http.MethodGet, base, nil, &scopes); err != nil {
		return fmt.Errorf("ensure roles in id token: %w", err)
	}
	for _, sc := range scopes {
		if sc.Name != "roles" {
			continue
		}
		for _, m := range sc.ProtocolMappers {
			if m.Name != "realm roles" && m.ProtocolMapper != "oidc-usermodel-realm-role-mapper" {
				continue
			}
			if m.Config["id.token.claim"] == "true" {
				return nil // already fixed — idempotent
			}
			if m.Config == nil {
				m.Config = map[string]string{}
			}
			m.Config["id.token.claim"] = "true"
			m.Config["access.token.claim"] = "true"
			path := base + "/" + url.PathEscape(sc.ID) + "/protocol-mappers/models/" + url.PathEscape(m.ID)
			if _, err := c.call(ctx, "update realm-roles mapper", http.MethodPut, path, m, nil); err != nil {
				return fmt.Errorf("ensure roles in id token: %w", err)
			}
			return nil
		}
		return errors.New(`ensure roles in id token: "realm roles" mapper not found in the "roles" client scope`)
	}
	return errors.New(`ensure roles in id token: "roles" client scope not found`)
}

// EnsureRealmRole creates the realm role when absent.
func (c *Client) EnsureRealmRole(ctx context.Context, realm, name string) error {
	base := "/admin/realms/" + url.PathEscape(realm) + "/roles"
	_, err := c.call(ctx, "get realm role", http.MethodGet, base+"/"+url.PathEscape(name), nil, nil)
	if err == nil {
		return nil
	}
	if !IsNotFound(err) {
		return fmt.Errorf("ensure realm role %q: %w", name, err)
	}
	if _, err := c.call(ctx, "create realm role", http.MethodPost, base, map[string]any{"name": name}, nil); err != nil {
		return fmt.Errorf("ensure realm role %q: %w", name, err)
	}
	return nil
}

// importIdPConfig converts IdP metadata into a Keycloak provider config map via
// POST /admin/realms/{r}/identity-provider/import-config — either from a URL
// (JSON body) or from raw uploaded metadata XML (multipart file), the same two
// paths the admin console offers.
func (c *Client) importIdPConfig(ctx context.Context, realm string, idp IdP) (map[string]string, error) {
	path := "/admin/realms/" + url.PathEscape(realm) + "/identity-provider/import-config"
	out := map[string]string{}
	if idp.Protocol == "saml" && idp.MetadataXML != "" {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		if err := mw.WriteField("providerId", "saml"); err != nil {
			return nil, fmt.Errorf("import idp config: %w", err)
		}
		fw, err := mw.CreateFormFile("file", "metadata.xml")
		if err != nil {
			return nil, fmt.Errorf("import idp config: %w", err)
		}
		if _, err := fw.Write([]byte(idp.MetadataXML)); err != nil {
			return nil, fmt.Errorf("import idp config: %w", err)
		}
		if err := mw.Close(); err != nil {
			return nil, fmt.Errorf("import idp config: %w", err)
		}
		cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
		defer cancel()
		if _, err := c.callRaw(cctx, "import idp config", http.MethodPost, path, mw.FormDataContentType(), buf.Bytes(), &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	fromURL := idp.MetadataURL
	if idp.Protocol == "oidc" {
		fromURL = idp.DiscoveryURL
	}
	in := map[string]any{"fromUrl": fromURL, "providerId": idp.Protocol}
	if _, err := c.call(ctx, "import idp config", http.MethodPost, path, in, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// pemToKeycloakCert strips PEM armor/whitespace down to the bare base64 DER
// Keycloak stores in signingCertificate.
func pemToKeycloakCert(pem string) string {
	var b strings.Builder
	for _, line := range strings.Split(pem, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

// EnsureIdentityProvider imports the IdP's metadata/discovery into a provider
// config and creates or updates the instance under its (immutable) alias.
func (c *Client) EnsureIdentityProvider(ctx context.Context, realm string, idp IdP) error {
	imported, err := c.importIdPConfig(ctx, realm, idp)
	if err != nil {
		return fmt.Errorf("ensure identity provider %q: %w", idp.Alias, err)
	}
	switch idp.Protocol {
	case "saml":
		// The SP entity ID is pinned to the public realm URL on BOTH sides
		// (Keycloak here, the IdP's Audience URI by the operator) — see the
		// "Bad SAML request" row of the runbook's troubleshooting table.
		imported["entityId"] = idp.EntityID
		if idp.SigningCertPEM != "" {
			imported["signingCertificate"] = pemToKeycloakCert(idp.SigningCertPEM)
			imported["validateSignature"] = "true"
		}
	case "oidc":
		imported["clientId"] = idp.ClientID
		if idp.ClientSecret != "" {
			imported["clientSecret"] = idp.ClientSecret
		}
	}

	base := "/admin/realms/" + url.PathEscape(realm) + "/identity-provider/instances"
	existing := map[string]any{}
	_, err = c.call(ctx, "get identity provider", http.MethodGet, base+"/"+url.PathEscape(idp.Alias), nil, &existing)
	switch {
	case IsNotFound(err):
		rep := map[string]any{
			"alias":       idp.Alias,
			"displayName": idp.DisplayName,
			"providerId":  idp.Protocol,
			"enabled":     idp.Enabled,
			"trustEmail":  true,
			"config":      imported,
		}
		if _, err := c.call(ctx, "create identity provider", http.MethodPost, base, rep, nil); err != nil {
			return fmt.Errorf("ensure identity provider %q: %w", idp.Alias, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("ensure identity provider %q: %w", idp.Alias, err)
	}
	// Update in place: overlay the freshly imported config over the stored one
	// so console-set keys we do not manage survive; alias stays immutable.
	cfg, _ := existing["config"].(map[string]any)
	if cfg == nil {
		cfg = map[string]any{}
	}
	for k, v := range imported {
		cfg[k] = v
	}
	existing["config"] = cfg
	existing["displayName"] = idp.DisplayName
	existing["enabled"] = idp.Enabled
	existing["providerId"] = idp.Protocol
	if _, err := c.call(ctx, "update identity provider", http.MethodPut, base+"/"+url.PathEscape(idp.Alias), existing, nil); err != nil {
		return fmt.Errorf("ensure identity provider %q: %w", idp.Alias, err)
	}
	return nil
}

// DeleteIdentityProvider removes the instance, tolerating already-gone.
func (c *Client) DeleteIdentityProvider(ctx context.Context, realm, alias string) error {
	path := "/admin/realms/" + url.PathEscape(realm) + "/identity-provider/instances/" + url.PathEscape(alias)
	_, err := c.call(ctx, "delete identity provider", http.MethodDelete, path, nil, nil)
	if err != nil && !IsNotFound(err) {
		return fmt.Errorf("delete identity provider %q: %w", alias, err)
	}
	return nil
}

// idpMapper is the identity-provider mapper representation we reconcile.
type idpMapper struct {
	ID                     string            `json:"id,omitempty"`
	Name                   string            `json:"name"`
	IdentityProviderAlias  string            `json:"identityProviderAlias"`
	IdentityProviderMapper string            `json:"identityProviderMapper"`
	Config                 map[string]string `json:"config"`
}

// desiredMappers builds the full managed-mapper set for one IdP: attribute
// importers (email/name/custom, syncMode FORCE so changed IdP attributes
// propagate on every login) and one advanced role mapper per role-mapping row.
func desiredMappers(alias, protocol string, attrs []AttrMapping, roles []RoleMapping) ([]idpMapper, error) {
	var out []idpMapper
	for _, a := range attrs {
		m := idpMapper{
			Name:                  ManagedPrefix + "attr-" + a.UserAttr,
			IdentityProviderAlias: alias,
		}
		switch protocol {
		case "saml":
			m.IdentityProviderMapper = "saml-user-attribute-idp-mapper"
			m.Config = map[string]string{
				"attribute.name": a.IdPAttr,
				"user.attribute": a.UserAttr,
				"syncMode":       "FORCE",
			}
		case "oidc":
			m.IdentityProviderMapper = "oidc-user-attribute-idp-mapper"
			m.Config = map[string]string{
				"claim":          a.IdPAttr,
				"user.attribute": a.UserAttr,
				"syncMode":       "FORCE",
			}
		}
		out = append(out, m)
	}
	for _, r := range roles {
		// The advanced mappers take the match list as a JSON-encoded string.
		match, err := json.Marshal([]map[string]string{{"key": r.GroupsAttr, "value": r.Value}})
		if err != nil {
			return nil, fmt.Errorf("encode role mapping %q: %w", r.Value, err)
		}
		m := idpMapper{
			Name:                  ManagedPrefix + "role-" + r.Value + "-" + r.Role,
			IdentityProviderAlias: alias,
		}
		switch protocol {
		case "saml":
			m.IdentityProviderMapper = "saml-advanced-role-idp-mapper"
			m.Config = map[string]string{
				"attributes":                 string(match),
				"role":                       r.Role,
				"syncMode":                   "FORCE",
				"are.attribute.values.regex": "false",
			}
		case "oidc":
			m.IdentityProviderMapper = "oidc-advanced-role-idp-mapper"
			m.Config = map[string]string{
				"claims":                 string(match),
				"role":                   r.Role,
				"syncMode":               "FORCE",
				"are.claim.values.regex": "false",
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// sameMapper reports whether an existing mapper already matches desired state.
func sameMapper(have, want idpMapper) bool {
	if have.IdentityProviderMapper != want.IdentityProviderMapper {
		return false
	}
	for k, v := range want.Config {
		if have.Config[k] != v {
			return false
		}
	}
	return true
}

// EnsureIdPMappers reconciles the managed mapper set: create absent, update
// drifted, and DELETE ManagedPrefix mappers that dropped out of desired state.
// Console-created (unprefixed) mappers are never touched.
func (c *Client) EnsureIdPMappers(ctx context.Context, realm, alias, protocol string, attrs []AttrMapping, roles []RoleMapping) error {
	want, err := desiredMappers(alias, protocol, attrs, roles)
	if err != nil {
		return fmt.Errorf("ensure idp mappers: %w", err)
	}
	base := "/admin/realms/" + url.PathEscape(realm) + "/identity-provider/instances/" + url.PathEscape(alias) + "/mappers"
	var have []idpMapper
	if _, err := c.call(ctx, "list idp mappers", http.MethodGet, base, nil, &have); err != nil {
		return fmt.Errorf("ensure idp mappers: %w", err)
	}
	byName := map[string]idpMapper{}
	for _, m := range have {
		byName[m.Name] = m
	}
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w.Name] = true
		h, ok := byName[w.Name]
		switch {
		case !ok:
			if _, err := c.call(ctx, "create idp mapper", http.MethodPost, base, w, nil); err != nil {
				return fmt.Errorf("ensure idp mappers: %w", err)
			}
		case !sameMapper(h, w):
			w.ID = h.ID
			if _, err := c.call(ctx, "update idp mapper", http.MethodPut, base+"/"+url.PathEscape(h.ID), w, nil); err != nil {
				return fmt.Errorf("ensure idp mappers: %w", err)
			}
		}
	}
	for _, m := range have {
		if strings.HasPrefix(m.Name, ManagedPrefix) && !wanted[m.Name] {
			if _, err := c.call(ctx, "delete idp mapper", http.MethodDelete, base+"/"+url.PathEscape(m.ID), nil, nil); err != nil {
				return fmt.Errorf("ensure idp mappers: %w", err)
			}
		}
	}
	return nil
}

// PingResult distinguishes the three ways "Keycloak isn't answering" presents.
type PingResult struct {
	Reachable   bool   `json:"reachable"`
	Authorized  bool   `json:"authorized"`
	RealmExists bool   `json:"realm_exists"`
	Version     string `json:"version,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// OK reports whether reconcile operations can proceed (the realm itself is
// created on demand, so its absence does not block).
func (r PingResult) OK() bool { return r.Reachable && r.Authorized }

// Ping probes the admin connection: unreachable vs unauthorized vs
// realm-missing, plus the server version when available.
func (c *Client) Ping(ctx context.Context) PingResult {
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	if _, err := c.authenticate(cctx, false); err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			detail := "admin authentication failed (check KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD)"
			if ae.Status != http.StatusUnauthorized {
				detail = ae.Error()
			}
			return PingResult{Reachable: true, Detail: detail}
		}
		return PingResult{Detail: "keycloak unreachable: " + err.Error()}
	}
	res := PingResult{Reachable: true, Authorized: true}
	var info struct {
		SystemInfo struct {
			Version string `json:"version"`
		} `json:"systemInfo"`
	}
	if _, err := c.call(ctx, "server info", http.MethodGet, "/admin/serverinfo", nil, &info); err == nil {
		res.Version = info.SystemInfo.Version
	}
	_, err := c.call(ctx, "get realm", http.MethodGet, "/admin/realms/"+url.PathEscape(c.cfg.Realm), nil, nil)
	switch {
	case err == nil:
		res.RealmExists = true
	case IsNotFound(err):
		res.Detail = fmt.Sprintf("realm %q does not exist yet (it is created on first save)", c.cfg.Realm)
	default:
		res.Detail = err.Error()
	}
	return res
}
