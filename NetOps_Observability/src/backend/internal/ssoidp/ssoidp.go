// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package ssoidp is the desired-state domain for GUI-configurable SSO identity
// providers (the Keycloak-side half of SSO; the relying-party half is the OIDC
// config domain). Each record describes ONE upstream IdP (Okta, Azure AD, …)
// brokered through the bundled Keycloak: its metadata/discovery source, the
// attribute importers, and the group→role mappings. The HTTP boundary and the
// reconcile-into-Keycloak apply path stay in main (oidc_config.go), which
// persists a record here and projects it via internal/keycloak.
//
// Mirrors the OIDC/LDAP config-store contracts exactly:
//
//   - The OIDC broker client secret is WRITE-ONLY: Public() replaces it with a
//     boolean, and a Set() that omits it PRESERVES the stored one.
//   - Every Set() is normalised and validated before persistence.
//   - Three-state load (absent / error / loaded), secrets sealed at rest under
//     the platform DEK via the injected transforms.
package ssoidp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"netops/backend/internal/platformdb"
	"netops/backend/internal/rbac"
)

// AttrMapping imports one IdP attribute (SAML) / claim (OIDC) into a Keycloak
// user attribute.
type AttrMapping struct {
	IdPAttr  string `json:"idp_attr"`
	UserAttr string `json:"user_attr"`
}

// RoleMapping maps one groups-attribute value onto a Correlix role. Ordered:
// rows are applied in the order saved.
type RoleMapping struct {
	Value string `json:"value"` // group / claim value from the IdP
	Role  string `json:"role"`  // Correlix role id (validated against the role registry)
}

// Config is one desired-state identity-provider record.
type Config struct {
	Alias       string `json:"alias"` // immutable in Keycloak (part of the broker ACS URL)
	DisplayName string `json:"display_name"`
	Protocol    string `json:"protocol"` // "saml" | "oidc"
	Enabled     bool   `json:"enabled"`

	// SAML: exactly one metadata source; optional signing-cert override.
	MetadataURL    string `json:"metadata_url,omitempty"`
	MetadataXML    string `json:"metadata_xml,omitempty"`
	SigningCertPEM string `json:"signing_cert_pem,omitempty"`

	// OIDC: discovery + broker credentials.
	DiscoveryURL string `json:"discovery_url,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"` // write-only; sealed at rest

	GroupsAttr   string        `json:"groups_attr"` // attribute/claim carrying group membership
	AttrMappings []AttrMapping `json:"attr_mappings"`
	RoleMappings []RoleMapping `json:"role_mappings"`
}

// aliasRe: aliases become URL path segments in Keycloak's broker endpoints.
var aliasRe = regexp.MustCompile(`^[a-z0-9-]{2,40}$`)

// Normalize trims and defaults so the stored document is canonical.
func (c Config) Normalize() Config {
	c.Alias = strings.ToLower(strings.TrimSpace(c.Alias))
	c.DisplayName = strings.TrimSpace(c.DisplayName)
	if c.DisplayName == "" {
		c.DisplayName = c.Alias
	}
	c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol))
	c.MetadataURL = strings.TrimSpace(c.MetadataURL)
	c.MetadataXML = strings.TrimSpace(c.MetadataXML)
	c.SigningCertPEM = strings.TrimSpace(c.SigningCertPEM)
	c.DiscoveryURL = strings.TrimSpace(c.DiscoveryURL)
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.GroupsAttr = strings.TrimSpace(c.GroupsAttr)
	if c.GroupsAttr == "" {
		c.GroupsAttr = "groups"
	}
	for i, a := range c.AttrMappings {
		c.AttrMappings[i] = AttrMapping{IdPAttr: strings.TrimSpace(a.IdPAttr), UserAttr: strings.TrimSpace(a.UserAttr)}
	}
	for i, r := range c.RoleMappings {
		c.RoleMappings[i] = RoleMapping{Value: strings.TrimSpace(r.Value), Role: strings.ToLower(strings.TrimSpace(r.Role))}
	}
	return c
}

// httpURL enforces http(s)-only absolute URLs at the trust boundary.
func httpURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("sso idp: %s must be an absolute http(s) URL", field)
	}
	return nil
}

// MetadataXMLMax caps an uploaded SAML metadata document (real IdP metadata is
// a few KiB).
const MetadataXMLMax = 256 << 10

// Validate enforces the invariants a record must satisfy BEFORE it can be
// persisted or reconciled into Keycloak. roleValid answers whether a Correlix
// role id exists; allowPlatformOwner reflects FEDERATION_ALLOW_PLATFORM_OWNER
// (both injected — the domain reads no env and no registry).
func (c Config) Validate(roleValid func(string) bool, allowPlatformOwner bool) error {
	if !aliasRe.MatchString(c.Alias) {
		return errors.New("sso idp: alias must match ^[a-z0-9-]{2,40}$")
	}
	switch c.Protocol {
	case "saml":
		if (c.MetadataURL == "") == (c.MetadataXML == "") {
			return errors.New("sso idp: saml requires exactly one of metadata_url or metadata_xml")
		}
		if c.MetadataURL != "" {
			if err := httpURL("metadata_url", c.MetadataURL); err != nil {
				return err
			}
		}
		if len(c.MetadataXML) > MetadataXMLMax {
			return fmt.Errorf("sso idp: metadata_xml exceeds %d bytes", MetadataXMLMax)
		}
	case "oidc":
		if c.DiscoveryURL == "" || c.ClientID == "" {
			return errors.New("sso idp: oidc requires discovery_url and client_id")
		}
		if err := httpURL("discovery_url", c.DiscoveryURL); err != nil {
			return err
		}
	default:
		return errors.New(`sso idp: protocol must be "saml" or "oidc"`)
	}
	for _, a := range c.AttrMappings {
		if a.IdPAttr == "" || a.UserAttr == "" {
			return errors.New("sso idp: attr_mappings entries need both idp_attr and user_attr")
		}
	}
	for _, r := range c.RoleMappings {
		if r.Value == "" {
			return errors.New("sso idp: role_mappings entries need a value")
		}
		if roleValid != nil && !roleValid(r.Role) {
			return fmt.Errorf("sso idp: role mapping %q: unknown role %q", r.Value, r.Role)
		}
		// Make the silent federation downgrade loud at CONFIG time:
		// guardFederatedRole (SR-025) would DOWNGRADE this mapping to read-only
		// at every sign-in, with only a server-side log line to explain why.
		// Refuse the config instead.
		if rbac.IsSuperAdminRole(r.Role) && !allowPlatformOwner {
			return fmt.Errorf("sso idp: role mapping %q → %q is refused: a federated identity mapping to the "+
				"platform owner (super-admin) is silently DOWNGRADED to read-only at sign-in by the SR-025 "+
				"federation guard (guardFederatedRole). Set FEDERATION_ALLOW_PLATFORM_OWNER=true on the api "+
				"service to allow platform-owner federation, or map this group to a different role", r.Value, r.Role)
		}
	}
	return nil
}

// Public is the redacted view: the broker client secret becomes a boolean.
// Metadata XML is not a secret and round-trips so the UI can edit it.
type Public struct {
	Alias           string        `json:"alias"`
	DisplayName     string        `json:"display_name"`
	Protocol        string        `json:"protocol"`
	Enabled         bool          `json:"enabled"`
	MetadataURL     string        `json:"metadata_url,omitempty"`
	MetadataXML     string        `json:"metadata_xml,omitempty"`
	SigningCertPEM  string        `json:"signing_cert_pem,omitempty"`
	DiscoveryURL    string        `json:"discovery_url,omitempty"`
	ClientID        string        `json:"client_id,omitempty"`
	ClientSecretSet bool          `json:"client_secret_set"`
	GroupsAttr      string        `json:"groups_attr"`
	AttrMappings    []AttrMapping `json:"attr_mappings"`
	RoleMappings    []RoleMapping `json:"role_mappings"`
}

func (c Config) Public() Public {
	return Public{
		Alias:           c.Alias,
		DisplayName:     c.DisplayName,
		Protocol:        c.Protocol,
		Enabled:         c.Enabled,
		MetadataURL:     c.MetadataURL,
		MetadataXML:     c.MetadataXML,
		SigningCertPEM:  c.SigningCertPEM,
		DiscoveryURL:    c.DiscoveryURL,
		ClientID:        c.ClientID,
		ClientSecretSet: c.ClientSecret != "",
		GroupsAttr:      c.GroupsAttr,
		AttrMappings:    c.AttrMappings,
		RoleMappings:    c.RoleMappings,
	}
}

// Deps supplies the store's injected cross-domain dependencies (the users.Deps
// pattern): the at-rest secret transforms, the role-registry membership test,
// the FEDERATION_ALLOW_PLATFORM_OWNER opt-in, and structured error logging.
type Deps struct {
	Seal               func(string) (string, error) // encrypt a client secret for persistence
	Open               func(string) (string, error) // decrypt a stored client secret
	RoleValid          func(string) bool
	AllowPlatformOwner func() bool
	Errorf             func(component, msg string, fields map[string]any)
}

func (d Deps) seal(v string) (string, error) {
	if d.Seal == nil {
		return v, nil
	}
	return d.Seal(v)
}

func (d Deps) open(v string) (string, error) {
	if d.Open == nil {
		return v, nil
	}
	return d.Open(v)
}

func (d Deps) errorf(component, msg string, fields map[string]any) {
	if d.Errorf != nil {
		d.Errorf(component, msg, fields)
	}
}

// Store is the kv-backed desired-state collection, ordered by save time.
type Store struct {
	mu   sync.RWMutex
	idps []Config
	path string
	deps Deps
	// loadErr: at least one stored client secret could not be unsealed — see the
	// LDAP config store. The affected in-memory secrets are blank, so the "empty
	// Set preserves the stored secret" shortcut would silently WIPE them; Set()
	// refuses to rely on a preserved secret until a save repairs the store.
	loadErr error
}

// NewStore opens the store; an unreadable stored document is logged and left
// repairable (loadErr), never fatal.
func NewStore(path string, deps Deps) *Store {
	s := &Store{path: path, deps: deps}
	if err := s.load(); err != nil {
		s.loadErr = err
		deps.errorf("sso.idp", "stored SSO identity-provider config unreadable", map[string]any{"error": err.Error()})
	}
	return s
}

// load reads the stored collection. THREE states, never two: the store did not
// answer (error) / it answered with nothing (absent or empty — no IdPs yet) /
// loaded (possibly with per-record unseal failures, secrets cleared).
func (s *Store) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = no IdPs configured yet
	}
	if err != nil {
		return fmt.Errorf("read SSO IdP config: %w", err)
	}
	if len(b) == 0 {
		return nil
	}
	var list []Config
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("decode SSO IdP config: %w", err)
	}
	var loadErr error
	for i, c := range list {
		if dec, derr := s.deps.open(c.ClientSecret); derr != nil {
			// Never hand the SEALED bytes to Keycloak as a broker secret.
			list[i].ClientSecret = ""
			loadErr = fmt.Errorf("unseal SSO IdP client secret (%s): %w", c.Alias, derr)
			s.deps.errorf("sso.idp", "decrypt secret", map[string]any{"error": derr.Error()})
		} else {
			list[i].ClientSecret = dec
		}
	}
	s.mu.Lock()
	s.idps = list
	s.mu.Unlock()
	return loadErr
}

// List returns a copy of the stored records (decrypted secrets included — for
// the reconcile path; HTTP callers must render Public()).
func (s *Store) List() []Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Config, len(s.idps))
	copy(out, s.idps)
	return out
}

// Get returns one record by alias.
func (s *Store) Get(alias string) (Config, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.idps {
		if c.Alias == alias {
			return c, true
		}
	}
	return Config{}, false
}

// Set validates and upserts one record, preserving the stored client secret
// when the incoming one is blank (the redacted round-trip), then persists the
// sealed collection. Returns the stored effective record.
func (s *Store) Set(in Config) (Config, error) {
	in = in.Normalize()
	allow := s.deps.AllowPlatformOwner != nil && s.deps.AllowPlatformOwner()
	if err := in.Validate(s.deps.RoleValid, allow); err != nil {
		return Config{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, c := range s.idps {
		if c.Alias == in.Alias {
			idx = i
			break
		}
	}
	if in.Protocol == "oidc" && in.ClientSecret == "" && idx >= 0 && s.idps[idx].ClientSecret == "" && s.loadErr != nil {
		return Config{}, errors.New("the stored client secret could not be read — re-enter it with this save")
	}
	if in.ClientSecret == "" && idx >= 0 {
		in.ClientSecret = s.idps[idx].ClientSecret
	}
	next := make([]Config, len(s.idps))
	copy(next, s.idps)
	if idx >= 0 {
		next[idx] = in
	} else {
		next = append(next, in)
	}
	if err := s.persist(next); err != nil {
		return Config{}, err
	}
	s.idps = next
	s.loadErr = nil // a successful save IS the repair
	return in, nil
}

// Remove deletes one record and persists. Absent alias → os.ErrNotExist.
func (s *Store) Remove(alias string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, c := range s.idps {
		if c.Alias == alias {
			idx = i
			break
		}
	}
	if idx < 0 {
		return os.ErrNotExist
	}
	next := append(append([]Config{}, s.idps[:idx]...), s.idps[idx+1:]...)
	if err := s.persist(next); err != nil {
		return err
	}
	s.idps = next
	return nil
}

// persist seals every record's client secret and writes the collection.
// Callers hold s.mu.
func (s *Store) persist(list []Config) error {
	sealed := make([]Config, len(list))
	for i, c := range list {
		sc, err := s.deps.seal(c.ClientSecret)
		if err != nil {
			return err
		}
		c.ClientSecret = sc
		sealed[i] = c
	}
	// #nosec G117 -- broker client secrets are intentionally persisted so IdPs are
	// UI-configurable; sealed above under the platform DEK before marshalling,
	// redacted from every API response by Public(), never logged.
	b, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}
