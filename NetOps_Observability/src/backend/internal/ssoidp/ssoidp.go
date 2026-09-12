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

// Provider KINDS — the ACCESS MODEL of a connection, orthogonal to Protocol
// (which is the wire format, saml|oidc).
//
// The pattern comes from the owner's customers (2026-09-07): "in extreme secure
// environments they maintain different IdPs, one for regular auth and another
// one to maintain the JIT access." A STANDING provider is the everyday front
// door — it provisions accounts and carries the standing role. An ELEVATION
// provider is a second, separately-governed door that provisions NOTHING: a
// successful sign-in through it mints a time-bound role binding on an account
// that ALREADY exists and nothing else. It cannot create an account, cannot
// move a tenant, and cannot change a standing role.
const (
	KindStanding  = "standing"
	KindElevation = "elevation"
)

// ElevationMaxMinutesDefault / Ceiling bound a grant when the operator gives no
// ceiling of its own, and cap the one they can give. Eight hours mirrors the
// break-glass ceiling (breakglass.go): past that the grant is standing access
// wearing a timer.
const (
	ElevationMaxMinutesDefault = 60
	ElevationMaxMinutesCeiling = 8 * 60
)

// Elevation is the policy an elevation provider applies to the binding a
// sign-in through it creates. Every field is the NAME of a claim to read, or a
// bound on what a claim may ask for — never a value the token supplies
// directly, so a token can only ever ask for LESS than the operator allowed.
type Elevation struct {
	// TTLClaim names the claim carrying how long the grant should last. Two
	// shapes are accepted and told apart by magnitude, not by configuration:
	// an absolute UNIX-seconds instant (e.g. `access_expires_at`, or the token's
	// own `exp`) or a duration in MINUTES (e.g. `max_session_minutes`). Blank,
	// absent or unreadable ⇒ the provider maximum, never longer.
	TTLClaim string `json:"ttl_claim,omitempty"`
	// MaxMinutes is the provider CEILING. The grant lasts
	// min(claim, MaxMinutes) — the claim can shorten it, never extend it.
	MaxMinutes int `json:"max_minutes,omitempty"`
	// ReasonClaim names the claim carrying the change/ticket id that justifies
	// the elevation. Absent ⇒ the reason reads "elevation login".
	ReasonClaim string `json:"reason_claim,omitempty"`
	// ScopeClaim names the claim carrying a RESOURCE the grant is confined to
	// (today: a device id). Absent ⇒ the grant is scoped to the account's own
	// tenant. A resource named by the claim is validated against THAT tenant's
	// resources before the grant is made; one that is not the caller's is
	// refused, never silently widened (§3a).
	ScopeClaim string `json:"scope_claim,omitempty"`
}

// Normalize trims the claim names and clamps the ceiling into [1, Ceiling].
func (e Elevation) Normalize() Elevation {
	e.TTLClaim = strings.TrimSpace(e.TTLClaim)
	e.ReasonClaim = strings.TrimSpace(e.ReasonClaim)
	e.ScopeClaim = strings.TrimSpace(e.ScopeClaim)
	if e.MaxMinutes <= 0 {
		e.MaxMinutes = ElevationMaxMinutesDefault
	}
	if e.MaxMinutes > ElevationMaxMinutesCeiling {
		e.MaxMinutes = ElevationMaxMinutesCeiling
	}
	return e
}

// Config is one desired-state identity-provider record.
type Config struct {
	Alias       string `json:"alias"` // immutable in Keycloak (part of the broker ACS URL)
	DisplayName string `json:"display_name"`
	Protocol    string `json:"protocol"` // "saml" | "oidc"
	Enabled     bool   `json:"enabled"`
	// Kind is the access model: standing (default) | elevation. Blank reads as
	// standing so every record written before this field existed keeps its
	// exact behaviour.
	Kind      string    `json:"kind,omitempty"`
	Elevation Elevation `json:"elevation,omitempty"`

	// TenantID BINDS this connection to exactly one tenant (design §6.1/§6.3,
	// tracker 276). It is the immutable tenant id, never a slug, and it is
	// stamped from the authenticated principal at the HTTP boundary — never
	// from the request body (CLAUDE.md §3a). Consequences of the binding:
	// the connection appears ONLY on that tenant's sign-in page, its redirect
	// URI is that tenant's per-tenant callback URL, and a token arriving on any
	// other tenant's callback URL is refused.
	//
	// BLANK is the PLATFORM REALM: a connection nobody has bound — every record
	// written before this field existed, and the env-configured buttons. Those
	// stay offered at every locator, because hiding them would lock existing
	// deployments out of their own front door.
	TenantID string `json:"tenant_id,omitempty"`

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
	c.Kind = strings.ToLower(strings.TrimSpace(c.Kind))
	if c.Kind == "" {
		c.Kind = KindStanding
	}
	c.TenantID = strings.ToLower(strings.TrimSpace(c.TenantID))
	c.Elevation = c.Elevation.Normalize()
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
	switch c.Kind {
	case "", KindStanding, KindElevation:
	default:
		return errors.New(`sso idp: kind must be "standing" or "elevation"`)
	}
	if c.Kind == KindElevation {
		// A grant nobody can end is not a grant. The ceiling is what makes an
		// elevation binding time-bound at all, so it is required to be sane
		// here rather than defaulted silently at sign-in time.
		if c.Elevation.MaxMinutes < 1 || c.Elevation.MaxMinutes > ElevationMaxMinutesCeiling {
			return fmt.Errorf("sso idp: elevation max_minutes must be between 1 and %d", ElevationMaxMinutesCeiling)
		}
		if !c.Enabled {
			// Not an error — a disabled elevation provider is a legitimate
			// state — but the sign-in path must never offer it. Enforced by the
			// caller's provider list, not here.
			_ = c.Enabled
		}
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
	Kind            string        `json:"kind"`
	Elevation       Elevation     `json:"elevation"`
	TenantID        string        `json:"tenant_id,omitempty"`
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
		Kind:            c.KindOrStanding(),
		Elevation:       c.Elevation,
		TenantID:        c.TenantID,
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

// KindOrStanding reads the access model of a record, treating a blank (written
// before the field existed) as standing — the behaviour-preserving default.
func (c Config) KindOrStanding() string {
	if k := strings.ToLower(strings.TrimSpace(c.Kind)); k != "" {
		return k
	}
	return KindStanding
}

// IsElevation reports whether this connection is an elevation door.
func (c Config) IsElevation() bool { return c.KindOrStanding() == KindElevation }

// Realm reports the tenant this connection is bound to, blank meaning the
// platform realm (offered at every locator). Read it through this accessor so
// the blank-is-platform rule lives in one place.
func (c Config) Realm() string { return strings.ToLower(strings.TrimSpace(c.TenantID)) }

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
