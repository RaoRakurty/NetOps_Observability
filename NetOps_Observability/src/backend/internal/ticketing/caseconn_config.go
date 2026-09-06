// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_config.go — per-tenant TAC connector configuration: the record, the
// write-only secret merge, the pinned vendor-host allowlists, and the
// tenant-keyed CRUD store.
//
// WHY A SEPARATE RECORD (research §5.1): ServiceNowConfig/JiraConfig describe
// the tenant's ITSM instance for RCA auto-ticketing. TAC connector settings are
// a different contract (the tenant's VENDOR support agreement) with different
// credentials and a different lifetime, so they get their own record rather
// than growing vendor fields onto the ITSM one.
//
// CREDENTIAL MODEL (research §5): bring-your-own, PER TENANT, opt-in. No vendor
// permits a shared Correlix-owned support identity — Arista domain-matches
// portal accounts, Juniper issues appId/customerSourceID per customer and
// requires a named human contact, Cisco entitles on the customer's own CCO-ID.
// Secrets are write-only: they are never serialized out, and a blank secret on
// update keeps the stored one.
//
// ISOLATION (CLAUDE.md §3a): the store is keyed by tenant and every read/write
// is scoped by the CALLER's tenant. A non-cross caller can never name another
// tenant; a cross-tenant caller narrowing to a tenant with no config gets
// ErrTenantNotFound, which the HTTP layer maps to 404 — a cross-tenant id is
// never confirmed to exist.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
	"netops/backend/safehttp"
)

// ── the record ──────────────────────────────────────────────────────────────

// ServiceNowAttachConfig tunes the ServiceNow ATTACH path only; the connection
// itself (instance URL, credentials) is the tenant's existing ITSM config.
// MaxAttachBytes mirrors the instance's com.glide.attachment.max_size property,
// whose default is 1024 MB (research §1, ServiceNow row).
type ServiceNowAttachConfig struct {
	Enabled        bool  `json:"enabled"`
	MaxAttachBytes int64 `json:"max_attach_bytes,omitempty"`
}

// JiraAttachConfig tunes the Jira ATTACH path. Deployment selects the documented
// default ceiling AND the auth/API-version pair: Cloud is email+API-token Basic
// on /rest/api/3 with X-Atlassian-Token: no-check and a 1 GB default; Data
// Center is a PAT bearer on /rest/api/2 with `nocheck` and a 10 MB default
// (research §1, Jira row). Both are read from config so an instance that has
// raised or lowered the property is honoured.
type JiraAttachConfig struct {
	Enabled        bool   `json:"enabled"`
	Deployment     string `json:"deployment,omitempty"` // cloud (default) | datacenter
	MaxAttachBytes int64  `json:"max_attach_bytes,omitempty"`
}

// EmailConnectorConfig is the universal fallback transport: the tenant's own
// SMTP relay. TLS is REQUIRED — an evidence bundle is customer network data and
// never leaves in the clear.
type EmailConnectorConfig struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"` // host:port
	From    string `json:"from"`
	User    string `json:"user,omitempty"`
	// Password is write-only: never serialized out, blank on update keeps stored.
	Password     string `json:"password,omitempty"`
	TLSOnConnect bool   `json:"tls_on_connect,omitempty"` // implicit TLS (465) instead of STARTTLS
	// ReplyTo is the named human the vendor replies to. Arista requires "your
	// name and contact information" in the case; several vendors thread on it.
	ReplyTo string `json:"reply_to,omitempty"`
}

// CiscoConnectorConfig covers both Cisco halves: CXD attach-to-existing (needs
// only an SR number + the per-case token the admin copies from SCM) and Smart
// Bonding create (needs a completed onboarding project).
type CiscoConnectorConfig struct {
	Enabled bool `json:"enabled"`
	// CCOID is required on every Smart Bonding create (research §1, Cisco row).
	CCOID string `json:"cco_id,omitempty"`
	// CustomerSourceID is issued by the Smart Bonding onboarding project.
	CustomerSourceID string `json:"customer_source_id,omitempty"`
	// SmartBondingEnabled gates the create half separately from CXD attach: a
	// tenant can use CXD on day one and never onboard Smart Bonding.
	SmartBondingEnabled bool `json:"smart_bonding_enabled,omitempty"`
	// StagingHost selects the onboarding/test environment. Cisco does not publish
	// the staging hostname, so it is supplied by the tenant's onboarding project
	// and constrained to the cisco.com suffix; blank means production.
	StagingHost string `json:"staging_host,omitempty"`
	// ClientID/ClientSecret are the Smart Bonding OAuth-proxy credentials issued
	// at onboarding. ClientSecret is write-only.
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	// TokenURL is the OAuth token endpoint. Defaults to Cisco's published
	// https://id.cisco.com/oauth2/default/v1/token (research §1) and is pinned to
	// the Cisco host allowlist.
	TokenURL string `json:"token_url,omitempty"`
	// FieldMap binds our canonical case fields to the request field names the
	// tenant's Smart Bonding onboarding issued. Cisco does not publish the
	// push/call request schema, so we refuse to guess: an unmapped required
	// field fails closed with ErrNotOnboarded rather than filing a malformed
	// case. See docs/runbooks/tac-case-connectors.md.
	FieldMap map[string]string `json:"field_map,omitempty"`
}

// JuniperConnectorConfig is the Service Case API (css-caseapi, Beta).
// appId / customerSourceID / userId are issued at onboarding; contactEmail must
// be a real registered person, never an alias (research §1, §5).
type JuniperConnectorConfig struct {
	Enabled          bool   `json:"enabled"`
	AppID            string `json:"app_id,omitempty"`
	CustomerSourceID string `json:"customer_source_id,omitempty"`
	UserID           string `json:"user_id,omitempty"`
	AccountID        string `json:"account_id,omitempty"`
	// DefaultContactEmail is the named human on the account.
	DefaultContactEmail string `json:"default_contact_email,omitempty"`
	// AuthMode: oauth (client_credentials) | apikey. Both are documented.
	AuthMode     string `json:"auth_mode,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"` // write-only
	APIKey       string `json:"api_key,omitempty"`       // write-only
}

// TACConnectorConfig is ONE tenant's TAC connector settings.
type TACConnectorConfig struct {
	ServiceNow ServiceNowAttachConfig `json:"servicenow"`
	Jira       JiraAttachConfig       `json:"jira"`
	Email      EmailConnectorConfig   `json:"email"`
	Cisco      CiscoConnectorConfig   `json:"cisco"`
	Juniper    JuniperConnectorConfig `json:"juniper"`
	// ITSM carries the tenant's existing ServiceNow/Jira CONNECTION (instance
	// URL + credentials) resolved from ITSMConfigStore. It is populated at call
	// time by the caller, never persisted here and never serialized out.
	ITSM SystemConfig `json:"-"`
}

// Redacted returns a copy safe to serialize to a client: every write-only
// secret is cleared and replaced by a "configured" boolean the UI renders as a
// masked field. Secrets never leave the process (CLAUDE.md §8).
func (c TACConnectorConfig) Redacted() TACConnectorConfig {
	c.Email.Password = ""
	c.Cisco.ClientSecret = ""
	c.Juniper.ClientSecret = ""
	c.Juniper.APIKey = ""
	c.ITSM = SystemConfig{}
	return c
}

// SecretsPresent reports which write-only secrets are stored, so the UI can show
// "configured" without ever receiving the value.
func (c TACConnectorConfig) SecretsPresent() map[string]bool {
	return map[string]bool{
		"email.password":        c.Email.Password != "",
		"cisco.client_secret":   c.Cisco.ClientSecret != "",
		"juniper.client_secret": c.Juniper.ClientSecret != "",
		"juniper.api_key":       c.Juniper.APIKey != "",
	}
}

// mergeSecrets keeps a stored secret when the incoming value is blank — the
// write-only contract the ITSM store already implements.
func mergeSecrets(in, prev TACConnectorConfig) TACConnectorConfig {
	if in.Email.Password == "" {
		in.Email.Password = prev.Email.Password
	}
	if in.Cisco.ClientSecret == "" {
		in.Cisco.ClientSecret = prev.Cisco.ClientSecret
	}
	if in.Juniper.ClientSecret == "" {
		in.Juniper.ClientSecret = prev.Juniper.ClientSecret
	}
	if in.Juniper.APIKey == "" {
		in.Juniper.APIKey = prev.Juniper.APIKey
	}
	return in
}

// ── validation ──────────────────────────────────────────────────────────────

// ValidateTACConnectorConfig checks one tenant's whole record. Every enabled
// connector must be complete; a disabled one is never validated (opt-in).
func ValidateTACConnectorConfig(c TACConnectorConfig) error {
	if c.Jira.Enabled {
		switch jiraDeployment(c.Jira.Deployment) {
		case jiraCloud, jiraDataCenter:
		default:
			return fmt.Errorf("jira: deployment must be %q or %q", jiraCloud, jiraDataCenter)
		}
		if c.Jira.MaxAttachBytes < 0 {
			return errors.New("jira: max_attach_bytes must not be negative")
		}
	}
	if c.ServiceNow.Enabled && c.ServiceNow.MaxAttachBytes < 0 {
		return errors.New("servicenow: max_attach_bytes must not be negative")
	}
	if c.Email.Enabled {
		if err := validateEmailConfig(c.Email); err != nil {
			return err
		}
	}
	if c.Cisco.Enabled {
		if err := validateCiscoConfig(c.Cisco); err != nil {
			return err
		}
	}
	if c.Juniper.Enabled {
		if err := validateJuniperConfig(c.Juniper); err != nil {
			return err
		}
	}
	return nil
}

func validateEmailConfig(e EmailConnectorConfig) error {
	if strings.TrimSpace(e.Host) == "" {
		return errors.New("email: SMTP host:port is required")
	}
	if !strings.Contains(e.Host, ":") {
		return errors.New("email: SMTP host must be host:port")
	}
	if !strings.Contains(strings.TrimSpace(e.From), "@") {
		return errors.New("email: a sender address is required")
	}
	if e.ReplyTo != "" && !strings.Contains(e.ReplyTo, "@") {
		return errors.New("email: reply_to must be an address")
	}
	host := e.Host[:strings.LastIndex(e.Host, ":")]
	return safehttp.ValidateURL(host)
}

func validateCiscoConfig(c CiscoConnectorConfig) error {
	if c.SmartBondingEnabled {
		if strings.TrimSpace(c.CCOID) == "" {
			return errors.New("cisco: cco_id is required for Smart Bonding (entitlement is checked on every create)")
		}
		if strings.TrimSpace(c.CustomerSourceID) == "" {
			return errors.New("cisco: customer_source_id is issued by your Smart Bonding onboarding project")
		}
		if strings.TrimSpace(c.ClientID) == "" || strings.TrimSpace(c.ClientSecret) == "" {
			return errors.New("cisco: Smart Bonding OAuth client_id and client_secret are required")
		}
	}
	if c.TokenURL != "" {
		if err := validatePinnedURL(c.TokenURL, ciscoHostAllowlist(c.StagingHost)); err != nil {
			return err
		}
	}
	if c.StagingHost != "" {
		h := strings.ToLower(strings.TrimSpace(c.StagingHost))
		if !strings.HasSuffix(h, ".cisco.com") {
			// Cisco does not publish the Smart Bonding staging hostname; it comes
			// from the onboarding project. We refuse anything off cisco.com rather
			// than accepting a free-form host (research §5.5).
			return errors.New("cisco: staging_host must be a cisco.com host issued by your onboarding project")
		}
		if err := safehttp.ValidateURL(h); err != nil {
			return err
		}
	}
	return nil
}

func validateJuniperConfig(j JuniperConnectorConfig) error {
	// Ordered, not a map range: the same incomplete config must always report
	// the same missing field, or an operator fixing them one at a time chases
	// a different error on every save.
	for _, f := range []struct{ name, value string }{
		{"app_id", j.AppID},
		{"customer_source_id", j.CustomerSourceID},
		{"user_id", j.UserID},
		{"account_id", j.AccountID},
	} {
		if strings.TrimSpace(f.value) == "" {
			return fmt.Errorf("juniper: %s is issued by Juniper onboarding and is required", f.name)
		}
	}
	switch strings.ToLower(strings.TrimSpace(orDefaultStr(j.AuthMode, "oauth"))) {
	case "oauth":
		if strings.TrimSpace(j.ClientID) == "" || strings.TrimSpace(j.ClientSecret) == "" {
			return errors.New("juniper: oauth mode requires client_id and client_secret")
		}
	case "apikey":
		if strings.TrimSpace(j.APIKey) == "" {
			return errors.New("juniper: apikey mode requires api_key")
		}
	default:
		return fmt.Errorf("juniper: auth_mode must be %q or %q", "oauth", "apikey")
	}
	if e := strings.TrimSpace(j.DefaultContactEmail); e != "" && !isNamedHumanEmail(e) {
		return errors.New("juniper: default_contact_email must be a real person, not an alias (Juniper rejects aliases)")
	}
	return nil
}

// aliasLocalParts are the mailbox names a shared alias uses. Juniper's API doc
// requires contactEmail to be "a real person and not an alias" (research §4.5);
// this is the cheapest honest enforcement of that rule at the boundary.
var aliasLocalParts = map[string]struct{}{
	"noc": {}, "soc": {}, "support": {}, "helpdesk": {}, "help": {}, "info": {},
	"admin": {}, "administrator": {}, "ops": {}, "operations": {}, "team": {},
	"alerts": {}, "alert": {}, "notifications": {}, "no-reply": {}, "noreply": {},
	"donotreply": {}, "do-not-reply": {}, "network": {}, "netops": {}, "it": {},
	"sysadmin": {}, "root": {}, "postmaster": {}, "abuse": {}, "sales": {},
	"contact": {}, "service": {}, "servicedesk": {}, "tac": {}, "escalations": {},
}

// isNamedHumanEmail rejects the obvious shared aliases. It cannot prove a
// mailbox belongs to a person; it refuses the ones that provably do not.
func isNamedHumanEmail(addr string) bool {
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return false
	}
	local := strings.ToLower(addr[:at])
	if strings.ContainsAny(local, " \t\r\n") {
		return false
	}
	if _, bad := aliasLocalParts[local]; bad {
		return false
	}
	return true
}

// validatePinnedURL enforces https, a host on the pinned allowlist, and the
// SSRF guard. Vendor API hosts are NEVER free-form (research §5.5).
func validatePinnedURL(raw string, allow []string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("vendor url %q does not parse: %w", Truncate(raw, 120), err)
	}
	if u.Host == "" {
		return fmt.Errorf("vendor url %q is not an absolute URL", Truncate(raw, 120))
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("vendor url must be https")
	}
	host := strings.ToLower(u.Hostname())
	for _, a := range allow {
		if host == a {
			return safehttp.ValidateURL(host)
		}
	}
	return fmt.Errorf("host %q is not on the pinned vendor allowlist (%s)", host, strings.Join(allow, ", "))
}

// ── the tenant-keyed store ──────────────────────────────────────────────────

// tacConfigFile is the persisted, versioned envelope.
type tacConfigFile struct {
	Version int                           `json:"version"`
	Tenants map[string]TACConnectorConfig `json:"tenants"`
}

// TACConnectorStore is the per-tenant CRUD store. Every method takes the
// CALLER's resolved scope (tenant, cross) — it never derives scope from a
// request body (CLAUDE.md §3a.2).
type TACConnectorStore struct {
	mu   sync.RWMutex
	path string
	cfgs map[string]TACConnectorConfig
}

// NewTACConnectorStore loads the persisted per-tenant map. An unreadable store
// is loud, not silently "fresh" (§10: no silent failures).
func NewTACConnectorStore(path string) *TACConnectorStore {
	s := &TACConnectorStore{path: path, cfgs: map[string]TACConnectorConfig{}}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, os.ErrNotExist), len(b) == 0 && err == nil:
		return s
	case err != nil:
		applog.Error("tac-connectors", "stored TAC connector config unreadable — starting empty; a save will OVERWRITE it",
			map[string]any{"err": err.Error()})
		return s
	}
	var f tacConfigFile
	if json.Unmarshal(b, &f) != nil || f.Tenants == nil {
		applog.Error("tac-connectors", "stored TAC connector config is not the expected envelope — starting empty", nil)
		return s
	}
	for k, v := range f.Tenants {
		s.cfgs[ITSMKey(k)] = v
	}
	return s
}

// NewTACConnectorStoreForTest builds an unpersisted store (tests only).
func NewTACConnectorStoreForTest() *TACConnectorStore {
	return &TACConnectorStore{cfgs: map[string]TACConnectorConfig{}}
}

// ResolveTACTenant maps a caller's scope + an optional as_tenant selector onto
// the tenant a request may act on. A NON-CROSS caller's as_tenant is IGNORED
// outright — the token is the only source of ownership (CLAUDE.md §3a.2).
// A cross-tenant caller may narrow to any tenant.
func ResolveTACTenant(tenant string, cross bool, asTenant string) string {
	if !cross {
		return ITSMKey(tenant)
	}
	if t := strings.TrimSpace(asTenant); t != "" {
		return ITSMKey(t)
	}
	return ITSMKey(tenant)
}

// Get returns the tenant's config. target names the row; a non-cross caller may
// only read its own, and asking for another tenant's returns ErrTenantNotFound
// (404 — never confirm another tenant's row exists).
func (s *TACConnectorStore) Get(tenant string, cross bool, target string) (TACConnectorConfig, error) {
	key, err := s.scope(tenant, cross, target)
	if err != nil {
		return TACConnectorConfig{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.cfgs[key]
	if !ok {
		return TACConnectorConfig{}, ErrTenantNotFound
	}
	return cfg, nil
}

// List returns the caller's OWN configs only; a cross-tenant caller sees all.
// Returned configs are redacted — a list surface never carries secrets.
func (s *TACConnectorStore) List(tenant string, cross bool) map[string]TACConnectorConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]TACConnectorConfig{}
	own := ITSMKey(tenant)
	for k, v := range s.cfgs {
		if !cross && k != own {
			continue
		}
		out[k] = v.Redacted()
	}
	return out
}

// Tenants lists the configured tenant keys visible to the caller, sorted.
func (s *TACConnectorStore) Tenants(tenant string, cross bool) []string {
	m := s.List(tenant, cross)
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Set validates and stores one tenant's config, merging write-only secrets.
// The OWNER is stamped from the caller's scope, never from the payload.
func (s *TACConnectorStore) Set(tenant string, cross bool, target string, in TACConnectorConfig) error {
	key, err := s.scope(tenant, cross, target)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in.ITSM = SystemConfig{} // never persisted: resolved at call time
	in = mergeSecrets(in, s.cfgs[key])
	if err := ValidateTACConnectorConfig(in); err != nil {
		return err
	}
	prev := s.cfgs[key]
	s.cfgs[key] = in
	if err := s.persist(); err != nil {
		s.cfgs[key] = prev // keep memory and storage consistent
		return err
	}
	return nil
}

// Delete removes one tenant's config. Cross-tenant delete is refused the same
// way a read is: ErrTenantNotFound.
func (s *TACConnectorStore) Delete(tenant string, cross bool, target string) error {
	key, err := s.scope(tenant, cross, target)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cfgs[key]; !ok {
		return ErrTenantNotFound
	}
	prev := s.cfgs[key]
	delete(s.cfgs, key)
	if err := s.persist(); err != nil {
		s.cfgs[key] = prev
		return err
	}
	return nil
}

// scope is the single isolation gate: it converts (caller scope, requested
// target) into the storage key, or refuses. Default-closed.
func (s *TACConnectorStore) scope(tenant string, cross bool, target string) (string, error) {
	own := ITSMKey(tenant)
	want := ITSMKey(target)
	if strings.TrimSpace(target) == "" {
		want = own
	}
	if cross {
		return want, nil
	}
	if want != own {
		return "", ErrTenantNotFound
	}
	return own, nil
}

// persist writes the whole map. Caller holds s.mu.
func (s *TACConnectorStore) persist() error {
	if s.path == "" {
		return nil // ForTest store: in-memory only
	}
	b, err := json.Marshal(tacConfigFile{Version: 1, Tenants: s.cfgs}) // #nosec G117 -- tenant TAC credentials are intentionally persisted to the kv store
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}
