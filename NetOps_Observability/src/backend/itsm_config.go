package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"netops/backend/notify"
	"netops/backend/safehttp"
)

// itsm_config.go — PER-TENANT, runtime-configurable, kv-persisted config for the
// ITSM connectors (ServiceNow + Jira), tunable live from the admin UI with NO
// restart.
//
// Multi-tenancy: every tenant configures its OWN ServiceNow/Jira (Acme → Acme's
// ServiceNow, Globex → Globex's Jira); the platform owner configures the global
// connector under the "" key (used for platform/infra incidents). The store keys
// config + live connectors by tenant; incident projection resolves the connector
// from the incident's TenantID, so a tenant's incidents can only ever reach its
// own ticketing system.
//
// Routing: ITSM is reached EXCLUSIVELY through the incident-projection path
// (incidents_sync.go), which carries inc.TenantID. The connectors are NOT
// registered in the broadcast alert Dispatcher — that dispatcher fans every alert
// to every channel regardless of tenant, so a per-tenant connector there would
// leak tenant A's alerts into tenant B's ticketing. The incident system already
// folds in all alerts/findings, so nothing is lost: an alert tickets via its
// (tenant-scoped) incident.
//
// On first run the GLOBAL ("") connector seeds from the legacy env vars
// (FEATURE_SERVICENOW_NOTIFICATIONS + SERVICENOW_*, FEATURE_JIRA_NOTIFICATIONS +
// JIRA_*) for back-compat; thereafter the kv store is the source of truth.
//
// SECURITY: an admin may read/write ONLY its own tenant's ITSM config. The
// platform owner manages the global connector and (via ?tenant=) any tenant's.
// Secrets (Password / APIToken) are write-only: persisted but never returned.

// serviceNowConfig / jiraConfig are the persisted, kv-backed connector settings.
type serviceNowConfig struct {
	Enabled         bool   `json:"enabled"`
	InstanceURL     string `json:"instance_url"`
	User            string `json:"user"`
	Password        string `json:"password,omitempty"`
	MinSeverity     string `json:"min_severity"`
	AssignmentGroup string `json:"assignment_group"`
}

// pagerDutyRCAConfig is the per-tenant PagerDuty destination for RCA
// auto-ticketing (#103) — the CUSTOMER paging lane. RoutingKey is the tenant's
// own Events API v2 integration key (write-only). Distinct from the
// platform-global notify channel, which serves platform self-health only.
type pagerDutyRCAConfig struct {
	Enabled    bool   `json:"enabled"`
	RoutingKey string `json:"routing_key,omitempty"`
}

type jiraConfig struct {
	Enabled           bool   `json:"enabled"`
	BaseURL           string `json:"base_url"`
	Email             string `json:"email"`
	APIToken          string `json:"api_token,omitempty"`
	ProjectKey        string `json:"project_key"`
	IssueType         string `json:"issue_type"`
	MinSeverity       string `json:"min_severity"`
	ResolveTransition string `json:"resolve_transition"`
}

// itsmConfig is ONE tenant's ITSM connector settings.
type itsmConfig struct {
	ServiceNow serviceNowConfig   `json:"servicenow"`
	Jira       jiraConfig         `json:"jira"`
	PagerDuty  pagerDutyRCAConfig `json:"pagerduty"`
}

// itsmLive holds a tenant's built connectors (nil when disabled/unconfigured).
type itsmLive struct {
	sn   *notify.ServiceNow
	jira *notify.Jira
}

// itsmConfigFile is the persisted, versioned envelope for the per-tenant map.
// Version >= 2 distinguishes it from the legacy single-object format, which is
// migrated under the global "" key on load.
type itsmConfigFile struct {
	Version int                   `json:"version"`
	Tenants map[string]itsmConfig `json:"tenants"`
}

type itsmConfigStore struct {
	mu   sync.RWMutex
	path string
	srv  *server
	cfgs map[string]itsmConfig // tenant key ("" = global) -> config, INCLUDING secrets
	live map[string]*itsmLive  // tenant key -> built connectors
}

// itsmKey normalizes a tenant id to the store/connector key. The global/platform
// tenant ("" or "global") collapses to "" so an incident tagged TenantID="" and
// the platform owner's config resolve to the same connector.
func itsmKey(tenant string) string {
	t := normTenant(tenant)
	if t == TenantGlobal {
		return ""
	}
	return t
}

// newITSMConfigStore loads the persisted per-tenant config (or seeds the global
// connector from env on first run), then builds the live connectors per tenant.
func newITSMConfigStore(srv *server, path string) *itsmConfigStore {
	s := &itsmConfigStore{path: path, srv: srv, cfgs: map[string]itsmConfig{}, live: map[string]*itsmLive{}}
	if !s.load() {
		// First run: the pre-per-tenant single connector was platform-wide → seed
		// it under the global "" key.
		s.cfgs[""] = itsmConfigFromEnv()
	}
	for tenant, cfg := range s.cfgs {
		s.apply(tenant, cfg)
	}
	return s
}

// load reads the persisted config. Returns false when absent/empty so the caller
// seeds from env. Migrates the legacy single-object format under the "" key.
func (s *itsmConfigStore) load() bool {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return false
	}
	// New per-tenant format (versioned envelope).
	var f itsmConfigFile
	if json.Unmarshal(b, &f) == nil && f.Version >= 2 && f.Tenants != nil {
		s.cfgs = map[string]itsmConfig{}
		for k, v := range f.Tenants {
			s.cfgs[itsmKey(k)] = v
		}
		return true
	}
	// Legacy single global connector → migrate under "".
	var c itsmConfig
	if json.Unmarshal(b, &c) != nil {
		return false
	}
	s.cfgs = map[string]itsmConfig{"": c}
	return true
}

// itsmConfigFromEnv seeds the GLOBAL connector from the legacy env vars so an
// existing env-configured deployment keeps working unchanged after upgrade.
func itsmConfigFromEnv() itsmConfig {
	return itsmConfig{
		ServiceNow: serviceNowConfig{
			Enabled:         envBool("FEATURE_SERVICENOW_NOTIFICATIONS"),
			InstanceURL:     envOr("SERVICENOW_INSTANCE_URL", ""),
			User:            envOr("SERVICENOW_USER", ""),
			Password:        envOr("SERVICENOW_PASSWORD", ""),
			MinSeverity:     envOr("SERVICENOW_MIN_SEVERITY", "critical"),
			AssignmentGroup: envOr("SERVICENOW_ASSIGNMENT_GROUP", ""),
		},
		Jira: jiraConfig{
			Enabled:           envBool("FEATURE_JIRA_NOTIFICATIONS"),
			BaseURL:           envOr("JIRA_BASE_URL", ""),
			Email:             envOr("JIRA_EMAIL", ""),
			APIToken:          envOr("JIRA_API_TOKEN", ""),
			ProjectKey:        envOr("JIRA_PROJECT_KEY", ""),
			IssueType:         envOr("JIRA_ISSUE_TYPE", ""),
			MinSeverity:       envOr("JIRA_MIN_SEVERITY", "critical"),
			ResolveTransition: envOr("JIRA_RESOLVE_TRANSITION", ""),
		},
	}
}

// set validates a tenant's config, merges (preserving blanked secrets), persists
// the whole map, then rebuilds and swaps that tenant's live connectors.
func (s *itsmConfigStore) set(tenant string, in itsmConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant = itsmKey(tenant)

	in.ServiceNow = normalizeServiceNow(in.ServiceNow)
	in.Jira = normalizeJira(in.Jira)

	// Write-only secrets: a blank secret on update KEEPS the stored one (so the UI
	// can mask it and never re-send it).
	prev := s.cfgs[tenant]
	if in.ServiceNow.Password == "" {
		in.ServiceNow.Password = prev.ServiceNow.Password
	}
	if in.Jira.APIToken == "" {
		in.Jira.APIToken = prev.Jira.APIToken
	}
	if in.PagerDuty == (pagerDutyRCAConfig{}) {
		// The combined ITSM PUT predates the PD lane — an omitted pagerduty
		// block must never silently disable RCA paging. The dedicated
		// /api/itsm/pagerduty-rca endpoint is the explicit mutation path.
		in.PagerDuty = prev.PagerDuty
	} else if in.PagerDuty.RoutingKey == "" {
		in.PagerDuty.RoutingKey = prev.PagerDuty.RoutingKey
	}

	if err := validateITSM(in); err != nil {
		return err
	}

	s.cfgs[tenant] = in
	if err := s.persist(); err != nil {
		return err
	}
	s.apply(tenant, in)
	return nil
}

// persist writes the whole per-tenant map as the versioned envelope. Caller holds s.mu.
func (s *itsmConfigStore) persist() error {
	b, err := json.Marshal(itsmConfigFile{Version: 2, Tenants: s.cfgs}) // #nosec G117 -- ITSM creds are intentionally persisted to the kv store
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

var itsmTenantSlug = regexp.MustCompile(`[^a-z0-9_-]+`)

// itsmStateFile returns the per-tenant ticket dedup-state path. The global
// connector keeps the legacy paths (so existing dedup state survives upgrade);
// each tenant gets its own file so dedup keys can never collide across tenants.
func itsmStateFile(system, tenant string) string {
	if tenant == "" {
		switch system {
		case "servicenow":
			return envOr("SERVICENOW_STATE_FILE", "/data/servicenow_tickets.json")
		case "jira":
			return envOr("JIRA_STATE_FILE", "/data/jira_tickets.json")
		}
	}
	slug := itsmTenantSlug.ReplaceAllString(tenant, "-")
	return "/data/" + system + "_tickets_" + slug + ".json"
}

// apply (re)builds a tenant's connectors from cfg and swaps them into the live
// map. Connectors are reached only via incident projection (NOT the dispatcher).
// Caller holds s.mu (or it's the constructor).
func (s *itsmConfigStore) apply(tenant string, cfg itsmConfig) {
	tenant = itsmKey(tenant)
	live := &itsmLive{}
	if cfg.ServiceNow.Enabled && cfg.ServiceNow.InstanceURL != "" {
		live.sn = notify.NewServiceNow(cfg.ServiceNow.InstanceURL, cfg.ServiceNow.User, cfg.ServiceNow.Password).
			WithThreshold(cfg.ServiceNow.MinSeverity).
			WithStateFile(itsmStateFile("servicenow", tenant)).
			WithAssignmentGroup(cfg.ServiceNow.AssignmentGroup)
	}
	if cfg.Jira.Enabled && cfg.Jira.BaseURL != "" && cfg.Jira.ProjectKey != "" {
		live.jira = notify.NewJira(cfg.Jira.BaseURL, cfg.Jira.Email, cfg.Jira.APIToken, cfg.Jira.ProjectKey).
			WithIssueType(cfg.Jira.IssueType).
			WithThreshold(cfg.Jira.MinSeverity).
			WithResolveTransition(cfg.Jira.ResolveTransition).
			WithStateFile(itsmStateFile("jira", tenant))
	}
	s.live[tenant] = live
}

// serviceNowFor / jiraFor resolve a tenant's live connector (nil if none).
func (s *itsmConfigStore) serviceNowFor(tenant string) *notify.ServiceNow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l := s.live[itsmKey(tenant)]; l != nil {
		return l.sn
	}
	return nil
}

func (s *itsmConfigStore) jiraFor(tenant string) *notify.Jira {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l := s.live[itsmKey(tenant)]; l != nil {
		return l.jira
	}
	return nil
}

// ticketSystemConfig resolves one tenant's external-ticketing connection for the
// RCA auto-ticketing worker (#78). It returns the tenant's OWN ServiceNow config
// (incl. write-only secrets, used only to dispatch) or ok=false when that tenant
// has no enabled, configured connection — a transient hold, not a failure. Only
// ServiceNow is wired today; other systems return ok=false.
func (s *itsmConfigStore) ticketSystemConfig(tenant, system string) (ticketSystemConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.cfgs[itsmKey(tenant)]
	if !ok {
		return ticketSystemConfig{}, false
	}
	switch orDefault(system, "servicenow") {
	case "servicenow":
		sn := cfg.ServiceNow
		if !sn.Enabled || sn.InstanceURL == "" {
			return ticketSystemConfig{}, false
		}
		return ticketSystemConfig{
			System:          "servicenow",
			TenantID:        tenant,
			InstanceURL:     sn.InstanceURL,
			AuthType:        "basic",
			User:            sn.User,
			Password:        sn.Password,
			AssignmentGroup: sn.AssignmentGroup,
		}, true
	case "pagerduty":
		pd := cfg.PagerDuty
		if !pd.Enabled || pd.RoutingKey == "" {
			return ticketSystemConfig{}, false
		}
		// InstanceURL doubles as the Events API base so tests can inject a
		// fake server; the worker's "connected" check requires it non-empty.
		return ticketSystemConfig{
			System:      "pagerduty",
			TenantID:    tenant,
			InstanceURL: pdDefaultEventsBase,
			AuthType:    "routing_key",
			APIToken:    pd.RoutingKey,
		}, true
	}
	return ticketSystemConfig{}, false
}

// setPagerDutyRCA mutates ONLY the tenant's PagerDuty RCA-paging destination
// (#103). Blank routing key on update preserves the stored one (write-only);
// disable works explicitly here (the combined PUT cannot express it).
func (s *itsmConfigStore) setPagerDutyRCA(tenant string, in pagerDutyRCAConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant = itsmKey(tenant)
	cfg := s.cfgs[tenant]
	if in.RoutingKey == "" {
		in.RoutingKey = cfg.PagerDuty.RoutingKey
	}
	if in.Enabled && strings.TrimSpace(in.RoutingKey) == "" {
		return errors.New("PagerDuty (RCA): routing key is required when enabled")
	}
	cfg.PagerDuty = in
	s.cfgs[tenant] = cfg
	if err := s.persist(); err != nil {
		return err
	}
	return nil
}

// public returns one tenant's redacted config for the admin UI — secrets become
// has_* flags; configured reflects whether that tenant's live connector is up.
func (s *itsmConfigStore) public(tenant string) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenant = itsmKey(tenant)
	cfg := s.cfgs[tenant]
	live := s.live[tenant]
	snLive := live != nil && live.sn != nil
	jrLive := live != nil && live.jira != nil
	sn := cfg.ServiceNow
	jr := cfg.Jira
	return map[string]any{
		"tenant": tenant,
		"servicenow": map[string]any{
			"enabled":          sn.Enabled,
			"instance_url":     sn.InstanceURL,
			"user":             sn.User,
			"has_password":     sn.Password != "",
			"min_severity":     sn.MinSeverity,
			"assignment_group": sn.AssignmentGroup,
			"configured":       snLive,
		},
		"pagerduty": map[string]any{
			"enabled":         cfg.PagerDuty.Enabled,
			"has_routing_key": cfg.PagerDuty.RoutingKey != "",
			"configured":      cfg.PagerDuty.Enabled && cfg.PagerDuty.RoutingKey != "",
		},
		"jira": map[string]any{
			"enabled":            jr.Enabled,
			"base_url":           jr.BaseURL,
			"email":              jr.Email,
			"has_token":          jr.APIToken != "",
			"project_key":        jr.ProjectKey,
			"issue_type":         jr.IssueType,
			"min_severity":       jr.MinSeverity,
			"resolve_transition": jr.ResolveTransition,
			"configured":         jrLive,
		},
	}
}

func normalizeServiceNow(c serviceNowConfig) serviceNowConfig {
	c.InstanceURL = strings.TrimRight(strings.TrimSpace(c.InstanceURL), "/")
	c.User = strings.TrimSpace(c.User)
	c.AssignmentGroup = strings.TrimSpace(c.AssignmentGroup)
	c.MinSeverity = strings.ToLower(strings.TrimSpace(c.MinSeverity))
	if c.MinSeverity == "" {
		c.MinSeverity = "critical"
	}
	return c
}

func normalizeJira(c jiraConfig) jiraConfig {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.Email = strings.TrimSpace(c.Email)
	c.ProjectKey = strings.ToUpper(strings.TrimSpace(c.ProjectKey))
	c.IssueType = strings.TrimSpace(c.IssueType)
	c.ResolveTransition = strings.TrimSpace(c.ResolveTransition)
	c.MinSeverity = strings.ToLower(strings.TrimSpace(c.MinSeverity))
	if c.MinSeverity == "" {
		c.MinSeverity = "critical"
	}
	return c
}

// validateITSM rejects an enabled connector missing its required identity so the
// UI can't persist a config that would silently never ticket.
func validateITSM(c itsmConfig) error {
	if c.ServiceNow.Enabled {
		if c.ServiceNow.InstanceURL == "" {
			return errors.New("ServiceNow: instance URL is required when enabled")
		}
		if !strings.HasPrefix(c.ServiceNow.InstanceURL, "http://") && !strings.HasPrefix(c.ServiceNow.InstanceURL, "https://") {
			return errors.New("ServiceNow: instance URL must start with http:// or https://")
		}
		if err := validateOutboundURL(c.ServiceNow.InstanceURL); err != nil {
			return fmt.Errorf("ServiceNow: %w", err)
		}
	}
	if c.PagerDuty.Enabled && strings.TrimSpace(c.PagerDuty.RoutingKey) == "" {
		return errors.New("PagerDuty (RCA): routing key is required when enabled")
	}
	if c.Jira.Enabled {
		if c.Jira.BaseURL == "" {
			return errors.New("Jira: base URL is required when enabled")
		}
		if c.Jira.ProjectKey == "" {
			return errors.New("Jira: project key is required when enabled")
		}
		if !strings.HasPrefix(c.Jira.BaseURL, "http://") && !strings.HasPrefix(c.Jira.BaseURL, "https://") {
			return errors.New("Jira: base URL must start with http:// or https://")
		}
		if err := validateOutboundURL(c.Jira.BaseURL); err != nil {
			return fmt.Errorf("Jira: %w", err)
		}
	}
	return nil
}

// validateOutboundURL rejects an integration target that the SSRF guard
// (safehttp) would refuse at request time (SR-015), giving the admin an
// immediate error at save rather than a silent never-tickets later. Internal
// targets (self-hosted ServiceNow/Jira, lab) are accommodated via
// SSRF_ALLOWED_HOSTS / SSRF_ALLOW_PRIVATE — see the safehttp package.
func validateOutboundURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	return safehttp.ValidateURL(u.Hostname())
}

// handleITSMPagerDutyRCA serves PUT /api/itsm/pagerduty-rca — the explicit
// mutation path for a tenant's PagerDuty RCA-paging destination (#103).
// Tenant-scoped exactly like handleITSMConfig; routing key is write-only.
func (s *server) handleITSMPagerDutyRCA(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	key := itsmKey(tenant)
	if cross {
		if q := strings.TrimSpace(r.URL.Query().Get("tenant")); q != "" {
			key = itsmKey(q)
		}
	}
	if s.itsmCfg == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("ITSM config store unavailable"))
		return
	}
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, errors.New("PUT only"))
		return
	}
	var in pagerDutyRCAConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.itsmCfg.setPagerDutyRCA(key, in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	logInfo("itsm", "pagerduty RCA destination updated", map[string]any{"tenant": key, "enabled": in.Enabled, "actor": claims.Sub})
	writeJSON(w, http.StatusOK, s.itsmCfg.public(key))
}

// handleITSMConfig serves GET/PUT /api/notify/itsm, scoped to the caller's tenant.
// A tenant admin manages only its own connector; the platform owner manages the
// global connector and (via ?tenant=) any specific tenant's.
func (s *server) handleITSMConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	key := itsmKey(tenant)
	if cross {
		if q := strings.TrimSpace(r.URL.Query().Get("tenant")); q != "" {
			key = itsmKey(q)
		}
	}
	if s.itsmCfg == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("ITSM config store unavailable"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.itsmCfg.public(key))
	case http.MethodPut:
		var in itsmConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.itsmCfg.set(key, in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("itsm", "ITSM config updated", map[string]any{"actor": claims.Sub, "tenant": key})
		writeJSON(w, http.StatusOK, s.itsmCfg.public(key))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
