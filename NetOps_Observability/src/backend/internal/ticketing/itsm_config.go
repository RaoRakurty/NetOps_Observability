// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// itsm_config.go — the per-tenant ITSM connector configuration domain
// (Phase-2 W3.1, extracted from package main): the four connector configs
// (ServiceNow / Jira / PagerDuty-RCA / Slack-RCA / Teams-RCA), the kv-persisted store with
// legacy-format migration and write-only secret merge, SSRF pre-validation,
// and the SystemConfig mapping the RCA worker resolves against. Env seeding
// and the ticket-state paths are INJECTED (env reads stay in main); the srv
// back-pointer the old store carried was never read and is gone.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
	"netops/backend/notify"
	"netops/backend/safehttp"
)

// orDefaultStr returns s unless blank, else def (duplicated at the boundary).
func orDefaultStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

type ServiceNowConfig struct {
	Enabled         bool   `json:"enabled"`
	InstanceURL     string `json:"instance_url"`
	User            string `json:"user"`
	Password        string `json:"password,omitempty"`
	MinSeverity     string `json:"min_severity"`
	AssignmentGroup string `json:"assignment_group"`
}

// PagerDutyRCAConfig is the per-tenant PagerDuty destination for RCA
// auto-ticketing (#103) — the CUSTOMER paging lane. RoutingKey is the tenant's
// own Events API v2 integration key (write-only). Distinct from the
// platform-global notify channel, which serves platform self-health only.
type PagerDutyRCAConfig struct {
	Enabled    bool   `json:"enabled"`
	RoutingKey string `json:"routing_key,omitempty"`
	// WatchAlerts opts this lane into the tenant's OWN watch alerts (its
	// BGP-watch prefix classes and cloud monitors; tracker 359). nil = never
	// chosen = OFF for PagerDuty: a page wakes someone, so it is opt-in.
	WatchAlerts *bool `json:"watch_alerts,omitempty"`
}

// WatchAlertsOn is the effective choice: PagerDuty is OFF unless the tenant
// turned it on.
func (c PagerDutyRCAConfig) WatchAlertsOn() bool { return c.WatchAlerts != nil && *c.WatchAlerts }

// SlackRCAConfig is the per-tenant Slack destination for RCA auto-ticketing
// (#103-E): the tenant's OWN incoming-webhook URL (a bearer secret —
// write-only). Distinct from the platform-global Slack notification channel.
type SlackRCAConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url,omitempty"`
	// WatchAlerts opts this lane into the tenant's own watch alerts. nil =
	// never chosen = ON for Slack: a channel message wakes nobody, and a tenant
	// that set up a watch and a Slack lane expects to hear about it there.
	WatchAlerts *bool `json:"watch_alerts,omitempty"`
}

// WatchAlertsOn is the effective choice: Slack is ON unless the tenant turned
// it off.
func (c SlackRCAConfig) WatchAlertsOn() bool { return c.WatchAlerts == nil || *c.WatchAlerts }

// TeamsRCAConfig is the per-tenant Microsoft Teams destination for problems:
// the tenant's OWN Teams webhook (a Workflows "When a Teams webhook request is
// received" URL or a classic Incoming Webhook — both carry a bearer secret, so
// write-only). Distinct from the platform-global Teams notification channel.
type TeamsRCAConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url,omitempty"`
	// WatchAlerts opts this lane into the tenant's own watch alerts. nil =
	// never chosen = ON, as for Slack: a channel message wakes nobody.
	WatchAlerts *bool `json:"watch_alerts,omitempty"`
}

// WatchAlertsOn is the effective choice: Teams is ON unless the tenant turned
// it off.
func (c TeamsRCAConfig) WatchAlertsOn() bool { return c.WatchAlerts == nil || *c.WatchAlerts }

type JiraConfig struct {
	Enabled           bool   `json:"enabled"`
	BaseURL           string `json:"base_url"`
	Email             string `json:"email"`
	APIToken          string `json:"api_token,omitempty"`
	ProjectKey        string `json:"project_key"`
	IssueType         string `json:"issue_type"`
	MinSeverity       string `json:"min_severity"`
	ResolveTransition string `json:"resolve_transition"`
}

// ITSMConfig is ONE tenant's ITSM connector settings.
type ITSMConfig struct {
	ServiceNow ServiceNowConfig   `json:"servicenow"`
	Jira       JiraConfig         `json:"jira"`
	PagerDuty  PagerDutyRCAConfig `json:"pagerduty"`
	Slack      SlackRCAConfig     `json:"slack"`
	Teams      TeamsRCAConfig     `json:"teams"`
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
	Tenants map[string]ITSMConfig `json:"tenants"`
}

type ITSMConfigStore struct {
	// envDefault seeds/falls back to the env-derived platform config;
	// stateFileFor resolves the per-(system, tenant) ticket-state path.
	// Both injected — env reads stay in main.
	envDefault   func() ITSMConfig
	stateFileFor func(system, tenant string) string
	// legacyAlertITSM gates the DEPRECATED broadcast-alert lane (emergency
	// escape hatch; dormant when nil/false). Injected — env reads stay in main.
	legacyAlertITSM func() bool
	// custody seals the write-only secrets at rest (itsm_custody.go).
	// Injected — the vault lives in main. Zero value = plaintext.
	custody SecretCustody
	// sealedUnreadable is set when a sealed (v3) store could not be opened;
	// persist then refuses, so a save never overwrites credentials it never read.
	sealedUnreadable error

	mu   sync.RWMutex
	path string
	cfgs map[string]ITSMConfig // tenant key ("" = global) -> config, INCLUDING secrets
	live map[string]*itsmLive  // tenant key -> built connectors
}

// NewITSMConfigStoreForTest builds a store seeded with cfgs and no
// persistence — tests only (the *ForTest idiom instead of field pokes).
func NewITSMConfigStoreForTest(cfgs map[string]ITSMConfig) *ITSMConfigStore {
	return &ITSMConfigStore{cfgs: cfgs, live: map[string]*itsmLive{}}
}

// SetConfigForTest stores a tenant's config directly (no validation, no
// persistence, no live rebuild) — tests only.
func (s *ITSMConfigStore) SetConfigForTest(tenant string, cfg ITSMConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfgs[ITSMKey(tenant)] = cfg
}

// ConfigFor returns tenant's stored config (keyed by ITSMKey), for read-side
// consumers that project it (e.g. the RCA notify lanes).
func (s *ITSMConfigStore) ConfigFor(tenant string) (ITSMConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.cfgs[ITSMKey(tenant)]
	return cfg, ok
}

// ITSMKey normalizes a tenant id to the store/connector key. The global/platform
// tenant ("" or "global") collapses to "" so an incident tagged TenantID="" and
// the platform owner's config resolve to the same connector.

func ITSMKey(tenant string) string {
	t := strings.ToLower(strings.TrimSpace(tenant))
	if t == "global" {
		return ""
	}
	return t
}

// NewITSMConfigStore loads the persisted per-tenant config (or seeds the global
// connector from env on first run), then builds the live connectors per tenant.
//
// custody seals the connector secrets at rest; a plaintext store found while
// custody is active is rewritten sealed here, once (tracker 456).
func NewITSMConfigStore(path string, envDefault func() ITSMConfig, stateFileFor func(system, tenant string) string, legacyAlertITSM func() bool, custody SecretCustody) *ITSMConfigStore {
	s := &ITSMConfigStore{path: path, envDefault: envDefault, stateFileFor: stateFileFor, legacyAlertITSM: legacyAlertITSM, custody: custody, cfgs: map[string]ITSMConfig{}, live: map[string]*itsmLive{}}
	loaded, plaintext := s.load()
	if !loaded {
		// First run: the pre-per-tenant single connector was platform-wide → seed
		// it under the global "" key.
		s.cfgs[""] = s.envDefault()
	} else if plaintext && s.custody.active() {
		// One-time migration: the store predates at-rest sealing (or custody
		// was switched on since). Rewrite it sealed now rather than on the
		// next save, so no plaintext secret outlives this boot.
		if err := s.persist(); err != nil {
			applog.Error("itsm", "stored ITSM config is still PLAINTEXT — sealing it failed; it is retried on the next save", map[string]any{"err": err.Error()})
		} else {
			applog.Info("itsm", "stored ITSM config sealed at rest (migrated from plaintext)", map[string]any{"tenants": len(s.cfgs)})
		}
	}
	for tenant, cfg := range s.cfgs {
		s.apply(tenant, cfg)
	}
	return s
}

// load reads the persisted config. loaded is false when absent/empty (or
// unreadable) so the caller seeds from env; plaintext reports a store whose
// secrets were read in the clear (v2 or the legacy format), which the caller
// seals when custody is active. Migrates the legacy single-object format under
// the "" key.
func (s *ITSMConfigStore) load() (loaded, plaintext bool) {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, false // absent = never configured; the env seed applies
	}
	if err != nil {
		// The store did not ANSWER — a different fact from "never configured"
		// (§10: an unreadable config must not silently read as a fresh install).
		// Fall back to the env defaults for liveness, but say so loudly: a
		// later Set() persists the whole map and would overwrite the stored
		// contents that were never read.
		applog.Error("itsm", "stored ITSM config unreadable — falling back to env defaults; a save will OVERWRITE the stored config", map[string]any{"err": err.Error()})
		return false, false
	}
	if len(b) == 0 {
		return false, false // present but empty = never configured
	}
	// New per-tenant format (versioned envelope).
	var f itsmConfigFile
	if json.Unmarshal(b, &f) == nil && f.Version >= itsmFileVersionPlain && f.Tenants != nil {
		cfgs := make(map[string]ITSMConfig, len(f.Tenants))
		for k, v := range f.Tenants {
			cfgs[ITSMKey(k)] = v
		}
		if f.Version < itsmFileVersionSealed {
			s.cfgs = cfgs
			return true, true
		}
		opened, err := s.custody.openAll(cfgs)
		if err != nil {
			// Sealed credentials we cannot open. Run on the env defaults for
			// liveness, but REFUSE every save (persist): overwriting would
			// destroy credentials that still open once custody is restored.
			s.sealedUnreadable = err
			applog.Error("itsm", "stored ITSM config is sealed and could not be opened — running on env defaults and refusing saves until custody is restored", map[string]any{"err": err.Error()})
			return false, false
		}
		s.cfgs = opened
		return true, false
	}
	// Legacy single global connector → migrate under "".
	var c ITSMConfig
	if json.Unmarshal(b, &c) != nil {
		return false, false
	}
	s.cfgs = map[string]ITSMConfig{"": c}
	return true, true
}

// itsmConfigFromEnv seeds the GLOBAL connector from the legacy env vars so an
// existing env-configured deployment keeps working unchanged after upgrade.
func (s *ITSMConfigStore) Set(tenant string, in ITSMConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	tenant = ITSMKey(tenant)

	in.ServiceNow = NormalizeServiceNow(in.ServiceNow)
	in.Jira = NormalizeJira(in.Jira)

	// Write-only secrets: a blank secret on update KEEPS the stored one (so the UI
	// can mask it and never re-send it).
	prev := s.cfgs[tenant]
	if in.ServiceNow.Password == "" {
		in.ServiceNow.Password = prev.ServiceNow.Password
	}
	if in.Jira.APIToken == "" {
		in.Jira.APIToken = prev.Jira.APIToken
	}
	if in.PagerDuty == (PagerDutyRCAConfig{}) {
		// The combined ITSM PUT predates the PD lane — an omitted pagerduty
		// block must never silently disable RCA paging. The dedicated
		// /api/itsm/pagerduty-rca endpoint is the explicit mutation path.
		in.PagerDuty = prev.PagerDuty
	} else {
		if in.PagerDuty.RoutingKey == "" {
			in.PagerDuty.RoutingKey = prev.PagerDuty.RoutingKey
		}
		if in.PagerDuty.WatchAlerts == nil {
			in.PagerDuty.WatchAlerts = prev.PagerDuty.WatchAlerts
		}
	}
	if in.Slack == (SlackRCAConfig{}) {
		in.Slack = prev.Slack
	} else {
		if in.Slack.WebhookURL == "" {
			in.Slack.WebhookURL = prev.Slack.WebhookURL
		}
		if in.Slack.WatchAlerts == nil {
			in.Slack.WatchAlerts = prev.Slack.WatchAlerts
		}
	}

	if in.Teams == (TeamsRCAConfig{}) {
		in.Teams = prev.Teams
	} else {
		if in.Teams.WebhookURL == "" {
			in.Teams.WebhookURL = prev.Teams.WebhookURL
		}
		if in.Teams.WatchAlerts == nil {
			in.Teams.WatchAlerts = prev.Teams.WatchAlerts
		}
	}

	if err := ValidateITSM(in); err != nil {
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
//
// The secrets are sealed under each tenant's DEK while custody is active
// (itsm_custody.go); the in-memory map stays plaintext for the connectors.
func (s *ITSMConfigStore) persist() error {
	if err := s.writable(); err != nil {
		return err
	}
	f, err := s.custody.sealAll(s.cfgs)
	if err != nil {
		return err
	}
	b, err := json.Marshal(f) // #nosec G117 -- ITSM creds are persisted sealed when custody is active (tracker 456); plaintext only with custody dormant
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *ITSMConfigStore) apply(tenant string, cfg ITSMConfig) {
	tenant = ITSMKey(tenant)
	live := &itsmLive{}
	// #103 lane rule: the LEGACY raw-incident→ITSM projection (severity-gated,
	// fingerprint-dedup, one ticket per Incident record) violates "customer
	// destinations receive only policy-qualified root-cause incidents" and
	// double-filed against the RCA lane into the same instance. DEPRECATED:
	// dormant unless explicitly re-enabled (emergency escape hatch only).
	// The config store itself stays — the RCA ticketing lane reads it.
	if s.legacyAlertITSM == nil || !s.legacyAlertITSM() {
		s.live[tenant] = live // no live connectors: legacy lane fully dormant
		return
	}
	if cfg.ServiceNow.Enabled && cfg.ServiceNow.InstanceURL != "" {
		live.sn = notify.NewServiceNow(cfg.ServiceNow.InstanceURL, cfg.ServiceNow.User, cfg.ServiceNow.Password).
			WithThreshold(cfg.ServiceNow.MinSeverity).
			WithStateFile(s.stateFileFor("servicenow", tenant)).
			WithAssignmentGroup(cfg.ServiceNow.AssignmentGroup)
	}
	if cfg.Jira.Enabled && cfg.Jira.BaseURL != "" && cfg.Jira.ProjectKey != "" {
		live.jira = notify.NewJira(cfg.Jira.BaseURL, cfg.Jira.Email, cfg.Jira.APIToken, cfg.Jira.ProjectKey).
			WithIssueType(cfg.Jira.IssueType).
			WithThreshold(cfg.Jira.MinSeverity).
			WithResolveTransition(cfg.Jira.ResolveTransition).
			WithStateFile(s.stateFileFor("jira", tenant))
	}
	s.live[tenant] = live
}

// serviceNowFor / jiraFor resolve a tenant's live connector (nil if none).
func (s *ITSMConfigStore) ServiceNowFor(tenant string) *notify.ServiceNow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l := s.live[ITSMKey(tenant)]; l != nil {
		return l.sn
	}
	return nil
}

func (s *ITSMConfigStore) JiraFor(tenant string) *notify.Jira {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l := s.live[ITSMKey(tenant)]; l != nil {
		return l.jira
	}
	return nil
}

// systemConfig resolves one tenant's external-ticketing connection for the
// RCA auto-ticketing worker (#78). It returns the tenant's OWN ServiceNow config
// (incl. write-only secrets, used only to dispatch) or ok=false when that tenant
// has no enabled, configured connection — a transient hold, not a failure. Only
// ServiceNow is wired today; other systems return ok=false.
func (s *ITSMConfigStore) SystemConfigFor(tenant, system string) (SystemConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.cfgs[ITSMKey(tenant)]
	if !ok {
		return SystemConfig{}, false
	}
	switch orDefaultStr(system, "servicenow") {
	case "servicenow":
		sn := cfg.ServiceNow
		if !sn.Enabled || sn.InstanceURL == "" {
			return SystemConfig{}, false
		}
		return SystemConfig{
			System:          "servicenow",
			TenantID:        tenant,
			InstanceURL:     sn.InstanceURL,
			AuthType:        "basic",
			User:            sn.User,
			Password:        sn.Password,
			AssignmentGroup: sn.AssignmentGroup,
		}, true
	case "slack":
		sl := cfg.Slack
		if !sl.Enabled || sl.WebhookURL == "" {
			return SystemConfig{}, false
		}
		// InstanceURL is the NON-SECRET origin only — it is persisted onto
		// ticket links and surfaced by the UI; the webhook URL (the secret)
		// travels solely in the write-only APIToken field.
		return SystemConfig{
			System:      "slack",
			TenantID:    tenant,
			InstanceURL: SlackHooksOrigin,
			AuthType:    "webhook",
			APIToken:    sl.WebhookURL,
		}, true
	case "teams":
		tm := cfg.Teams
		if !tm.Enabled || tm.WebhookURL == "" {
			return SystemConfig{}, false
		}
		// As for Slack: InstanceURL is a fixed, non-secret label persisted on
		// ticket links; the webhook (the secret) rides only in APIToken.
		return SystemConfig{
			System:      "teams",
			TenantID:    tenant,
			InstanceURL: TeamsOrigin,
			AuthType:    "webhook",
			APIToken:    tm.WebhookURL,
		}, true
	case "pagerduty":
		pd := cfg.PagerDuty
		if !pd.Enabled || pd.RoutingKey == "" {
			return SystemConfig{}, false
		}
		// InstanceURL doubles as the Events API base so tests can inject a
		// fake server; the worker's "connected" check requires it non-empty.
		return SystemConfig{
			System:      "pagerduty",
			TenantID:    tenant,
			InstanceURL: PagerDutyEventsBase,
			AuthType:    "routing_key",
			APIToken:    pd.RoutingKey,
		}, true
	case "jira":
		jr := cfg.Jira
		if !jr.Enabled || jr.BaseURL == "" || jr.ProjectKey == "" {
			return SystemConfig{}, false
		}
		return SystemConfig{
			System:            "jira",
			TenantID:          tenant,
			InstanceURL:       jr.BaseURL,
			AuthType:          "basic",
			User:              jr.Email,
			APIToken:          jr.APIToken,
			ProjectKey:        jr.ProjectKey,
			IssueType:         jr.IssueType,
			ResolveTransition: jr.ResolveTransition,
		}, true
	}
	return SystemConfig{}, false
}

// setPagerDutyRCA mutates ONLY the tenant's PagerDuty RCA-paging destination
// (#103). Blank routing key on update preserves the stored one (write-only);
// disable works explicitly here (the combined PUT cannot express it).
func (s *ITSMConfigStore) SetPagerDutyRCA(tenant string, in PagerDutyRCAConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	tenant = ITSMKey(tenant)
	cfg := s.cfgs[tenant]
	if in.RoutingKey == "" {
		in.RoutingKey = cfg.PagerDuty.RoutingKey
	}
	if in.WatchAlerts == nil { // omitted = keep the tenant's earlier choice
		in.WatchAlerts = cfg.PagerDuty.WatchAlerts
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

// setSlackRCA mirrors setPagerDutyRCA for the Slack RCA destination.
func (s *ITSMConfigStore) SetSlackRCA(tenant string, in SlackRCAConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	tenant = ITSMKey(tenant)
	cfg := s.cfgs[tenant]
	if in.WebhookURL == "" {
		in.WebhookURL = cfg.Slack.WebhookURL
	}
	if in.WatchAlerts == nil { // omitted = keep the tenant's earlier choice
		in.WatchAlerts = cfg.Slack.WatchAlerts
	}
	if in.Enabled {
		if strings.TrimSpace(in.WebhookURL) == "" {
			return errors.New("Slack (RCA): webhook URL is required when enabled")
		}
		if err := ValidateOutboundURL(in.WebhookURL); err != nil {
			return fmt.Errorf("Slack (RCA): %w", err)
		}
	}
	cfg.Slack = in
	s.cfgs[tenant] = cfg
	return s.persist()
}

// SetTeamsRCA mirrors SetSlackRCA for the Teams destination. A blank URL on
// update keeps the stored one (write-only); disable works explicitly here.
func (s *ITSMConfigStore) SetTeamsRCA(tenant string, in TeamsRCAConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	tenant = ITSMKey(tenant)
	cfg := s.cfgs[tenant]
	in.WebhookURL = strings.TrimSpace(in.WebhookURL)
	if in.WebhookURL == "" {
		in.WebhookURL = cfg.Teams.WebhookURL
	}
	if in.WatchAlerts == nil { // omitted = keep the tenant's earlier choice
		in.WatchAlerts = cfg.Teams.WatchAlerts
	}
	if in.Enabled {
		if err := validateTeamsRCA(in.WebhookURL); err != nil {
			return err
		}
	}
	cfg.Teams = in
	s.cfgs[tenant] = cfg
	return s.persist()
}

// validateTeamsRCA is the save-time check for a tenant Teams webhook: https
// shape, then the SSRF pre-check on its host (the dial-time guard in safehttp
// is the enforcement; this refuses an obviously internal URL up front).
func validateTeamsRCA(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("Teams (RCA): webhook URL is required when enabled")
	}
	if err := notify.ValidateTeamsWebhookURL(raw); err != nil {
		return errors.New("Teams (RCA): webhook URL must be an https URL")
	}
	if err := ValidateOutboundURL(raw); err != nil {
		return fmt.Errorf("Teams (RCA): %w", err)
	}
	return nil
}

// public returns one tenant's redacted config for the admin UI — secrets become
// has_* flags; configured reflects whether that tenant's live connector is up.
func (s *ITSMConfigStore) Public(tenant string) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenant = ITSMKey(tenant)
	cfg := s.cfgs[tenant]
	// "configured" = the connection is usable by its CURRENT consumer. The
	// legacy live connectors are flag-dormant (#103), so config-level truth
	// (enabled + identity present) is the honest signal — it is exactly what
	// the RCA ticketing lane resolves against.
	snLive := cfg.ServiceNow.Enabled && cfg.ServiceNow.InstanceURL != ""
	jrLive := cfg.Jira.Enabled && cfg.Jira.BaseURL != "" && cfg.Jira.ProjectKey != ""
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
			// The EFFECTIVE choice (default applied), so the UI never has to
			// know the per-lane default.
			"watch_alerts": cfg.PagerDuty.WatchAlertsOn(),
		},
		"slack": map[string]any{
			"enabled":      cfg.Slack.Enabled,
			"has_webhook":  cfg.Slack.WebhookURL != "",
			"configured":   cfg.Slack.Enabled && cfg.Slack.WebhookURL != "",
			"watch_alerts": cfg.Slack.WatchAlertsOn(),
		},
		"teams": map[string]any{
			"enabled":      cfg.Teams.Enabled,
			"has_webhook":  cfg.Teams.WebhookURL != "",
			"configured":   cfg.Teams.Enabled && cfg.Teams.WebhookURL != "",
			"watch_alerts": cfg.Teams.WatchAlertsOn(),
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

func NormalizeServiceNow(c ServiceNowConfig) ServiceNowConfig {
	c.InstanceURL = strings.TrimRight(strings.TrimSpace(c.InstanceURL), "/")
	c.User = strings.TrimSpace(c.User)
	c.AssignmentGroup = strings.TrimSpace(c.AssignmentGroup)
	c.MinSeverity = strings.ToLower(strings.TrimSpace(c.MinSeverity))
	if c.MinSeverity == "" {
		c.MinSeverity = "critical"
	}
	return c
}

func NormalizeJira(c JiraConfig) JiraConfig {
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

// ValidateITSM rejects an enabled connector missing its required identity so the
// UI can't persist a config that would silently never ticket.
func ValidateITSM(c ITSMConfig) error {
	if c.ServiceNow.Enabled {
		if c.ServiceNow.InstanceURL == "" {
			return errors.New("ServiceNow: instance URL is required when enabled")
		}
		if !strings.HasPrefix(c.ServiceNow.InstanceURL, "http://") && !strings.HasPrefix(c.ServiceNow.InstanceURL, "https://") {
			return errors.New("ServiceNow: instance URL must start with http:// or https://")
		}
		if err := ValidateOutboundURL(c.ServiceNow.InstanceURL); err != nil {
			return fmt.Errorf("ServiceNow: %w", err)
		}
	}
	if c.PagerDuty.Enabled && strings.TrimSpace(c.PagerDuty.RoutingKey) == "" {
		return errors.New("PagerDuty (RCA): routing key is required when enabled")
	}
	if c.Slack.Enabled {
		if strings.TrimSpace(c.Slack.WebhookURL) == "" {
			return errors.New("Slack (RCA): webhook URL is required when enabled")
		}
		if err := ValidateOutboundURL(c.Slack.WebhookURL); err != nil {
			return fmt.Errorf("Slack (RCA): %w", err)
		}
	}
	if c.Teams.Enabled {
		if err := validateTeamsRCA(c.Teams.WebhookURL); err != nil {
			return err
		}
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
		if err := ValidateOutboundURL(c.Jira.BaseURL); err != nil {
			return fmt.Errorf("Jira: %w", err)
		}
	}
	return nil
}

// ValidateOutboundURL rejects an integration target that the SSRF guard
// (safehttp) would refuse at request time (SR-015), giving the admin an
// immediate error at save rather than a silent never-tickets later. Internal
// targets (self-hosted ServiceNow/Jira, lab) are accommodated via
// SSRF_ALLOWED_HOSTS / SSRF_ALLOW_PRIVATE — see the safehttp package.
func ValidateOutboundURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	return safehttp.ValidateURL(u.Hostname())
}

// handleITSMPagerDutyRCA serves PUT /api/itsm/pagerduty-rca — the explicit
// mutation path for a tenant's PagerDuty RCA-paging destination (#103).
// Tenant-scoped exactly like handleITSMConfig; routing key is write-only.
