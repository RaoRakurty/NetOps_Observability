package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/internal/ticketing"
	"os"
	"regexp"
	"strings"
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
// The ITSM config domain moved to internal/ticketing/itsm_config.go (Phase-2
// W3.1). Aliases + the env seams keep main's handlers and notify wiring
// source-compatible.
type (
	itsmConfig         = ticketing.ITSMConfig
	serviceNowConfig   = ticketing.ServiceNowConfig
	jiraConfig         = ticketing.JiraConfig
	pagerDutyRCAConfig = ticketing.PagerDutyRCAConfig
	slackRCAConfig     = ticketing.SlackRCAConfig
	itsmConfigStore    = ticketing.ITSMConfigStore
)

func itsmKey(tenant string) string { return ticketing.ITSMKey(tenant) }

func newITSMConfigStore(_ *server, path string) *itsmConfigStore {
	return ticketing.NewITSMConfigStore(path, itsmConfigFromEnv, itsmStateFile,
		func() bool { return os.Getenv("FEATURE_LEGACY_ALERT_ITSM") == "true" })
}

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
	if err := s.itsmCfg.SetPagerDutyRCA(key, in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	logInfo("itsm", "pagerduty RCA destination updated", map[string]any{"tenant": key, "enabled": in.Enabled, "actor": claims.Sub})
	writeJSON(w, http.StatusOK, s.itsmCfg.Public(key))
}

// handleITSMSlackRCA serves PUT /api/itsm/slack-rca — the explicit mutation
// path for a tenant's Slack RCA destination (#103-E). Webhook is write-only.
func (s *server) handleITSMSlackRCA(w http.ResponseWriter, r *http.Request) {
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
	var in slackRCAConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.itsmCfg.SetSlackRCA(key, in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	logInfo("itsm", "slack RCA destination updated", map[string]any{"tenant": key, "enabled": in.Enabled, "actor": claims.Sub})
	writeJSON(w, http.StatusOK, s.itsmCfg.Public(key))
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
		writeJSON(w, http.StatusOK, s.itsmCfg.Public(key))
	case http.MethodPut:
		var in itsmConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.itsmCfg.Set(key, in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("itsm", "ITSM config updated", map[string]any{"actor": claims.Sub, "tenant": key})
		writeJSON(w, http.StatusOK, s.itsmCfg.Public(key))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
