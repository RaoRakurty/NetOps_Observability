package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"netops/backend/notify"
)

// itsm_config.go — runtime-configurable, kv-persisted config for the ITSM
// connectors (ServiceNow + Jira), tunable live from the admin UI with NO restart.
//
// Before this, the connectors were built ONCE in newServer() straight from env
// (FEATURE_SERVICENOW_NOTIFICATIONS + SERVICENOW_*, FEATURE_JIRA_NOTIFICATIONS +
// JIRA_*), so the integrations showed greyed in the UI — an operator had to edit
// compose/.env and restart. This store seeds from those same env vars on first
// run (back-compat), then becomes the source of truth.
//
// On a successful set() the store rebuilds each live connector and:
//   - atomically swaps it into s.servicenow / s.jira (read lock-free by the
//     incident-projection worker and the ITSM status endpoints), and
//   - Replace()s / Remove()s it in the alert Dispatcher (the auto-ticketing path),
// so both ITSM consumers pick up the change immediately.
//
// SECURITY: only the PLATFORM OWNER may read/change ITSM config — the connectors
// are a single platform-wide integration, and the credentials are global.

// serviceNowConfig / jiraConfig are the persisted, kv-backed connector settings.
// Secrets (Password / APIToken) are write-only: persisted to the kv store but
// never returned by the public() view.
type serviceNowConfig struct {
	Enabled         bool   `json:"enabled"`
	InstanceURL     string `json:"instance_url"`
	User            string `json:"user"`
	Password        string `json:"password,omitempty"`
	MinSeverity     string `json:"min_severity"`
	AssignmentGroup string `json:"assignment_group"`
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

type itsmConfig struct {
	ServiceNow serviceNowConfig `json:"servicenow"`
	Jira       jiraConfig       `json:"jira"`
}

type itsmConfigStore struct {
	mu   sync.Mutex
	path string
	srv  *server
	cfg  itsmConfig // current config, INCLUDING secrets (never logged/returned)
}

// newITSMConfigStore loads persisted config (or seeds from env on first run),
// then applies it so the live connectors reflect the stored config at boot.
func newITSMConfigStore(srv *server, path string) *itsmConfigStore {
	s := &itsmConfigStore{path: path, srv: srv}
	if !s.load() {
		s.cfg = itsmConfigFromEnv()
	}
	s.apply(s.cfg)
	return s
}

// load reads the persisted config; returns false when absent/empty so the caller
// seeds from env instead.
func (s *itsmConfigStore) load() bool {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return false
	}
	var c itsmConfig
	if json.Unmarshal(b, &c) != nil {
		return false
	}
	s.cfg = c
	return true
}

// itsmConfigFromEnv seeds the store from the legacy env vars so an existing
// env-configured deployment keeps working unchanged after upgrade.
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

// set validates, merges (preserving blanked secrets), persists, then rebuilds and
// atomically swaps the live connectors.
func (s *itsmConfigStore) set(in itsmConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	in.ServiceNow = normalizeServiceNow(in.ServiceNow)
	in.Jira = normalizeJira(in.Jira)

	// Write-only secrets: a blank secret on update KEEPS the stored one (so the UI
	// never has to re-enter it), so the form can mask it.
	if in.ServiceNow.Password == "" {
		in.ServiceNow.Password = s.cfg.ServiceNow.Password
	}
	if in.Jira.APIToken == "" {
		in.Jira.APIToken = s.cfg.Jira.APIToken
	}

	if err := validateITSM(in); err != nil {
		return err
	}

	b, err := json.Marshal(in) // #nosec G117 -- ITSM creds are intentionally persisted to the kv store
	if err != nil {
		return err
	}
	if err := kvSave(s.path, b); err != nil {
		return err
	}
	s.cfg = in
	s.apply(in)
	return nil
}

// apply (re)builds each connector from cfg and swaps it into the live server +
// the alert dispatcher. Must hold s.mu (or be called from the constructor).
func (s *itsmConfigStore) apply(cfg itsmConfig) {
	if cfg.ServiceNow.Enabled && cfg.ServiceNow.InstanceURL != "" {
		sn := notify.NewServiceNow(cfg.ServiceNow.InstanceURL, cfg.ServiceNow.User, cfg.ServiceNow.Password).
			WithThreshold(cfg.ServiceNow.MinSeverity).
			WithStateFile(envOr("SERVICENOW_STATE_FILE", "/data/servicenow_tickets.json")).
			WithAssignmentGroup(cfg.ServiceNow.AssignmentGroup)
		s.srv.servicenow.Store(sn)
		s.srv.notifier.Replace(sn)
	} else {
		s.srv.servicenow.Store(nil)
		s.srv.notifier.Remove("servicenow")
	}

	if cfg.Jira.Enabled && cfg.Jira.BaseURL != "" && cfg.Jira.ProjectKey != "" {
		j := notify.NewJira(cfg.Jira.BaseURL, cfg.Jira.Email, cfg.Jira.APIToken, cfg.Jira.ProjectKey).
			WithIssueType(cfg.Jira.IssueType).
			WithThreshold(cfg.Jira.MinSeverity).
			WithResolveTransition(cfg.Jira.ResolveTransition).
			WithStateFile(envOr("JIRA_STATE_FILE", "/data/jira_tickets.json"))
		s.srv.jira.Store(j)
		s.srv.notifier.Replace(j)
	} else {
		s.srv.jira.Store(nil)
		s.srv.notifier.Remove("jira")
	}
}

// public returns the redacted config for the admin UI — secrets are replaced with
// a has_* flag, and a configured flag reflects whether the live connector is up.
func (s *itsmConfigStore) public() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn := s.cfg.ServiceNow
	jr := s.cfg.Jira
	return map[string]any{
		"servicenow": map[string]any{
			"enabled":          sn.Enabled,
			"instance_url":     sn.InstanceURL,
			"user":             sn.User,
			"has_password":     sn.Password != "",
			"min_severity":     sn.MinSeverity,
			"assignment_group": sn.AssignmentGroup,
			"configured":       s.srv.serviceNow() != nil,
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
			"configured":         s.srv.jiraConn() != nil,
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
	}
	return nil
}

// handleITSMConfig serves GET/PUT /api/notify/itsm — platform-owner only.
func (s *server) handleITSMConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if _, cross := principalTenant(claims); !cross {
		writeError(w, http.StatusForbidden, errors.New("only the platform owner may configure ITSM integrations"))
		return
	}
	if s.itsmCfg == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("ITSM config store unavailable"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.itsmCfg.public())
	case http.MethodPut:
		var in itsmConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.itsmCfg.set(in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("itsm", "ITSM config updated", map[string]any{"actor": claims.Sub})
		writeJSON(w, http.StatusOK, s.itsmCfg.public())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
