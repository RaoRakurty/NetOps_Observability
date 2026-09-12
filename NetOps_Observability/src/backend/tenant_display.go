// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tenant_display.go — per-tenant DISPLAY preferences (first real Settings
// editor of Wave 4 #11, owner directive 2026-07-17).
//
// The Local/UTC time-display knob moves OFF the top bar into Settings and
// becomes a TENANT-scoped, persisted, audited preference: a tenant admin sets
// how every user of that tenant reads timestamps; storage stays UTC (the
// log-time standard) and only rendering changes. §3a: the record is keyed by
// the caller's principal tenant in the store itself — the tenant in a request
// body is ignored, and no unscoped listing exists.
//
//   GET /api/settings/display — any authenticated user (rendering needs it)
//   PUT /api/settings/display — administration:admin (tenant admin), audited

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/platformdb"
	"os"
	"strings"
	"sync"
)

// timeDisplayDefault is what an unconfigured tenant renders: operator-local
// time, matching the product's behavior before this setting existed.
const timeDisplayDefault = "local"

var errBadTimeDisplay = errors.New(`time_display must be "local" or "utc"`)

type tenantDisplayConfig struct {
	TenantID string `json:"tenant_id"`
	// TimeDisplay: "local" | "utc". "" means unset → timeDisplayDefault.
	TimeDisplay string `json:"time_display,omitempty"`
}

// tenantDisplayStore is a file-backed per-tenant map, keyed by tenant in the
// store itself (§3a for file/kv stores). Mirrors aiTenantConfigStore, minus
// the vault — nothing here is a secret.
type tenantDisplayStore struct {
	mu   sync.RWMutex
	cfgs map[string]tenantDisplayConfig
	path string
	// loadErr: the stored file could not be READ — not "no tenant customised its
	// display". Conflating them let one tenant's save erase every other
	// tenant's branding (§10).
	loadErr error
}

func newTenantDisplayStore(path string) *tenantDisplayStore {
	s := &tenantDisplayStore{cfgs: map[string]tenantDisplayConfig{}, path: path}
	if err := s.load(); err != nil {
		s.loadErr = err
		logError("tenant.display", "stored display config unreadable — every tenant reads as default and writes are refused until it is repaired", errf(err))
	}
	return s
}

// tenantDisplayPath resolves the store's kv key (env-overridable like every
// other file-backed store; blank env keeps the default).
func tenantDisplayPath() string {
	if p := strings.TrimSpace(os.Getenv("TENANT_DISPLAY_PATH")); p != "" {
		return p
	}
	return "/data/tenant_display.json"
}

// load reads the stored per-tenant display config. THREE states, never two (the
// cloud_monitor_eval.go shape): the store did not answer (error) / it answered
// with nothing (absent key or empty blob) / loaded.
func (s *tenantDisplayStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = nothing customised yet
	}
	if err != nil {
		return fmt.Errorf("read tenant display config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = nothing customised yet
	}
	var m map[string]tenantDisplayConfig
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("decode tenant display config: %w", err)
	}
	for id, c := range m {
		c.TenantID = id
		m[id] = c
	}
	s.cfgs = m
	return nil
}

// saveLocked persists the map. Caller holds s.mu. Blank path = in-memory only.
// F-62/F-63: returns error. A swallowed persist failure here made the
// handler above structurally unable to report that the write did not
// land — 200 with nothing saved. Callers roll back and answer 500.
func (s *tenantDisplayStore) saveLocked() error {
	// The in-memory map is not the stored state when the load failed: flushing it
	// would erase every other tenant's stored rows. Fail closed (F-62 shape).
	if s.loadErr != nil {
		return fmt.Errorf("refusing to overwrite the stored display config: its stored contents were never read: %w", s.loadErr)
	}
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.cfgs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode tenant display prefs: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		logError("settings", "persist tenant display prefs failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist tenant display prefs: %w", err)
	}
	return nil
}

// get returns the tenant's record; unconfigured tenants get the default.
// Nil-safe: a server built without the store behaves as "all defaults".
func (s *tenantDisplayStore) get(tenant string) tenantDisplayConfig {
	if s == nil {
		return tenantDisplayConfig{TenantID: tenant, TimeDisplay: timeDisplayDefault}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	if c.TimeDisplay == "" {
		c.TimeDisplay = timeDisplayDefault
	}
	return c
}

// setTimeDisplay stamps the tenant FROM THE PRINCIPAL (callers pass the
// principalTenant result, never body input) and persists.
func (s *tenantDisplayStore) setTimeDisplay(tenant, mode string) (tenantDisplayConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.cfgs[tenant]
	c := prev
	c.TenantID = tenant
	c.TimeDisplay = mode
	s.cfgs[tenant] = c
	if err := s.saveLocked(); err != nil {
		if had {
			s.cfgs[tenant] = prev
		} else {
			delete(s.cfgs, tenant)
		}
		return prev, err
	}
	return c, nil
}

// normalizeTimeDisplay validates the caller's value — anything off the closed
// enum fails the request, never silently defaults.
func normalizeTimeDisplay(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "local":
		return "local", nil
	case "utc":
		return "utc", nil
	}
	return "", errBadTimeDisplay
}

// handleDisplaySettings serves GET/PUT /api/settings/display.
func (s *server) handleDisplaySettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := userFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		tenant, _ := principalTenant(claims)
		writeJSON(w, http.StatusOK, s.displayPrefs.get(tenant))
	case http.MethodPut:
		// Tenant-scoped config → scope-aware admin gate (§3a rule 3): a tenant
		// admin sets its OWN tenant's preference; the platform owner (cross)
		// sets the global tenant's — never another tenant's by id.
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var body struct {
			TimeDisplay string `json:"time_display"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		mode, err := normalizeTimeDisplay(body.TimeDisplay)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		cfg, err := s.displayPrefs.setTimeDisplay(tenant, mode)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("display preference was not saved"))
			return
		}
		if s.audit != nil {
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
				Remote: auditClientIP(r),
				Detail: map[string]any{"action": "set_time_display", "time_display": mode},
			})
		}
		writeJSON(w, http.StatusOK, cfg)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}
