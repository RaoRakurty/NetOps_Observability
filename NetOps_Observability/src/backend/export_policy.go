package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/platformdb"
	"os"
	"strconv"
	"sync"
	"time"
)

// export_policy.go — runtime-configurable Log Export limits (the hardening knobs),
// tunable live from the admin UI with NO restart. Env-seeded defaults; apply()
// pushes each value into the process env so all the existing env readers in the
// export paths (envInt/envDuration) pick them up — the store is the single source
// of truth with zero changes to the read sites.
//
// SECURITY: only the PLATFORM OWNER may change these. A tenant must never raise its
// own export caps, or the anti-exfiltration limits are meaningless.

type exportPolicyConfig struct {
	RatePerMin     int `json:"rate_per_min"`        // EXPORT_RATE_PER_MIN (per tenant)
	MaxRows        int `json:"max_rows"`            // MAX_EXPORT_ROWS
	MaxBytes       int `json:"max_bytes"`           // MAX_EXPORT_BYTES
	MaxRuntimeSec  int `json:"max_runtime_seconds"` // MAX_EXPORT_RUNTIME
	MaxRangeHours  int `json:"max_range_hours"`     // MAX_EXPORT_TIME_RANGE
	LinkTTLSeconds int `json:"link_ttl_seconds"`    // EXPORT_LINK_TTL (clamped 5–15m at read)
	SyncMaxRows    int `json:"sync_max_rows"`       // EXPORT_SYNC_MAX_ROWS (sync→async threshold)
}

type exportPolicyStore struct {
	mu   sync.Mutex
	path string
}

func newExportPolicyStore(path string) *exportPolicyStore {
	s := &exportPolicyStore{path: path}
	if err := s.load(); err != nil {
		// Security-relevant: these are the anti-exfiltration caps. An unreadable
		// file silently REVERTS an operator-tightened limit to the (looser) env
		// default, so the failure must be loud rather than shaped like "nothing
		// was ever configured" (§10).
		logError("export.policy", "stored export limits unreadable — the LOOSER env defaults are in force; re-save the policy", errf(err))
	}
	return s
}

// load reads the stored limits. THREE states, never two (the
// cloud_monitor_eval.go shape): the store did not answer (error) / it answered
// with nothing (absent key or empty blob — env defaults are the policy) /
// loaded and applied.
func (s *exportPolicyStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = never customised; env defaults ARE the policy
	}
	if err != nil {
		return fmt.Errorf("read export policy: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = never customised
	}
	var c exportPolicyConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("decode export policy: %w", err)
	}
	s.apply(c)
	return nil
}

func setPositiveIntEnv(key string, v int) {
	if v > 0 {
		_ = os.Setenv(key, strconv.Itoa(v))
	}
}

func (s *exportPolicyStore) apply(c exportPolicyConfig) {
	setPositiveIntEnv("EXPORT_RATE_PER_MIN", c.RatePerMin)
	setPositiveIntEnv("MAX_EXPORT_ROWS", c.MaxRows)
	setPositiveIntEnv("MAX_EXPORT_BYTES", c.MaxBytes)
	setPositiveIntEnv("EXPORT_SYNC_MAX_ROWS", c.SyncMaxRows)
	if c.MaxRuntimeSec > 0 {
		_ = os.Setenv("MAX_EXPORT_RUNTIME", (time.Duration(c.MaxRuntimeSec) * time.Second).String())
	}
	if c.MaxRangeHours > 0 {
		_ = os.Setenv("MAX_EXPORT_TIME_RANGE", (time.Duration(c.MaxRangeHours) * time.Hour).String())
	}
	if c.LinkTTLSeconds > 0 {
		_ = os.Setenv("EXPORT_LINK_TTL", (time.Duration(c.LinkTTLSeconds) * time.Second).String())
	}
}

// effective returns the values actually in force (read through the same env +
// defaults the export paths use, so the UI shows the truth post-clamp).
func (s *exportPolicyStore) effective() exportPolicyConfig {
	return exportPolicyConfig{
		RatePerMin:     envInt("EXPORT_RATE_PER_MIN", 10),
		MaxRows:        envInt("MAX_EXPORT_ROWS", 500_000),
		MaxBytes:       envInt("MAX_EXPORT_BYTES", 256*1024*1024),
		MaxRuntimeSec:  int(envDuration("MAX_EXPORT_RUNTIME", 5*time.Minute).Seconds()),
		MaxRangeHours:  int(exportMaxTimeRange().Hours()),
		LinkTTLSeconds: int(exportLinkTTL().Seconds()),
		SyncMaxRows:    envInt("EXPORT_SYNC_MAX_ROWS", 5000),
	}
}

func (s *exportPolicyStore) set(c exportPolicyConfig) (exportPolicyConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apply(c)
	eff := s.effective()
	b, err := json.MarshalIndent(eff, "", "  ")
	if err != nil {
		return exportPolicyConfig{}, err
	}
	if err := platformdb.Save(s.path, b); err != nil {
		return exportPolicyConfig{}, err
	}
	return eff, nil
}

// handleExportPolicy: GET (admin) / PUT (platform owner) /api/exports/policy.
func (s *server) handleExportPolicy(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.exportPolicy.effective())
	case http.MethodPut:
		if !isPlatformOwner(claims) { // identity check — ignore any view-as-tenant override
			writeError(w, http.StatusForbidden, errors.New("only the platform owner may change export limits"))
			return
		}
		var c exportPolicyConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		eff, err := s.exportPolicy.set(c)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("export", "export policy updated", map[string]any{"rate_per_min": eff.RatePerMin, "max_rows": eff.MaxRows, "actor": claims.Sub})
		writeJSON(w, http.StatusOK, eff)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
