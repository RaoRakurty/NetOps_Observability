package main

// cloud_monitors.go — per-tenant cloud monitor authoring (Wave 5 #14 slice 3).
// A monitor is a tenant-owned rule on ONE cloud metric of the closed catalog
// (cloud_metrics_series.go): either a threshold (above/below a value) or an
// anomaly toggle (deviation from the metric's own recent behaviour). Evaluated
// by the bounded poll loop in cloud_monitor_eval.go against the SAME
// tenant-scoped resource_id selectors the chart endpoint uses.
//
//	GET    /api/cloud/monitors        — list (alerts:read)
//	POST   /api/cloud/monitors        — create (alerts:write, audited)
//	GET    /api/cloud/monitors/{id}   — read one (cross-tenant id → 404)
//	PUT    /api/cloud/monitors/{id}   — update (alerts:write, audited)
//	DELETE /api/cloud/monitors/{id}   — delete (alerts:write, audited)
//
// §3a: the store is tenant-keyed (file/kv pattern of tenant_governance.go);
// TenantID is stamped from the principal, never the body; every by-id access
// resolves inside the caller's tenant bucket only.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"netops/backend/internal/platformdb"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	cloudMonitorsMaxPerTenant = 50
	cloudMonitorNameMaxLen    = 80
)

// Monitor modes and conditions — closed vocabularies.
const (
	monitorModeThreshold = "threshold"
	monitorModeAnomaly   = "anomaly"
	monitorCondAbove     = "above"
	monitorCondBelow     = "below"
)

// Evaluation states (written by the evaluator; read-only over the API).
const (
	monitorStateNever    = "never_evaluated"
	monitorStateOK       = "ok"
	monitorStateFiring   = "firing"
	monitorStateNoData   = "no_data"
	monitorStateError    = "error"
	monitorStateDisabled = "disabled"
)

// cloudMonitor is one tenant-authored rule plus its last evaluation outcome.
type cloudMonitor struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Metric   string `json:"metric"` // closed catalog (cloudMetricInfo)
	// ResourceID scopes the monitor to one resource; "" = every cloud resource
	// in the tenant's inventory (bounded at evaluation time).
	ResourceID string  `json:"resource_id,omitempty"`
	Mode       string  `json:"mode"`                // threshold | anomaly
	Condition  string  `json:"condition,omitempty"` // above | below (threshold mode)
	Threshold  float64 `json:"threshold,omitempty"` // threshold mode
	Enabled    bool    `json:"enabled"`
	CreatedAt  string  `json:"created_at,omitempty"`
	UpdatedAt  string  `json:"updated_at,omitempty"`

	// Last evaluation — written by the evaluator, never by the API caller.
	LastState  string   `json:"last_state"`
	LastValue  *float64 `json:"last_value,omitempty"`
	LastReason string   `json:"last_reason,omitempty"`
	LastEvalAt string   `json:"last_eval_at,omitempty"`
}

// cloudMonitorStore is a file-backed per-tenant map (tenant_governance.go
// pattern): every accessor is keyed by tenant; no unscoped list exists on the
// API path. snapshot() exists ONLY for the in-process evaluator.
type cloudMonitorStore struct {
	mu       sync.RWMutex
	monitors map[string][]cloudMonitor
	path     string
	// loadErr: the stored file could not be READ, which is not "no tenant has
	// defined a monitor". Conflating them left every monitor silently
	// unevaluated and let the next write flush an empty map over the file (§10).
	loadErr error
}

func cloudMonitorsPath() string {
	if p := strings.TrimSpace(os.Getenv("CLOUD_MONITORS_PATH")); p != "" {
		return p
	}
	return "/data/cloud_monitors.json"
}

func newCloudMonitorStore(path string) *cloudMonitorStore {
	s := &cloudMonitorStore{monitors: map[string][]cloudMonitor{}, path: path}
	if err := s.load(); err != nil {
		s.loadErr = err
		logError("cloud.monitors", "stored monitors unreadable — NOTHING is being evaluated and writes are refused until it is repaired", errf(err))
	}
	return s
}

// load reads the stored per-tenant monitors. THREE states, never two (the
// cloud_monitor_eval.go shape, which this store feeds): the store did not
// answer / it answered with nothing / loaded.
func (s *cloudMonitorStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = no monitors defined yet
	}
	if err != nil {
		return fmt.Errorf("read cloud monitors: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = none defined yet
	}
	var m map[string][]cloudMonitor
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("decode cloud monitors: %w", err)
	}
	// §3: never trust cached data — re-stamp the tenant from the bucket key.
	for tenant, list := range m {
		for i := range list {
			list[i].TenantID = tenant
		}
		m[tenant] = list
	}
	s.monitors = m
	return nil
}

// F-62/F-63: returns error. A swallowed persist failure here made the
// handler above structurally unable to report that the write did not
// land — 200 with nothing saved. Callers roll back and answer 500.
func (s *cloudMonitorStore) saveLocked() error {
	// The in-memory map is not the stored state when the load failed: flushing it
	// would erase every other tenant's stored rows. Fail closed (F-62 shape).
	if s.loadErr != nil {
		return fmt.Errorf("refusing to overwrite the stored monitors: its stored contents were never read: %w", s.loadErr)
	}
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.monitors, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cloud monitors: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		logError("monitors", "persist cloud monitors failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist cloud monitors: %w", err)
	}
	return nil
}

// list returns the tenant's monitors (copy). Nil-safe.
func (s *cloudMonitorStore) list(tenant string) []cloudMonitor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]cloudMonitor(nil), s.monitors[tenant]...)
}

// get resolves an id INSIDE the tenant bucket only — a foreign tenant's id is
// indistinguishable from an absent one (handler maps to 404).
func (s *cloudMonitorStore) get(tenant, id string) (cloudMonitor, bool) {
	if s == nil {
		return cloudMonitor{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.monitors[tenant] {
		if m.ID == id {
			return m, true
		}
	}
	return cloudMonitor{}, false
}

// restoreLocked puts a tenant's bucket back after a failed persist so RAM and
// disk cannot disagree. The caller snapshots BEFORE mutating (append can share
// backing storage, so the snapshot is a copy). Caller holds s.mu.
func (s *cloudMonitorStore) restoreLocked(tenant string, prev []cloudMonitor) {
	if prev == nil {
		delete(s.monitors, tenant)
		return
	}
	s.monitors[tenant] = prev
}

// snapshotLocked copies a tenant's bucket for rollback. Caller holds s.mu.
func (s *cloudMonitorStore) snapshotLocked(tenant string) []cloudMonitor {
	list, ok := s.monitors[tenant]
	if !ok {
		return nil
	}
	return append([]cloudMonitor(nil), list...)
}

// upsert stamps the tenant FROM THE PRINCIPAL and persists. Returns false when
// creating would exceed the per-tenant cap, and an error when the write did not
// reach the store (F-62 class: never report success for an unpersisted write).
func (s *cloudMonitorStore) upsert(tenant string, m cloudMonitor) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.TenantID = tenant
	prev := s.snapshotLocked(tenant)
	list := s.monitors[tenant]
	for i := range list {
		if list[i].ID == m.ID {
			list[i] = m
			s.monitors[tenant] = list
			if err := s.saveLocked(); err != nil {
				s.restoreLocked(tenant, prev)
				return false, err
			}
			return true, nil
		}
	}
	if len(list) >= cloudMonitorsMaxPerTenant {
		return false, nil
	}
	s.monitors[tenant] = append(list, m)
	if err := s.saveLocked(); err != nil {
		s.restoreLocked(tenant, prev)
		return false, err
	}
	return true, nil
}

// delete removes an id inside the tenant bucket. Returns found, and an error
// when the deletion did not reach the store.
func (s *cloudMonitorStore) delete(tenant, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.snapshotLocked(tenant)
	list := s.monitors[tenant]
	for i := range list {
		if list[i].ID == id {
			s.monitors[tenant] = append(list[:i], list[i+1:]...)
			if err := s.saveLocked(); err != nil {
				s.restoreLocked(tenant, prev)
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// setStatus records an evaluation outcome (evaluator-only writer). The
// evaluator is a background loop with no caller to answer, so it returns the
// error for the loop to LOG — an unpersisted evaluation must not be silent
// (§10: no silent failures).
func (s *cloudMonitorStore) setStatus(tenant, id, state, reason string, value *float64, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.snapshotLocked(tenant)
	list := s.monitors[tenant]
	for i := range list {
		if list[i].ID == id {
			list[i].LastState = state
			list[i].LastReason = reason
			list[i].LastValue = value
			list[i].LastEvalAt = at.UTC().Format(time.RFC3339)
			s.monitors[tenant] = list
			if err := s.saveLocked(); err != nil {
				s.restoreLocked(tenant, prev)
				return err
			}
			return nil
		}
	}
	return nil
}

// snapshot copies the whole map for the in-process evaluator (NOT an API
// surface — the evaluator is the platform's own bounded loop and queries each
// tenant's monitors against that tenant's own resource scope).
func (s *cloudMonitorStore) snapshot() map[string][]cloudMonitor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]cloudMonitor, len(s.monitors))
	for tenant, list := range s.monitors {
		out[tenant] = append([]cloudMonitor(nil), list...)
	}
	return out
}

// normalizeCloudMonitor validates caller input (closed vocabularies, bounded
// strings, finite numbers). Returns the cleaned definition or an error.
func normalizeCloudMonitor(m cloudMonitor) (cloudMonitor, error) {
	out := cloudMonitor{}
	name := strings.TrimSpace(m.Name)
	if name == "" || len(name) > cloudMonitorNameMaxLen {
		return out, fmt.Errorf("name must be 1..%d characters", cloudMonitorNameMaxLen)
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return out, errors.New("name must not contain control characters")
		}
	}
	if _, ok := cloudMetricInfo(strings.TrimSpace(m.Metric)); !ok {
		return out, errors.New("metric must be one of the cloud metric catalog (e.g. cloud_cpu_util)")
	}
	rid := strings.TrimSpace(m.ResourceID)
	if rid != "" && !validCloudResourceID(rid) {
		return out, errors.New("invalid resource_id")
	}
	switch m.Mode {
	case monitorModeThreshold:
		if m.Condition != monitorCondAbove && m.Condition != monitorCondBelow {
			return out, errors.New("condition must be above or below")
		}
		if math.IsNaN(m.Threshold) || math.IsInf(m.Threshold, 0) {
			return out, errors.New("threshold must be a finite number")
		}
	case monitorModeAnomaly:
		// anomaly mode has no threshold/condition — refuse leftovers so a
		// caller cannot believe an ignored field is in force.
		if m.Condition != "" || m.Threshold != 0 {
			return out, errors.New("anomaly mode takes no condition/threshold")
		}
	default:
		return out, errors.New("mode must be threshold or anomaly")
	}
	out = cloudMonitor{
		Name: name, Metric: strings.TrimSpace(m.Metric), ResourceID: rid,
		Mode: m.Mode, Condition: m.Condition, Threshold: m.Threshold, Enabled: m.Enabled,
	}
	return out, nil
}

// auditMonitor records a monitor write with a bounded detail payload.
func (s *server) auditMonitor(r *http.Request, claims jwtClaims, action string, m cloudMonitor) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r),
		Detail: map[string]any{"action": action, "monitor_id": m.ID, "name": m.Name, "metric": m.Metric, "mode": m.Mode},
	})
}

// handleCloudMonitors serves GET/POST /api/cloud/monitors.
func (s *server) handleCloudMonitors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		list := s.cloudMonitors.list(tenant)
		if list == nil {
			list = []cloudMonitor{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"monitors": list, "count": len(list), "max_monitors": cloudMonitorsMaxPerTenant,
		})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		var body cloudMonitor
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		m, err := normalizeCloudMonitor(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		m.ID = randID()
		now := time.Now().UTC().Format(time.RFC3339)
		m.CreatedAt, m.UpdatedAt = now, now
		m.LastState = monitorStateNever
		tenant, _ := principalTenant(claims) // §3a rule 2: owner from the token
		fits, err := s.cloudMonitors.upsert(tenant, m)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("monitor was not saved"))
			return
		}
		if !fits {
			writeError(w, http.StatusBadRequest, fmt.Errorf("at most %d monitors per tenant", cloudMonitorsMaxPerTenant))
			return
		}
		m.TenantID = tenant
		s.auditMonitor(r, claims, "create_cloud_monitor", m)
		writeJSON(w, http.StatusCreated, m)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

// handleCloudMonitorByID serves GET/PUT/DELETE /api/cloud/monitors/{id}.
func (s *server) handleCloudMonitorByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/cloud/monitors/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusNotFound, errors.New("monitor not found"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		m, found := s.cloudMonitors.get(tenant, id)
		if !found {
			writeError(w, http.StatusNotFound, errors.New("monitor not found"))
			return
		}
		writeJSON(w, http.StatusOK, m)
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		existing, found := s.cloudMonitors.get(tenant, id)
		if !found {
			writeError(w, http.StatusNotFound, errors.New("monitor not found"))
			return
		}
		var body cloudMonitor
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		m, err := normalizeCloudMonitor(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Definition changed → the old verdict no longer describes this rule.
		m.ID = existing.ID
		m.CreatedAt = existing.CreatedAt
		m.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		m.LastState = monitorStateNever
		if _, err := s.cloudMonitors.upsert(tenant, m); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("monitor was not saved"))
			return
		}
		m.TenantID = tenant
		s.auditMonitor(r, claims, "update_cloud_monitor", m)
		writeJSON(w, http.StatusOK, m)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		m, found := s.cloudMonitors.get(tenant, id)
		if !found {
			writeError(w, http.StatusNotFound, errors.New("monitor not found"))
			return
		}
		if _, err := s.cloudMonitors.delete(tenant, id); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("monitor was not deleted"))
			return
		}
		s.auditMonitor(r, claims, "delete_cloud_monitor", m)
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}
