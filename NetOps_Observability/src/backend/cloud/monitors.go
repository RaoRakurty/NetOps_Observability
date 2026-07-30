package cloud

// monitors.go — the tenant-scoped cloud monitor store (Phase-2 W4.5,
// extracted from package main's cloud_monitors.go): the monitor model with
// its closed vocabularies, the tenant-keyed JSON store with rollback-on-
// persist-failure, and NormalizeMonitor's validation. The evaluator loop,
// transitions/notifications, audit and handlers stay in main.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// normTenantMon mirrors main's tenant normalization (duplicated).
func normTenantMon(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

const (
	MonitorsMaxPerTenant = 50
	MonitorNameMaxLen    = 80
)

// Monitor modes and conditions — closed vocabularies.
const (
	MonitorModeThreshold = "threshold"
	MonitorModeAnomaly   = "anomaly"
	MonitorCondAbove     = "above"
	MonitorCondBelow     = "below"
)

// Evaluation states (written by the evaluator; read-only over the API).
const (
	MonitorStateNever    = "never_evaluated"
	MonitorStateOK       = "ok"
	MonitorStateFiring   = "firing"
	MonitorStateNoData   = "no_data"
	MonitorStateError    = "error"
	MonitorStateDisabled = "disabled"
)

// Monitor is one tenant-authored rule plus its last evaluation outcome.
type Monitor struct {
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

// MonitorStore is a file-backed per-tenant map (tenant_governance.go
// pattern): every accessor is keyed by tenant; no unscoped list exists on the
// API path. snapshot() exists ONLY for the in-process evaluator.
type MonitorStore struct {
	mu       sync.RWMutex
	monitors map[string][]Monitor
	path     string
	// loadErr: the stored file could not be READ, which is not "no tenant has
	// defined a monitor". Conflating them left every monitor silently
	// unevaluated and let the next write flush an empty map over the file (§10).
	loadErr error
}

func NewMonitorStore(path string) *MonitorStore {
	s := &MonitorStore{monitors: map[string][]Monitor{}, path: path}
	if err := s.load(); err != nil {
		s.loadErr = err
		applog.Error("cloud.monitors", "stored monitors unreadable — NOTHING is being evaluated and writes are refused until it is repaired", map[string]any{"error": err.Error()})
	}
	return s
}

// load reads the stored per-tenant monitors. THREE states, never two (the
// cloud_monitor_eval.go shape, which this store feeds): the store did not
// answer / it answered with nothing / loaded.
func (s *MonitorStore) load() error {
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
	var m map[string][]Monitor
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
func (s *MonitorStore) saveLocked() error {
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
		applog.Error("monitors", "persist cloud monitors failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist cloud monitors: %w", err)
	}
	return nil
}

// list returns the tenant's monitors (copy). Nil-safe.
// SeedForTest stores one tenant's monitors and persists — tests only.
func (s *MonitorStore) SeedForTest(tenantID string, ms []Monitor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.monitors[normTenantMon(tenantID)] = ms
	return s.saveLocked()
}

func (s *MonitorStore) List(tenant string) []Monitor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Monitor(nil), s.monitors[tenant]...)
}

// get resolves an id INSIDE the tenant bucket only — a foreign tenant's id is
// indistinguishable from an absent one (handler maps to 404).
func (s *MonitorStore) Get(tenant, id string) (Monitor, bool) {
	if s == nil {
		return Monitor{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.monitors[tenant] {
		if m.ID == id {
			return m, true
		}
	}
	return Monitor{}, false
}

// restoreLocked puts a tenant's bucket back after a failed persist so RAM and
// disk cannot disagree. The caller snapshots BEFORE mutating (append can share
// backing storage, so the snapshot is a copy). Caller holds s.mu.
func (s *MonitorStore) restoreLocked(tenant string, prev []Monitor) {
	if prev == nil {
		delete(s.monitors, tenant)
		return
	}
	s.monitors[tenant] = prev
}

// snapshotLocked copies a tenant's bucket for rollback. Caller holds s.mu.
func (s *MonitorStore) snapshotLocked(tenant string) []Monitor {
	list, ok := s.monitors[tenant]
	if !ok {
		return nil
	}
	return append([]Monitor(nil), list...)
}

// upsert stamps the tenant FROM THE PRINCIPAL and persists. Returns false when
// creating would exceed the per-tenant cap, and an error when the write did not
// reach the store (F-62 class: never report success for an unpersisted write).
func (s *MonitorStore) Upsert(tenant string, m Monitor) (bool, error) {
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
	if len(list) >= MonitorsMaxPerTenant {
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
func (s *MonitorStore) Delete(tenant, id string) (bool, error) {
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
func (s *MonitorStore) SetStatus(tenant, id, state, reason string, value *float64, at time.Time) error {
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
func (s *MonitorStore) Snapshot() map[string][]Monitor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]Monitor, len(s.monitors))
	for tenant, list := range s.monitors {
		out[tenant] = append([]Monitor(nil), list...)
	}
	return out
}

// NormalizeMonitor validates caller input (closed vocabularies, bounded
// strings, finite numbers). Returns the cleaned definition or an error.
func NormalizeMonitor(m Monitor) (Monitor, error) {
	out := Monitor{}
	name := strings.TrimSpace(m.Name)
	if name == "" || len(name) > MonitorNameMaxLen {
		return out, fmt.Errorf("name must be 1..%d characters", MonitorNameMaxLen)
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return out, errors.New("name must not contain control characters")
		}
	}
	if _, ok := MetricInfo(strings.TrimSpace(m.Metric)); !ok {
		return out, errors.New("metric must be one of the cloud metric catalog (e.g. cloud_cpu_util)")
	}
	rid := strings.TrimSpace(m.ResourceID)
	if rid != "" && !ValidResourceID(rid) {
		return out, errors.New("invalid resource_id")
	}
	switch m.Mode {
	case MonitorModeThreshold:
		if m.Condition != MonitorCondAbove && m.Condition != MonitorCondBelow {
			return out, errors.New("condition must be above or below")
		}
		if math.IsNaN(m.Threshold) || math.IsInf(m.Threshold, 0) {
			return out, errors.New("threshold must be a finite number")
		}
	case MonitorModeAnomaly:
		// anomaly mode has no threshold/condition — refuse leftovers so a
		// caller cannot believe an ignored field is in force.
		if m.Condition != "" || m.Threshold != 0 {
			return out, errors.New("anomaly mode takes no condition/threshold")
		}
	default:
		return out, errors.New("mode must be threshold or anomaly")
	}
	out = Monitor{
		Name: name, Metric: strings.TrimSpace(m.Metric), ResourceID: rid,
		Mode: m.Mode, Condition: m.Condition, Threshold: m.Threshold, Enabled: m.Enabled,
	}
	return out, nil
}

// auditMonitor records a monitor write with a bounded detail payload.

const (
	// SeriesMinWindowMin / SeriesMaxWindowMin / SeriesDefaultWindow bound the
	// metric-series read window (one provider period … 7 days; 3h default).
	SeriesMinWindowMin  = 5
	SeriesMaxWindowMin  = 10080
	SeriesDefaultWindow = 180
	// SeriesMaxPoints caps chart density; SeriesMaxResourceIDLen bounds ARM ids.
	SeriesMaxPoints        = 400
	SeriesMaxResourceIDLen = 512
)

// ── the cloud metric registry (moved with the monitor validation it feeds) ──

type MetricMeta struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Unit  string `json:"unit"` // percent | bytes | count
}

// MetricCatalog returns the closed vocabulary in stable display order.
func MetricCatalog() []MetricMeta {
	return []MetricMeta{
		{Name: "cloud_cpu_util", Label: "CPU utilization", Unit: "percent"},
		{Name: "cloud_net_in_bytes", Label: "Network in", Unit: "bytes"},
		{Name: "cloud_net_out_bytes", Label: "Network out", Unit: "bytes"},
		{Name: "cloud_status_check_failed", Label: "Provider status check failed", Unit: "count"},
		{Name: "cloud_status_check_failed_system", Label: "Status check failed (provider side)", Unit: "count"},
		{Name: "cloud_status_check_failed_instance", Label: "Status check failed (instance side)", Unit: "count"},
		{Name: "cloud_cpu_credit_balance", Label: "CPU credit balance", Unit: "count"},
	}
}

// MetricInfo resolves a metric name against the closed catalog.
func MetricInfo(name string) (MetricMeta, bool) {
	for _, m := range MetricCatalog() {
		if m.Name == name {
			return m, true
		}
	}
	return MetricMeta{}, false
}

// ClampSeriesWindow bounds a caller's window to 5m..7d; 0/absent gets the
// default. Pure — unit-tested.
func ClampSeriesWindow(minutes int) int {
	if minutes <= 0 {
		return SeriesDefaultWindow
	}
	if minutes < SeriesMinWindowMin {
		return SeriesMinWindowMin
	}
	if minutes > SeriesMaxWindowMin {
		return SeriesMaxWindowMin
	}
	return minutes
}

// SeriesStepSeconds sizes the query step so one series never exceeds the
// point cap, floored at 60s (the lane's data is 5-min resolution anyway) and
// rounded to whole minutes for tidy axis ticks. Pure — unit-tested.
func SeriesStepSeconds(windowMinutes int) int {
	windowSec := windowMinutes * 60
	step := windowSec / SeriesMaxPoints
	if step < 60 {
		return 60
	}
	// Round UP to a whole minute so the cap holds after rounding.
	if step%60 != 0 {
		step += 60 - step%60
	}
	return step
}

// ValidResourceID bounds a caller-supplied resource id before it goes
// anywhere near a query string: non-empty, bounded length, no quotes /
// backslashes / control chars (regexp.QuoteMeta handles the rest).
func ValidResourceID(id string) bool {
	if id == "" || len(id) > SeriesMaxResourceIDLen {
		return false
	}
	for _, c := range id {
		if c < 0x20 || c == '"' || c == '\\' || c == 0x7f {
			return false
		}
	}
	return true
}

// cloudSeriesPoint is one [unix_seconds, value] sample (Prometheus convention;
// the UI multiplies by 1000 for its time axis).
