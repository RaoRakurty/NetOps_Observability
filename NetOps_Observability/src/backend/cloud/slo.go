package cloud

// slo.go — per-tenant SLOs / error budgets (Wave 5 #14 slice 2, extracted P2
// RA.9). A tenant defines an availability target on an app; the actual is
// MEASURED from the provider status-check lane (0/1 per 5-min period —
// avg_over_time is the failed fraction, availability = 100 × (1 − avg)).
// Honesty contract: an app with no attributed resources, or whose resources
// have NO ingested status-check samples, is "not measurable" — never a
// fabricated 100%. Ingestion gaps are named in the basis text, not silently
// counted as uptime (or downtime).
//
// Store: file/kv-backed per-tenant map, the tenant-governance pattern (§3a
// for file stores — every read/write is keyed by the caller's principal
// tenant; no unscoped listing exists). Env path, principal resolution, the
// VM transport and handlers stay with the entrypoint.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

const (
	SLOMaxPerTenant  = 20
	SLOMinTargetPct  = 50.0
	SLOMaxTargetPct  = 99.999
	SLOMinWindowDays = 1
	SLOMaxWindowDays = 30
)

// SLO is one tenant-defined objective: an availability target on an app.
type SLO struct {
	AppName     string  `json:"app_name"`
	TargetPct   float64 `json:"target_pct"`
	WindowDays  int     `json:"window_days"`
	Description string  `json:"description,omitempty"`
}

// SLOStatus is the MEASURED side, computed at read time. Measurable=false
// carries a Basis naming exactly what is missing.
type SLOStatus struct {
	Measurable         bool    `json:"measurable"`
	ActualPct          float64 `json:"actual_pct,omitempty"`
	BudgetPct          float64 `json:"budget_pct"`
	BudgetRemainingPct float64 `json:"budget_remaining_pct,omitempty"`
	BurnRatio          float64 `json:"burn_ratio,omitempty"`
	ResourcesTotal     int     `json:"resources_total"`
	ResourcesReporting int     `json:"resources_reporting"`
	Basis              string  `json:"basis"`
}

// IsCloudAppToken validates an app name as a safe vocabulary token (it is
// interpolated into VM selectors and SQL literals downstream — the zero-trust
// gate for the whole cloud app namespace).
func IsCloudAppToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_' || c == ':' || c == '/' || c == ' '
		if !ok {
			return false
		}
	}
	return true
}

// SLOStore is a file-backed per-tenant map (the tenant-governance pattern).
type SLOStore struct {
	mu   sync.RWMutex
	slos map[string][]SLO
	path string
	// loadErr: the stored file could not be READ, which is not "no tenant has
	// defined an SLO". Both used to take the same branch, so a read failure
	// showed every tenant zero SLOs and the next single-tenant write flushed an
	// empty map over everyone else's (§10).
	loadErr error
}

// NewSLOStore opens the store at path ("" = memory-only, tests).
func NewSLOStore(path string) *SLOStore {
	s := &SLOStore{slos: map[string][]SLO{}, path: path}
	if err := s.load(); err != nil {
		s.loadErr = err
		applog.Error("cloud.slo", "stored SLOs unreadable — every tenant reads as having none and writes are refused until it is repaired", map[string]any{"error": err.Error()})
	}
	return s
}

// load reads the stored per-tenant SLOs. THREE states, never two: the store
// did not answer (error) / it answered with nothing / loaded.
func (s *SLOStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = no SLOs defined yet
	}
	if err != nil {
		return fmt.Errorf("read cloud SLOs: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = none defined yet
	}
	var m map[string][]SLO
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("decode cloud SLOs: %w", err)
	}
	s.slos = m
	return nil
}

// F-62/F-63: returns error; callers roll back and answer 500.
func (s *SLOStore) saveLocked() error {
	if s.loadErr != nil {
		return fmt.Errorf("refusing to overwrite the stored SLOs: their contents were never read: %w", s.loadErr)
	}
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.slos, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cloud slos: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		applog.Error("settings", "persist cloud slos failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist cloud slos: %w", err)
	}
	return nil
}

// List returns the tenant's SLO definitions (copy). Nil-safe.
func (s *SLOStore) List(tenant string) []SLO {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]SLO(nil), s.slos[tenant]...)
}

// Set stamps the tenant FROM THE PRINCIPAL (callers pass principalTenant) and
// persists. defs==nil clears the tenant's SLOs.
func (s *SLOStore) Set(tenant string, defs []SLO) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.slos[tenant]
	if defs == nil {
		delete(s.slos, tenant)
	} else {
		s.slos[tenant] = defs
	}
	if err := s.saveLocked(); err != nil {
		if had {
			s.slos[tenant] = prev
		} else {
			delete(s.slos, tenant)
		}
		return err
	}
	return nil
}

// SeedForTest bypasses validation and writes a tenant's defs straight through
// the persistence path (the *ForTest idiom — the persistence-matrix tests
// exercise saveLocked without white-box field pokes).
func (s *SLOStore) SeedForTest(tenant string, defs []SLO) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slos[tenant] = defs
	return s.saveLocked()
}

// NormalizeSLOs validates a caller's list: bounded count, real app tokens,
// target within 50..99.999, window 1..30 days, one SLO per app. Off-spec fails
// the request — never a silent trim.
func NormalizeSLOs(raw []SLO) ([]SLO, error) {
	if len(raw) == 0 {
		return nil, errors.New("slos must list at least one objective (or pass reset)")
	}
	if len(raw) > SLOMaxPerTenant {
		return nil, fmt.Errorf("slos: at most %d objectives per tenant", SLOMaxPerTenant)
	}
	seen := map[string]bool{}
	out := make([]SLO, 0, len(raw))
	for _, d := range raw {
		app := strings.TrimSpace(d.AppName)
		if !IsCloudAppToken(app) {
			return nil, fmt.Errorf("slos: invalid app name %q", d.AppName)
		}
		key := strings.ToLower(app)
		if seen[key] {
			return nil, fmt.Errorf("slos: duplicate objective for app %q", app)
		}
		seen[key] = true
		if math.IsNaN(d.TargetPct) || d.TargetPct < SLOMinTargetPct || d.TargetPct > SLOMaxTargetPct {
			return nil, fmt.Errorf("slos.%s: target_pct must be %.0f..%.3f", app, SLOMinTargetPct, SLOMaxTargetPct)
		}
		if d.WindowDays < SLOMinWindowDays || d.WindowDays > SLOMaxWindowDays {
			return nil, fmt.Errorf("slos.%s: window_days must be %d..%d", app, SLOMinWindowDays, SLOMaxWindowDays)
		}
		desc := strings.TrimSpace(d.Description)
		if len(desc) > 200 {
			return nil, fmt.Errorf("slos.%s: description must be at most 200 characters", app)
		}
		out = append(out, SLO{AppName: app, TargetPct: d.TargetPct, WindowDays: d.WindowDays, Description: desc})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].AppName) < strings.ToLower(out[j].AppName) })
	return out, nil
}

// SLOBudget is the error-budget arithmetic, kept pure for unit tests:
// budget = 100 − target; burn = spent/budget; remaining = 100 × (1 − burn),
// floored at 0 (an over-spent budget is 0 remaining with burn > 1 — the burn
// ratio carries the overshoot, the remaining never goes negative).
func SLOBudget(targetPct, actualPct float64) (budgetPct, burnRatio, remainingPct float64) {
	budgetPct = 100 - targetPct
	if budgetPct <= 0 {
		return 0, 0, 0
	}
	spent := 100 - actualPct
	if spent < 0 {
		spent = 0
	}
	burnRatio = spent / budgetPct
	remainingPct = 100 * (1 - burnRatio)
	if remainingPct < 0 {
		remainingPct = 0
	}
	return budgetPct, burnRatio, remainingPct
}

// MeasureSLO computes one SLO's status from the tenant's OWN resources
// (caller passes its principal-scoped inventory) and the status-check lane.
// queryFn is the caller's VM transport; injected for tests.
func MeasureSLO(ctx context.Context, slo SLO, tenantResources map[string][]string,
	queryFn func(ctx context.Context, q string) map[string]float64) SLOStatus {
	budget, _, _ := SLOBudget(slo.TargetPct, 100)
	st := SLOStatus{BudgetPct: budget}
	ids := tenantResources[strings.ToLower(slo.AppName)]
	st.ResourcesTotal = len(ids)
	if len(ids) == 0 {
		st.Basis = "not measurable — no cloud resources are attributed to this app"
		return st
	}
	q := fmt.Sprintf(`avg_over_time(cloud_status_check_failed{resource_id=~"%s"}[%dd])`,
		monitorRegexAlternation(ids), slo.WindowDays)
	vals := queryFn(ctx, q)
	if vals == nil {
		st.Basis = "not measurable — the metric store did not answer"
		return st
	}
	sum, n := 0.0, 0
	for _, id := range ids {
		if v, ok := vals[id]; ok {
			// The lane is 0/1 per period; clamp defensively (a >1 sample would
			// otherwise mint negative availability).
			if v < 0 {
				v = 0
			}
			if v > 1 {
				v = 1
			}
			sum += v
			n++
		}
	}
	st.ResourcesReporting = n
	if n == 0 {
		st.Basis = fmt.Sprintf("not measurable — no provider status-check samples ingested for this app's %d resource(s) in the %dd window", len(ids), slo.WindowDays)
		return st
	}
	actual := 100 * (1 - sum/float64(n))
	_, burn, remaining := SLOBudget(slo.TargetPct, actual)
	st.Measurable = true
	st.ActualPct = actual
	st.BurnRatio = burn
	st.BudgetRemainingPct = remaining
	st.Basis = fmt.Sprintf("measured from provider status checks on %d of %d resource(s) over %dd; ingestion gaps are not counted", n, len(ids), slo.WindowDays)
	return st
}
