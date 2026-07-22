package main

// cloud_slo.go — per-tenant SLOs / error budgets (Wave 5 #14 slice 2).
//
// A tenant defines an availability target (e.g. 99.9%) on an app; the actual
// is MEASURED from the provider status-check lane already in VictoriaMetrics
// (cloud_status_check_failed — AWS status checks / Azure VM availability,
// 0 = passing, >0 = failed, per 5-min period). avg_over_time of that 0/1
// series over the SLO window is the failed-period fraction, so
// availability = 100 × (1 − avg). Honesty contract: an app with no attributed
// resources, or whose resources have NO ingested status-check samples, is
// "not measurable" — never a fabricated 100%. Ingestion gaps are named in the
// basis text, not silently counted as uptime (or downtime).
//
//	GET /api/cloud/slos — any authenticated infra reader; defs + measured status
//	PUT /api/cloud/slos — administration:admin, tenant-stamped, audited
//
// Store: file/kv-backed per-tenant map, the tenant_governance.go pattern
// (§3a for file stores — every read/write is keyed by the caller's principal
// tenant; no unscoped listing exists).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	cloudSLOMaxPerTenant  = 20
	cloudSLOMinTargetPct  = 50.0
	cloudSLOMaxTargetPct  = 99.999
	cloudSLOMinWindowDays = 1
	cloudSLOMaxWindowDays = 30
	cloudSLOQueryTimeout  = 6 * time.Second
)

// cloudSLO is one tenant-defined objective: an availability target on an app.
type cloudSLO struct {
	AppName     string  `json:"app_name"`
	TargetPct   float64 `json:"target_pct"`
	WindowDays  int     `json:"window_days"`
	Description string  `json:"description,omitempty"`
}

// cloudSLOStatus is the MEASURED side, computed at read time. Measurable=false
// carries a Basis naming exactly what is missing.
type cloudSLOStatus struct {
	Measurable         bool    `json:"measurable"`
	ActualPct          float64 `json:"actual_pct,omitempty"`
	BudgetPct          float64 `json:"budget_pct"`
	BudgetRemainingPct float64 `json:"budget_remaining_pct,omitempty"`
	BurnRatio          float64 `json:"burn_ratio,omitempty"`
	ResourcesTotal     int     `json:"resources_total"`
	ResourcesReporting int     `json:"resources_reporting"`
	Basis              string  `json:"basis"`
}

// cloudSLOStore is a file-backed per-tenant map (tenant_governance.go pattern).
type cloudSLOStore struct {
	mu   sync.RWMutex
	slos map[string][]cloudSLO
	path string
}

func cloudSLOPath() string {
	if p := strings.TrimSpace(os.Getenv("CLOUD_SLO_PATH")); p != "" {
		return p
	}
	return "/data/cloud_slos.json"
}

func newCloudSLOStore(path string) *cloudSLOStore {
	s := &cloudSLOStore{slos: map[string][]cloudSLO{}, path: path}
	s.load()
	return s
}

func (s *cloudSLOStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var m map[string][]cloudSLO
	if json.Unmarshal(b, &m) != nil {
		return
	}
	s.slos = m
}

// F-62/F-63: returns error. A swallowed persist failure here made the
// handler above structurally unable to report that the write did not
// land — 200 with nothing saved. Callers roll back and answer 500.
func (s *cloudSLOStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.slos, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cloud slos: %w", err)
	}
	if err := kvSave(s.path, b); err != nil {
		logError("settings", "persist cloud slos failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist cloud slos: %w", err)
	}
	return nil
}

// list returns the tenant's SLO definitions (copy). Nil-safe.
func (s *cloudSLOStore) list(tenant string) []cloudSLO {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]cloudSLO(nil), s.slos[tenant]...)
}

// set stamps the tenant FROM THE PRINCIPAL (callers pass principalTenant) and
// persists. defs==nil clears the tenant's SLOs.
func (s *cloudSLOStore) set(tenant string, defs []cloudSLO) error {
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

// normalizeCloudSLOs validates a caller's list: bounded count, real app tokens,
// target within 50..99.999, window 1..30 days, one SLO per app. Off-spec fails
// the request — never a silent trim.
func normalizeCloudSLOs(raw []cloudSLO) ([]cloudSLO, error) {
	if len(raw) == 0 {
		return nil, errors.New("slos must list at least one objective (or pass reset)")
	}
	if len(raw) > cloudSLOMaxPerTenant {
		return nil, fmt.Errorf("slos: at most %d objectives per tenant", cloudSLOMaxPerTenant)
	}
	seen := map[string]bool{}
	out := make([]cloudSLO, 0, len(raw))
	for _, d := range raw {
		app := strings.TrimSpace(d.AppName)
		if !isCloudAppToken(app) {
			return nil, fmt.Errorf("slos: invalid app name %q", d.AppName)
		}
		key := strings.ToLower(app)
		if seen[key] {
			return nil, fmt.Errorf("slos: duplicate objective for app %q", app)
		}
		seen[key] = true
		if math.IsNaN(d.TargetPct) || d.TargetPct < cloudSLOMinTargetPct || d.TargetPct > cloudSLOMaxTargetPct {
			return nil, fmt.Errorf("slos.%s: target_pct must be %.0f..%.3f", app, cloudSLOMinTargetPct, cloudSLOMaxTargetPct)
		}
		if d.WindowDays < cloudSLOMinWindowDays || d.WindowDays > cloudSLOMaxWindowDays {
			return nil, fmt.Errorf("slos.%s: window_days must be %d..%d", app, cloudSLOMinWindowDays, cloudSLOMaxWindowDays)
		}
		desc := strings.TrimSpace(d.Description)
		if len(desc) > 200 {
			return nil, fmt.Errorf("slos.%s: description must be at most 200 characters", app)
		}
		out = append(out, cloudSLO{AppName: app, TargetPct: d.TargetPct, WindowDays: d.WindowDays, Description: desc})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].AppName) < strings.ToLower(out[j].AppName) })
	return out, nil
}

// sloBudget is the error-budget arithmetic, kept pure for unit tests:
// budget = 100 − target; burn = spent/budget; remaining = 100 × (1 − burn),
// floored at 0 (an over-spent budget is 0 remaining with burn > 1 — the burn
// ratio carries the overshoot, the remaining never goes negative).
func sloBudget(targetPct, actualPct float64) (budgetPct, burnRatio, remainingPct float64) {
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

// measureCloudSLO computes one SLO's status from the tenant's OWN resources
// (caller passes its principal-scoped inventory) and the status-check lane.
// queryFn is vmQuery in production; injected for tests.
func measureCloudSLO(ctx context.Context, slo cloudSLO, tenantResources map[string][]string,
	queryFn func(ctx context.Context, q string) map[string]float64) cloudSLOStatus {
	budget, _, _ := sloBudget(slo.TargetPct, 100)
	st := cloudSLOStatus{BudgetPct: budget}
	ids := tenantResources[strings.ToLower(slo.AppName)]
	st.ResourcesTotal = len(ids)
	if len(ids) == 0 {
		st.Basis = "not measurable — no cloud resources are attributed to this app"
		return st
	}
	q := fmt.Sprintf(`avg_over_time(cloud_status_check_failed{resource_id=~"%s"}[%dd])`,
		regexAlternation(ids), slo.WindowDays)
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
	_, burn, remaining := sloBudget(slo.TargetPct, actual)
	st.Measurable = true
	st.ActualPct = actual
	st.BurnRatio = burn
	st.BudgetRemainingPct = remaining
	st.Basis = fmt.Sprintf("measured from provider status checks on %d of %d resource(s) over %dd; ingestion gaps are not counted", n, len(ids), slo.WindowDays)
	return st
}

// handleCloudSLOs serves GET/PUT /api/cloud/slos.
func (s *server) handleCloudSLOs(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string, withStatus bool) {
		defs := s.cloudSLOs.list(tenant)
		type row struct {
			cloudSLO
			Status *cloudSLOStatus `json:"status,omitempty"`
		}
		rows := make([]row, 0, len(defs))
		if withStatus && len(defs) > 0 {
			res, _, _, err := s.cloudResources(r)
			idx := map[string][]string{}
			if err == nil {
				for _, cr := range res {
					if cr.AppName == "" {
						continue
					}
					k := strings.ToLower(cr.AppName)
					idx[k] = append(idx[k], cr.ResourceID)
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), cloudSLOQueryTimeout)
			defer cancel()
			for _, d := range defs {
				st := measureCloudSLO(ctx, d, idx, vmQuery)
				rows = append(rows, row{cloudSLO: d, Status: &st})
			}
		} else {
			for _, d := range defs {
				rows = append(rows, row{cloudSLO: d})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": tenant, "slos": rows, "count": len(rows),
			"max_slos": cloudSLOMaxPerTenant,
		})
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, _ := principalTenant(claims)
		writeState(tenant, true)
	case http.MethodPut:
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var body struct {
			SLOs  []cloudSLO `json:"slos"`
			Reset bool       `json:"reset,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		var defs []cloudSLO
		if !body.Reset {
			var err error
			if defs, err = normalizeCloudSLOs(body.SLOs); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		tenant, cross := principalTenant(claims)
		if err := s.cloudSLOs.set(tenant, defs); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("SLOs were not saved"))
			return
		}
		if s.audit != nil {
			apps := make([]string, 0, len(defs))
			for _, d := range defs {
				apps = append(apps, d.AppName)
			}
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
				Remote: auditClientIP(r),
				Detail: map[string]any{"action": "set_cloud_slos", "apps": apps, "reset": body.Reset},
			})
		}
		writeState(tenant, true)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}
