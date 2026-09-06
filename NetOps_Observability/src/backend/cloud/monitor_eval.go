// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// monitor_eval.go — the bounded poll evaluator for per-tenant cloud monitors
// (Wave 5 #14 slice 3, extracted P2 W4.18). Mirrors the alerts.Engine loop
// shape (single goroutine, tick-grained, injected seams for query/clock) but is
// tenant-aware: every VM query a monitor runs is constrained to THAT tenant's
// own inventory resource ids — exactly the scoping the chart endpoint enforces
// — so one tenant's rule can never read another tenant's series (§3a).
//
// Honesty: "no samples" is MonitorStateNoData with the reason spelled out; an
// unreachable metric store is MonitorStateError — neither ever reads as "ok".
// Bounded (§9): per-tick query budget, per-monitor scope cap, per-query
// timeout inherited from the caller's query seam, 30m sample freshness window.
//
// All external dependencies arrive through MonitorEvalDeps (§5) so the loop
// unit-tests without VM, inventory, or notifiers; the eval-interval env read
// stays with the entrypoint.

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/models"
)

const (
	monitorMaxScopeIDs     = 200 // per-monitor resource scope cap
	monitorTickQueryBudget = 400 // VM queries per evaluation cycle
	monitorFreshWindow     = "30m"
	monitorBaselineWindow  = "6h"
	monitorAnomalySigma    = 3.0
)

// MonitorEvalDeps are the injected seams the evaluator runs over.
type MonitorEvalDeps struct {
	// ResourceIDs lists the tenant's own cloud inventory resource ids — the
	// scope wall every query is constrained to.
	ResourceIDs func(ctx context.Context, tenant string) ([]string, error)
	// Query runs one instant VM query and returns resource_id → value
	// (nil = the metric store did not answer).
	Query func(ctx context.Context, q string) map[string]float64
	// Fire / Resolve dispatch notifications on state EDGES only.
	Fire    func(a models.Alert)
	Resolve func(a models.Alert)
	// Now is the clock seam (nil → time.Now().UTC).
	Now func() time.Time
}

// MonitorEvaluator drives the per-tenant monitor rules.
type MonitorEvaluator struct {
	store    *MonitorStore
	deps     MonitorEvalDeps
	interval time.Duration
}

// NewMonitorEvaluator builds the evaluator; a zero/negative interval makes
// Start a no-op (explicit opt-out).
func NewMonitorEvaluator(store *MonitorStore, deps MonitorEvalDeps, interval time.Duration) *MonitorEvaluator {
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	return &MonitorEvaluator{store: store, deps: deps, interval: interval}
}

// Start launches the loop; a zero interval is an explicit opt-out.
func (e *MonitorEvaluator) Start(ctx context.Context) {
	if e == nil || e.interval <= 0 {
		return
	}
	go e.loop(ctx)
}

func (e *MonitorEvaluator) loop(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.evaluateAll(ctx)
		}
	}
}

// evaluateAll runs one bounded cycle over every tenant's monitors.
func (e *MonitorEvaluator) evaluateAll(ctx context.Context) {
	snap := e.store.Snapshot()
	tenants := make([]string, 0, len(snap))
	for t := range snap {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants) // deterministic budget spending
	budget := monitorTickQueryBudget
	for _, tenant := range tenants {
		monitors := snap[tenant]
		if len(monitors) == 0 {
			continue
		}
		idCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ids, err := e.deps.ResourceIDs(idCtx, tenant)
		cancel()
		for _, m := range monitors {
			if !m.Enabled {
				if m.LastState != MonitorStateDisabled {
					if err := e.store.SetStatus(tenant, m.ID, MonitorStateDisabled, "monitor is disabled", nil, e.deps.Now()); err != nil {
						applog.Error("monitors", "persist monitor state failed", map[string]any{"monitor": m.ID, "err": err.Error()})
					}
				}
				continue
			}
			if budget <= 0 {
				// Out of budget: leave the previous verdict standing rather
				// than minting a state the cycle did not measure.
				applog.Warn("monitors", "cloud monitor evaluation budget exhausted", map[string]any{"tenant": tenant})
				return
			}
			if err != nil {
				e.transition(tenant, m, MonitorStateError, "inventory unavailable — cannot resolve this tenant's resources", nil)
				continue
			}
			used := e.evaluateOne(ctx, tenant, m, ids, budget)
			budget -= used
		}
	}
}

// evaluateOne measures one monitor and applies the state transition. Returns
// the number of VM queries spent.
func (e *MonitorEvaluator) evaluateOne(ctx context.Context, tenant string, m Monitor, tenantIDs []string, budget int) int {
	scope := tenantIDs
	if m.ResourceID != "" {
		found := false
		for _, id := range tenantIDs {
			if id == m.ResourceID {
				found = true
				break
			}
		}
		if !found {
			e.transition(tenant, m, MonitorStateNoData, "the monitored resource is no longer in this tenant's inventory", nil)
			return 0
		}
		scope = []string{m.ResourceID}
	}
	if len(scope) == 0 {
		e.transition(tenant, m, MonitorStateNoData, "this tenant has no cloud resources in inventory", nil)
		return 0
	}
	if len(scope) > monitorMaxScopeIDs {
		e.transition(tenant, m, MonitorStateError,
			fmt.Sprintf("monitor scope covers %d resources (limit %d) — scope it to one resource", len(scope), monitorMaxScopeIDs), nil)
		return 0
	}
	need := 1
	if m.Mode == MonitorModeAnomaly {
		need = 3
	}
	if budget < need {
		return 0 // out of budget — previous verdict stands (evaluateAll logs)
	}

	sel := fmt.Sprintf(`%s{resource_id=~"%s"}`, m.Metric, monitorRegexAlternation(scope))
	last := e.deps.Query(ctx, fmt.Sprintf(`last_over_time(%s[%s])`, sel, monitorFreshWindow))
	if last == nil {
		e.transition(tenant, m, MonitorStateError, "the metric store did not answer", nil)
		return need
	}
	if len(last) == 0 {
		e.transition(tenant, m, MonitorStateNoData,
			fmt.Sprintf("no %s samples ingested for the monitored scope in the last %s", m.Metric, monitorFreshWindow), nil)
		return need
	}

	switch m.Mode {
	case MonitorModeThreshold:
		e.applyThreshold(tenant, m, last)
		return 1
	case MonitorModeAnomaly:
		avg := e.deps.Query(ctx, fmt.Sprintf(`avg_over_time(%s[%s])`, sel, monitorBaselineWindow))
		sd := e.deps.Query(ctx, fmt.Sprintf(`stddev_over_time(%s[%s])`, sel, monitorBaselineWindow))
		if avg == nil || sd == nil {
			e.transition(tenant, m, MonitorStateError, "the metric store did not answer the baseline query", nil)
			return 3
		}
		e.applyAnomaly(tenant, m, last, avg, sd)
		return 3
	default:
		e.transition(tenant, m, MonitorStateError, "unknown monitor mode", nil)
		return need
	}
}

func (e *MonitorEvaluator) applyThreshold(tenant string, m Monitor, last map[string]float64) {
	worstID, worst, firing := "", math.NaN(), false
	for id, v := range last {
		crosses := (m.Condition == MonitorCondAbove && v > m.Threshold) ||
			(m.Condition == MonitorCondBelow && v < m.Threshold)
		better := math.IsNaN(worst) ||
			(m.Condition == MonitorCondAbove && v > worst) ||
			(m.Condition == MonitorCondBelow && v < worst)
		if better {
			worst, worstID = v, id
		}
		if crosses {
			firing = true
		}
	}
	v := worst
	if firing {
		e.transition(tenant, m, MonitorStateFiring,
			fmt.Sprintf("%s is %s on %s (%s %s)", m.Metric, fmtMonitorVal(worst), worstID, m.Condition, fmtMonitorVal(m.Threshold)), &v)
		return
	}
	e.transition(tenant, m, MonitorStateOK,
		fmt.Sprintf("%s worst reading %s on %s (threshold %s %s)", m.Metric, fmtMonitorVal(worst), worstID, m.Condition, fmtMonitorVal(m.Threshold)), &v)
}

func (e *MonitorEvaluator) applyAnomaly(tenant string, m Monitor, last, avg, sd map[string]float64) {
	worstID, worstDev, worstVal, firing, compared := "", -1.0, 0.0, false, 0
	for id, v := range last {
		a, okA := avg[id]
		s, okS := sd[id]
		if !okA || !okS {
			continue // no baseline for this resource — cannot judge it
		}
		compared++
		dev := math.Abs(v - a)
		if dev > worstDev {
			worstDev, worstID, worstVal = dev, id, v
		}
		if dev > monitorAnomalySigma*s && dev > 0 {
			firing = true
		}
	}
	if compared == 0 {
		e.transition(tenant, m, MonitorStateNoData,
			fmt.Sprintf("no %s baseline over the last %s — anomaly detection needs history", m.Metric, monitorBaselineWindow), nil)
		return
	}
	v := worstVal
	if firing {
		e.transition(tenant, m, MonitorStateFiring,
			fmt.Sprintf("%s on %s reads %s — more than %.0fσ from its %s average", m.Metric, worstID, fmtMonitorVal(worstVal), monitorAnomalySigma, monitorBaselineWindow), &v)
		return
	}
	e.transition(tenant, m, MonitorStateOK,
		fmt.Sprintf("%s within %.0fσ of its %s average across %d resource(s)", m.Metric, monitorAnomalySigma, monitorBaselineWindow, compared), &v)
}

// transition records the outcome and dispatches notifications ONLY on a state
// edge (ok/…→firing fires; firing→ok/no_data resolves), never on repeats.
func (e *MonitorEvaluator) transition(tenant string, m Monitor, state, reason string, value *float64) {
	prev := m.LastState
	if err := e.store.SetStatus(tenant, m.ID, state, reason, value, e.deps.Now()); err != nil {
		// The verdict was computed and is now unrecorded — the operator must be
		// able to see that, or the monitor silently stops reporting.
		applog.Error("monitors", "persist monitor state failed", map[string]any{"monitor": m.ID, "err": err.Error()})
	}
	alert := models.Alert{
		ID: "cloud-monitor-" + m.ID, Rule: m.Name, Severity: "warning",
		Summary:     fmt.Sprintf("Cloud monitor %q: %s", m.Name, reason),
		Description: reason,
		Labels:      map[string]string{"tenant_id": tenant, "metric": m.Metric, "mode": m.Mode, "source": "cloud_monitor"},
		FiredAt:     e.deps.Now(),
	}
	if state == MonitorStateFiring && prev != MonitorStateFiring {
		e.deps.Fire(alert)
	}
	if prev == MonitorStateFiring && state != MonitorStateFiring {
		e.deps.Resolve(alert)
	}
}

func fmtMonitorVal(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e9 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// monitorRegexAlternation renders values as an anchored RE2 alternation
// suitable for a `label=~"..."` matcher (e.g. ["a","b.c"] -> `a|b\.c`). Each
// value is regex-quoted so metacharacters in resource ids are treated
// literally. VM anchors =~ matchers at both ends, so the alternation matches
// the full label value. Returns "" for an empty input. (Private copy of main's
// regexAlternation per the no-utils rule.)
func monitorRegexAlternation(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, regexp.QuoteMeta(v))
	}
	return strings.Join(parts, "|")
}
