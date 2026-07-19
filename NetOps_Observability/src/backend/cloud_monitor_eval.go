package main

// cloud_monitor_eval.go — the bounded poll evaluator for per-tenant cloud
// monitors (Wave 5 #14 slice 3). Mirrors the alerts.Engine loop shape (single
// goroutine, tick-grained, test seams for query/clock) but is tenant-aware:
// every VM query a monitor runs is constrained to THAT tenant's own inventory
// resource ids — exactly the scoping the chart endpoint enforces — so one
// tenant's rule can never read another tenant's series (§3a).
//
// Honesty: "no samples" is monitorStateNoData with the reason spelled out; an
// unreachable metric store is monitorStateError — neither ever reads as "ok".
// Bounded (§9): per-tick query budget, per-monitor scope cap, per-query
// timeout inherited from vmQuery (4s), 30m sample freshness window.

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/models"
)

const (
	cloudMonitorDefaultIntervalS = 60
	cloudMonitorMaxScopeIDs      = 200 // per-monitor resource scope cap
	cloudMonitorTickQueryBudget  = 400 // VM queries per evaluation cycle
	cloudMonitorFreshWindow      = "30m"
	cloudMonitorBaselineWindow   = "6h"
	cloudMonitorAnomalySigma     = 3.0
)

// cloudMonitorEvaluator drives the per-tenant monitor rules. All external
// dependencies are injected (§5: interfaces/funcs for everything external) so
// the loop unit-tests without VM, inventory, or notifiers.
type cloudMonitorEvaluator struct {
	store       *cloudMonitorStore
	resourceIDs func(ctx context.Context, tenant string) ([]string, error)
	queryFn     func(ctx context.Context, q string) map[string]float64
	fire        func(a models.Alert)
	resolve     func(a models.Alert)
	interval    time.Duration
	now         func() time.Time
}

// newCloudMonitorEvaluator wires the production seams: the tenant-scoped cloud
// inventory and the shared vmQuery/notify plumbing.
func newCloudMonitorEvaluator(s *server, interval time.Duration) *cloudMonitorEvaluator {
	return &cloudMonitorEvaluator{
		store: s.cloudMonitors,
		resourceIDs: func(ctx context.Context, tenant string) ([]string, error) {
			res, err := s.cloud.ListResources(ctx, tenant, false)
			if err != nil {
				return nil, err
			}
			ids := make([]string, 0, len(res))
			for _, r := range res {
				ids = append(ids, r.ResourceID)
			}
			return ids, nil
		},
		queryFn:  vmQuery,
		fire:     func(a models.Alert) { s.notifier.Dispatch(a) },
		resolve:  func(a models.Alert) { s.notifier.DispatchResolve(a) },
		interval: interval,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// cloudMonitorEvalInterval reads CLOUD_MONITOR_EVAL_SECONDS (default 60;
// "0"/"off" disables the loop → returns 0).
func cloudMonitorEvalInterval() time.Duration {
	raw := strings.ToLower(strings.TrimSpace(envOr("CLOUD_MONITOR_EVAL_SECONDS", strconv.Itoa(cloudMonitorDefaultIntervalS))))
	if raw == "0" || raw == "off" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 5 {
		n = cloudMonitorDefaultIntervalS
	}
	return time.Duration(n) * time.Second
}

// Start launches the loop; a zero interval is an explicit opt-out.
func (e *cloudMonitorEvaluator) Start(ctx context.Context) {
	if e == nil || e.interval <= 0 {
		return
	}
	go e.loop(ctx)
}

func (e *cloudMonitorEvaluator) loop(ctx context.Context) {
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
func (e *cloudMonitorEvaluator) evaluateAll(ctx context.Context) {
	snap := e.store.snapshot()
	tenants := make([]string, 0, len(snap))
	for t := range snap {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants) // deterministic budget spending
	budget := cloudMonitorTickQueryBudget
	for _, tenant := range tenants {
		monitors := snap[tenant]
		if len(monitors) == 0 {
			continue
		}
		idCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ids, err := e.resourceIDs(idCtx, tenant)
		cancel()
		for _, m := range monitors {
			if !m.Enabled {
				if m.LastState != monitorStateDisabled {
					e.store.setStatus(tenant, m.ID, monitorStateDisabled, "monitor is disabled", nil, e.now())
				}
				continue
			}
			if budget <= 0 {
				// Out of budget: leave the previous verdict standing rather
				// than minting a state the cycle did not measure.
				logWarn("monitors", "cloud monitor evaluation budget exhausted", map[string]any{"tenant": tenant})
				return
			}
			if err != nil {
				e.transition(tenant, m, monitorStateError, "inventory unavailable — cannot resolve this tenant's resources", nil)
				continue
			}
			used := e.evaluateOne(ctx, tenant, m, ids, budget)
			budget -= used
		}
	}
}

// evaluateOne measures one monitor and applies the state transition. Returns
// the number of VM queries spent.
func (e *cloudMonitorEvaluator) evaluateOne(ctx context.Context, tenant string, m cloudMonitor, tenantIDs []string, budget int) int {
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
			e.transition(tenant, m, monitorStateNoData, "the monitored resource is no longer in this tenant's inventory", nil)
			return 0
		}
		scope = []string{m.ResourceID}
	}
	if len(scope) == 0 {
		e.transition(tenant, m, monitorStateNoData, "this tenant has no cloud resources in inventory", nil)
		return 0
	}
	if len(scope) > cloudMonitorMaxScopeIDs {
		e.transition(tenant, m, monitorStateError,
			fmt.Sprintf("monitor scope covers %d resources (limit %d) — scope it to one resource", len(scope), cloudMonitorMaxScopeIDs), nil)
		return 0
	}
	need := 1
	if m.Mode == monitorModeAnomaly {
		need = 3
	}
	if budget < need {
		return 0 // out of budget — previous verdict stands (evaluateAll logs)
	}

	sel := fmt.Sprintf(`%s{resource_id=~"%s"}`, m.Metric, regexAlternation(scope))
	last := e.queryFn(ctx, fmt.Sprintf(`last_over_time(%s[%s])`, sel, cloudMonitorFreshWindow))
	if last == nil {
		e.transition(tenant, m, monitorStateError, "the metric store did not answer", nil)
		return need
	}
	if len(last) == 0 {
		e.transition(tenant, m, monitorStateNoData,
			fmt.Sprintf("no %s samples ingested for the monitored scope in the last %s", m.Metric, cloudMonitorFreshWindow), nil)
		return need
	}

	switch m.Mode {
	case monitorModeThreshold:
		e.applyThreshold(tenant, m, last)
		return 1
	case monitorModeAnomaly:
		avg := e.queryFn(ctx, fmt.Sprintf(`avg_over_time(%s[%s])`, sel, cloudMonitorBaselineWindow))
		sd := e.queryFn(ctx, fmt.Sprintf(`stddev_over_time(%s[%s])`, sel, cloudMonitorBaselineWindow))
		if avg == nil || sd == nil {
			e.transition(tenant, m, monitorStateError, "the metric store did not answer the baseline query", nil)
			return 3
		}
		e.applyAnomaly(tenant, m, last, avg, sd)
		return 3
	default:
		e.transition(tenant, m, monitorStateError, "unknown monitor mode", nil)
		return need
	}
}

func (e *cloudMonitorEvaluator) applyThreshold(tenant string, m cloudMonitor, last map[string]float64) {
	worstID, worst, firing := "", math.NaN(), false
	for id, v := range last {
		crosses := (m.Condition == monitorCondAbove && v > m.Threshold) ||
			(m.Condition == monitorCondBelow && v < m.Threshold)
		better := math.IsNaN(worst) ||
			(m.Condition == monitorCondAbove && v > worst) ||
			(m.Condition == monitorCondBelow && v < worst)
		if better {
			worst, worstID = v, id
		}
		if crosses {
			firing = true
		}
	}
	v := worst
	if firing {
		e.transition(tenant, m, monitorStateFiring,
			fmt.Sprintf("%s is %s on %s (%s %s)", m.Metric, fmtMonitorVal(worst), worstID, m.Condition, fmtMonitorVal(m.Threshold)), &v)
		return
	}
	e.transition(tenant, m, monitorStateOK,
		fmt.Sprintf("%s worst reading %s on %s (threshold %s %s)", m.Metric, fmtMonitorVal(worst), worstID, m.Condition, fmtMonitorVal(m.Threshold)), &v)
}

func (e *cloudMonitorEvaluator) applyAnomaly(tenant string, m cloudMonitor, last, avg, sd map[string]float64) {
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
		if dev > cloudMonitorAnomalySigma*s && dev > 0 {
			firing = true
		}
	}
	if compared == 0 {
		e.transition(tenant, m, monitorStateNoData,
			fmt.Sprintf("no %s baseline over the last %s — anomaly detection needs history", m.Metric, cloudMonitorBaselineWindow), nil)
		return
	}
	v := worstVal
	if firing {
		e.transition(tenant, m, monitorStateFiring,
			fmt.Sprintf("%s on %s reads %s — more than %.0fσ from its %s average", m.Metric, worstID, fmtMonitorVal(worstVal), cloudMonitorAnomalySigma, cloudMonitorBaselineWindow), &v)
		return
	}
	e.transition(tenant, m, monitorStateOK,
		fmt.Sprintf("%s within %.0fσ of its %s average across %d resource(s)", m.Metric, cloudMonitorAnomalySigma, cloudMonitorBaselineWindow, compared), &v)
}

// transition records the outcome and dispatches notifications ONLY on a state
// edge (ok/…→firing fires; firing→ok/no_data resolves), never on repeats.
func (e *cloudMonitorEvaluator) transition(tenant string, m cloudMonitor, state, reason string, value *float64) {
	prev := m.LastState
	e.store.setStatus(tenant, m.ID, state, reason, value, e.now())
	alert := models.Alert{
		ID: "cloud-monitor-" + m.ID, Rule: m.Name, Severity: "warning",
		Summary:     fmt.Sprintf("Cloud monitor %q: %s", m.Name, reason),
		Description: reason,
		Labels:      map[string]string{"tenant_id": tenant, "metric": m.Metric, "mode": m.Mode, "source": "cloud_monitor"},
		FiredAt:     e.now(),
	}
	if state == monitorStateFiring && prev != monitorStateFiring {
		e.fire(alert)
	}
	if prev == monitorStateFiring && state != monitorStateFiring {
		e.resolve(alert)
	}
}

func fmtMonitorVal(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e9 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}
