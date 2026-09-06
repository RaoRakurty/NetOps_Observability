// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Scope health score (#69 front-page §4) — the Health-strip backend.
// Design rule (owner): HONEST BEFORE IMPRESSIVE. The score blends multiple signal
// classes for a scope (global / site); with fewer than 2 live classes it returns
// INSUFFICIENT_TELEMETRY rather than a confident verdict from one source. Probes
// alone never make the network look unhealthy. Every score is explainable
// (per-contribution points) — never a black-box. Reuses the Path Behavior Health
// primitives (path_health.go: pathgraph.LossSeverity / pathgraph.SeverityPctDistance / hinge-style).
//
//   GET /api/health/score?scope=global|site&id=<site>
//
// Each class fetcher is best-effort + independent: a dead correlation service or a
// missing metric drops that class (not live), it never errors the strip
// (non-goal: the dashboard must not depend on correlation availability).

import (
	"context"
	"errors"
	"net/http"
	"netops/backend/pathgraph"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/chschema"

	"netops/backend/internal/healthscore"
)

// signal-class weights (front-page §4 defaults). Availability is non-negotiable;
// path (customer probes) and trusted correlation rank above raw device counters.
func (s *server) handleHealthScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "global"
	}
	if scope != "global" && scope != "site" && scope != "service" {
		writeError(w, http.StatusBadRequest, errors.New("scope must be global, site or service"))
		return
	}
	// #69 P2: per-service score — bindings + flow attribution + correlation,
	// tenant-scoped, same explainable contract (svc_health.go).
	if scope == "service" {
		s.serveServiceHealthScore(w, r, claims)
		return
	}
	site := sanitizeCHText(r.URL.Query().Get("id"))
	ctx := r.Context()

	// SEC (2026-08-04): every VictoriaMetrics read below MUST carry the caller's
	// device boundary. These classes emit device NAMES and their metrics, so an
	// unscoped read renders other tenants' devices into this tenant's score —
	// the same defect gatherTopoMetrics was hardened against (topology_view.go:86-91).
	// metricsScopeFilters fails closed: a tenant with no visible device gets the
	// __netops_no_visible_device__ sentinel, so a class reports "not live"
	// rather than the whole fleet.
	ids, names, cross := s.visibleDeviceMetricLabels(claims)
	f := metricsScopeFilters(ids, names, cross)

	// best-effort, independent class fetchers (a dead source → class not live)
	classes := []healthscore.ClassResult{
		s.fetchAvailabilityClass(ctx, site, f),
		s.fetchDeviceHealthClass(ctx, site, f),
		s.fetchPathHealthClass(ctx, f),
		s.fetchCorrelationClass(r, site),
	}
	resp := healthscore.Aggregate(scope, site, classes, time.Now().UTC().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, resp)
}

// qVecByScoped is qVecBy constrained to a principal's visible devices.
func (s *server) qVecByScoped(ctx context.Context, query, key string, filters []string) (map[string]float64, bool) {
	samples, err := s.vmInstantScoped(ctx, query, filters)
	if err != nil {
		return nil, false
	}
	out := map[string]float64{}
	for _, sm := range samples {
		if k := sm.Labels[key]; k != "" {
			if sm.Value > out[k] {
				out[k] = sm.Value
			}
		}
	}
	return out, true
}

// qVecBy2Scoped runs a VM vector query keyed by two labels, taking the max
// value seen per (k1,k2) pair, constrained to a principal's visible devices.
// Returns nil (not an empty map) when the query fails, so callers can treat
// "unreachable" and "no series" identically (both yield no lookups).
//
// SEC (2026-08-04): the unscoped convenience wrappers qVecBy/qVecBy2 that used
// to sit here — one-liners passing a literal nil filter — were DELETED. They
// were the proximate cause of three cross-tenant leaks (/api/health/score,
// the /api/topology/view path enrichers, /api/wan/interfaces): a caller
// reaching for the obvious short name silently got a fleet-wide read. If you
// genuinely need an unscoped read (a background worker with no principal),
// pass nil explicitly at the call site so it is visible in review.
func (s *server) qVecBy2Scoped(ctx context.Context, query, k1, k2 string, filters []string) map[[2]string]float64 {
	samples, err := s.vmInstantScoped(ctx, query, filters)
	if err != nil {
		return nil
	}
	out := map[[2]string]float64{}
	for _, sm := range samples {
		a, b := sm.Labels[k1], sm.Labels[k2]
		if a == "" || b == "" {
			continue
		}
		k := [2]string{a, b}
		if v, seen := out[k]; !seen || sm.Value > v {
			out[k] = sm.Value
		}
	}
	return out
}

// fetchAvailabilityClass: admin-up interfaces that are oper-down, per device.
func (s *server) fetchAvailabilityClass(ctx context.Context, site string, f []string) healthscore.ClassResult {
	res := healthscore.ClassResult{Class: "availability"}
	total, ok1 := s.qVecByScoped(ctx, `count by (device) (device_if_admin_status == 1)`, "device", f)
	down, ok2 := s.qVecByScoped(ctx, `count by (device) (device_if_admin_status == 1 and device_if_oper_status != 1)`, "device", f)
	if !ok1 || len(total) == 0 {
		return res // not live
	}
	res.Live = true
	for dev, tot := range total {
		d := down[dev]
		if d <= 0 || tot <= 0 {
			continue
		}
		b := pathgraph.ClampF(d/tot, 0, 1)
		if b > res.Badness {
			res.Badness = b
		}
		if b >= 0.34 {
			res.Contribs = append(res.Contribs, healthscore.Contribution{
				SignalClass: "availability", Entity: dev, Badness: b,
				Reason: strconv.Itoa(int(d)) + " of " + strconv.Itoa(int(tot)) + " interfaces down on " + dev,
			})
		}
	}
	_ = ok2
	return res
}

// fetchDeviceHealthClass: utilization / errors+discards / CPU / mem, per device.
func (s *server) fetchDeviceHealthClass(ctx context.Context, site string, f []string) healthscore.ClassResult {
	res := healthscore.ClassResult{Class: "device_health"}
	type dh struct {
		b      float64
		reason string
	}
	devs := map[string]*dh{}
	bump := func(dev string, b float64, reason string) {
		if dev == "" {
			return
		}
		d := devs[dev]
		if d == nil {
			d = &dh{}
			devs[dev] = d
		}
		if b > d.b {
			d.b = b
			d.reason = reason
		}
	}
	live := false
	if util, ok := s.qVecByScoped(ctx, `max by (device) (rate(device_if_in_octets[5m])*8 / ((device_if_speed > 0)*1000000))`, "device", f); ok && len(util) > 0 {
		live = true
		for dev, u := range util {
			bump(dev, healthscore.HingeN(u, 0.70, 0.95), "Link utilization "+healthscore.Pct1(u)+" on "+dev)
		}
	}
	if errs, ok := s.qVecByScoped(ctx, `max by (device) (rate(device_if_in_errors[5m])+rate(device_if_out_errors[5m])+rate(device_if_in_discards[5m])+rate(device_if_out_discards[5m]))`, "device", f); ok {
		if len(errs) > 0 {
			live = true
		}
		for dev, e := range errs {
			bump(dev, healthscore.HingeN(e, 0.1, 5), "Interface errors/discards "+healthscore.Round2s(e)+"/s on "+dev)
		}
	}
	if cpu, ok := s.qVecByScoped(ctx, `max by (device) (device_cpu_percent)`, "device", f); ok {
		if len(cpu) > 0 {
			live = true
		}
		for dev, c := range cpu {
			bump(dev, healthscore.HingeN(c, 70, 95), "CPU "+healthscore.Pct0(c)+" on "+dev)
		}
	}
	if mem, ok := s.qVecByScoped(ctx, `max by (device) (device_mem_percent)`, "device", f); ok {
		for dev, mv := range mem {
			bump(dev, healthscore.HingeN(mv, 75, 95), "Memory "+healthscore.Pct0(mv)+" on "+dev)
		}
	}
	res.Live = live
	for dev, d := range devs {
		if d.b > res.Badness {
			res.Badness = d.b
		}
		if d.b >= 0.40 {
			res.Contribs = append(res.Contribs, healthscore.Contribution{
				SignalClass: "device_health", Entity: dev, Badness: d.b, Reason: d.reason,
			})
		}
	}
	return res
}

// fetchPathHealthClass: customer path latency/jitter/loss via probes, reusing the
// PBH severity curves. GUARDRAIL: internal monitoring targets (env list) are
// excluded so internal self-probes never drive customer health. (Full scope/
// authority-based exclusion is V1 when probe metrics carry those labels.)
func (s *server) fetchPathHealthClass(ctx context.Context, f []string) healthscore.ClassResult {
	return s.fetchPathHealthClassFiltered(ctx, nil, f)
}

// fetchPathHealthClassFiltered is fetchPathHealthClass restricted to an allowed
// destination set (nil = all paths; empty = none — used by the per-service
// scope, where only the service's BOUND probes/paths may drive its score).
func (s *server) fetchPathHealthClassFiltered(ctx context.Context, allow map[string]bool, f []string) healthscore.ClassResult {
	res := healthscore.ClassResult{Class: "path_health"}
	if allow != nil && len(allow) == 0 {
		return res // no bound paths → class honestly not live
	}
	internal := map[string]bool{}
	for _, t := range strings.Split(envOr("HEALTH_INTERNAL_PROBE_TARGETS", ""), ",") {
		if t = strings.TrimSpace(t); t != "" {
			internal[t] = true
		}
	}
	curLat, ok := s.qVecByScoped(ctx, `quantile_over_time(0.95, probe_rtt_ms[5m])`, "dst", f)
	baseP50, _ := s.qVecByScoped(ctx, `quantile_over_time(0.50, probe_rtt_ms[7d])`, "dst", f)
	baseP99, _ := s.qVecByScoped(ctx, `quantile_over_time(0.99, probe_rtt_ms[7d])`, "dst", f)
	loss, _ := s.qVecByScoped(ctx, `avg_over_time(probe_loss_pct[5m])`, "dst", f)
	if !ok {
		return res
	}
	considered := 0
	for dst, lat := range curLat {
		if internal[dst] || internal[hostOnly(dst)] {
			continue // internal monitoring target — excluded from customer health
		}
		if allow != nil && !allow[dst] && !allow[hostOnly(dst)] {
			continue // not bound to the scoped service
		}
		considered++
		var b float64
		if sev, sevOK := pathgraph.SeverityPctDistance(lat, baseP50[dst], baseP99[dst]); sevOK {
			b = sev
		}
		if lb := pathgraph.LossSeverity(loss[dst], 0); lb > b {
			b = lb
		}
		if b > res.Badness {
			res.Badness = b
		}
		if b >= 0.40 {
			res.Contribs = append(res.Contribs, healthscore.Contribution{
				SignalClass: "path_health", Entity: dst, Badness: b,
				Reason: "Path to " + dst + " worse than its normal baseline",
			})
		}
	}
	res.Live = considered > 0 // only live if there is a customer-facing path to judge
	return res
}

// fetchCorrelationClass: ONLY trusted, customer-facing RCA objects drive health —
// confirmed/suspected, grounded, cross-plane, not low-authority, not debug-excluded,
// not undetermined. Weak/probe-only/internal objects are excluded (guardrail).
// Best-effort: a ClickHouse/engine outage drops the class, never errors the strip.
func (s *server) fetchCorrelationClass(r *http.Request, site string) healthscore.ClassResult {
	res := healthscore.ClassResult{Class: "correlation"}
	// Bounded read (#100 hardening): served ENTIRELY from the corr_current HOT
	// projection — one narrow row per object, triage badges included as narrow
	// columns, so neither history nor the hypotheses blob is ever read here.
	// Only the edges decorate touches another table, keyed by the picked set.
	// The old shapes — o.hypotheses through a full-table LIMIT-1-BY sort and a
	// whole-table corr_edges GROUP BY — are exactly what pinned ClickHouse.
	sql := `
WITH picked AS (
     SELECT correlation_id, version, created_at
       FROM netops.corr_current FINAL
      WHERE state='open' AND verdict_tier IN ('confirmed','suspected')
        AND top_hypothesis != 'undetermined'
      ORDER BY created_at DESC
      LIMIT 200
)
SELECT toString(c.correlation_id) AS id, c.top_hypothesis AS hyp, c.top_confidence AS conf,
       c.verdict_tier AS tier, ` + chschema.ISO("c.created_at") + ` AS created_at,
       coalesce(e.grounding,'none') AS grounding,
       c.plane_count AS planes,
       c.debug_excluded > 0 AS debug_excluded,
       c.low_authority > 0 AS low_authority
  FROM netops.corr_current AS c FINAL
  LEFT JOIN (SELECT correlation_id, version, arrayStringConcat(arraySort(groupUniqArray(grounding_kind)),'+') AS grounding
               FROM netops.corr_edges
              WHERE (correlation_id, version) IN (SELECT correlation_id, version FROM picked)
              GROUP BY correlation_id, version) AS e
    ON e.correlation_id = c.correlation_id AND e.version = c.version
 WHERE (c.correlation_id, c.version) IN (SELECT correlation_id, version FROM picked)
 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		return res // engine/CH down → class not live (strip still scores from infra)
	}
	res.Live = true
	for _, row := range rows {
		grounding, _ := row["grounding"].(string)
		if grounding == "" || grounding == "none" {
			continue // ungrounded → not trusted
		}
		if truthy(row["debug_excluded"]) || truthy(row["low_authority"]) {
			continue // internal/test or low-authority → excluded from customer health
		}
		if asFloat(row["planes"]) < 2 {
			continue // single-plane → not strong enough to drive customer health
		}
		conf := asFloat(row["conf"])
		if conf > res.Badness {
			res.Badness = conf
		}
		hyp, _ := row["hyp"].(string)
		created, _ := row["created_at"].(string)
		res.Contribs = append(res.Contribs, healthscore.Contribution{
			SignalClass: "correlation", Entity: hyp, Badness: conf,
			Reason: "Trusted RCA: " + hyp + " (" + asString(row["tier"]) + ")", Timestamp: created,
		})
	}
	return res
}

// ── small helpers ────────────────────────────────────────────────────────────

func hostOnly(dst string) string {
	if i := strings.LastIndex(dst, ":"); i > 0 {
		return dst[:i]
	}
	return dst
}
