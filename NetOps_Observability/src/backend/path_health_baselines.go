// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// path_health_baselines.go — Path Behavior Health V1 baseline precompute
// (docs/design/path-behavior-health.md §9, tier 2 "this path at this time of
// week"). A ticker (FEATURE_PATH_BASELINES=true, PATH_BASELINE_INTERVAL
// seconds, default 900) pulls the SAME VictoriaMetrics probe series
// /api/paths/health scores against as one bounded range query per metric,
// buckets the samples by hour-of-week (UTC, Monday 00:00 = 0), computes exact
// p50/p90/p95/p99 per (path, bucket), and writes netops.path_baselines.
// handlePathsHealth then feeds the current bucket into the §4 cascade as the
// pathgraph.BaselinePathHour tier, above the live per-path tier 3.
//
// HONEST SUBSET — tier 1 (pathgraph.BaselinePathRouteHour) is NOT populated: there is no
// route-conditioned metric source. The VM probe series carry no route/
// fingerprint label, and the traceroute path_observations stream does not
// carry the probe RTT series being scored — conditioning these percentiles on
// a fingerprint would fabricate a correlation we never measured. The
// route_fingerprint column exists ('' on every row) so tier 1 lands without a
// migration when probes learn route labels; until then pathgraph.BaselinePathRouteHour
// stays a declared stub in the cascade.
//
// Rows are written with tenant_id='' under the STRICT row policy — the house
// rule pins EVERY netops.path_* table strict (TestCorrRowPoliciesStrict), so
// an untagged row is platform-only at the database layer, and no tenant scope
// can reach it. The tier-2 reader therefore fetches at an explicit platform
// scope, and the caller's boundary on that read is the SET OF PATH IDS it is
// allowed to name: fetchHourBaselines takes the path ids the caller's own
// scoped VictoriaMetrics read produced and puts them in the WHERE clause, so
// the read can return a bucket for a path the caller already measures and
// nothing else. An empty set reads nothing.
//
// The old justification for asking for every path_id was that these rows are
// pure derivations of "the SAME unlabelled VM probe series /api/paths/health
// already serves unscoped". That premise died when the endpoint's eight
// baseline queries gained the caller's device boundary (path_health_api.go):
// the series are no longer served unscoped, so neither is their precompute.
//
// WHAT IS STILL SHARED, stated honestly: a bucket's percentiles are computed
// across every probe to that destination, whoever ran it. Two tenants probing
// the same public destination therefore score against one common baseline, and
// its sample_count counts both. That is the untenanted precompute's own shape,
// not this reader's: when probe metrics gain tenant labels the precompute must
// stamp them and this read must narrow on tenant_id instead of path id.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"netops/backend/internal/chschema"
	"netops/backend/internal/seriesroll"
	"netops/backend/models"
	"netops/backend/pathgraph"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pathBaselineMinBucketSamples = 24   // ≥ ~2 weeks of 5-min samples in an hour bucket
	pathBaselineMaxSeries        = 1000 // bound the precompute fan-out
	pathBaselineStepSec          = 300
)

func pathBaselineSchemaDDL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS netops.path_baselines
(
    tenant_id         LowCardinality(String) DEFAULT '',
    path_id           String,
    route_fingerprint String DEFAULT '',
    hour_of_week      UInt8,
    latency_p50       Float64 DEFAULT 0,
    latency_p90       Float64 DEFAULT 0,
    latency_p95       Float64 DEFAULT 0,
    latency_p99       Float64 DEFAULT 0,
    jitter_p50        Float64 DEFAULT 0,
    jitter_p90        Float64 DEFAULT 0,
    jitter_p95        Float64 DEFAULT 0,
    jitter_p99        Float64 DEFAULT 0,
    loss_p50          Float64 DEFAULT 0,
    loss_p95          Float64 DEFAULT 0,
    sample_count      UInt32 DEFAULT 0,
    samples_total     UInt32 DEFAULT 0,
    window_days       UInt16 DEFAULT 0,
    computed_at       DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(computed_at)
PARTITION BY (tenant_id)
ORDER BY (tenant_id, path_id, route_fingerprint, hour_of_week)
TTL computed_at + INTERVAL 14 DAY
SETTINGS index_granularity = 8192`,

		// STRICT (the path_* family rule): untagged precompute rows are
		// platform-only at the DB layer; the tier-2 reader is the one sanctioned
		// consumer (see file header).
		chschema.StrictRowPolicyDDL("path_baselines"),
	}
}

// hourOfWeek buckets a UTC instant: Monday 00:00 UTC = 0 … Sunday 23:00 = 167.
func hourOfWeek(t time.Time) int {
	t = t.UTC()
	return (int(t.Weekday())+6)%7*24 + t.Hour()
}

// quantileAt returns the q-quantile of an ASCENDING-sorted slice (nearest-rank
// with linear interpolation). 0 for an empty slice.
func quantileAt(sorted []float64, q float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sorted[0]
	}
	pos := q * float64(n-1)
	lo := int(pos)
	if lo >= n-1 {
		return sorted[n-1]
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[lo+1]*frac
}

// vmRangeSeries is one query_range series: dst label + (unix, value) points.
type vmRangeSeries struct {
	Dst    string
	Points [][2]float64
}

// vmRangeByDst runs a VictoriaMetrics range query and keys each series by its
// dst label (the probe path identity). Bounded: response capped, series
// capped, per-call timeout.
func (s *server) vmRangeByDst(ctx context.Context, query string, start, end time.Time, stepSec int) ([]vmRangeSeries, error) {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))
	endpoint := trimRightSlash(base) + "/api/v1/query_range?query=" + url.QueryEscape(query) +
		"&start=" + strconv.FormatInt(start.Unix(), 10) +
		"&end=" + strconv.FormatInt(end.Unix(), 10) +
		"&step=" + strconv.Itoa(stepSec)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := backendHTTPClient(60 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("victoriametrics range status %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, err
	}
	series := make([]vmRangeSeries, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		if len(series) >= pathBaselineMaxSeries {
			log.Printf("path-baselines: series cap %d reached for %q — remaining series skipped this tick", pathBaselineMaxSeries, query)
			break
		}
		dst := r.Metric["dst"]
		if dst == "" {
			continue
		}
		pts := make([][2]float64, 0, len(r.Values))
		for _, v := range r.Values {
			ts, tok := v[0].(float64)
			sv, sok := v[1].(string)
			if !tok || !sok {
				continue
			}
			f, err := strconv.ParseFloat(sv, 64)
			if err != nil {
				continue
			}
			pts = append(pts, [2]float64{ts, f})
		}
		series = append(series, vmRangeSeries{Dst: dst, Points: pts})
	}
	return series, nil
}

// pathBaselineRow is one computed (path, hour-of-week) percentile row.
type pathBaselineRow struct {
	PathID       string
	HourOfWeek   int
	Latency      [4]float64 // p50 p90 p95 p99
	Jitter       [4]float64
	Loss         [2]float64 // p50 p95
	SampleCount  int
	SamplesTotal int
	WindowDays   int
}

// computePathBaselines is the PURE bucketing/quantile core (unit-tested):
// latency drives row existence (a bucket without enough latency samples is not
// written — readiness over fabrication); jitter/loss decorate when present.
func computePathBaselines(latency, jitter, loss []vmRangeSeries, windowDays int) []pathBaselineRow {
	type buckets struct {
		lat, jit, los map[int][]float64
		total         int
	}
	byDst := map[string]*buckets{}
	get := func(dst string) *buckets {
		b := byDst[dst]
		if b == nil {
			b = &buckets{lat: map[int][]float64{}, jit: map[int][]float64{}, los: map[int][]float64{}}
			byDst[dst] = b
		}
		return b
	}
	fold := func(series []vmRangeSeries, pick func(*buckets) map[int][]float64, countTotal bool) {
		for _, sr := range series {
			key := hostOnly(sr.Dst)
			b := get(key)
			m := pick(b)
			for _, p := range sr.Points {
				h := hourOfWeek(time.Unix(int64(p[0]), 0))
				m[h] = append(m[h], p[1])
			}
			if countTotal {
				b.total += len(sr.Points)
			}
		}
	}
	fold(latency, func(b *buckets) map[int][]float64 { return b.lat }, true)
	fold(jitter, func(b *buckets) map[int][]float64 { return b.jit }, false)
	fold(loss, func(b *buckets) map[int][]float64 { return b.los }, false)

	var dsts []string
	for d := range byDst {
		dsts = append(dsts, d)
	}
	sort.Strings(dsts) // deterministic output (testability)

	var rows []pathBaselineRow
	for _, dst := range dsts {
		b := byDst[dst]
		for h := 0; h < 168; h++ {
			lat := b.lat[h]
			if len(lat) < pathBaselineMinBucketSamples {
				continue
			}
			sort.Float64s(lat)
			row := pathBaselineRow{
				PathID: dst, HourOfWeek: h,
				SampleCount: len(lat), SamplesTotal: b.total, WindowDays: windowDays,
			}
			for i, q := range []float64{0.50, 0.90, 0.95, 0.99} {
				row.Latency[i] = quantileAt(lat, q)
			}
			if jit := b.jit[h]; len(jit) >= pathBaselineMinBucketSamples {
				sort.Float64s(jit)
				for i, q := range []float64{0.50, 0.90, 0.95, 0.99} {
					row.Jitter[i] = quantileAt(jit, q)
				}
			}
			if los := b.los[h]; len(los) > 0 {
				sort.Float64s(los)
				row.Loss[0] = quantileAt(los, 0.50)
				row.Loss[1] = quantileAt(los, 0.95)
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// insertPathBaselines writes the rows (tenant_id=”, see file header).
// ReplacingMergeTree on (path, fingerprint, hour) keyed by computed_at makes
// each tick's re-write idempotent.
func insertPathBaselines(ctx context.Context, rows []pathBaselineRow) error {
	if len(rows) == 0 {
		return nil
	}
	now := time.Now().UTC().Unix()
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"tenant_id": "", "path_id": r.PathID, "route_fingerprint": "",
			"hour_of_week": r.HourOfWeek,
			"latency_p50":  r.Latency[0], "latency_p90": r.Latency[1], "latency_p95": r.Latency[2], "latency_p99": r.Latency[3],
			"jitter_p50": r.Jitter[0], "jitter_p90": r.Jitter[1], "jitter_p95": r.Jitter[2], "jitter_p99": r.Jitter[3],
			"loss_p50": r.Loss[0], "loss_p95": r.Loss[1],
			"sample_count": r.SampleCount, "samples_total": r.SamplesTotal,
			"window_days": r.WindowDays, "computed_at": now,
		})
	}
	body, err := jsonEachRow("netops.path_baselines", out)
	if err != nil {
		return err
	}
	return chWorkerExec(ctx, body)
}

// pathBaselineTick runs one precompute pass: three bounded VM range queries →
// bucket → insert. Latency falls back to synthetic ICMP for dsts with no
// probe_rtt series (same fallback the live endpoint applies).
func (s *server) pathBaselineTick(ctx context.Context) error {
	windowDays, _ := strconv.Atoi(envOr("PATH_BASELINE_WINDOW_DAYS", "28")) // best-effort: non-numeric → 0
	if windowDays < 7 || windowDays > 60 {
		windowDays = 28
	}
	end := time.Now().UTC()
	start := end.Add(-time.Duration(windowDays) * 24 * time.Hour)

	latency, err := s.vmRangeByDst(ctx, "probe_rtt_ms", start, end, pathBaselineStepSec)
	if err != nil {
		return fmt.Errorf("latency range: %w", err)
	}
	seen := map[string]bool{}
	for _, sr := range latency {
		seen[hostOnly(sr.Dst)] = true
	}
	if synth, err := s.vmRangeByDst(ctx, "synthetic_icmp_rtt_ms", start, end, pathBaselineStepSec); err == nil {
		for _, sr := range synth {
			if !seen[hostOnly(sr.Dst)] {
				latency = append(latency, sr)
			}
		}
	}
	jitter, err := s.vmRangeByDst(ctx, "probe_pdv_ms", start, end, pathBaselineStepSec)
	if err != nil {
		jitter = nil // jitter is decoration; latency alone still yields a baseline
	}
	loss, err := s.vmRangeByDst(ctx, "probe_loss_pct", start, end, pathBaselineStepSec)
	if err != nil {
		loss = nil
	}
	rows := computePathBaselines(latency, jitter, loss, windowDays)
	if len(rows) == 0 {
		return nil // no path has enough bucketed history yet — honest no-op
	}
	if err := insertPathBaselines(ctx, rows); err != nil {
		return fmt.Errorf("insert %d baseline rows: %w", len(rows), err)
	}
	return nil
}

// startPathBaselinePrecompute wires the ticker (FEATURE_PATH_BASELINES).
func (s *server) startPathBaselinePrecompute(ctx context.Context) {
	if envOr("CLICKHOUSE_URL", "") == "" {
		log.Printf("path-baselines: FEATURE_PATH_BASELINES set but CLICKHOUSE_URL is empty — precompute not started")
		return
	}
	interval := envDurationSeconds("PATH_BASELINE_INTERVAL", 900)
	logInfo("path-baselines", "hour-of-week baseline precompute enabled", map[string]any{"interval": interval.String()})
	go func() {
		if err := s.pathBaselineTick(ctx); err != nil {
			log.Printf("path-baselines: initial tick: %v", err)
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.pathBaselineTick(ctx); err != nil {
					log.Printf("path-baselines: tick: %v", err)
				}
			}
		}
	}()
}

// fetchHourBaselines reads the CURRENT hour-of-week bucket for the paths the
// CALLER can see (tier 2 of the cascade). Best-effort: any error yields nil and
// the cascade falls through to tiers 3–5 exactly as before. route_fingerprint=”
// rows only (tier 1 is not populated — see file header).
//
// pathIDs is the set of path ids the caller's OWN scoped VictoriaMetrics read
// produced, and it is the tenant boundary on this read. The precompute rows are
// untagged (tenant_id=”), so the strict row policy cannot narrow them and the
// scope has to be the platform one; the SQL therefore names the caller's paths
// explicitly. An empty set reads nothing at all rather than every path in the
// table — which is also what a denied operator gets, because the sentinel
// filter leaves that caller with no paths to name.
//
// Before this the read asked for EVERY path_id at the platform scope, and its
// only protection was that the handler happened to look the map up by key. The
// file header justified that on the grounds that the endpoint "already serves
// these series unscoped" — a premise that stopped being true the moment the
// eight baseline queries above gained the caller's device boundary.
func (s *server) fetchHourBaselines(r *http.Request, now time.Time, pathIDs []string) map[string]pathgraph.PathBaseline {
	if envOr("CLICKHOUSE_URL", "") == "" || len(pathIDs) == 0 {
		return nil
	}
	sql := `SELECT path_id, latency_p50, latency_p99, jitter_p50, jitter_p99,
       sample_count, samples_total, window_days
  FROM netops.path_baselines FINAL
 WHERE hour_of_week = ` + strconv.Itoa(hourOfWeek(now)) + ` AND route_fingerprint = '' AND tenant_id = ''
   AND path_id IN (` + sqlInList(pathIDs) + `)
 LIMIT ` + strconv.Itoa(pathBaselineMaxSeries) + ` FORMAT JSON`
	// Explicit platform scope (the rows are untagged, so no tenant scope can
	// reach them), hard-bounded to the untagged precompute rows for the caller's
	// OWN paths.
	rows, err := s.chRowsScope(r.Context(), "__all__", sql, "api:/api/paths/health")
	if err != nil {
		return nil
	}
	out := make(map[string]pathgraph.PathBaseline, len(rows))
	for _, row := range rows {
		id, _ := row["path_id"].(string)
		if id == "" {
			continue
		}
		p50, p99 := asFloat(row["latency_p50"]), asFloat(row["latency_p99"])
		if p99 <= p50 {
			continue // degenerate bucket — scoring against it would divide by zero trust
		}
		out[id] = pathgraph.PathBaseline{
			Source:      pathgraph.BaselinePathHour,
			Latency:     pathgraph.MetricBaseline{P50: p50, P99: p99},
			Jitter:      pathgraph.MetricBaseline{P50: asFloat(row["jitter_p50"]), P99: asFloat(row["jitter_p99"])},
			SampleCount: int(asFloat(row["samples_total"])),
			Days:        asFloat(row["window_days"]),
			RouteStable: true, // no route-change signal wired yet (tier-1 gap)
		}
	}
	return out
}

func trimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// ── Seasonal roll-up (tracker 337 N-H6 PR 2) ─────────────────────────────────
//
// The second baseline precompute in this file, for the same reason the first
// lives here: a background job with no caller (FEATURE_SEASONAL_ROLLUP). Once
// per closed hour it reads each eligible metric's p10/p50/p90 and count from
// VictoriaMetrics — fleet-wide, because there is no principal — and writes
// netops.series_hourly with EVERY row stamped by its device's inventory owner:
// an unowned or ambiguous device is skipped and counted, never written
// untagged (the table's row policy is STRICT). internal/seriesroll owns the
// bounds and counters; this is only its VictoriaMetrics, ClickHouse and
// inventory adapters.

// seasonalRollMetrics are the device-owned catalog metrics whose series the
// roll-up keeps. Each expression and its key labels are the planner's own
// template for that metric (internal/nlquery/plan/templates.go), so a stored
// row's entity key is the key the seasonal reference looks up. Probe series
// (keyed by destination, no device) and the workspace check series (tenant
// labelled) have no device owner and are not rolled up.
func seasonalRollMetrics() []seriesroll.Metric {
	dev := []string{"device"}
	ifl := []string{"device", "ifName"}
	cir := []string{"circuit", "local_device"}
	return []seriesroll.Metric{
		{Name: "cpu_util_pct", Expr: "avg by (device) (device_cpu_percent)", Labels: dev},
		{Name: "mem_util_pct", Expr: "device_mem_percent", Labels: dev},
		{Name: "if_in_bps", Expr: "rate(device_if_in_octets[5m]) * 8", Labels: ifl},
		{Name: "if_out_bps", Expr: "rate(device_if_out_octets[5m]) * 8", Labels: ifl},
		{Name: "if_in_errors", Expr: "rate(device_if_in_errors[5m])", Labels: ifl},
		{Name: "if_out_errors", Expr: "rate(device_if_out_errors[5m])", Labels: ifl},
		{Name: "if_in_discards", Expr: "rate(device_if_in_discards[5m])", Labels: ifl},
		{Name: "if_out_discards", Expr: "rate(device_if_out_discards[5m])", Labels: ifl},
		{Name: "circuit_loss_pct", Expr: "circuit_loss_pct", Labels: cir},
		{Name: "circuit_latency_ms", Expr: "circuit_latency_ms", Labels: cir},
		{Name: "circuit_jitter_ms", Expr: "circuit_jitter_ms", Labels: cir},
		{Name: "circuit_qoe", Expr: "circuit_qoe", Labels: cir},
	}
}

// seasonalRollVM is the roll-up's VictoriaMetrics read: the platform's unscoped
// door (this file is on vmUnscopedAllowlist for exactly this job).
type seasonalRollVM struct{ s *server }

func (v seasonalRollVM) Query(ctx context.Context, query string) ([]seriesroll.Sample, error) {
	samples, err := v.s.vmInstantUnscoped(ctx, query)
	if err != nil {
		return nil, err
	}
	out := make([]seriesroll.Sample, len(samples))
	for i, sm := range samples {
		out[i] = seriesroll.Sample{Labels: sm.Labels, Value: sm.Value}
	}
	return out, nil
}

// seasonalRollStore writes one hour's rows (ReplacingMergeTree(version): a re-roll
// of the hour replaces).
type seasonalRollStore struct{}

func (seasonalRollStore) Insert(ctx context.Context, rows []seriesroll.Row) error {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"tenant_id": r.Tenant, "metric": r.Metric, "entity_key": r.EntityKey, "hour": r.Hour.Unix(),
			"p10": r.P10, "p50": r.P50, "p90": r.P90, "n": r.N, "version": r.Version,
		})
	}
	body, err := jsonEachRow("netops.series_hourly", out)
	if err != nil {
		return err
	}
	return chWorkerExec(ctx, body)
}

// seasonalRollOwners answers a series' device label with the device's inventory
// owner, from a snapshot refreshed at most every seasonalRollOwnersTTL. A label
// that names devices of TWO different owners (the same name in two tenants)
// is ambiguous and owned by nobody — the series is skipped, never guessed.
type seasonalRollOwners struct {
	s     *server
	mu    sync.Mutex
	at    time.Time
	owner map[string]string
}

const seasonalRollOwnersTTL = 5 * time.Minute

func newSeasonalRollOwners(s *server) *seasonalRollOwners { return &seasonalRollOwners{s: s} }

func (o *seasonalRollOwners) Owner(device string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.owner == nil || time.Since(o.at) > seasonalRollOwnersTTL {
		o.owner = seasonalRollOwnerIndex(o.s.discovery.Devices())
		o.at = time.Now()
	}
	t, ok := o.owner[device]
	return t, ok && t != ""
}

// seasonalRollOwnerIndex maps each device id and name to its owner tenant; a key
// two owners share maps to "" (ambiguous).
func seasonalRollOwnerIndex(devs []models.Device) map[string]string {
	idx := map[string]string{}
	put := func(k, t string) {
		if k == "" {
			return
		}
		if prev, seen := idx[k]; seen && prev != t {
			idx[k] = ""
			return
		}
		idx[k] = t
	}
	for _, d := range devs {
		t := deviceTenant(d)
		put(d.ID, t)
		put(strings.TrimSpace(d.Name), t)
	}
	return idx
}

// startSeasonalRollup wires the roll-up (FEATURE_SEASONAL_ROLLUP).
func (s *server) startSeasonalRollup(ctx context.Context) {
	if envOr("CLICKHOUSE_URL", "") == "" {
		log.Printf("seasonal-rollup: FEATURE_SEASONAL_ROLLUP set but CLICKHOUSE_URL is empty — roll-up not started")
		return
	}
	roller, err := seriesroll.New(seriesroll.Config{Metrics: seasonalRollMetrics()}, seasonalRollVM{s}, seasonalRollStore{}, newSeasonalRollOwners(s))
	if err != nil {
		log.Printf("seasonal-rollup: not started: %v", err)
		return
	}
	s.seasonalRoll.Store(roller)
	interval := envDurationSeconds("SEASONAL_ROLLUP_INTERVAL", 900)
	logInfo("seasonal-rollup", "hourly metric roll-up enabled", map[string]any{"interval": interval.String(), "metrics": len(seasonalRollMetrics())})
	go roller.Run(ctx, interval, func(err error) {
		logWarn("seasonal-rollup", "hour not written", map[string]any{"error": err.Error()})
	})
}

// writeSeasonalRollupMetrics exposes the roll-up's counters on /metrics (§10:
// every skip and failure is observable).
func (s *server) writeSeasonalRollupMetrics(w io.Writer) {
	r := s.seasonalRoll.Load()
	if r == nil {
		return
	}
	for _, m := range []struct {
		name, help string
		v          int64
	}{
		{"netops_seasonal_rollup_hours_total", "Hours the seasonal roll-up wrote.", r.Stats.Hours.Load()},
		{"netops_seasonal_rollup_rows_total", "Rows the seasonal roll-up wrote.", r.Stats.Rows.Load()},
		{"netops_seasonal_rollup_unowned_total", "Series skipped because their device has no (or an ambiguous) inventory owner.", r.Stats.Unowned.Load()},
		{"netops_seasonal_rollup_cap_dropped_total", "Series dropped past the per-hour series cap.", r.Stats.CapDropped.Load()},
		{"netops_seasonal_rollup_vm_errors_total", "Metric reads that failed (that metric skipped for the hour).", r.Stats.VMErrors.Load()},
		{"netops_seasonal_rollup_store_errors_total", "Hour writes to ClickHouse that failed.", r.Stats.StoreErrors.Load()},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", m.name, m.help, m.name, m.name, m.v)
	}
}
