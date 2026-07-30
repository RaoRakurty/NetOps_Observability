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
// an untagged row is platform-only at the database layer. The tier-2 reader
// therefore fetches at an explicit platform scope but hard-bounds the SQL to
// tenant_id='' AND route_fingerprint='' precompute rows: those rows are pure
// derivations (percentiles) of the SAME unlabelled VM probe series that
// /api/paths/health already serves to every infra-read principal, so the read
// exposes nothing the endpoint doesn't. When probe metrics gain tenant
// labels, the precompute must stamp them and this read must become
// caller-scoped.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"netops/backend/internal/chschema"
	"netops/backend/pathgraph"
	"sort"
	"strconv"
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
	windowDays, _ := strconv.Atoi(envOr("PATH_BASELINE_WINDOW_DAYS", "28"))
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

// fetchHourBaselines reads the CURRENT hour-of-week bucket for every path
// (tier 2 of the cascade). Best-effort: any error yields nil and the cascade
// falls through to tiers 3–5 exactly as before. route_fingerprint=” rows only
// (tier 1 is not populated — see file header).
func (s *server) fetchHourBaselines(r *http.Request, now time.Time) map[string]pathgraph.PathBaseline {
	if envOr("CLICKHOUSE_URL", "") == "" {
		return nil
	}
	sql := `SELECT path_id, latency_p50, latency_p99, jitter_p50, jitter_p99,
       sample_count, samples_total, window_days
  FROM netops.path_baselines FINAL
 WHERE hour_of_week = ` + strconv.Itoa(hourOfWeek(now)) + ` AND route_fingerprint = '' AND tenant_id = ''
 LIMIT ` + strconv.Itoa(pathBaselineMaxSeries) + ` FORMAT JSON`
	// Explicit platform scope, hard-bounded to untagged precompute rows — see
	// the file header for why this is not a tenant leak (strict path_* policy
	// + rows derived from series this endpoint already serves unscoped).
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
