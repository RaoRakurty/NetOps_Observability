// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// stats.go — turning the experience time series into WindowStats.
//
// The api never lets a caller supply PromQL. Every expression here is BUILT
// from a closed metric vocabulary plus a server-derived tenant filter, which is
// the cloud_metrics_series.go precedent and the reason this surface cannot be
// used to read another tenant's series (§3, §3a rule 4).
//
// TENANT SCOPING (the one that bit the existing probe metrics): the platform's
// generic metricsScopeFilters keys on device/hostname/source labels, and the
// legacy synthetic_*/probe_* series carry none of them — so a scoped tenant sees
// nothing from them at all. The dem_* series therefore carry an explicit
// `tenant` label written by the prober, and this package filters on THAT. A
// non-cross caller always gets `{tenant="…"}`; there is no code path that omits
// it (TenantFilter refuses an empty tenant for a non-cross caller).

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// The closed metric vocabulary. Nothing outside this list is ever queried, and
// nothing outside dem's own emitter writes these names.
const (
	MetricSuccess         = "dem_probe_success"
	MetricLatencyMs       = "dem_probe_latency_ms"
	MetricLossPct         = "dem_probe_loss_pct"
	MetricTTFBMs          = "dem_probe_ttfb_ms"
	MetricPathFingerprint = "dem_path_fingerprint"
	MetricPathHops        = "dem_path_hops"
	MetricTargets         = "dem_targets"
	// The budget gauges the prober publishes beside each measurement, so the
	// alert rules are a pure PromQL comparison that keeps working with the api
	// down. MetricLatencyBudgetMs is emitted ONLY when the operator declared a
	// latency budget — a rule must never fire against a threshold nobody set.
	MetricAvailBudgetPct  = "dem_target_availability_budget_pct"
	MetricLatencyBudgetMs = "dem_target_latency_budget_ms"
)

// Windows the API accepts. Bounded on purpose (§9): an operator-supplied range
// is an unbounded query against a shared time-series database.
const (
	Window1h  = "1h"
	Window24h = "24h"
)

// MaxScoredTargets bounds one scoring request. It matches the catalogue's
// per-tenant cap, so a full tenant is exactly one page of work and never more.
const MaxScoredTargets = MaxTargetsPerTenant

// ParseWindow maps the requested window label to its duration, refusing
// anything else rather than silently substituting a default.
func ParseWindow(raw string) (string, time.Duration, error) {
	switch strings.TrimSpace(raw) {
	case "", Window1h:
		return Window1h, time.Hour, nil
	case Window24h:
		return Window24h, 24 * time.Hour, nil
	default:
		return "", 0, fmt.Errorf("window must be %s or %s", Window1h, Window24h)
	}
}

// Sample is one time-series result row.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Querier is the metrics-backend seam. The integrator injects the platform's
// VictoriaMetrics instant-query client; this package never opens a socket.
//
// filters are VictoriaMetrics `extra_filters[]` entries — series selectors AND'd
// into every metric in the expression by the backend, which is why they cannot
// be evaded by a crafted expression the way a string-rewritten PromQL could.
type Querier interface {
	Instant(ctx context.Context, expr string, filters []string) ([]Sample, error)
}

// tenantLabelRe is what a tenant id must look like before it may be embedded in
// a series selector. The ids the platform mints are hex/slug shaped; refusing
// anything else means no quote, brace or backslash can ever reach the selector.
var tenantLabelRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// TenantFilter builds the extra_filters[] entry that scopes every dem query.
//
// FAIL CLOSED: a non-cross caller with no usable tenant gets a match-nothing
// selector, never an unfiltered query. That is the metrics_query.go
// __netops_no_visible_device__ sentinel idiom, and the reason a wiring mistake
// here degrades to "no data" rather than to "everyone's data".
func TenantFilter(tenant string, cross bool) []string {
	if cross {
		return nil
	}
	t := normTenant(tenant)
	if !tenantLabelRe.MatchString(t) {
		return []string{`{tenant="__netops_no_visible_tenant__"}`}
	}
	return []string{fmt.Sprintf(`{tenant=%q}`, t)}
}

// FetchWindow collects the per-target statistics for one tenant scope over one
// window. Six bounded instant queries, each folded by the `target` label; the
// site/app grouping is done in Go from the catalogue, so a relabelled target
// cannot smear two tenants' rows together.
//
// A query that fails is reported, never silently treated as zero: the caller
// turns the error into ReasonQueryFailed, which the UI renders as "not
// measured — the metrics store did not answer".
func FetchWindow(ctx context.Context, q Querier, tenant string, cross bool, window string) (map[string]WindowStats, error) {
	if q == nil {
		return nil, errors.New("dem: no metrics backend is configured")
	}
	label, _, err := ParseWindow(window)
	if err != nil {
		return nil, err
	}
	f := TenantFilter(tenant, cross)
	out := map[string]WindowStats{}

	// fold applies one query's rows into the accumulator, keyed by target.
	fold := func(expr string, set func(*WindowStats, float64, map[string]string)) error {
		rows, err := q.Instant(ctx, expr, f)
		if err != nil {
			return err
		}
		if len(rows) > MaxScoredTargets*4 {
			// A response far larger than the catalogue can be is a signal the
			// filter did not apply. Refuse it rather than rendering it.
			return fmt.Errorf("dem: metrics response holds %d series, over the bound for %d targets", len(rows), MaxScoredTargets)
		}
		for _, r := range rows {
			id := r.Labels["target"]
			if id == "" {
				continue
			}
			st := out[id]
			set(&st, r.Value, r.Labels)
			out[id] = st
		}
		return nil
	}

	type step struct {
		expr string
		set  func(*WindowStats, float64, map[string]string)
	}
	steps := []step{
		{fmt.Sprintf(`sum by (target) (count_over_time(%s[%s]))`, MetricSuccess, label),
			func(s *WindowStats, v float64, _ map[string]string) { s.Samples = int(v + 0.5) }},
		{fmt.Sprintf(`sum by (target) (sum_over_time(%s[%s]))`, MetricSuccess, label),
			func(s *WindowStats, v float64, _ map[string]string) { s.Successes = int(v + 0.5) }},
		{fmt.Sprintf(`sum by (target) (count_over_time(%s[%s]))`, MetricLatencyMs, label),
			func(s *WindowStats, v float64, _ map[string]string) { s.LatencySamples = int(v + 0.5) }},
		{fmt.Sprintf(`max by (target) (quantile_over_time(0.50, %s[%s]))`, MetricLatencyMs, label),
			func(s *WindowStats, v float64, _ map[string]string) { s.LatencyP50Ms = v }},
		{fmt.Sprintf(`max by (target) (quantile_over_time(0.95, %s[%s]))`, MetricLatencyMs, label),
			func(s *WindowStats, v float64, _ map[string]string) { s.LatencyP95Ms = v }},
		{fmt.Sprintf(`sum by (target) (count_over_time(%s[%s]))`, MetricPathFingerprint, label),
			func(s *WindowStats, v float64, _ map[string]string) { s.PathSamples = int(v + 0.5) }},
		{fmt.Sprintf(`sum by (target) (changes(%s[%s]))`, MetricPathFingerprint, label),
			func(s *WindowStats, v float64, _ map[string]string) { s.PathChanges = int(v + 0.5) }},
		{fmt.Sprintf(`max by (target) (timestamp(%s))`, MetricSuccess),
			func(s *WindowStats, v float64, _ map[string]string) {
				if v > 0 {
					s.LastProbe = time.Unix(int64(v), 0).UTC()
				}
			}},
	}
	for _, st := range steps {
		if err := fold(st.expr, st.set); err != nil {
			return nil, err
		}
	}
	// A success count can never exceed the sample count; a backend that says
	// otherwise is not a backend we render an availability from.
	for id, s := range out {
		if s.Successes > s.Samples {
			s.Successes = s.Samples
		}
		out[id] = s
	}
	return out, nil
}

// ProberReporting reports whether ANY dem series has arrived for this scope in
// the last lookback. It is the honest answer to "is the prober running": the
// prober is not a scrape target and exports no up gauge, so the only evidence
// that it is alive is that its samples are arriving (docs/runbooks/
// engine-liveness-matrix.md — the probe lane is observable only at its ends).
//
// Absent series means "not measured", NEVER "healthy" and never "0%".
func ProberReporting(ctx context.Context, q Querier, tenant string, cross bool, lookback string) (bool, error) {
	if q == nil {
		return false, errors.New("dem: no metrics backend is configured")
	}
	if !validLookback(lookback) {
		return false, fmt.Errorf("lookback must be one of %s", strings.Join(allowedLookbacks, ", "))
	}
	rows, err := q.Instant(ctx,
		fmt.Sprintf(`sum(count_over_time(%s[%s]))`, MetricSuccess, lookback),
		TenantFilter(tenant, cross))
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.Value > 0 {
			return true, nil
		}
	}
	return false, nil
}

// allowedLookbacks is a closed list — the lookback reaches a range selector, so
// it is never taken from the caller unchecked.
var allowedLookbacks = []string{"5m", "15m", "1h", "24h"}

func validLookback(v string) bool {
	for _, a := range allowedLookbacks {
		if v == a {
			return true
		}
	}
	return false
}
