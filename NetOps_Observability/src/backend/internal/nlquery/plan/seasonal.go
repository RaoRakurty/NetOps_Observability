// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// seasonal.go — seasonal baselines for metric answers (tracker 337 N-H6).
//
// The same windowed value an answer reports is read again at the same hour in
// each of the previous MaxWeeks weeks and MaxDays days — one instant read per
// offset, through the SAME scoped Scope.MetricInstant every other metric read
// uses (the caller's extra_filters[] ride on each), so a seasonal reference can
// never see further than the answer itself. internal/nlquery/seasonal turns the
// references into a tiered profile:
//
//	A  ≥3 earlier weeks at this hour   "for this time of week"
//	B  ≥5 earlier days at this hour    "for this time of day" (never a weekday)
//	C  neither                          "not enough history" — the flat 7-day
//	                                    95th percentile stands in, and says so
//
// A reference that a declared maintenance window covered is left out and
// counted, when the deployment's Scope can tell (MaintenanceScope).

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/mql"
	"netops/backend/internal/nlquery/seasonal"
)

// seasonalProfiles reads e at every reference offset before `to` and fits a
// profile for each entity key in keys. win is the answer's window length (a
// reference is excluded when maintenance covered any part of it).
func seasonalProfiles(ctx context.Context, sc Scope, t template, e mql.Expr, to time.Time, win time.Duration, unit string, keys map[string]map[string]string, rs *ResultSet) (map[string]seasonal.Profile, error) {
	// One instant read per distinct offset: the 7th day back IS the first
	// week back, and is read once.
	cache := map[time.Duration]map[string]float64{}
	read := func(offs []time.Duration) (map[string][]seasonal.Ref, error) {
		out := map[string][]seasonal.Ref{}
		for _, off := range offs {
			at := to.Add(-off)
			got, seen := cache[off]
			if !seen {
				samples, trunc, err := sc.MetricInstant(ctx, e, at, MaxMatchValues)
				if err != nil {
					return nil, err
				}
				rs.Truncated = rs.Truncated || trunc
				got = map[string]float64{}
				for _, s := range samples {
					got[entityKey(t.labels, s.Labels)] = s.Value
				}
				cache[off] = got
			}
			for k := range keys {
				v, ok := got[k]
				out[k] = append(out[k], seasonal.Ref{At: at, Value: v, Present: ok && !math.IsNaN(v) && !math.IsInf(v, 0)})
			}
		}
		return out, nil
	}
	weekly, err := read(seasonal.WeekOffsets())
	if err != nil {
		return nil, err
	}
	daily, err := read(seasonal.DayOffsets())
	if err != nil {
		return nil, err
	}
	rs.Provenance.Physical = append(rs.Provenance.Physical, fmt.Sprintf("%s @ -1..%dw, -1..%dd (seasonal reference)", e.String(), seasonal.MaxWeeks, seasonal.MaxDays))

	covered := maintenanceCoverer(ctx, sc, rs)
	floor := seasonal.UnitFloor(unit)
	out := make(map[string]seasonal.Profile, len(keys))
	for k, labels := range keys {
		w, d := weekly[k], daily[k]
		if covered != nil {
			dev := labels["device"]
			if dev == "" {
				dev = labels["local_device"]
			}
			if dev != "" {
				exclude(w, dev, win, covered)
				exclude(d, dev, win, covered)
			}
		}
		out[k] = seasonal.Fit(to, w, d, floor)
	}
	return out, nil
}

// exclude marks a reference whose window a maintenance window covered at its
// start, middle or end.
func exclude(refs []seasonal.Ref, device string, win time.Duration, covered func(string, time.Time) bool) {
	for i := range refs {
		at := refs[i].At
		if covered(device, at) || covered(device, at.Add(-win/2)) || covered(device, at.Add(-win)) {
			refs[i].Excluded = true
		}
	}
}

// maintenanceCoverer returns the caller's maintenance predicate, or nil when
// the Scope cannot tell. A failed read is said in a note and excludes nothing:
// an unreadable window list must not quietly shrink the reference set.
func maintenanceCoverer(ctx context.Context, sc Scope, rs *ResultSet) func(string, time.Time) bool {
	ms, ok := sc.(MaintenanceScope)
	if !ok {
		return nil
	}
	fn, err := ms.MaintenanceCoverer(ctx)
	if err != nil {
		rs.Notes = append(rs.Notes, "Maintenance windows could not be read, so no seasonal reference was left out for planned work.")
		return nil
	}
	return fn
}

// annotateSeasonal adds the seasonal columns to each row: expected (the
// profile's centre), z (robust, two decimals) and baseline (the comparison
// made, in words). keys[i] is rows[i]'s entity key. Tier C rows get only the
// words. It returns the tier counts.
func annotateSeasonal(rows []Row, keys []string, prof map[string]seasonal.Profile) map[seasonal.Tier]int {
	counts := map[seasonal.Tier]int{}
	for i, row := range rows {
		p, ok := prof[keys[i]]
		if !ok {
			continue
		}
		counts[p.Tier]++
		row["baseline"] = p.Describe()
		v, vok := row["value"].(float64)
		if p.Tier == seasonal.TierNone || !vok {
			continue
		}
		row["expected"] = round2(p.Centre)
		if z, ok := p.Z(v); ok {
			row["z"] = round2(z)
		}
	}
	return counts
}

// seasonalNote says, once per answer, which comparison each row got.
func seasonalNote(counts map[seasonal.Tier]int, fallback string) string {
	var parts []string
	if n := counts[seasonal.TierWeek]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d against their usual level for this time of week (at least %d earlier weeks)", n, seasonal.MinWeeks))
	}
	if n := counts[seasonal.TierDay]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d against their usual level for this time of day (at least %d earlier days; not enough weeks yet)", n, seasonal.MinDays))
	}
	if n := counts[seasonal.TierNone]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d with not enough history for a time-of-day baseline%s", n, fallback))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Seasonal baseline: " + strings.Join(parts, "; ") + "."
}

// aboveBaseline answers predicate above_baseline: each entity's current
// windowed value is judged against its seasonal profile — kept when its robust
// z is at least seasonal.AboveZ (tiers A and B) — or, with not enough history
// (tier C), against the flat 95th percentile of the previous 7 days, the rule
// this predicate always had. Every read goes through sc.
func (p Planner) aboveBaseline(ctx context.Context, sc Scope, q *ast.AST, t template, c tctx, res resolved, rs *ResultSet, step time.Duration, unit string) error {
	e, err := aggregate(t, c, q.Agg, step)
	if err != nil {
		return err
	}
	to := rs.Window.To
	rs.Provenance.Physical = append(rs.Provenance.Physical, e.String())
	cur, trunc, err := sc.MetricInstant(ctx, e, to, MaxMatchValues)
	if err != nil {
		return err
	}
	rs.Truncated = trunc
	keys := map[string]map[string]string{}
	vals := map[string]float64{}
	for _, s := range cur {
		if !res.keep(s.Labels) || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			continue
		}
		k := entityKey(t.labels, s.Labels)
		keys[k], vals[k] = s.Labels, s.Value
	}
	if len(keys) == 0 {
		source(rs, "victoriametrics")
		return nil
	}
	prof, err := seasonalProfiles(ctx, sc, t, e, to, c.win, unit, keys, rs)
	if err != nil {
		return err
	}
	// The flat fallback, read only when some entity needs it.
	flat := map[string]float64{}
	for _, pr := range prof {
		if pr.Tier != seasonal.TierNone {
			continue
		}
		s, err := t.series(c)
		if err != nil {
			return err
		}
		base, err := mql.QuantileSubquery(0.95, s, BaselineWindow, step)
		if err != nil {
			return err
		}
		if base, err = mql.Offset(base, c.win); err != nil {
			return err
		}
		rs.Provenance.Physical = append(rs.Provenance.Physical, base.String())
		samples, _, err := sc.MetricInstant(ctx, base, to, MaxMatchValues)
		if err != nil {
			return err
		}
		for _, s := range samples {
			flat[entityKey(t.labels, s.Labels)] = s.Value
		}
		break
	}
	counts := map[seasonal.Tier]int{}
	for k, labels := range keys {
		v, pr := vals[k], prof[k]
		counts[pr.Tier]++
		row := Row{}
		for lk, lv := range entityOf(t.labels, labels) {
			row[lk] = lv
		}
		row["value"] = v
		row["baseline"] = pr.Describe()
		if above, ok := pr.Above(v); ok {
			if !above {
				continue
			}
			row["expected"] = round2(pr.Centre)
			if z, ok := pr.Z(v); ok {
				row["z"] = round2(z)
			}
		} else {
			p95, ok := flat[k]
			if !ok || !(v > p95) {
				continue
			}
			row["expected"] = round2(p95)
			row["baseline"] = pr.Describe() + " — compared with the 95th percentile of the previous 7 days"
		}
		rs.Rows = append(rs.Rows, row)
	}
	sortRows(rs.Rows, "value", true)
	if n := q.LimitOr(MaxSeries); len(rs.Rows) > n {
		rs.Rows, rs.Truncated = rs.Rows[:n], true
	}
	if note := seasonalNote(counts, " (compared with the 95th percentile of the previous 7 days instead)"); note != "" {
		rs.Notes = append(rs.Notes, note)
	}
	source(rs, "victoriametrics")
	return nil
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
