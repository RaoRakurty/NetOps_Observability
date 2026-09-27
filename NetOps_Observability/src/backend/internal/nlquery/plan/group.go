// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"fmt"
	"math"
	"sort"

	"netops/backend/internal/nlquery/ast"
)

// Metric grouping (design §4: "site grouping in Go after fetch"). A metric
// query may group by ONE of site, device or provider. Per-entity results are
// fetched through the same scoped reads, then combined here with the query's
// own aggregation — so a group never contains an entity the caller could not
// see. An entity whose group is not known (a circuit with no provider mapping
// yet, a device with no site) is COUNTED in a note, never merged into a
// made-up group.

// GroupableMetricDims are the group-by dimensions metric queries support.
var GroupableMetricDims = map[string]bool{"site": true, "device": true, "provider": true}

// groupKeyFunc returns an entity's group, or "" when it is unknown.
type groupKeyFunc func(entity map[string]string) string

func (p Planner) groupKeys(ctx context.Context, sc Scope, target, by string) (groupKeyFunc, error) {
	switch by {
	case "device":
		return func(e map[string]string) string { return e["device"] }, nil
	case "site":
		devs, err := sc.Devices(ctx, DeviceFilter{})
		if err != nil {
			return nil, err
		}
		site := map[string]string{}
		for _, d := range devs {
			site[d.ID], site[d.Name] = d.Site, d.Site
		}
		if target == "circuit" {
			cs, err := sc.Circuits(ctx, CircuitFilter{Sites: uniqueSites(devs)})
			if err != nil {
				return nil, err
			}
			bySite := map[string]string{}
			for _, c := range cs {
				bySite[c.ID] = c.Site
			}
			return func(e map[string]string) string { return firstNonEmptyStr(bySite[e["circuit"]], site[e["device"]]) }, nil
		}
		return func(e map[string]string) string { return site[e["device"]] }, nil
	case "provider":
		cs, err := sc.Circuits(ctx, CircuitFilter{})
		if err != nil {
			return nil, err
		}
		prov := map[string]string{}
		for _, c := range cs {
			prov[c.ID] = c.Provider
		}
		return func(e map[string]string) string { return prov[e["circuit"]] }, nil
	}
	return nil, fmt.Errorf("plan: metrics cannot group by %q", by)
}

func uniqueSites(devs []DeviceRef) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range devs {
		if d.Site != "" && !seen[d.Site] {
			seen[d.Site] = true
			out = append(out, d.Site)
		}
	}
	return out
}

func firstNonEmptyStr(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// combine reduces member values with the query's aggregation. "last" over
// several entities at one instant has no single meaning, so it averages.
func combine(agg string, vals []float64) float64 {
	if len(vals) == 0 {
		return math.NaN()
	}
	switch agg {
	case "max":
		m := vals[0]
		for _, v := range vals[1:] {
			m = math.Max(m, v)
		}
		return m
	case "min":
		m := vals[0]
		for _, v := range vals[1:] {
			m = math.Min(m, v)
		}
		return m
	case "sum", "count":
		s := 0.0
		for _, v := range vals {
			s += v
		}
		return s
	case "p95":
		c := append([]float64(nil), vals...)
		sort.Float64s(c)
		idx := int(math.Ceil(0.95*float64(len(c)))) - 1
		if idx < 0 {
			idx = 0
		}
		return c[idx]
	}
	s := 0.0
	for _, v := range vals {
		s += v
	}
	return s / float64(len(vals))
}

// groupSeries combines per-entity series into one series per group, point by
// point.
func groupSeries(in []OutSeries, by string, key groupKeyFunc, agg string) ([]OutSeries, int) {
	type acc struct {
		members int
		points  map[int64][]float64
	}
	groups := map[string]*acc{}
	unknown := 0
	for _, s := range in {
		k := key(s.Entity)
		if k == "" {
			unknown++
			continue
		}
		g := groups[k]
		if g == nil {
			g = &acc{points: map[int64][]float64{}}
			groups[k] = g
		}
		g.members++
		for _, p := range s.Points {
			g.points[p.T] = append(g.points[p.T], p.V)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]OutSeries, 0, len(keys))
	for _, k := range keys {
		g := groups[k]
		ts := make([]int64, 0, len(g.points))
		for t := range g.points {
			ts = append(ts, t)
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
		pts := make([]Point, 0, len(ts))
		for _, t := range ts {
			pts = append(pts, Point{T: t, V: combine(agg, g.points[t])})
		}
		out = append(out, OutSeries{Entity: map[string]string{by: k, "members": fmt.Sprint(g.members)}, Points: pts})
	}
	return out, unknown
}

// groupRows combines per-entity instant rows into one row per group.
func groupRows(in []Row, by string, key groupKeyFunc, agg, valueCol string) ([]Row, int) {
	vals := map[string][]float64{}
	unknown := 0
	for _, r := range in {
		e := map[string]string{}
		for k, v := range r {
			if s, ok := v.(string); ok {
				e[k] = s
			}
		}
		k := key(e)
		v, ok := r[valueCol].(float64)
		if k == "" || !ok {
			unknown++
			continue
		}
		vals[k] = append(vals[k], v)
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Row, 0, len(keys))
	for _, k := range keys {
		out = append(out, Row{by: k, valueCol: combine(agg, vals[k]), "members": len(vals[k])})
	}
	return out, unknown
}

// applyGrouping groups a metric ResultSet in place when the query asks for it.
func (p Planner) applyGrouping(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	if len(q.GroupBy) == 0 {
		return nil
	}
	by := q.GroupBy[0]
	key, err := p.groupKeys(ctx, sc, q.Target, by)
	if err != nil {
		return err
	}
	unknown := 0
	if len(rs.Series) > 0 {
		rs.Series, unknown = groupSeries(rs.Series, by, key, q.Agg)
	}
	if len(rs.Rows) > 0 {
		var u int
		rs.Rows, u = groupRows(rs.Rows, by, key, q.Agg, "value")
		unknown += u
		sortRows(rs.Rows, "value", orderDesc(q))
	}
	if unknown > 0 {
		rs.Notes = append(rs.Notes, fmt.Sprintf("%d result(s) could not be placed in a %s group (the %s is not known for them) and are not included", unknown, by, by))
	}
	return nil
}
