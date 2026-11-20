// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// estate.go — the estate-wide seasonal answer (tracker 337 N-H6 step 3):
// "what stands out against its usual level for the time".
//
// One bounded read of the hourly roll-up (EstateSeasonalScope, the caller's own
// rows only) returns, for every rolled-up series of the asked type, its hourly
// median at the roll-up's latest closed hour and at each seasonal reference
// hour before it. Each series is fitted with the same maths every other
// seasonal answer uses (internal/nlquery/seasonal):
//
//	A  ≥3 earlier weeks at this hour   ranked, "for this time of week"
//	B  ≥5 earlier days at this hour    ranked, "for this time of day"
//	C  neither                          NOT ranked — counted and said
//
// A series is unusual when its robust z is at least seasonal.AboveZ away from
// its usual level (above only, for above_baseline). References a declared
// maintenance window covered are left out, as PR 1 does; a series whose
// judged hour a maintenance window covered is marked, not hidden. Device names
// are the caller's own inventory names; a series whose device the caller
// cannot see is dropped before anything is counted.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/seasonal"
)

// Estate bounds.
const (
	// MaxEstateSeries is the most rolled-up series one estate answer judges.
	MaxEstateSeries = 10000
	// EstateReadTimeout bounds the roll-up read.
	EstateReadTimeout = 15 * time.Second
	// EstateFreshness is how old the judged hour may be: the roll-up writes
	// the previous closed hour every 15 minutes, so anything older means it
	// is not running, and "right now" cannot be answered.
	EstateFreshness = 3 * time.Hour
)

// estateLabels are the key labels of each rolled-up entity type, in entity-key
// order (the planner's templates and the roll-up worker use the same).
var estateLabels = map[string][]string{
	"device":    deviceLabels,
	"interface": ifLabels,
	"circuit":   circuitLabels,
}

func estateDeviceAt(entity string) int {
	if entity == "circuit" {
		return 1 // local_device
	}
	return 0
}

func (p Planner) seasonalOutliers(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	source(rs, "clickhouse")
	st, ok := sc.(EstateSeasonalScope)
	if !ok {
		rs.Notes = append(rs.Notes, "This deployment keeps no hourly seasonal history, so Iris cannot say what is unusual for this time of week.")
		return nil
	}
	names := seasonal.EstateMetrics(q.Target)
	switch {
	case q.Metric != "":
		names = []string{q.Metric}
	case len(q.Filters) == 1 && q.Filters[0].Field == ast.FilterMetric:
		names = append([]string(nil), q.Filters[0].Values...)
		sort.Strings(names)
	}
	// The N-B5 gate the validator applies to a named metric applies to the
	// estate too: a gated metric (circuit loss/latency/jitter/QoE) is read
	// only for a platform operator, and its absence is said, never silent. A
	// Scope that cannot say is treated as workspace-scoped.
	cross := false
	if ct, ok := sc.(interface{ CrossTenant() bool }); ok {
		cross = ct.CrossTenant()
	}
	var metrics []EstateMetric
	gated := 0
	for _, n := range names {
		if cm, ok := p.Cat.Metric(n); ok && cm.Scope == "gated:N-B5" && !cross {
			gated++
			continue
		}
		metrics = append(metrics, EstateMetric{Name: n, DeviceAt: estateDeviceAt(seasonal.RolledMetrics[n])})
	}
	if gated > 0 {
		rs.Notes = append(rs.Notes, "Circuit measurements are not yet visible to a workspace-scoped user, so circuits are not included.")
	}
	if len(metrics) == 0 {
		return nil
	}

	// The caller's visible devices: the names an answer may use, and (when
	// the question names devices or sites) the narrowing of the read.
	var devIDs, sites []string
	for _, r := range q.Refs {
		switch r.Type {
		case "device":
			devIDs = append(devIDs, stripPrefix(r.ID))
		case "site":
			sites = append(sites, stripPrefix(r.ID))
		}
	}
	devs, err := sc.Devices(ctx, DeviceFilter{IDs: devIDs, Sites: sites})
	if err != nil {
		return err
	}
	if len(devs) == 0 {
		if len(q.Refs) > 0 {
			return ErrEmptyScope
		}
		rs.Notes = append(rs.Notes, "You can see no devices, so there is nothing to judge.")
		return nil
	}
	visible := map[string]string{} // device label (id or name) → inventory name
	devID := map[string]string{}   // device label → inventory id (maintenance windows name ids)
	var narrow []string
	for _, d := range devs {
		name := d.Name
		if name == "" {
			name = d.ID
		}
		visible[d.ID] = name
		devID[d.ID] = d.ID
		narrow = append(narrow, d.ID)
		if d.Name != "" && d.Name != d.ID {
			visible[d.Name] = name
			devID[d.Name] = d.ID
			narrow = append(narrow, d.Name)
		}
	}
	eq := EstateQuery{Metrics: metrics, Since: sc.Now().UTC().Truncate(time.Hour).Add(-EstateFreshness), MaxSeries: MaxEstateSeries}
	if len(q.Refs) > 0 {
		res := resolved{}
		eq.Devices = res.cap(narrow)
		if res.capped {
			rs.Truncated = true
			rs.Notes = append(rs.Notes, fmt.Sprintf("The places named cover more than %d devices; only the first %d were judged.", MaxMatchValues, MaxMatchValues))
		}
	}

	timeout := p.EstateTimeout
	if timeout <= 0 {
		timeout = EstateReadTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	read, err := st.SeasonalEstate(rctx, eq)
	if err == nil && rctx.Err() != nil {
		err = rctx.Err() // a read that ignored its deadline is not trusted
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(rctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("plan: the seasonal history read took longer than %s; narrow the question to a device, site or metric: %w", timeout, context.DeadlineExceeded)
		}
		return err
	}
	rs.Provenance.Physical = append(rs.Provenance.Physical, fmt.Sprintf("netops.series_hourly FINAL p50 for %d metric(s) at the latest closed hour and %d reference hours", len(metrics), seasonal.MaxDays+seasonal.MaxWeeks-1))
	if read.Hour.IsZero() {
		rs.Notes = append(rs.Notes, fmt.Sprintf("The hourly seasonal history has no closed hour in the last %s, so Iris cannot say what is unusual right now. It is kept only while Seasonal baselines history is switched on (Platform → Configuration → Features).", hoursWord(EstateFreshness)))
		return nil
	}
	h := read.Hour.UTC()
	if h.Truncate(time.Hour) != h || h.Before(eq.Since) || h.After(sc.Now()) {
		return fmt.Errorf("plan: the seasonal history returned an hour (%s) outside the one asked for", h.Format(time.RFC3339))
	}
	rs.Window = Window{From: h, To: h.Add(time.Hour)}
	if len(read.Series) > eq.MaxSeries {
		read.Series, read.Truncated = read.Series[:eq.MaxSeries], true
	}
	if read.Truncated {
		rs.Truncated = true
		rs.Notes = append(rs.Notes, fmt.Sprintf("More than %d series are rolled up; only the first %d were judged — name a device, site, metric or entity type to see the rest.", MaxEstateSeries, MaxEstateSeries))
	}

	covered := maintenanceCoverer(ctx, sc, rs)
	judged := map[string]bool{}
	for _, m := range metrics {
		judged[m.Name] = true
	}
	counts := map[seasonal.Tier]int{}
	inMaint := 0
	var rows []Row
	for _, s := range read.Series {
		if !judged[s.Metric] {
			continue // the read returned a metric not asked for: never trusted
		}
		entity := seasonal.RolledMetrics[s.Metric]
		labels := estateLabels[entity]
		parts := splitKey(s.EntityKey, len(labels))
		if parts == nil {
			continue
		}
		devLabel := parts[estateDeviceAt(entity)]
		devName, ok := visible[devLabel]
		if !ok {
			continue // a device the caller cannot see: dropped before counting
		}
		cur, ok := s.P50[h.Unix()]
		if !ok || math.IsNaN(cur) || math.IsInf(cur, 0) {
			continue
		}
		weekly := estateRefs(s.P50, h, seasonal.WeekOffsets())
		daily := estateRefs(s.P50, h, seasonal.DayOffsets())
		id := devID[devLabel]
		if covered != nil {
			exclude(weekly, id, time.Hour, covered)
			exclude(daily, id, time.Hour, covered)
		}
		unit := ""
		if cm, ok := p.Cat.Metric(s.Metric); ok {
			unit = cm.Unit
		}
		pr := seasonal.Fit(h.Add(time.Hour), weekly, daily, seasonal.UnitFloor(unit))
		counts[pr.Tier]++
		z, ok := pr.Z(cur)
		if !ok {
			continue // tier C: counted, never ranked
		}
		if math.Abs(z) < seasonal.AboveZ || (q.Predicate != nil && z < seasonal.AboveZ) {
			continue
		}
		row := Row{"metric": s.Metric, "value": cur, "expected": round2(pr.Centre), "z": round2(z), "baseline": pr.Describe()}
		row["direction"] = "above"
		if z < 0 {
			row["direction"] = "below"
		}
		row["device"] = devName
		switch entity {
		case "interface":
			row["interface"] = parts[1]
		case "circuit":
			row["circuit"] = parts[0]
		}
		if covered != nil && (covered(id, h) || covered(id, h.Add(30*time.Minute)) || covered(id, h.Add(time.Hour))) {
			row["maintenance"] = true
			inMaint++
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := math.Abs(rows[i]["z"].(float64)), math.Abs(rows[j]["z"].(float64))
		if a != b {
			return a > b
		}
		return estateRowKey(rows[i]) < estateRowKey(rows[j])
	})
	if n := q.LimitOr(MaxSeries); len(rows) > n {
		rows, rs.Truncated = rows[:n], true
	}
	rs.Rows = rows
	if len(q.Metric) > 0 {
		rs.Metric = q.Metric
		if cm, ok := p.Cat.Metric(q.Metric); ok {
			rs.Unit = cm.Unit
		}
	}
	checked := counts[seasonal.TierWeek] + counts[seasonal.TierDay]
	rs.Notes = append(rs.Notes, fmt.Sprintf("Judged the hour %s–%s UTC: %d series checked against their own usual level.", h.Format("2006-01-02 15:04"), h.Add(time.Hour).Format("15:04"), checked))
	ranked := map[seasonal.Tier]int{seasonal.TierWeek: counts[seasonal.TierWeek], seasonal.TierDay: counts[seasonal.TierDay]}
	if note := seasonalNote(ranked, ""); note != "" {
		rs.Notes = append(rs.Notes, note)
	}
	if n := counts[seasonal.TierNone]; n > 0 {
		rs.Notes = append(rs.Notes, fmt.Sprintf("Not enough history for %d series, so they are not ranked.", n))
	}
	if inMaint > 0 {
		rs.Notes = append(rs.Notes, fmt.Sprintf("%d of these %s under a declared maintenance window during the hour judged.", inMaint, wasWere(inMaint)))
	}
	return nil
}

// estateRefs builds the references at h minus each offset. A reference's At is
// the END of its hour, so maintenance exclusion (exclude, with a one-hour
// window) checks the hour's end, middle and start.
func estateRefs(p50 map[int64]float64, h time.Time, offs []time.Duration) []seasonal.Ref {
	out := make([]seasonal.Ref, 0, len(offs))
	for _, off := range offs {
		start := h.Add(-off)
		v, ok := p50[start.Unix()]
		out = append(out, seasonal.Ref{At: start.Add(time.Hour), Value: v, Present: ok && !math.IsNaN(v) && !math.IsInf(v, 0)})
	}
	return out
}

// splitKey splits an entity key into exactly n label values (nil otherwise).
func splitKey(key string, n int) []string {
	parts := make([]string, 0, n)
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '\x1f' {
			parts = append(parts, key[start:i])
			start = i + 1
		}
	}
	parts = append(parts, key[start:])
	if len(parts) != n {
		return nil
	}
	for _, p := range parts {
		if p == "" {
			return nil
		}
	}
	return parts
}

func estateRowKey(r Row) string {
	s := func(k string) string { v, _ := r[k].(string); return v }
	return s("metric") + "\x1f" + s("device") + "\x1f" + s("interface") + "\x1f" + s("circuit")
}

func hoursWord(d time.Duration) string {
	return fmt.Sprintf("%d hours", int(d/time.Hour))
}

func wasWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}
