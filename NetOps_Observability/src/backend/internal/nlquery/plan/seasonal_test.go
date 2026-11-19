// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// seasonal_test.go — N-H6 seasonal baselines in the planner: compare_windows
// rows carry how each value sits against its usual level for this time of
// week / day, above_baseline judges each entity by its own tier, a reference
// taken during maintenance is left out and counted, and every reference is
// read through the Scope (the caller's boundary) — never anywhere else.

import (
	"context"
	"strings"
	"testing"
	"time"
)

const week = 7 * 24 * time.Hour
const day = 24 * time.Hour

func dev(d string) map[string]string { return map[string]string{"device": d} }

// history answers the same windowed read at the current instant and at
// earlier ones: values[entity][offset] (offset 0 = now).
func history(values map[string]map[time.Duration]float64) func(string, time.Time) []Sample {
	return func(_ string, at time.Time) []Sample {
		off := now.Sub(at)
		var out []Sample
		for d, byOff := range values {
			if v, ok := byOff[off]; ok {
				out = append(out, Sample{Labels: dev(d), Value: v})
			}
		}
		return out
	}
}

func rowFor(t *testing.T, rs *ResultSet, device string) Row {
	t.Helper()
	for _, r := range rs.Rows {
		if r["device"] == device {
			return r
		}
	}
	t.Fatalf("no row for %s in %+v", device, rs.Rows)
	return nil
}

const compareCPU = `{"v":1,"query_type":"compare_windows","target":"device","metric":"cpu_util_pct","time_range":{"kind":"relative","last":"1h"},"compare_to":{"kind":"relative","last":"1h","offset":"1d"}}`

func TestCompareCarriesTheSeasonalReference(t *testing.T) {
	sc := &fakeScope{instantFn: history(map[string]map[time.Duration]float64{
		// edge-1: four earlier weeks around 40 %, now 60 % → well above.
		"edge-1": {0: 60, day: 41, week: 40, 2 * week: 42, 3 * week: 38, 4 * week: 41},
		// edge-2: only today and yesterday → not enough history.
		"edge-2": {0: 20, day: 22},
	})}
	rs := run(t, sc, compareCPU)
	e1 := rowFor(t, rs, "edge-1")
	if b, _ := e1["baseline"].(string); !strings.Contains(b, "this time of week (4 of 4 weeks used)") {
		t.Fatalf("edge-1 baseline = %q", b)
	}
	if e1["expected"] != 40.5 {
		t.Fatalf("edge-1 expected = %v, want the median 40.5", e1["expected"])
	}
	if z, _ := e1["z"].(float64); z < 3 {
		t.Fatalf("edge-1 z = %v, want ≥ 3", e1["z"])
	}
	e2 := rowFor(t, rs, "edge-2")
	if b, _ := e2["baseline"].(string); !strings.HasPrefix(b, "not enough history") {
		t.Fatalf("edge-2 baseline = %q", b)
	}
	if _, ok := e2["z"]; ok {
		t.Fatal("a tier C row must carry no z")
	}
	if !strings.Contains(strings.Join(rs.Notes, " "), "Seasonal baseline: 1 against their usual level for this time of week") {
		t.Fatalf("notes = %v", rs.Notes)
	}
	// Every reference went through the Scope's instant read — no range read,
	// and the 7th day back was read once (it is the first week back).
	if sc.ranges != 0 {
		t.Fatalf("seasonal references must be instant reads, saw %d range reads", sc.ranges)
	}
	seen := map[time.Time]int{}
	for _, at := range sc.instants[2:] { // [0],[1] are the two window ends
		seen[at]++
	}
	for at, n := range seen {
		if n > 1 {
			t.Errorf("reference instant %s read %d times", at, n)
		}
	}
	if len(seen) != 10 { // 4 weeks + 7 days − the shared 7-day instant
		t.Fatalf("distinct reference instants = %d, want 10", len(seen))
	}
}

func TestTierBSaysTimeOfDayNeverAWeekday(t *testing.T) {
	byOff := map[time.Duration]float64{0: 90}
	for i := 1; i <= 6; i++ {
		byOff[time.Duration(i)*day] = 30 + float64(i)
	}
	sc := &fakeScope{instantFn: history(map[string]map[time.Duration]float64{"edge-1": byOff})}
	rs := run(t, sc, compareCPU)
	b, _ := rowFor(t, rs, "edge-1")["baseline"].(string)
	if !strings.Contains(b, "this time of day (6 of 7 days used)") {
		t.Fatalf("baseline = %q", b)
	}
	for _, wd := range []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"} {
		if strings.Contains(strings.ToLower(b+strings.Join(rs.Notes, " ")), wd) {
			t.Fatalf("tier B must never name a weekday: %q / %v", b, rs.Notes)
		}
	}
}

const aboveCPU = `{"v":1,"query_type":"metric_filter","target":"device","metric":"cpu_util_pct","predicate":{"op":"above_baseline"},"time_range":{"kind":"relative","last":"1h"}}`

func TestAboveBaselineJudgesEachEntityByItsOwnTier(t *testing.T) {
	weeks := func(cur float64, vals ...float64) map[time.Duration]float64 {
		m := map[time.Duration]float64{0: cur}
		for i, v := range vals {
			m[time.Duration(i+1)*week] = v
		}
		return m
	}
	hist := history(map[string]map[time.Duration]float64{
		"hot":    weeks(80, 40, 41, 39, 40), // tier A, far above → kept
		"normal": weeks(41, 40, 41, 39, 40), // tier A, normal → dropped
		"young":  {0: 70},                   // tier C → the flat p95 decides
		"young2": {0: 10},                   // tier C, below its p95 → dropped
	})
	sc := &fakeScope{instantFn: func(expr string, at time.Time) []Sample {
		if strings.Contains(expr, "quantile_over_time(0.95, ") {
			return []Sample{{Labels: dev("young"), Value: 50}, {Labels: dev("young2"), Value: 50}}
		}
		return hist(expr, at)
	}}
	rs := run(t, sc, aboveCPU)
	got := map[string]Row{}
	for _, r := range rs.Rows {
		got[r["device"].(string)] = r
	}
	if len(got) != 2 || got["hot"] == nil || got["young"] == nil {
		t.Fatalf("kept %v, want hot (seasonal) and young (flat p95)", rs.Rows)
	}
	if b, _ := got["hot"]["baseline"].(string); !strings.Contains(b, "this time of week") {
		t.Fatalf("hot baseline = %q", b)
	}
	if b, _ := got["young"]["baseline"].(string); !strings.Contains(b, "95th percentile of the previous 7 days") || got["young"]["expected"] != 50.0 {
		t.Fatalf("young row = %+v", got["young"])
	}
	note := strings.Join(rs.Notes, " ")
	if !strings.Contains(note, "2 against their usual level for this time of week") || !strings.Contains(note, "2 with not enough history") {
		t.Fatalf("notes = %v", rs.Notes)
	}
}

// The flat p95 is read only when some entity needs it.
func TestAboveBaselineSkipsTheFlatReadWhenEveryEntityHasHistory(t *testing.T) {
	sc := &fakeScope{instantFn: history(map[string]map[time.Duration]float64{
		"edge-1": {0: 80, week: 40, 2 * week: 41, 3 * week: 39},
	})}
	run(t, sc, aboveCPU)
	for _, e := range sc.exprs {
		if strings.Contains(e, "quantile_over_time(0.95, ") {
			t.Fatalf("flat p95 read although no entity is tier C: %v", sc.exprs)
		}
	}
}

// maintScope is a fakeScope that also says which device a declared
// maintenance window covered, and when.
type maintScope struct {
	*fakeScope
	cover map[string][]time.Time
	err   error
}

func (m maintScope) MaintenanceCoverer(context.Context) (func(string, time.Time) bool, error) {
	if m.err != nil {
		return nil, m.err
	}
	return func(device string, at time.Time) bool {
		for _, c := range m.cover[device] {
			if c.Equal(at) {
				return true
			}
		}
		return false
	}, nil
}

func TestMaintenanceReferencesAreLeftOutAndCounted(t *testing.T) {
	sc := maintScope{
		fakeScope: &fakeScope{instantFn: history(map[string]map[time.Duration]float64{
			"edge-1": {0: 60, day: 41, week: 40, 2 * week: 95, 3 * week: 38, 4 * week: 41},
		})},
		cover: map[string][]time.Time{"edge-1": {now.Add(-2 * week)}}, // the 95 % week was planned work
	}
	rs := runScope(t, sc, compareCPU)
	b, _ := rowFor(t, rs, "edge-1")["baseline"].(string)
	if !strings.Contains(b, "3 of 4 weeks used, 1 left out for maintenance") {
		t.Fatalf("baseline = %q", b)
	}
	if rowFor(t, rs, "edge-1")["expected"] != 40.0 {
		t.Fatalf("the maintenance week must not move the centre: %+v", rs.Rows)
	}
	// An unreadable window list excludes nothing and says so.
	sc.err = context.DeadlineExceeded
	rs = runScope(t, sc, compareCPU)
	if b, _ := rowFor(t, rs, "edge-1")["baseline"].(string); !strings.Contains(b, "4 of 4 weeks used") {
		t.Fatalf("baseline = %q", b)
	}
	if !strings.Contains(strings.Join(rs.Notes, " "), "Maintenance windows could not be read") {
		t.Fatalf("notes = %v", rs.Notes)
	}
}

// A device the Scope does not return now (another tenant's, or filtered out)
// never gets a row, whatever its history: references are fitted only for the
// entities the current, scoped read returned.
func TestSeasonalOnlyForEntitiesTheScopeReturned(t *testing.T) {
	sc := &fakeScope{instantFn: func(_ string, at time.Time) []Sample {
		if at.Equal(now) {
			return []Sample{{Labels: dev("edge-1"), Value: 80}}
		}
		return []Sample{{Labels: dev("edge-1"), Value: 40}, {Labels: dev("foreign"), Value: 40}}
	}}
	rs := run(t, sc, aboveCPU)
	for _, r := range rs.Rows {
		if r["device"] == "foreign" {
			t.Fatalf("an entity absent from the current read got a row: %+v", rs.Rows)
		}
	}
}
