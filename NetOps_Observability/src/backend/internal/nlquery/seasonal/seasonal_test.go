// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seasonal

import (
	"math"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC) // a Monday, 09:00 UTC

func refs(offsets []time.Duration, vals ...float64) []Ref {
	out := make([]Ref, len(offsets))
	for i, off := range offsets {
		out[i] = Ref{At: now.Add(-off)}
		if i < len(vals) && !math.IsNaN(vals[i]) {
			out[i].Value, out[i].Present = vals[i], true
		}
	}
	return out
}

func TestHourOfWeek(t *testing.T) {
	if got := HourOfWeek(now); got != 9 {
		t.Fatalf("Monday 09:00 UTC = %d, want 9", got)
	}
	if got := HourOfWeek(time.Date(2026, 11, 29, 23, 30, 0, 0, time.UTC)); got != 167 {
		t.Fatalf("Sunday 23:30 = %d, want 167", got)
	}
	// A non-UTC instant buckets by its UTC hour.
	loc := time.FixedZone("CDT", -5*3600)
	if got := HourOfWeek(time.Date(2026, 11, 23, 4, 0, 0, 0, loc)); got != 9 {
		t.Fatalf("04:00 CDT Monday = %d, want 9 (UTC)", got)
	}
}

func TestFitTiers(t *testing.T) {
	nan := math.NaN()
	cases := []struct {
		name   string
		weekly []float64
		daily  []float64
		tier   Tier
		used   int
		centre float64
	}{
		{"four weeks", []float64{10, 12, 11, 13}, nil, TierWeek, 4, 11.5},
		{"three weeks, one gap", []float64{10, nan, 12, 11}, nil, TierWeek, 3, 11},
		{"two weeks → days", []float64{10, 12}, []float64{20, 21, 22, 23, 24}, TierDay, 5, 22},
		{"one week, four days → none", []float64{10}, []float64{1, 2, 3, 4}, TierNone, 0, 0},
		{"nothing", nil, nil, TierNone, 0, 0},
	}
	for _, c := range cases {
		p := Fit(now, refs(WeekOffsets(), c.weekly...), refs(DayOffsets(), c.daily...), 0)
		if p.Tier != c.tier || p.Used != c.used || p.Centre != c.centre {
			t.Errorf("%s: %+v, want tier %s used %d centre %v", c.name, p, c.tier, c.used, c.centre)
		}
	}
}

func TestScaleFloors(t *testing.T) {
	// Zero MAD: a perfectly flat series still has a positive scale — the
	// relative floor (5 % of 50 = 2.5) beats the unit floor (0.5).
	p := Fit(now, refs(WeekOffsets(), 50, 50, 50, 50), nil, UnitFloor("percent"))
	if p.Scale != 2.5 {
		t.Fatalf("flat series scale = %v, want 2.5", p.Scale)
	}
	if z, ok := p.Z(57.5); !ok || z != 3 {
		t.Fatalf("z(57.5) = %v %v, want 3", z, ok)
	}
	// A flat zero series: only the unit floor remains.
	p = Fit(now, refs(WeekOffsets(), 0, 0, 0, 0), nil, UnitFloor("percent"))
	if p.Scale != 0.5 {
		t.Fatalf("flat zero scale = %v, want the unit floor 0.5", p.Scale)
	}
	// MAD wins when it is larger: values 10,20,30,40 → median 25, MAD 10.
	p = Fit(now, refs(WeekOffsets(), 10, 20, 30, 40), nil, 0)
	if math.Abs(p.Scale-MADScale*10) > 1e-9 {
		t.Fatalf("scale = %v, want 1.4826×10", p.Scale)
	}
}

func TestRobustToOneOddWeek(t *testing.T) {
	// One maintenance-shaped spike among four weeks moves the median and MAD
	// very little; a mean/σ baseline would have swallowed it.
	p := Fit(now, refs(WeekOffsets(), 100, 102, 98, 900), nil, 0)
	if p.Centre != 101 {
		t.Fatalf("centre = %v, want 101 (median ignores the spike)", p.Centre)
	}
	if above, ok := p.Above(130); !ok || !above {
		z, _ := p.Z(130)
		t.Fatalf("130 against a ~100 week must be above (z=%v)", z)
	}
}

func TestMaintenanceExclusionIsCounted(t *testing.T) {
	w := refs(WeekOffsets(), 10, 11, 12, 13)
	w[1].Excluded = true
	w[2].Excluded = true
	p := Fit(now, w, refs(DayOffsets(), 5, 5, 6, 6, 7, 7, 8), 0)
	if p.Tier != TierDay || p.Excluded != 0 {
		t.Fatalf("two of four weeks excluded leaves two — tier B from days: %+v", p)
	}
	w[2].Excluded = false
	p = Fit(now, w, nil, 0)
	if p.Tier != TierWeek || p.Used != 3 || p.Excluded != 1 {
		t.Fatalf("one excluded: %+v", p)
	}
	if !strings.Contains(p.Describe(), "3 of 4 weeks used, 1 left out for maintenance") {
		t.Fatalf("describe = %q", p.Describe())
	}
}

func TestDescribeWording(t *testing.T) {
	day := Fit(now, nil, refs(DayOffsets(), 1, 2, 3, 4, 5, 6, 7), 0)
	if d := day.Describe(); !strings.Contains(d, "this time of day") || strings.Contains(strings.ToLower(d), "monday") {
		t.Fatalf("tier B must say 'this time of day', never a weekday: %q", d)
	}
	none := Fit(now, nil, refs(DayOffsets(), 1, 2), 0)
	if d := none.Describe(); d != "not enough history for a time-of-day baseline (2 days)" {
		t.Fatalf("tier C = %q", d)
	}
	if _, ok := none.Z(5); ok {
		t.Fatal("tier C has no z")
	}
	if _, ok := none.Above(5); ok {
		t.Fatal("tier C must leave the decision to the caller's fallback")
	}
}

func TestZRejectsNonFinite(t *testing.T) {
	p := Fit(now, refs(WeekOffsets(), 1, 2, 3, 4), nil, 0)
	for _, x := range []float64{math.NaN(), math.Inf(1)} {
		if _, ok := p.Z(x); ok {
			t.Errorf("z(%v) must be refused", x)
		}
	}
	vals := refs(WeekOffsets(), 1, 0, 3, 4)
	vals[1].Value = math.Inf(1)
	if p := Fit(now, vals, nil, 0); p.Used != 3 {
		t.Fatalf("an infinite reference is not usable: %+v", p)
	}
}
