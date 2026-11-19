// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package seasonal is the pure maths of Iris's seasonal baselines (tracker 337
// N-H6): "is this value normal for this time of week?", answered from the same
// metric read at the same hour in earlier weeks — or earlier days, when weeks
// are not there yet — with robust statistics, and an honest tier that says
// which comparison was made.
//
// Tiers (the path-health cascade, docs/design/path-behavior-health.md):
//
//	A  hour of week  ≥ MinWeeks qualifying earlier weeks at this hour
//	B  hour of day   ≥ MinDays qualifying earlier days at this hour — worded
//	                 "for this time of day", NEVER "for a Monday"
//	C  none          not enough history; the caller falls back to the flat
//	                 7-day 95th percentile and says so
//
// Centre is the median of the reference values; scale is 1.4826 × MAD (the
// normal-consistent median absolute deviation), floored so a series that has
// been perfectly flat does not turn every wobble into an infinite z. A
// reference that fell in a maintenance window is excluded and counted ("k of n
// weeks used"). Nothing here does IO or knows about tenants: the caller reads
// the references through its own scoped reads and hands them in.
package seasonal

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	// MaxWeeks / MaxDays are how many earlier weeks / days a profile reads.
	// Four weeks fit inside VictoriaMetrics' default 30-day retention.
	MaxWeeks = 4
	MaxDays  = 7
	// MinWeeks / MinDays are the qualifying references tiers A and B need.
	MinWeeks = 3
	MinDays  = 5
	// MADScale makes the MAD a consistent estimator of σ for normal data.
	MADScale = 1.4826
	// RelFloor floors the scale at this fraction of |centre|.
	RelFloor = 0.05
	// AboveZ is the robust z at or above which a value is "above its usual
	// level" (three robust standard deviations).
	AboveZ = 3.0
)

// Tier names the comparison a Profile supports.
type Tier string

// The three tiers.
const (
	TierWeek Tier = "hour_of_week" // A
	TierDay  Tier = "hour_of_day"  // B
	TierNone Tier = "none"         // C
)

// Ref is one reference observation: the same windowed value read at an earlier
// instant. Present is false when the read returned no value for the entity
// (a gap); Excluded is true when the reference fell in a maintenance window.
type Ref struct {
	At       time.Time
	Value    float64
	Present  bool
	Excluded bool
}

// Profile is what an entity's references support.
type Profile struct {
	Tier   Tier    `json:"tier"`
	Centre float64 `json:"centre"`
	Scale  float64 `json:"scale"`
	// Used is how many references qualified; Considered how many were read
	// for the chosen tier; Excluded how many were left out for maintenance.
	Used       int `json:"used"`
	Considered int `json:"considered"`
	Excluded   int `json:"excluded"`
	// HistoryDays is how far back the oldest present reference of either
	// kind reaches, in whole days (what tier C reports).
	HistoryDays int `json:"history_days"`
}

// HourOfWeek buckets a UTC instant: Monday 00:00 UTC = 0 … Sunday 23:00 = 167
// (the convention path_health_baselines.go already uses).
func HourOfWeek(t time.Time) int {
	t = t.UTC()
	return (int(t.Weekday())+6)%7*24 + t.Hour()
}

// WeekOffsets are the weekly reference offsets a caller reads, nearest first.
func WeekOffsets() []time.Duration {
	out := make([]time.Duration, MaxWeeks)
	for i := range out {
		out[i] = time.Duration(i+1) * 7 * 24 * time.Hour
	}
	return out
}

// DayOffsets are the daily reference offsets a caller reads, nearest first.
func DayOffsets() []time.Duration {
	out := make([]time.Duration, MaxDays)
	for i := range out {
		out[i] = time.Duration(i+1) * 24 * time.Hour
	}
	return out
}

// Fit chooses the best tier the references support and computes its centre
// and scale. now is the instant being judged (for HistoryDays); floor is the
// absolute scale floor for the metric's unit (UnitFloor).
func Fit(now time.Time, weekly, daily []Ref, floor float64) Profile {
	hist := historyDays(now, weekly, daily)
	if vals, excl := usable(weekly); len(vals) >= MinWeeks {
		c, s := centreScale(vals, floor)
		return Profile{Tier: TierWeek, Centre: c, Scale: s, Used: len(vals), Considered: len(weekly), Excluded: excl, HistoryDays: hist}
	}
	if vals, excl := usable(daily); len(vals) >= MinDays {
		c, s := centreScale(vals, floor)
		return Profile{Tier: TierDay, Centre: c, Scale: s, Used: len(vals), Considered: len(daily), Excluded: excl, HistoryDays: hist}
	}
	_, ew := usable(weekly)
	_, ed := usable(daily)
	return Profile{Tier: TierNone, Excluded: ew + ed, HistoryDays: hist}
}

// Z is the robust z of x against the profile; ok=false for tier C.
func (p Profile) Z(x float64) (float64, bool) {
	if p.Tier == TierNone || p.Scale <= 0 || math.IsNaN(x) || math.IsInf(x, 0) {
		return 0, false
	}
	return (x - p.Centre) / p.Scale, true
}

// Above reports whether x is above the usual level: z ≥ AboveZ. ok=false for
// tier C (the caller applies its flat fallback).
func (p Profile) Above(x float64) (above, ok bool) {
	z, ok := p.Z(x)
	if !ok {
		return false, false
	}
	return z >= AboveZ, true
}

// Describe is the operator-facing phrase for the comparison made.
func (p Profile) Describe() string {
	switch p.Tier {
	case TierWeek:
		return fmt.Sprintf("its usual level for this time of week (%d of %d weeks used%s)", p.Used, p.Considered, exclNote(p.Excluded))
	case TierDay:
		return fmt.Sprintf("its usual level for this time of day (%d of %d days used%s)", p.Used, p.Considered, exclNote(p.Excluded))
	}
	return fmt.Sprintf("not enough history for a time-of-day baseline (%d day%s)", p.HistoryDays, plural(p.HistoryDays))
}

func exclNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d left out for maintenance", n)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// UnitFloor is the smallest scale a metric of this unit may have: below it a
// difference is not operationally meaningful, whatever the MAD says.
func UnitFloor(unit string) float64 {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "percent", "pct", "%":
		return 0.5
	case "bps", "bits/s", "bit/s":
		return 1000
	case "bytes", "byte", "b":
		return 1024
	case "ms", "milliseconds":
		return 1
	case "s", "seconds":
		return 0.001
	case "pps", "packets/s", "count", "errors", "per_second", "/s", "prefixes":
		return 1
	case "score":
		return 0.5
	}
	return 1e-9
}

// usable returns the present, non-excluded values and the excluded count.
func usable(refs []Ref) ([]float64, int) {
	var vals []float64
	excl := 0
	for _, r := range refs {
		switch {
		case r.Excluded:
			excl++
		case r.Present && !math.IsNaN(r.Value) && !math.IsInf(r.Value, 0):
			vals = append(vals, r.Value)
		}
	}
	return vals, excl
}

func centreScale(vals []float64, floor float64) (float64, float64) {
	c := Median(vals)
	dev := make([]float64, len(vals))
	for i, v := range vals {
		dev[i] = math.Abs(v - c)
	}
	s := MADScale * Median(dev)
	s = math.Max(s, RelFloor*math.Abs(c))
	s = math.Max(s, floor)
	return c, s
}

func historyDays(now time.Time, sets ...[]Ref) int {
	var oldest time.Duration
	for _, refs := range sets {
		for _, r := range refs {
			if r.Present {
				if d := now.Sub(r.At); d > oldest {
					oldest = d
				}
			}
		}
	}
	return int(oldest / (24 * time.Hour))
}

// Median of vals (0 for none); vals is not modified.
func Median(vals []float64) float64 {
	n := len(vals)
	if n == 0 {
		return 0
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
