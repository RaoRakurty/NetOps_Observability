// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// seasonal_rollup_test.go — N-H6 PR 2: when the metric store no longer holds
// an earlier week, the hourly roll-up (SeasonalStore) fills it — only for the
// entities and hours the answer needs, only for short windows, and a failed
// roll-up read fills nothing and says so.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type rollupScope struct {
	*fakeScope
	p50   map[string]map[int64]float64
	err   error
	calls []struct {
		metric string
		keys   []string
		hours  []time.Time
	}
}

func (r *rollupScope) SeasonalHours(_ context.Context, metric string, keys []string, hours []time.Time) (map[string]map[int64]float64, error) {
	r.calls = append(r.calls, struct {
		metric string
		keys   []string
		hours  []time.Time
	}{metric, keys, hours})
	return r.p50, r.err
}

// The answer window is 1h ending at now: a reference's hour is the hour
// holding its window's middle.
func refHour(back time.Duration) int64 {
	return now.Add(-back).Add(-30 * time.Minute).UTC().Truncate(time.Hour).Unix()
}

func TestRollupFillsWeeksTheMetricStoreNoLongerKeeps(t *testing.T) {
	// The metric store holds the current value and the first week only.
	sc := &rollupScope{
		fakeScope: &fakeScope{instantFn: history(map[string]map[time.Duration]float64{
			"edge-1": {0: 80, week: 40},
		})},
		p50: map[string]map[int64]float64{"edge-1": {
			refHour(2 * week): 41, refHour(3 * week): 39, refHour(4 * week): 40,
		}},
	}
	rs := runScope(t, sc, compareCPU)
	b, _ := rowFor(t, rs, "edge-1")["baseline"].(string)
	if !strings.Contains(b, "this time of week (4 of 4 weeks used)") {
		t.Fatalf("baseline = %q — the roll-up must fill weeks 2–4", b)
	}
	if len(sc.calls) != 1 || sc.calls[0].metric != "cpu_util_pct" || len(sc.calls[0].keys) != 1 || sc.calls[0].keys[0] != "edge-1" {
		t.Fatalf("roll-up read = %+v, want one read of cpu_util_pct for edge-1", sc.calls)
	}
	if len(sc.calls[0].hours) != 3 {
		t.Fatalf("roll-up hours = %v, want only the three missing weeks", sc.calls[0].hours)
	}
	if !strings.Contains(strings.Join(rs.Notes, " "), "3 earlier-week references came from the hourly roll-up") {
		t.Fatalf("notes = %v", rs.Notes)
	}
}

func TestRollupIsNotUsedForLongWindows(t *testing.T) {
	sc := &rollupScope{fakeScope: &fakeScope{instantFn: history(map[string]map[time.Duration]float64{"edge-1": {0: 80}})},
		p50: map[string]map[int64]float64{"edge-1": {}}}
	long := strings.ReplaceAll(compareCPU, `"last":"1h"`, `"last":"6h"`)
	runScope(t, sc, long)
	if len(sc.calls) != 0 {
		t.Fatalf("a 6h window must not stand an hourly median in for its value: %+v", sc.calls)
	}
}

func TestAnUnreadableRollupFillsNothingAndSaysSo(t *testing.T) {
	sc := &rollupScope{fakeScope: &fakeScope{instantFn: history(map[string]map[time.Duration]float64{"edge-1": {0: 80, week: 40}})},
		err: errors.New("clickhouse down")}
	rs := runScope(t, sc, compareCPU)
	b, _ := rowFor(t, rs, "edge-1")["baseline"].(string)
	if strings.Contains(b, "time of week") {
		t.Fatalf("nothing may be filled from a failed read: %q", b)
	}
	if !strings.Contains(strings.Join(rs.Notes, " "), "hourly roll-up could not be read") {
		t.Fatalf("notes = %v", rs.Notes)
	}
}

// The roll-up never adds an entity: it is asked only about the keys the
// current, scoped read returned.
func TestRollupIsAskedOnlyAboutTheAnswersEntities(t *testing.T) {
	sc := &rollupScope{fakeScope: &fakeScope{instantFn: history(map[string]map[time.Duration]float64{"edge-1": {0: 80}})},
		p50: map[string]map[int64]float64{"foreign": {refHour(week): 1}}}
	rs := runScope(t, sc, compareCPU)
	for _, c := range sc.calls {
		for _, k := range c.keys {
			if k != "edge-1" {
				t.Fatalf("the roll-up was asked about %q", k)
			}
		}
	}
	for _, r := range rs.Rows {
		if r["device"] == "foreign" {
			t.Fatalf("a roll-up row became an answer row: %+v", rs.Rows)
		}
	}
}
