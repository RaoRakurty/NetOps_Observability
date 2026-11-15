// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeCH struct {
	execs   []string
	failOn  string
	state   []map[string]any
	raw     []map[string]any
	rolled  []map[string]any
	queries []string
}

func (f *fakeCH) exec(_ context.Context, sql string) error {
	if f.failOn != "" && strings.Contains(sql, f.failOn) {
		return errors.New("boom")
	}
	f.execs = append(f.execs, sql)
	return nil
}

func (f *fakeCH) query(_ context.Context, sql string) ([]map[string]any, error) {
	f.queries = append(f.queries, sql)
	switch {
	case strings.Contains(sql, "min(recv_minute)"):
		return f.state, nil
	case strings.Contains(sql, "FROM netops.flows"):
		return f.raw, nil
	}
	return f.rolled, nil
}

func newRoller(f *fakeCH, now time.Time) *Roller {
	return &Roller{Exec: f.exec, Query: f.query, Now: func() time.Time { return now }, Retention: 7 * 24 * time.Hour}
}

// A cold start rolls a bounded recent slice and backfills one older slice; the
// reader's interval covers exactly what was rolled.
func TestRollerColdStartThenBackfill(t *testing.T) {
	now := utc("2026-11-14T10:20:30Z")
	f := &fakeCH{}
	r := newRoller(f, now)
	if _, ok := r.State(); ok {
		t.Fatal("state before any roll")
	}
	if err := r.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.execs) != 2 {
		t.Fatalf("execs = %d (forward + backfill)", len(f.execs))
	}
	// Forward: [10:08, 10:18) — closed minutes before now−lag.
	if !strings.Contains(f.execs[0], "ts >= toDateTime64(1794650880, 3, 'UTC') AND ts < toDateTime64(1794651480, 3, 'UTC')") {
		t.Errorf("forward roll window:\n%s", f.execs[0])
	}
	// Backfill: the hour before that.
	if !strings.Contains(f.execs[1], "ts >= toDateTime64(1794649080, 3, 'UTC') AND ts < toDateTime64(1794650880, 3, 'UTC')") {
		t.Errorf("backfill window:\n%s", f.execs[1])
	}
	st, ok := r.State()
	if !ok || !st.Lo.Equal(utc("2026-11-14T09:38:00Z")) || !st.Hi.Equal(utc("2026-11-14T10:18:00Z")) {
		t.Errorf("state = %+v %v", st, ok)
	}
}

// A failed roll keeps the interval where it was, so a reader never trusts
// minutes that were not rolled.
func TestRollerFailureKeepsTheInterval(t *testing.T) {
	now := utc("2026-11-14T10:20:30Z")
	f := &fakeCH{state: []map[string]any{{"lo": float64(utc("2026-11-14T09:00:00Z").Unix()), "hi": float64(utc("2026-11-14T10:00:00Z").Unix()), "n": "10"}}, failOn: "INSERT"}
	r := newRoller(f, now)
	if err := r.Tick(context.Background()); err == nil {
		t.Fatal("expected the failed insert to surface")
	}
	st, ok := r.State()
	if !ok || !st.Hi.Equal(utc("2026-11-14T10:01:00Z")) || !st.Lo.Equal(utc("2026-11-14T09:00:00Z")) {
		t.Errorf("state moved on a failed roll: %+v", st)
	}
}

// Late records: a minute whose raw count differs from the rolled count is
// re-rolled whole; matching minutes are left alone.
func TestReconcileRerollsOnlyMinutesThatDiffer(t *testing.T) {
	now := utc("2026-11-14T10:20:30Z")
	m1, m2 := utc("2026-11-14T10:01:00Z").Unix(), utc("2026-11-14T10:02:00Z").Unix()
	f := &fakeCH{
		state:  []map[string]any{{"lo": float64(utc("2026-11-14T09:00:00Z").Unix()), "hi": float64(utc("2026-11-14T10:17:00Z").Unix()), "n": "10"}},
		raw:    []map[string]any{{"m": float64(m1), "c": "5"}, {"m": float64(m2), "c": "7"}},
		rolled: []map[string]any{{"m": float64(m1), "c": "5"}, {"m": float64(m2), "c": "6"}},
	}
	r := newRoller(f, now)
	if err := r.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	n, err := r.Reconcile(context.Background())
	if err != nil || n != 1 || len(f.execs) != 1 {
		t.Fatalf("rerolled %d (%v), execs %d", n, err, len(f.execs))
	}
	if !strings.Contains(f.execs[0], "ts >= toDateTime64(1794650520, 3, 'UTC') AND ts < toDateTime64(1794650580, 3, 'UTC')") {
		t.Errorf("re-roll window:\n%s", f.execs[0])
	}
	// The rolled count is read from FINAL rows, current signature, one direction.
	q := f.queries[len(f.queries)-1]
	if !strings.Contains(q, "FINAL") || !strings.Contains(q, "direction = 'in'") || !strings.Contains(q, "platform_sig = ") {
		t.Errorf("rolled-count query:\n%s", q)
	}
}

func TestMinutesToRerollCountsAMissingMinute(t *testing.T) {
	got := MinutesToReroll([]map[string]any{{"m": float64(120), "c": "3"}, {"m": float64(60), "c": "1"}}, nil)
	if len(got) != 2 || got[0].Unix() != 60 || got[1].Unix() != 120 {
		t.Errorf("got %v", got)
	}
}
