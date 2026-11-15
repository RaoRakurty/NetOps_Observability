// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

// rollup.go — tracker 401 (a): the Roller that keeps netops.flow_iface_1m.
//
// Every tick it:
//  1. rolls forward: the received minutes after the newest rolled one, up to
//     the newest CLOSED minute minus a short lag, at most MaxRollMinutes;
//  2. backfills: one bounded slice of older received minutes, until the
//     rollup reaches back to the flows retention horizon;
//  3. reconciles (every ReconcileEvery ticks): compares, per received minute
//     over the last ReconcileSpan, the raw record count with the rolled one and
//     re-rolls each minute that differs (records that reached ClickHouse after
//     their minute was rolled — a Kafka backlog, a slow sink). A re-roll inserts
//     the whole minute again under a higher version; the ReplacingMergeTree
//     keeps the newest.
//
// What it guarantees the readers (State): every received minute in
// [Lo, Hi) is rolled under the current platform signature. A reader takes
// rollup rows for those minutes and raw rows for everything else.
//
// All IO is injected (Exec, Query, Now), so the logic is tested without a
// server. Exec and Query run at the PLATFORM scope ("__all__"): one statement
// covers every tenant's records, and each rolled row keeps its record's own
// tenant_id — no rollup row can ever mix tenants (the GROUP BY includes it).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	// RollLag is how long after a minute closes before it is rolled: records
	// are stamped when received, and the pipeline needs a moment to land them.
	RollLag = 2 * time.Minute
	// MaxRollMinutes bounds one forward or backfill slice.
	MaxRollMinutes = 10
	// BackfillMinutes bounds one backfill slice.
	BackfillMinutes = 30
	// ReconcileSpan is how far back late records are looked for.
	ReconcileSpan = 6 * time.Hour
	// ReconcileEvery: reconcile on every n-th tick.
	ReconcileEvery = 10
	// MaxRerollsPerTick bounds re-rolls of late minutes in one tick.
	MaxRerollsPerTick = 30
)

// Roller materialises the per-interface rollup.
type Roller struct {
	Exec  func(ctx context.Context, sql string) error
	Query func(ctx context.Context, sql string) ([]map[string]any, error)
	Now   func() time.Time
	// PlatformCond classifies Correlix's own monitoring traffic on raw columns
	// ("" = none configured). Its signature tags every rolled row.
	PlatformCond string
	// Retention is how far back raw records are kept (the backfill floor).
	Retention time.Duration

	mu      sync.RWMutex
	loaded  bool
	lo, hi  time.Time
	ticks   int
	lastErr error
}

// State is what readers may rely on.
type State struct {
	Lo, Hi time.Time
	Sig    uint64
}

// State returns the rolled interval [Lo, Hi) and the signature its rows carry.
// ok is false until the first successful roll.
func (r *Roller) State() (State, bool) {
	if r == nil {
		return State{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.loaded || !r.hi.After(r.lo) {
		return State{}, false
	}
	return State{Lo: r.lo, Hi: r.hi, Sig: PlatformSignature(r.PlatformCond)}, true
}

func (r *Roller) sig() uint64 { return PlatformSignature(r.PlatformCond) }

// load reads the rolled interval from the table (current signature only).
func (r *Roller) load(ctx context.Context) error {
	rows, err := r.Query(ctx, fmt.Sprintf(`SELECT toUnixTimestamp(min(recv_minute)) AS lo, toUnixTimestamp(max(recv_minute)) AS hi, count() AS n
  FROM netops.flow_iface_1m WHERE platform_sig = %d FORMAT JSON`, r.sig()))
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loaded = true
	if len(rows) == 1 && Num(rows[0]["n"]) > 0 {
		r.lo = time.Unix(int64(Num(rows[0]["lo"])), 0).UTC()
		r.hi = time.Unix(int64(Num(rows[0]["hi"])), 0).UTC().Add(time.Minute)
	}
	return nil
}

func (r *Roller) roll(ctx context.Context, from, to time.Time) error {
	return r.Exec(ctx, RollupInsertSQL(from, to, r.PlatformCond, r.Now().UnixMilli()))
}

// Tick runs one cycle. It returns the first error; partial progress is kept.
func (r *Roller) Tick(ctx context.Context) error {
	r.mu.RLock()
	loaded := r.loaded
	r.mu.RUnlock()
	if !loaded {
		if err := r.load(ctx); err != nil {
			return fmt.Errorf("read rollup state: %w", err)
		}
	}
	now := r.Now().UTC()
	limit := now.Truncate(time.Minute).Add(-RollLag) // received minutes before this are closed and settled
	r.mu.RLock()
	lo, hi := r.lo, r.hi
	r.mu.RUnlock()

	// 1. Forward.
	from := hi
	if hi.IsZero() {
		from = limit.Add(-MaxRollMinutes * time.Minute) // cold start: bounded; older minutes come by backfill
		lo = from
	}
	if from.Before(limit) {
		to := from.Add(MaxRollMinutes * time.Minute)
		if to.After(limit) {
			to = limit
		}
		if err := r.roll(ctx, from, to); err != nil {
			return fmt.Errorf("roll %s..%s: %w", from.Format(time.RFC3339), to.Format(time.RFC3339), err)
		}
		r.mu.Lock()
		if r.lo.IsZero() {
			r.lo = lo
		}
		r.hi = to
		lo = r.lo
		r.mu.Unlock()
	}

	// 2. Backfill one slice toward the retention horizon.
	if r.Retention > 0 && !lo.IsZero() {
		floor := now.Add(-r.Retention).Truncate(time.Minute).Add(time.Minute)
		if lo.After(floor) {
			bf := lo.Add(-BackfillMinutes * time.Minute)
			if bf.Before(floor) {
				bf = floor
			}
			if err := r.roll(ctx, bf, lo); err != nil {
				return fmt.Errorf("backfill %s..%s: %w", bf.Format(time.RFC3339), lo.Format(time.RFC3339), err)
			}
			r.mu.Lock()
			r.lo = bf
			r.mu.Unlock()
		}
	}

	// 3. Reconcile late records.
	r.mu.Lock()
	r.ticks++
	due := r.ticks%ReconcileEvery == 0
	r.mu.Unlock()
	if due {
		if _, err := r.Reconcile(ctx); err != nil {
			return fmt.Errorf("reconcile: %w", err)
		}
	}
	return nil
}

// Reconcile re-rolls each recently received minute whose raw record count
// differs from the rolled count, and returns how many it re-rolled.
func (r *Roller) Reconcile(ctx context.Context) (int, error) {
	r.mu.RLock()
	lo, hi := r.lo, r.hi
	r.mu.RUnlock()
	if !hi.After(lo) {
		return 0, nil
	}
	from := hi.Add(-ReconcileSpan)
	if from.Before(lo) {
		from = lo
	}
	raw, err := r.Query(ctx, `SELECT toUnixTimestamp(toStartOfMinute(ts)) AS m, count() AS c
  FROM netops.flows WHERE ts >= `+TSLit(from)+` AND ts < `+TSLit(hi)+`
 GROUP BY m FORMAT JSON`)
	if err != nil {
		return 0, err
	}
	rolled, err := r.Query(ctx, fmt.Sprintf(`SELECT toUnixTimestamp(recv_minute) AS m, sum(records) AS c
  FROM netops.flow_iface_1m FINAL
 WHERE platform_sig = %d AND direction = 'in' AND recv_minute >= %s AND recv_minute < %s
 GROUP BY m FORMAT JSON`, r.sig(), minuteLit(from), minuteLit(hi)))
	if err != nil {
		return 0, err
	}
	diff := MinutesToReroll(raw, rolled)
	if len(diff) > MaxRerollsPerTick {
		diff = diff[:MaxRerollsPerTick]
	}
	n := 0
	var firstErr error
	for _, m := range diff {
		if err := r.roll(ctx, m, m.Add(time.Minute)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n++
	}
	return n, firstErr
}

// MinutesToReroll compares per-minute raw record counts with rolled counts and
// returns the minutes that differ, oldest first.
func MinutesToReroll(raw, rolled []map[string]any) []time.Time {
	got := map[int64]float64{}
	for _, row := range rolled {
		got[int64(Num(row["m"]))] = Num(row["c"])
	}
	var out []time.Time
	for _, row := range raw {
		m := int64(Num(row["m"]))
		if Num(row["c"]) != got[m] {
			out = append(out, time.Unix(m, 0).UTC())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// Run ticks every interval until ctx ends, backing off after failures.
func (r *Roller) Run(ctx context.Context, interval time.Duration, logf func(msg string, err error)) {
	if r == nil || r.Exec == nil || r.Query == nil {
		return
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	wait := interval
	t := time.NewTimer(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := r.Tick(tctx)
		cancel()
		r.mu.Lock()
		changed := (err == nil) != (r.lastErr == nil)
		r.lastErr = err
		r.mu.Unlock()
		switch {
		case err != nil && !errors.Is(err, context.Canceled):
			if changed && logf != nil {
				logf("the per-interface flow rollup could not roll; the link views read raw records until it recovers", err)
			}
			if wait < 10*time.Minute {
				wait *= 2
			}
		default:
			if changed && logf != nil {
				logf("the per-interface flow rollup is rolling again", nil)
			}
			wait = interval
		}
		t.Reset(wait)
	}
}
