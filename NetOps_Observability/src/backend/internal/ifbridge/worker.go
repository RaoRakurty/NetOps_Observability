// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"context"
	"fmt"
	"time"

	"netops/backend/internal/applog"
)

// worker.go — the bridge's IO seam and its minute cycle.
//
// IO is the key-value store as functions (collectors supplies them in the api,
// fakes in tests: §1, every dependency explicit). Any half that could not be
// read is an error: the bridge's readers keep their previous answer rather than
// proceed on a bridge missing a feeder (tracker 307).

// IO is the bridge's key-value IO.
type IO struct {
	// SNMP reads the collector's half: both maps, the ifAlias map, the walk times.
	SNMP func(context.Context) (SNMP, error)
	// NMSRows reads the stored NMS rows (unsanitized).
	NMSRows func(context.Context) (State, error)
	// Publish stores the NMS rows.
	Publish func(context.Context, State) error
}

// Fetch reads both halves and merges them. The stored NMS rows are sanitized
// against now first (never trust cached data unvalidated).
func (io IO) Fetch(ctx context.Context, now time.Time, same SamePort) (Merged, error) {
	nmsRows, err := io.NMSRows(ctx)
	if err != nil {
		return Merged{}, fmt.Errorf("NMS interface rows unread: %w", err)
	}
	nmsRows.Sanitize(now)
	return io.merge(ctx, nmsRows, same, nil)
}

func (io IO) merge(ctx context.Context, nmsRows State, same SamePort, owners map[string]string) (Merged, error) {
	snmp, err := io.SNMP(ctx)
	if err != nil {
		return Merged{}, err
	}
	return Merge(snmp, nmsRows, same, owners), nil
}

// Worker runs the minute cycle: project the NMS rows onto inventory, store
// them, count. Its loaded flag belongs to the one goroutine that runs Cycle.
type Worker struct {
	Store   *Store
	Metrics *Metrics
	IO      IO
	Same    SamePort

	loaded bool
}

// Loaded reports whether the persisted rows have been read back.
func (w *Worker) Loaded() bool { return w.loaded }

// Cycle is one minute of the bridge. owners maps every inventory device id to
// its owner. Until the persisted rows have been read back the state is not
// stored, because writing now would overwrite rows this api has not yet
// managed to read (the SNMP side's rule, collectors/if_rows_retention.go).
func (w *Worker) Cycle(ctx context.Context, owners map[string]string, now time.Time) {
	if !w.loaded {
		st, err := w.IO.NMSRows(ctx)
		if err != nil {
			w.Metrics.ReadFailed()
			applog.Warn("if-bridge", "stored NMS interface rows unread: retrying next cycle, and not storing until then", map[string]any{"error": err.Error()})
		} else {
			w.Store.Load(st, now)
			w.loaded = true
		}
	}
	st, snap := w.Store.Snapshot(owners, now)
	if w.loaded {
		if err := w.IO.Publish(ctx, st); err != nil {
			w.Metrics.PublishFailed()
			applog.Error("if-bridge", "NMS interface rows not stored: the bridge's readers keep the previous rows until the next cycle", map[string]any{"error": err.Error()})
		} else {
			w.Metrics.Published(now.Unix())
		}
	}
	merged, err := w.IO.merge(ctx, st, w.Same, owners)
	if err != nil {
		w.Metrics.ReadFailed()
		applog.Warn("if-bridge", "SNMP interface rows unread: the bridge counts keep their last values", map[string]any{"error": err.Error()})
		return
	}
	w.Metrics.Set(merged.Stats, w.Store.IngestCounts(now), snap)
}
