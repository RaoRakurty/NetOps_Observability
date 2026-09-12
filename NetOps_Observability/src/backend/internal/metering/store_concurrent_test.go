// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// store_concurrent_test.go — the file backend hands out rows that share NOTHING
// with the rows it keeps.
//
// This is the invariant behind a crash we shipped: List released the mutex and
// returned records whose Meters map was still the store's live map, so the
// hourly snapshot wrote into a map the usage handler was iterating and the Go
// runtime killed the process with "concurrent map read and map write". The
// api dies, and every collector and the alert receiver die with it.
//
// The detachment tests below fail WITHOUT the race detector, deterministically,
// because a shared map is observable in one goroutine. The concurrency test is
// what CI's `-race` run aims at the same defect.
//
// There are two detachment tests and they are not redundant: the first snapshots
// again between the read and the write, so it is Fold's purity it actually
// measures; the second does not, and is the only one that can fail when
// collectRange stops cloning.

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"
)

// TestFileStoreListHandsOutDetachedRows pins the store contract: a row a caller
// already holds does not change when the next snapshot lands.
func TestFileStoreListHandsOutDetachedRows(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	snapshot(t, s, day("2026-09-05T01:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 2)},
	})

	rows, err := s.List(ctx, "acme", false, "2026-09-05", "2026-09-05")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("list returned %d rows, want 1", len(rows))
	}
	before := meterValue(t, rows[0], MeterMonitoredDevicesPeak)

	// The next hourly snapshot raises the peak. It must not reach back into the
	// slice the previous reader is still holding.
	snapshot(t, s, day("2026-09-05T02:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 9)},
	})

	if after := meterValue(t, rows[0], MeterMonitoredDevicesPeak); after != before {
		t.Fatalf("a row already handed to a caller changed from %v to %v when the snapshot landed — List is sharing the store's live map", before, after)
	}

	// And the other direction: a caller scribbling on its own copy must not
	// reach the store.
	rows[0].Meters[MeterMonitoredDevicesPeak] = MeterValue{Meter: MeterMonitoredDevicesPeak}
	again, err := s.List(ctx, "acme", false, "2026-09-05", "2026-09-05")
	if err != nil {
		t.Fatalf("list again: %v", err)
	}
	if got := meterValue(t, again[0], MeterMonitoredDevicesPeak); got != 9 {
		t.Fatalf("the store's row reads %v after a caller edited its own copy, want 9", got)
	}
}

// TestFileStoreListCopiesTheStoresOwnMap pins collectRange's Clone SPECIFICALLY.
//
// Why this exists as well as the detachment test above: that test snapshots
// again between the List and the scribble, and the second snapshot replaces the
// store's row with a fresh map (Fold is pure). The map the reader is holding is
// an orphan by then, so scribbling on it proves nothing about collectRange —
// deleting the `.Clone()` in collectRange leaves that test GREEN. Verified by
// deleting it: every metering test still passed. A guard that cannot fail on the
// line it guards is not a guard.
//
// So: no fold in between. The map List hands back is the one the store is
// holding at this instant, and writing through it must not reach the register.
func TestFileStoreListCopiesTheStoresOwnMap(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	snapshot(t, s, day("2026-09-05T01:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 2)},
	})

	rows, err := s.List(ctx, "acme", false, "2026-09-05", "2026-09-05")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("list returned %d rows, want 1", len(rows))
	}

	// A caller writing into the row it was handed — which is what an encoder,
	// a roll-up or a report renderer is entitled to do with a value it owns.
	scribble := 4242.0
	rows[0].Meters[MeterMonitoredDevicesPeak] = MeterValue{
		Meter: MeterMonitoredDevicesPeak, Value: &scribble, Samples: 1,
	}
	rows[0].Meters["not-a-meter"] = MeterValue{Meter: "not-a-meter"}

	again, err := s.List(ctx, "acme", false, "2026-09-05", "2026-09-05")
	if err != nil {
		t.Fatalf("list again: %v", err)
	}
	if got := meterValue(t, again[0], MeterMonitoredDevicesPeak); got != 2 {
		t.Fatalf("the store's row reads %v after a caller edited the row List gave it, want 2 — List is handing out the store's live Meters map", got)
	}
	if _, ok := again[0].Meters["not-a-meter"]; ok {
		t.Fatal("a key a caller added to its own row appeared in the store's row — List is handing out the store's live Meters map")
	}
}

// TestFoldDoesNotMutateTheRowItWasGiven holds Fold to the purity its doc
// comment claims. A fold that writes into the caller's map is how the store's
// live rows leaked into a reader's hands in the first place.
func TestFoldDoesNotMutateTheRowItWasGiven(t *testing.T) {
	row, err := Fold(DailyRecord{Day: "2026-09-05", TenantID: "acme"},
		[]Reading{Measured(MeterMonitoredDevicesPeak, "acme", 2)}, day("2026-09-05T01:00:00Z"))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	next, err := Fold(row, []Reading{Measured(MeterMonitoredDevicesPeak, "acme", 9)}, day("2026-09-05T02:00:00Z"))
	if err != nil {
		t.Fatalf("fold again: %v", err)
	}
	if got := meterValue(t, row, MeterMonitoredDevicesPeak); got != 2 {
		t.Fatalf("the row handed to Fold now reads %v, want the 2 it went in with — Fold mutated its input", got)
	}
	if got := meterValue(t, next, MeterMonitoredDevicesPeak); got != 9 {
		t.Fatalf("the folded row reads %v, want 9", got)
	}
}

// TestFileStoreConcurrentRecordAndList is the shape that crashed: the hourly
// snapshot folding while the usage handler encodes what List gave it.
//
// Without the fix the Go runtime throws "concurrent map read and map write" and
// takes the test binary down; under CI's `-race` the detector reports it first.
func TestFileStoreConcurrentRecordAndList(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	at := day("2026-09-05T01:00:00Z")
	snapshot(t, s, at, map[string][]Reading{
		"acme":            {Unique(MeterMonitoredDevicesUnique, "acme", []string{"d1"}), Measured(MeterMonitoredDevicesPeak, "acme", 1)},
		ScopeInstallation: {Measured(MeterTenants, ScopeInstallation, 1)},
	})

	const rounds = 500
	var readers, writer sync.WaitGroup
	stop := make(chan struct{})

	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// Same day, same tenant: this is the hourly fold rewriting the row
			// a reader may be holding.
			if err := s.Record(ctx, at.Add(time.Duration(i)*time.Millisecond), map[string][]Reading{
				"acme":            {Unique(MeterMonitoredDevicesUnique, "acme", []string{"d1", "d2"}), Measured(MeterMonitoredDevicesPeak, "acme", float64(i%97))},
				ScopeInstallation: {Measured(MeterTenants, ScopeInstallation, 1)},
			}); err != nil {
				t.Errorf("record: %v", err)
				return
			}
		}
	}()

	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < rounds; i++ {
				rows, err := s.List(ctx, "", true, "2026-09-05", "2026-09-05")
				if err != nil {
					t.Errorf("list: %v", err)
					return
				}
				// What GET /api/system/licence/usage does with the answer: walk
				// every meter map and encode it, with the store's mutex long
				// released.
				for _, row := range rows {
					for _, mv := range row.Meters {
						_ = mv.Samples
					}
					_ = RollUp([]DailyRecord{row})
				}
				if err := json.NewEncoder(io.Discard).Encode(rows); err != nil {
					t.Errorf("encode: %v", err)
					return
				}
			}
		}()
	}

	readers.Wait()
	close(stop)
	writer.Wait()
}

func meterValue(t *testing.T, r DailyRecord, meter string) float64 {
	t.Helper()
	mv, ok := r.Meters[meter]
	if !ok || mv.Value == nil {
		t.Fatalf("row %s/%s has no value for %s", r.Day, r.TenantID, meter)
	}
	return *mv.Value
}
