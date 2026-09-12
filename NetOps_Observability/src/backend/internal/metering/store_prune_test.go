// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// store_prune_test.go — the retention sweep must not drop rows it could not
// persist.
//
// THE DEFECT. Prune deleted every expired row from the in-memory register for
// every tenant and only THEN wrote the file. When the write failed the rows
// were already gone from memory, while the recorder logged that the history
// "is being kept instead" — the opposite of what had happened. The next hourly
// snapshot serialised the register as it stood and made the loss permanent.
// This is billing data.
//
// The shape of the failure below is a broken write path: the register's parent
// directory is a regular file, which is what a full or read-only volume looks
// like to atomicWrite.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStorePruneKeepsRowsItCouldNotPersist(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	path := filepath.Join(reg, "metering.json")

	s := NewFileStore(path)
	// One row far past the retention horizon, one inside it.
	snapshot(t, s, day("2024-01-01T01:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 7)},
	})
	snapshot(t, s, day("2026-09-05T01:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 2)},
	})

	// Break the write path.
	if err := os.RemoveAll(reg); err != nil {
		t.Fatalf("clear register dir: %v", err)
	}
	if err := os.WriteFile(reg, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("block register dir: %v", err)
	}

	horizon := PruneHorizon(day("2026-09-05T01:00:00Z"))
	n, err := s.Prune(ctx, horizon)
	if err == nil {
		t.Fatalf("prune reported success with a broken write path — the failure must be visible (§10)")
	}
	if n != 0 {
		t.Errorf("prune reported %d rows dropped after a failed write; nothing was durably dropped, so the pruned counter must not move", n)
	}

	// The register still holds every row, with its contents intact.
	rows, lerr := s.List(ctx, "acme", false, "2024-01-01", "2026-12-31")
	if lerr != nil {
		t.Fatalf("list: %v", lerr)
	}
	byDay := map[string]float64{}
	for _, r := range rows {
		byDay[r.Day] = meterValue(t, r, MeterMonitoredDevicesPeak)
	}
	if got, ok := byDay["2024-01-01"]; !ok || got != 7 {
		t.Errorf("the expired row was dropped from memory although it was never persisted as dropped: rows=%v", byDay)
	}
	if got, ok := byDay["2026-09-05"]; !ok || got != 2 {
		t.Errorf("the current row is missing or wrong: rows=%v", byDay)
	}

	// Repair the volume. The next successful write must carry every row, so a
	// restart reads them back.
	if err := os.Remove(reg); err != nil {
		t.Fatalf("repair register dir: %v", err)
	}
	snapshot(t, s, day("2026-09-06T01:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 3)},
	})

	reloaded := NewFileStore(path)
	back, rerr := reloaded.List(ctx, "acme", false, "2024-01-01", "2026-12-31")
	if rerr != nil {
		t.Fatalf("reload: %v", rerr)
	}
	seen := map[string]float64{}
	for _, r := range back {
		seen[r.Day] = meterValue(t, r, MeterMonitoredDevicesPeak)
	}
	for day, want := range map[string]float64{"2024-01-01": 7, "2026-09-05": 2, "2026-09-06": 3} {
		if got, ok := seen[day]; !ok || got != want {
			t.Errorf("after the write path recovered, day %s reads %v (present=%v), want %v — a row was lost to a failed prune: %v", day, got, ok, want, seen)
		}
	}
}

// TestFileStorePruneStillDropsWhenItCanPersist is the other half: the sweep
// must actually work when the volume is healthy.
func TestFileStorePruneStillDropsWhenItCanPersist(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "metering.json")
	s := NewFileStore(path)
	snapshot(t, s, day("2024-01-01T01:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 7)},
	})
	snapshot(t, s, day("2026-09-05T01:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 2)},
	})
	n, err := s.Prune(ctx, PruneHorizon(day("2026-09-05T01:00:00Z")))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("prune dropped %d rows, want the single expired one", n)
	}
	reloaded := NewFileStore(path)
	rows, err := reloaded.List(ctx, "acme", false, "2024-01-01", "2026-12-31")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(rows) != 1 || rows[0].Day != "2026-09-05" {
		t.Fatalf("the expired row is still on disk after a successful prune: %+v", rows)
	}
}
