// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// store_record_test.go — a snapshot the store could not write must not be in
// the numbers.
//
// THE DEFECT. Record folded the sample into the in-memory register and sealed
// every OTHER day's rows there, and only THEN wrote the file. When the write
// failed the recorder logged that "the day's roll-up is short one sample" while
// the register already held it, so the next hour's snapshot folded a SECOND
// sample on top of the first and persisted both. On a summing meter that is a
// billing figure counting an hour twice. The seal is worse in kind: it drops a
// day's identity sets, which is a lossy transform the file never agreed to.
//
// The shape of the failure below is the one store_prune_test.go uses: the
// register's parent directory is a regular file, which is what a full or
// read-only volume looks like to atomicWrite.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func meterOnDay(t *testing.T, rows []DailyRecord, day, meter string) MeterValue {
	t.Helper()
	for _, r := range rows {
		if r.Day != day {
			continue
		}
		v, ok := r.Meters[meter]
		if !ok {
			t.Fatalf("day %s has no %s meter", day, meter)
		}
		return v
	}
	t.Fatalf("no row for day %s", day)
	return MeterValue{}
}

func TestRecordThatCouldNotPersistIsNotInTheNumbers(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	path := filepath.Join(reg, "metering.json")

	s := NewFileStore(path)
	snapshot(t, s, day("2026-09-05T01:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterDEMChecks, "acme", 10)},
	})

	// Break the write path.
	if err := os.RemoveAll(reg); err != nil {
		t.Fatalf("clear register dir: %v", err)
	}
	if err := os.WriteFile(reg, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("block register dir: %v", err)
	}

	if err := s.Record(ctx, day("2026-09-05T02:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterDEMChecks, "acme", 10)},
	}); err == nil {
		t.Fatal("Record reported success with a broken write path — the failure must be visible (§10)")
	}

	// Unbreak it and take the next hour's snapshot, exactly as the recorder
	// does: a fresh sample, never a retry of the one that failed.
	if err := os.Remove(reg); err != nil {
		t.Fatalf("unblock register dir: %v", err)
	}
	snapshot(t, s, day("2026-09-05T03:00:00Z"), map[string][]Reading{
		"acme": {Measured(MeterDEMChecks, "acme", 10)},
	})

	reloaded := NewFileStore(path)
	rows, err := reloaded.List(ctx, "acme", false, "2026-09-01", "2026-09-30")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := meterOnDay(t, rows, "2026-09-05", MeterDEMChecks)
	if got.Value == nil {
		t.Fatal("on disk: the summing meter has no value")
	}
	if *got.Value != 20 {
		t.Fatalf("on disk: %s totals %v over two recorded samples, want 20 — the snapshot the store refused was counted anyway", MeterDEMChecks, *got.Value)
	}
	if got.Samples != 2 {
		t.Fatalf("on disk: %d samples, want 2 — one snapshot was not recorded and must not be counted", got.Samples)
	}
}

func TestRecordThatCouldNotPersistSealsNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	path := filepath.Join(reg, "metering.json")

	s := NewFileStore(path)
	snapshot(t, s, day("2026-09-05T01:00:00Z"), map[string][]Reading{
		"acme": {Unique(MeterMonitoredDevicesUnique, "acme", []string{"d1", "d2"})},
	})

	if err := os.RemoveAll(reg); err != nil {
		t.Fatalf("clear register dir: %v", err)
	}
	if err := os.WriteFile(reg, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("block register dir: %v", err)
	}

	// A snapshot on the NEXT day seals the 05th. The seal drops the identity
	// set behind the unique-device count, so it must not happen until the file
	// has agreed to it.
	if err := s.Record(ctx, day("2026-09-06T01:00:00Z"), map[string][]Reading{
		"acme": {Unique(MeterMonitoredDevicesUnique, "acme", []string{"d3"})},
	}); err == nil {
		t.Fatal("Record reported success with a broken write path")
	}
	s.mu.Lock()
	row := s.rows["acme"]["2026-09-05"]
	s.mu.Unlock()
	if row.Sealed() {
		t.Fatal("in memory: the 05th was sealed by a snapshot that never persisted — the identity set is gone with nothing on disk saying so")
	}
	if len(row.Open[MeterMonitoredDevicesUnique]) != 2 {
		t.Fatalf("in memory: the 05th holds %d identities, want the 2 it was recorded with", len(row.Open[MeterMonitoredDevicesUnique]))
	}
}
