// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// store_test.go — the file backend, and the isolation posture that lives IN it
// (CLAUDE.md §3a rule 4). The point of these tests is that a handler cannot
// forget the tenant filter, because there is no method that would let it.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func snapshot(t *testing.T, s Store, at time.Time, by map[string][]Reading) {
	t.Helper()
	if err := s.Record(context.Background(), at, by); err != nil {
		t.Fatalf("record: %v", err)
	}
}

func fixture(t *testing.T, s Store) {
	t.Helper()
	for _, d := range []string{"2026-09-03", "2026-09-04", "2026-09-05"} {
		snapshot(t, s, day(d+"T01:00:00Z"), map[string][]Reading{
			"acme":            {Unique(MeterMonitoredDevicesUnique, "acme", []string{"d1", "d2"}), Measured(MeterMonitoredDevicesPeak, "acme", 2)},
			"globex":          {Unique(MeterMonitoredDevicesUnique, "globex", []string{"g1"}), Measured(MeterMonitoredDevicesPeak, "globex", 1)},
			ScopeInstallation: {Measured(MeterTenants, ScopeInstallation, 2), Measured(MeterOrgs, ScopeInstallation, 1)},
		})
	}
}

func TestFileStoreScopedReadSeesOnlyItsOwnRows(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "metering.json"))
	fixture(t, s)

	acme, err := s.List(context.Background(), "acme", false, "2026-09-01", "2026-09-30")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(acme) != 3 {
		t.Fatalf("acme sees %d rows, want its own 3", len(acme))
	}
	for _, r := range acme {
		if r.TenantID != "acme" {
			t.Fatalf("acme was handed a %q row — cross-tenant leak", r.TenantID)
		}
	}
}

func TestFileStoreScopedReadNeverSeesTheInstallationRow(t *testing.T) {
	s := NewFileStore("")
	fixture(t, s)
	// The installation row's key is the empty string, which is also what an
	// unresolved tenant scope looks like. A caller with no scope must get
	// NOTHING rather than the installation's own meters.
	rows, err := s.List(context.Background(), "", false, "2026-09-01", "2026-09-30")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("an unscoped read returned %d rows — default-closed means none", len(rows))
	}
	// And a real tenant never sees it either.
	acme, _ := s.List(context.Background(), "acme", false, "2026-09-01", "2026-09-30")
	for _, r := range acme {
		if r.TenantID == ScopeInstallation {
			t.Fatalf("a tenant was handed the installation row")
		}
	}
}

func TestFileStoreCrossReadSeesEverything(t *testing.T) {
	s := NewFileStore("")
	fixture(t, s)
	rows, err := s.List(context.Background(), "", true, "2026-09-01", "2026-09-30")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 9 {
		t.Fatalf("cross read sees %d rows, want 9 (3 days × acme, globex, installation)", len(rows))
	}
	// Day then tenant order, so a report reads chronologically.
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Day > rows[i].Day {
			t.Fatalf("rows are not in day order")
		}
	}
}

func TestFileStoreRangeIsInclusiveAndValidated(t *testing.T) {
	s := NewFileStore("")
	fixture(t, s)
	rows, err := s.List(context.Background(), "acme", false, "2026-09-04", "2026-09-04")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].Day != "2026-09-04" {
		t.Fatalf("a single-day range returned %d rows", len(rows))
	}
	if _, err := s.List(context.Background(), "acme", false, "2026-09-05", "2026-09-04"); err == nil {
		t.Errorf("a reversed range was accepted — a quietly empty answer to a malformed period is the wrong failure")
	}
	if _, err := s.List(context.Background(), "acme", false, "yesterday", "today"); err == nil {
		t.Errorf("a malformed day was accepted")
	}
}

func TestFileStorePersistsAndSealsClosedDays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metering.json")
	s := NewFileStore(path)
	snapshot(t, s, day("2026-09-04T01:00:00Z"), map[string][]Reading{
		"acme": {Unique(MeterMonitoredDevicesUnique, "acme", []string{"d1", "d2", "d3"})},
	})
	snapshot(t, s, day("2026-09-05T01:00:00Z"), map[string][]Reading{
		"acme": {Unique(MeterMonitoredDevicesUnique, "acme", []string{"d1"})},
	})

	// A fresh store over the same file must read the same numbers back.
	again := NewFileStore(path)
	rows, err := again.List(context.Background(), "acme", false, "2026-09-01", "2026-09-30")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("reloaded %d rows, want 2", len(rows))
	}
	if v := rows[0].Meters[MeterMonitoredDevicesUnique].Value; v == nil || *v != 3 {
		t.Fatalf("the closed day lost its count: %+v", rows[0].Meters[MeterMonitoredDevicesUnique])
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The CLOSED day must no longer carry its identity set: the count is the
	// answer, and keeping thousands of ids per tenant per day for 400 days is a
	// storage bill nobody asked for.
	var f meteringFile
	mustJSON(t, raw, &f)
	for _, r := range f.Records {
		if r.Day == "2026-09-04" && len(r.Open) != 0 {
			t.Fatalf("a closed day still carries its accumulator state")
		}
	}
}

func TestFileStorePruneKeepsTheBound(t *testing.T) {
	s := NewFileStore("")
	snapshot(t, s, day("2024-01-01T01:00:00Z"), map[string][]Reading{"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 1)}})
	snapshot(t, s, day("2026-09-05T01:00:00Z"), map[string][]Reading{"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 1)}})
	if n, _ := s.Rows(context.Background()); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
	dropped, err := s.Prune(context.Background(), PruneHorizon(day("2026-09-05T01:00:00Z")))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("pruned %d rows, want the one outside the %d-day bound", dropped, RetentionDays)
	}
	if n, _ := s.Rows(context.Background()); n != 1 {
		t.Fatalf("rows after prune = %d, want 1", n)
	}
	if _, err := s.Prune(context.Background(), "not-a-day"); err == nil {
		t.Errorf("prune accepted a malformed horizon")
	}
}

func TestFileStoreCorruptFileServesEmptyAndSaysSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metering.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewFileStore(path)
	if err := s.LoadErr(); err == nil {
		t.Fatalf("a corrupt store reported no problem — a blank history and an unreadable one are different facts")
	}
	rows, err := s.List(context.Background(), "acme", false, "2026-09-01", "2026-09-30")
	if err != nil {
		t.Fatalf("a corrupt store must still SERVE: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %d from a corrupt store", len(rows))
	}
}

func mustJSON(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}
