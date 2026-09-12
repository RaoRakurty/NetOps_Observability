// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// investigation_memory_unreadable_test.go — the silent-data-loss regression. An
// unreadable memory file used to load as an EMPTY one: nothing was recorded,
// nothing was logged, and the next Record renamed a temp file over the original,
// so every tenant's investigation history was gone. A chmod is enough to stage
// it, because the directory stays writable so the rename still succeeds.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stageUnreadable makes path unreadable and returns its bytes from before.
// It skips the test where a 0000 file can still be read (running as root).
func stageUnreadable(t *testing.T, path string) []byte {
	t.Helper()
	before, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read seeded file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(path); err == nil { // #nosec G304 -- test-owned temp path
		t.Skip("this environment can read a 0000 file (running as root?), so the case cannot be staged")
	}
	return before
}

// assertUntouched proves the file on disk is byte-identical to `before`.
func assertUntouched(t *testing.T, path string, before []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read file after: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("the file was rewritten while it could not be read:\nbefore %s\nafter  %s", before, after)
	}
}

func memoryRow(id, verdict string) InvestigationRow {
	at := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	return InvestigationRow{TenantID: "acme", ID: id, DeviceID: "dev-1", Verdict: verdict,
		Outcome: OutcomeConfirmed, CreatedAt: at, ResolvedAt: at}
}

func TestMemoryFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "investigation_memory.json")
	seed := NewInvestigationFileStore(path)
	if err := seed.Record(ctx, memoryRow("inv-1", "the optic was dirty")); err != nil {
		t.Fatalf("seed memory: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewInvestigationFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable memory file loaded silently — every past investigation is forgotten with no reason, and the next Record destroys the file")
	}
	err := s.Record(ctx, memoryRow("inv-2", "second"))
	if !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a Record over an unreadable memory file returned %v", err)
	}
	if rows, _ := s.Recall(ctx, "acme", false, InvestigationQuery{Device: "dev-1"}); len(rows) != 0 {
		t.Fatalf("the refused row stayed in memory: %+v", rows)
	}

	assertUntouched(t, path, before)
	reopened := NewInvestigationFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	rows, rerr := reopened.Recall(ctx, "acme", false, InvestigationQuery{Device: "dev-1"})
	if rerr != nil || len(rows) != 1 || rows[0].ID != "inv-1" {
		t.Fatalf("the seeded memory did not survive: %v %+v", rerr, rows)
	}
}

// A memory file we cannot PARSE is unknown for the same reason.
func TestMemoryCorruptFileRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "investigation_memory.json")
	before := []byte("{not json")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewInvestigationFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt memory file loaded silently")
	}
	if err := s.Record(context.Background(), memoryRow("inv-1", "v")); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a Record over an unparsable memory file returned %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the unparsable file was overwritten: %s", after)
	}
}

// An OWNERLESS ROW is a row-level drop, not an unreadable file: we read the file
// and made a deliberate choice, so writes stay allowed and rewriting the file is
// the intended repair.
func TestOwnerlessRowIsDroppedButDoesNotBlockWrites(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "investigation_memory.json")
	if err := os.WriteFile(path, []byte(`[{"id":"orphan","device_id":"dev-1","verdict":"v","tenant_id":""}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewInvestigationFileStore(path)
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a row we deliberately dropped was reported as an unreadable file: %v", err)
	}
	if err := s.Record(ctx, memoryRow("inv-1", "v")); err != nil {
		t.Fatalf("a row-level drop blocked writes: %v", err)
	}
}

// A file that is ABSENT is still just an empty memory, with nothing reported and
// writes allowed. This is the half the fix must NOT break.
func TestAbsentMemoryFileStaysEmptyAndWritable(t *testing.T) {
	s := NewInvestigationFileStore(filepath.Join(t.TempDir(), "never-written.json"))
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a memory that was never written reported %v", err)
	}
	if err := s.Record(context.Background(), memoryRow("inv-1", "v")); err != nil {
		t.Fatalf("the first Record on a fresh memory failed: %v", err)
	}
}
