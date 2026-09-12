// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package verify

// runstore_unreadable_test.go — the silent-data-loss regression for the RUN
// register. The config store beside it already got this right; the run register
// still folded an unreadable file into "nothing stored yet", started empty with
// nothing logged, and let the next run rename a temp file over the original.
// A chmod is enough to stage it, because the directory stays writable so the
// rename still succeeds.

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func runRow(caseID string) RunRecord {
	return RunRecord{RunID: "run-" + caseID, TenantID: "acme", CorrelationID: caseID,
		Trigger: "manual", Actor: "u@acme", Status: "completed",
		StartedAt: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), Devices: []string{"dev-1"}}
}

func TestRunFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verify_runs.json")
	seed := NewRunStore(path)
	seed.Put(runRow("corr-1"))
	before, rerr := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if rerr != nil {
		t.Fatalf("read seeded file: %v", rerr)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(path); err == nil { // #nosec G304 -- test-owned temp path
		t.Skip("this environment can read a 0000 file (running as root?), so the case cannot be staged")
	}

	s := NewRunStore(path)
	if s.Unavailable() == nil {
		t.Fatal("an unreadable run register loaded silently — every verified case reads as never verified, and the next run destroys the file")
	}
	// Put has no error channel; the proof is that the FILE is untouched.
	s.Put(runRow("corr-2"))

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, aerr := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if aerr != nil {
		t.Fatalf("read file after: %v", aerr)
	}
	if string(after) != string(before) {
		t.Fatalf("the run register was rewritten while it could not be read:\nbefore %s\nafter  %s", before, after)
	}
	reopened := NewRunStore(path)
	if reopened.Unavailable() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.Unavailable())
	}
	if rec, ok := reopened.Latest("acme", "corr-1"); !ok || rec.RunID != "run-corr-1" {
		t.Fatalf("the seeded run did not survive: %+v %v", rec, ok)
	}
}

// A run register we cannot PARSE is unknown for the same reason, and it must not
// leave the in-memory map half-decoded either.
func TestRunFileCorruptRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verify_runs.json")
	before := []byte(`{"acme": {"corr-1": "not a run record"}}`)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewRunStore(path)
	if s.Unavailable() == nil {
		t.Fatal("a corrupt run register loaded silently")
	}
	if _, ok := s.Latest("acme", "corr-1"); ok {
		t.Fatal("a half-decoded document became rows")
	}
	s.Put(runRow("corr-2"))
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the unparsable file was overwritten: %s", after)
	}
}

// A file that is ABSENT is still just an empty register, with nothing reported
// and the run persisted as normal. This is the half the fix must NOT break.
func TestAbsentRunFileStaysEmptyAndWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written.json")
	s := NewRunStore(path)
	if err := s.Unavailable(); err != nil {
		t.Fatalf("a run register that was never written reported %v", err)
	}
	s.Put(runRow("corr-1"))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the first run on a fresh register did not persist: %v", err)
	}
}
