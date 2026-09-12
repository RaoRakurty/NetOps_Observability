// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rcafeedback

// unreadable_test.go — the silent-data-loss regression. An unreadable verdict
// file used to load as an EMPTY one: nothing was recorded, nothing was logged,
// and the next Add renamed a temp file over the original, so every operator's
// judgement on every RCA was gone. A chmod is enough to stage it, because the
// directory stays writable so the rename still succeeds.

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

func verdict(caseID, v string) Feedback {
	return Feedback{TenantID: "acme", CorrelationID: caseID, Verdict: v,
		CreatedAt: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)}
}

func TestVerdictFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rca_feedback.json")
	seed := NewFileStore(path)
	kept, err := seed.Add(ctx, "acme", false, verdict("c-1", "correct"))
	if err != nil {
		t.Fatalf("seed verdict: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable verdict file loaded silently — every judged case reads as never judged, and the next Add destroys the file")
	}
	_, aerr := s.Add(ctx, "acme", false, verdict("c-1", "partial"))
	if !errors.Is(aerr, ErrStoreUnreadable) {
		t.Fatalf("an Add over an unreadable verdict file returned %v", aerr)
	}
	if rows, _ := s.List(ctx, "acme", false, "c-1"); len(rows) != 0 {
		t.Fatalf("the refused verdict stayed in memory: %+v", rows)
	}

	assertUntouched(t, path, before)
	reopened := NewFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	rows, lerr := reopened.List(ctx, "acme", false, "c-1")
	if lerr != nil || len(rows) != 1 || rows[0].ID != kept.ID {
		t.Fatalf("the seeded verdict did not survive: %v %+v", lerr, rows)
	}
}

// A verdict file we cannot PARSE is unknown for the same reason.
func TestVerdictCorruptFileRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rca_feedback.json")
	before := []byte("{not json")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt verdict file loaded silently")
	}
	if _, err := s.Add(context.Background(), "acme", false, verdict("c-1", "correct")); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("an Add over an unparsable verdict file returned %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the unparsable file was overwritten: %s", after)
	}
}

// A file that is ABSENT is still just an empty register, with nothing reported
// and writes allowed. This is the half the fix must NOT break.
func TestAbsentVerdictFileStaysEmptyAndWritable(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "never-written.json"))
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a register that was never written reported %v", err)
	}
	if _, err := s.Add(context.Background(), "acme", false, verdict("c-1", "correct")); err != nil {
		t.Fatalf("the first Add on a fresh register failed: %v", err)
	}
}
