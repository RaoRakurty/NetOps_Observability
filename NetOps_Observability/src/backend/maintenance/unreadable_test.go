// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package maintenance

// unreadable_test.go — the silent-data-loss regression. An unreadable window
// file used to load as an EMPTY one: nothing was recorded, nothing was logged,
// and the next Create renamed a temp file over the original, so every tenant's
// declared maintenance was gone and nothing was suppressed any more. A chmod is
// enough to stage it, because the directory stays writable so the rename still
// succeeds.

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

func maintWindow(name string) Window {
	start := time.Date(2026, 9, 10, 22, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	return Window{TenantID: "acme", Name: name, Enabled: true, StartsAt: &start, EndsAt: &end}
}

func TestWindowFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "maintenance.json")
	seed := NewFileStore(path)
	kept, err := seed.Create(ctx, "acme", false, maintWindow("friday change"))
	if err != nil {
		t.Fatalf("seed window: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable window file loaded silently — nothing is suppressed, nobody is told, and the next Create destroys the file")
	}
	_, cerr := s.Create(ctx, "acme", false, maintWindow("second"))
	if !errors.Is(cerr, ErrStoreUnreadable) {
		t.Fatalf("a Create over an unreadable window file returned %v", cerr)
	}
	if rows, _ := s.List(ctx, "acme", false); len(rows) != 0 {
		t.Fatalf("the refused window stayed in memory: %+v", rows)
	}

	assertUntouched(t, path, before)
	reopened := NewFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	got, ok, gerr := reopened.Get(ctx, "acme", false, kept.ID)
	if gerr != nil || !ok || got.Name != "friday change" {
		t.Fatalf("the seeded window did not survive: %v %v %+v", gerr, ok, got)
	}
}

// A window file we cannot PARSE is unknown for the same reason.
func TestWindowCorruptFileRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance.json")
	before := []byte("{not json")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt window file loaded silently")
	}
	if _, err := s.Create(context.Background(), "acme", false, maintWindow("x")); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a Create over an unparsable window file returned %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the unparsable file was overwritten: %s", after)
	}
}

// A file that is ABSENT is still just an empty store, with nothing reported and
// writes allowed. This is the half the fix must NOT break.
func TestAbsentWindowFileStaysEmptyAndWritable(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "never-written.json"))
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a store that was never written reported %v", err)
	}
	if _, err := s.Create(context.Background(), "acme", false, maintWindow("first")); err != nil {
		t.Fatalf("the first Create on a fresh store failed: %v", err)
	}
}
