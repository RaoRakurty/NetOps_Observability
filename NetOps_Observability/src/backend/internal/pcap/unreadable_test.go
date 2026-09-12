// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

// unreadable_test.go — the silent-data-loss regression. An unreadable register
// file used to load as an EMPTY one: nothing was recorded, nothing was logged,
// and the next capture renamed a temp file over the original, orphaning every
// sealed capture blob it indexed. A chmod is enough to stage it, because the
// directory stays writable so the rename still succeeds.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func seedCapture(id string) Capture {
	return Capture{TenantID: "acme", DeviceID: "dev-1", ID: id, Interface: "eth0",
		StartedAt: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), Status: StatusRunning}
}

func TestCaptureRegisterUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pcap_captures.json")
	seed := NewFileStore(path)
	if err := seed.Put(ctx, "acme", false, seedCapture("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); err != nil {
		t.Fatalf("seed capture: %v", err)
	}
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

	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable capture register loaded silently — every sealed capture reads as never taken, and the next capture destroys the file")
	}
	err := s.Put(ctx, "acme", false, seedCapture("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	if !errors.Is(err, ErrRegisterUnreadable) {
		t.Fatalf("a Put over an unreadable capture register returned %v", err)
	}
	if rows, _ := s.List(ctx, "acme", false, "dev-1", 0); len(rows) != 0 {
		t.Fatalf("the refused capture stayed in memory: %+v", rows)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, aerr := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if aerr != nil {
		t.Fatalf("read file after: %v", aerr)
	}
	if string(after) != string(before) {
		t.Fatalf("the register was rewritten while it could not be read:\nbefore %s\nafter  %s", before, after)
	}
	reopened := NewFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	rows, lerr := reopened.List(ctx, "acme", false, "dev-1", 0)
	if lerr != nil || len(rows) != 1 || rows[0].ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("the seeded capture did not survive: %v %+v", lerr, rows)
	}
}

// A register we cannot PARSE is unknown for the same reason.
func TestCaptureRegisterCorruptFileRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pcap_captures.json")
	before := []byte("{not json")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt capture register loaded silently")
	}
	if err := s.Put(context.Background(), "acme", false, seedCapture("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); !errors.Is(err, ErrRegisterUnreadable) {
		t.Fatalf("a Put over an unparsable register returned %v", err)
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
func TestAbsentCaptureRegisterStaysEmptyAndWritable(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "never-written.json"))
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a register that was never written reported %v", err)
	}
	if err := s.Put(context.Background(), "acme", false, seedCapture("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); err != nil {
		t.Fatalf("the first Put on a fresh register failed: %v", err)
	}
}
