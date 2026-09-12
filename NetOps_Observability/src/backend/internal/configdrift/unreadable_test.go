// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configdrift

// unreadable_test.go — the silent-data-loss regression, and the ONE place the
// platform deliberately RECOVERS instead of refusing.
//
// The half that was broken everywhere: an unreadable file loaded as an EMPTY
// one, with nothing recorded and nothing logged. That is fixed here too —
// LoadErr now reports it, so a reader can say "unknown" rather than show a
// fleet with no drift.
//
// The half that is deliberate: this register is DERIVED. Every row is recomputed
// from the next capture of that device, so rewriting the file IS the repair.
// Writes stay allowed, and the recovery is explicit and logged rather than
// silent.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func driftRow(deviceID, state string) State {
	return State{TenantID: "acme", DeviceID: deviceID, State: state,
		UpdatedAt: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)}
}

// An unreadable register is REPORTED. Before the fix it was indistinguishable
// from a fleet that had never been captured.
func TestDriftRegisterUnreadableIsReportedNotSilentlyEmpty(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config_drift.json")
	seed := NewFileStore(path)
	if err := seed.Put(ctx, "acme", false, driftRow("dev-1", StateDrifted)); err != nil {
		t.Fatalf("seed state: %v", err)
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
		t.Fatal("an unreadable drift register loaded silently — every device reads as in-sync with no reason given")
	}
	counts, cerr := s.Counts(ctx, Principal{Tenant: "acme"})
	if cerr != nil || len(counts) != 0 {
		t.Fatalf("an unreadable register produced counts: %v %v", cerr, counts)
	}
}

// The DELIBERATE part: this register is derived, so the next capture is allowed
// to rewrite the file. Every other file store in the platform refuses; this one
// recovers, and the load has already logged that it will.
func TestDriftRegisterRecoversBecauseEveryRowIsRederived(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config_drift.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unparsable drift register loaded silently")
	}
	if err := s.Put(ctx, "acme", false, driftRow("dev-1", StateInSync)); err != nil {
		t.Fatalf("the next capture could not rewrite a derived register: %v", err)
	}
	reopened := NewFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the rewritten file no longer loads: %v", reopened.LoadErr())
	}
	st, ok, gerr := reopened.Get(ctx, "acme", false, "dev-1")
	if gerr != nil || !ok || st.State != StateInSync {
		t.Fatalf("the recapture did not land: %v %v %+v", gerr, ok, st)
	}
}

// A file that is ABSENT is still just an empty register, with nothing reported.
func TestAbsentDriftRegisterStaysEmptyAndWritable(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "never-written.json"))
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a register that was never written reported %v", err)
	}
	if err := s.Put(context.Background(), "acme", false, driftRow("dev-1", StateInSync)); err != nil {
		t.Fatalf("the first Put on a fresh register failed: %v", err)
	}
}
