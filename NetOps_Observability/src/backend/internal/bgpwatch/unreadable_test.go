// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// unreadable_test.go — the silent-data-loss regression for BOTH file stores in
// this package. An unreadable file used to load as an EMPTY one: LoadErr stayed
// nil, nothing was logged, and the next write renamed a temp file over the
// original. A chmod is enough to stage it, because the directory stays writable
// so the rename still succeeds.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
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

// The WATCHLIST: an unreadable file is not an empty watchlist, and the next Add
// must not destroy it.
func TestWatchlistFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bgp_watchlist.json")
	seed := NewWatchFileStore(path)
	if err := seed.Add(ctx, "acme", WatchEntry{Resource: "203.0.113.0/24", Kind: "prefix", Note: "dc egress"}); err != nil {
		t.Fatalf("seed add: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewWatchFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable watchlist loaded silently — the operator sees no watches with no reason, and the next Add destroys the file")
	}
	err := s.Add(ctx, "acme", WatchEntry{Resource: "198.51.100.0/24", Kind: "prefix"})
	if err == nil {
		t.Fatal("an Add was accepted over a watchlist whose file could not be read")
	}
	if !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("the refusal does not carry the package sentinel: %v", err)
	}
	if rows, _ := s.List(ctx, "acme", false); len(rows) != 0 {
		t.Fatalf("the refused row stayed in memory: %v", rows)
	}

	assertUntouched(t, path, before)
	reopened := NewWatchFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	rows, _ := reopened.List(ctx, "acme", false)
	if len(rows) != 1 || rows[0].Resource != "203.0.113.0/24" {
		t.Fatalf("the seeded watch did not survive: %v", rows)
	}
}

// A watchlist file we cannot PARSE is unknown for the same reason, so a write
// would replace it rather than update it.
func TestWatchlistCorruptFileRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bgp_watchlist.json")
	before := []byte("{not json")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewWatchFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt watchlist loaded silently")
	}
	if err := s.Add(context.Background(), "acme", WatchEntry{Resource: "203.0.113.0/24", Kind: "prefix"}); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("an Add over an unparsable watchlist returned %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the unparsable file was overwritten: %s", after)
	}
}

// The POLICY store: same defect, same proof.
func TestPolicyFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bgp_policy.json")
	seed := NewFileStore(path)
	if err := seed.SetPolicy(ctx, "acme", "u@acme", TenantPolicy{Default: PolicyConfig{ExpectedOrigins: []uint32{64496}}}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable policy file loaded silently — every tenant reads as having no policy and the next save destroys the file")
	}
	err := s.SetPolicy(ctx, "globex", "u@globex", TenantPolicy{Default: PolicyConfig{ExpectedOrigins: []uint32{64500}}})
	if !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a policy save over an unreadable file returned %v", err)
	}

	assertUntouched(t, path, before)
	reopened := NewFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	p, perr := reopened.Policy(ctx, "acme")
	if perr != nil || len(p.Default.ExpectedOrigins) != 1 || p.Default.ExpectedOrigins[0] != 64496 {
		t.Fatalf("the seeded policy did not survive: %v %+v", perr, p)
	}
}

// A file that is ABSENT is still just an empty store, with nothing reported and
// writes allowed. This is the half the fix must NOT break.
func TestAbsentFilesStayEmptyAndWritable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w := NewWatchFileStore(filepath.Join(dir, "never-written.json"))
	if err := w.LoadErr(); err != nil {
		t.Fatalf("a watchlist that was never written reported %v", err)
	}
	if err := w.Add(ctx, "acme", WatchEntry{Resource: "203.0.113.0/24", Kind: "prefix"}); err != nil {
		t.Fatalf("the first Add on a fresh watchlist failed: %v", err)
	}
	p := NewFileStore(filepath.Join(dir, "never-written-policy.json"))
	if err := p.LoadErr(); err != nil {
		t.Fatalf("a policy store that was never written reported %v", err)
	}
	if err := p.SetPolicy(ctx, "acme", "u@acme", TenantPolicy{}); err != nil {
		t.Fatalf("the first SetPolicy on a fresh store failed: %v", err)
	}
}
