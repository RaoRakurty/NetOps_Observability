// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

// episodes_unreadable_test.go — the silent-data-loss regression. An unreadable
// episode file used to load as an EMPTY one: nothing was recorded, nothing was
// logged, and the next transition renamed a temp file over the original, so
// every episode's history, triage notes, mutes and snoozes were gone. A chmod is
// enough to stage it, because the directory stays writable so the rename still
// succeeds.

import (
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

func newEpisodeTestStore(path string) *EpisodeStore {
	return NewEpisodeStore(path, 15*time.Minute, 6, 15*time.Minute)
}

func TestEpisodeFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alert_episodes.json")
	seed := newEpisodeTestStore(path)
	seed.Observe("acme", "dev-1", "BGPPeerDown", "critical", "peer down", true)
	before := stageUnreadable(t, path)

	s := newEpisodeTestStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable episode file loaded silently — every mute and triage note is gone with no reason, and the next transition destroys the file")
	}
	// Folding CONTINUES in memory by design: an unwritable disk must never stop
	// alerts from being evaluated. What must not happen is the file being
	// replaced by what this process holds.
	s.Observe("acme", "dev-2", "BGPPeerDown", "critical", "peer down", true)
	if eps, _, _ := s.List("acme", false, EpisodeQuery{}); len(eps) != 1 {
		t.Fatalf("folding stopped when the file could not be read: %+v", eps)
	}

	assertUntouched(t, path, before)
	reopened := newEpisodeTestStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	eps, _, _ := reopened.List("acme", false, EpisodeQuery{})
	if len(eps) != 1 || eps[0].Resource != "dev-1" {
		t.Fatalf("the seeded episode did not survive: %+v", eps)
	}
}

// An episode file we cannot PARSE is unknown for the same reason.
func TestEpisodeCorruptFileRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alert_episodes.json")
	before := []byte("{not json")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newEpisodeTestStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt episode file loaded silently")
	}
	s.Observe("acme", "dev-1", "BGPPeerDown", "critical", "peer down", true)
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the unparsable file was overwritten: %s", after)
	}
}

// A file that is ABSENT is still just an empty set, with nothing reported and
// folding persisted as normal. This is the half the fix must NOT break.
func TestAbsentEpisodeFileStaysEmptyAndWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written.json")
	s := newEpisodeTestStore(path)
	if err := s.LoadErr(); err != nil {
		t.Fatalf("an episode file that was never written reported %v", err)
	}
	s.Observe("acme", "dev-1", "BGPPeerDown", "critical", "peer down", true)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the first transition on a fresh store did not persist: %v", err)
	}
}
