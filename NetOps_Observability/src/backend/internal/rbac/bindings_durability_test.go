// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rbac

import (
	"os"
	"path/filepath"
	"testing"
)

// breakWrites turns the register's parent directory into a FILE, so the next
// platformdb.Save fails at MkdirAll the way a full or read-only volume does.
// The returned func puts the directory back so a later write can succeed.
func breakWrites(t *testing.T, dir string) func() {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("clearing %s: %v", dir, err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("blocking %s: %v", dir, err)
	}
	return func() {
		if err := os.Remove(dir); err != nil {
			t.Fatalf("unblocking %s: %v", dir, err)
		}
	}
}

func seedBindings(t *testing.T, s *BindingStore, principals ...string) {
	t.Helper()
	for _, p := range principals {
		if _, err := s.Add(RoleBinding{PrincipalID: p, RoleID: "viewer", ScopeID: "tenant:acme"}); err != nil {
			t.Fatalf("seeding %s: %v", p, err)
		}
	}
}

// TestRemoveByPrincipalKeepsBindingsWhenTheFlushFails is the durability half of
// the persist-then-adopt contract: a purge whose write fails must leave the
// principal's bindings BOTH in memory and, once an unrelated write succeeds, on
// disk. The old order deleted from the map first, so a failed flush dropped the
// grants silently and the next successful write made the loss permanent.
func TestRemoveByPrincipalKeepsBindingsWhenTheFlushFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reg")
	path := filepath.Join(dir, "role_bindings.json")
	s, err := NewBindingStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	seedBindings(t, s, "alice", "bob")

	restore := breakWrites(t, dir)
	if err := s.RemoveByPrincipal("alice"); err == nil {
		t.Fatal("RemoveByPrincipal reported success with the write path broken")
	}
	if got := len(s.ListByPrincipal("alice")); got != 1 {
		t.Fatalf("in memory: alice has %d bindings after a failed purge, want 1", got)
	}
	restore()

	// An unrelated write serialises the register as it now stands. If the purge
	// had been applied in memory, this is where the loss becomes durable.
	seedBindings(t, s, "carol")

	reloaded, err := NewBindingStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(reloaded.ListByPrincipal("alice")); got != 1 {
		t.Fatalf("on disk: alice has %d bindings after a failed purge, want 1", got)
	}
	if got := len(reloaded.ListByPrincipal("bob")); got != 1 {
		t.Fatalf("on disk: bob has %d bindings, want 1", got)
	}
}

// TestRemoveKeepsTheBindingWhenTheFlushFails is the same contract for the
// single-binding delete.
func TestRemoveKeepsTheBindingWhenTheFlushFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reg")
	path := filepath.Join(dir, "role_bindings.json")
	s, err := NewBindingStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	seedBindings(t, s, "alice", "bob")
	id := s.ListByPrincipal("alice")[0].ID

	restore := breakWrites(t, dir)
	if err := s.Remove(id); err == nil {
		t.Fatal("Remove reported success with the write path broken")
	}
	if got := len(s.ListByPrincipal("alice")); got != 1 {
		t.Fatalf("in memory: alice has %d bindings after a failed remove, want 1", got)
	}
	restore()
	seedBindings(t, s, "carol")

	reloaded, err := NewBindingStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(reloaded.ListByPrincipal("alice")); got != 1 {
		t.Fatalf("on disk: alice has %d bindings after a failed remove, want 1", got)
	}
}

// TestAddDoesNotKeepAGrantTheDiskRefused is the mirror hazard: a grant whose
// write failed must not sit in memory waiting for an unrelated write to make it
// durable. Add reported the error, so the caller believes nobody was granted
// anything.
func TestAddDoesNotKeepAGrantTheDiskRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reg")
	path := filepath.Join(dir, "role_bindings.json")
	s, err := NewBindingStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	seedBindings(t, s, "alice")

	restore := breakWrites(t, dir)
	if _, err := s.Add(RoleBinding{PrincipalID: "mallory", RoleID: "admin", ScopeID: "tenant:acme"}); err == nil {
		t.Fatal("Add reported success with the write path broken")
	}
	if got := len(s.ListByPrincipal("mallory")); got != 0 {
		t.Fatalf("in memory: mallory holds %d bindings after a refused grant, want 0", got)
	}
	restore()
	seedBindings(t, s, "carol")

	reloaded, err := NewBindingStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(reloaded.ListByPrincipal("mallory")); got != 0 {
		t.Fatalf("on disk: mallory holds %d bindings after a refused grant, want 0", got)
	}
}
