package main

import (
	"netops/backend/internal/token"
	"path/filepath"
	"testing"
)

func TestUserStoreCRUD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := newUserStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if s.Count() != 0 {
		t.Fatalf("fresh store should be empty, has %d", s.Count())
	}

	if _, err := s.Create("alice", "shortpw", "admin"); err == nil {
		t.Fatalf("expected create to reject short password")
	}

	u, err := s.Create("Alice", "longenoughpw", "admin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Username != "Alice" || u.Role != "admin" {
		t.Fatalf("returned user wrong: %+v", u)
	}

	if _, err := s.Create("alice", "anotherpw", "admin"); err == nil {
		t.Fatalf("expected duplicate username (case-insensitive) to fail")
	}

	got, ok := s.Get("ALICE") // case-insensitive lookup
	if !ok || got.Username != "Alice" {
		t.Fatalf("case-insensitive get failed: ok=%v got=%+v", ok, got)
	}

	// Reload from disk and make sure state survived.
	s2, err := newUserStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s2.Count() != 1 {
		t.Fatalf("reloaded count = %d, want 1", s2.Count())
	}
	if !token.VerifyPassword("longenoughpw", got.PasswordHash) {
		t.Fatalf("stored hash doesn't verify the original password")
	}
}

func TestSeedAdminOnlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, _ := newUserStore(path)
	if err := s.SeedAdmin("admin", "initial-password"); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("expected 1 user after seed, got %d", s.Count())
	}
	// Second seed must be a no-op (different password should be ignored).
	if err := s.SeedAdmin("admin", "different"); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	u, _ := s.Get("admin")
	if !token.VerifyPassword("initial-password", u.PasswordHash) {
		t.Fatalf("second seed silently overwrote the password")
	}
}
