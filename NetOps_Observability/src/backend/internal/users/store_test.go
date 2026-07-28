package users

import (
	"netops/backend/internal/token"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fileKV is a plain file backend for tests.
type fileKV struct{}

func (fileKV) Load(key string) ([]byte, error)    { return os.ReadFile(key) }
func (fileKV) Save(key string, data []byte) error { return os.WriteFile(key, data, 0o600) }

// testDeps supplies minimal stand-ins for the injected cross-domain deps.
func testDeps() Deps {
	return Deps{
		KV:           fileKV{},
		Errorf:       func(string, string, map[string]any) {},
		GuardRole:    func(role, _, _, _ string) string { return role },
		IsSuperAdmin: func(role string) bool { return role == "super-admin" || role == "admin" },
		ApplyPasswordChange: func(u *User, hash string, now time.Time) {
			u.PasswordHash = hash
			u.PasswordChangedAt = now
		},
		DefaultTenant: "global",
	}
}

func TestUserStoreCRUD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "json")
	s, err := NewFileStore(path, testDeps())
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
	s2, err := NewFileStore(path, testDeps())
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
	path := filepath.Join(t.TempDir(), "json")
	s, _ := NewFileStore(path, testDeps())
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
