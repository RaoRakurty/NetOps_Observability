// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// local_source_test.go — H1 regression coverage for the local/federated split:
// the IsLocalSource predicate (""=local), the AuthSource stamp on the
// bootstrap/seed write paths, and the one-time load migration that normalizes
// pre-stamp rows. The UpsertFederated refusal these enable is proven in the
// cross-backend authorization contract (federated_contract_test.go).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsLocalSource(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{"", true}, // legacy/bootstrap rows — the H1 hole when read as federated
		{"local", true},
		{"  Local  ", true},
		{"oidc", false},
		{"saml", false},
		{"ldap", false},
		{"tacacs", false},
	} {
		if got := IsLocalSource(tc.source); got != tc.want {
			t.Errorf("IsLocalSource(%q) = %v, want %v", tc.source, got, tc.want)
		}
	}
}

func TestSeedAdminStampsLocalAuthSource(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "users.json"), testDeps())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SeedAdmin("admin", "Passw0rd!2345"); err != nil {
		t.Fatal(err)
	}
	u, ok := s.Get("admin")
	if !ok {
		t.Fatal("seeded admin not found")
	}
	if u.AuthSource != "local" {
		t.Errorf("seeded admin AuthSource = %q, want %q — an empty source used to count as federated (H1)", u.AuthSource, "local")
	}
}

// TestFileStoreLoadMigratesEmptyAuthSource: a users.json written before the
// AuthSource stamp (rows carry "") is normalized to "local" at load — in memory
// AND back to disk — so UpsertFederated's local-account refusal applies to the
// pre-existing bootstrap admin, not just freshly created accounts.
func TestFileStoreLoadMigratesEmptyAuthSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	legacy := `[
		{"username":"admin","role":"admin","password_hash":"x","created_at":"2025-01-01T00:00:00Z"},
		{"username":"fed-user","role":"read-only","auth_source":"oidc","created_at":"2025-01-01T00:00:00Z"}
	]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewFileStore(path, testDeps())
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := s.Get("admin"); u.AuthSource != "local" {
		t.Errorf("legacy row AuthSource = %q after load, want %q", u.AuthSource, "local")
	}
	if u, _ := s.Get("fed-user"); u.AuthSource != "oidc" {
		t.Errorf("federated row AuthSource = %q after load, want %q (migration must not touch it)", u.AuthSource, "oidc")
	}
	// The refusal the migration exists for:
	if _, err := s.UpsertFederated("admin", "a@idp", "IdP", "super-admin", "oidc", ""); err == nil {
		t.Fatal("UpsertFederated against the migrated local admin must refuse")
	}
	// And the normalization persisted (a restart must not resurrect "").
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"auth_source": "local"`) {
		t.Errorf("migrated auth_source not persisted; file:\n%s", b)
	}
}
