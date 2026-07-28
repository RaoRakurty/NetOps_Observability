package main

import (
	"errors"
	"netops/backend/internal/users"
	"strings"
	"testing"

	"netops/backend/internal/token"
)

// Shuttled back from the token package split: password POLICY (length rules,
// account-type predicates) is integrator domain; only the KDF moved.
// SR-013: over-long passwords are rejected at create/change and cheaply refused
// by token.VerifyPassword BEFORE the 600k-round KDF runs (pre-hash amplification DoS).
func TestPasswordLengthBounds(t *testing.T) {
	long := strings.Repeat("a", token.MaxPasswordLen+1)
	if err := users.ValidatePassword(long); !errors.Is(err, users.ErrLongPassword) {
		t.Errorf("over-long password should be users.ErrLongPassword, got %v", err)
	}
	if err := users.ValidatePassword("short"); !errors.Is(err, users.ErrShortPassword) {
		t.Errorf("short password should be users.ErrShortPassword, got %v", err)
	}
	if err := users.ValidatePassword("a-perfectly-fine-passphrase"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}
	hash, err := token.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("token.HashPassword: %v", err)
	}
	if token.VerifyPassword(long, hash) {
		t.Error("token.VerifyPassword accepted an over-long password")
	}
}

// TestIsLocalAccount locks which auth sources may change their password in-app:
// only local (or legacy empty); federated sources are managed by the IdP.
func TestIsLocalAccount(t *testing.T) {
	local := []string{"", "local", "LOCAL", " local "}
	for _, s := range local {
		if !isLocalAccount(s) {
			t.Errorf("isLocalAccount(%q) = false, want true", s)
		}
	}
	federated := []string{"oidc", "saml", "ldap", "tacacs", "OIDC"}
	for _, s := range federated {
		if isLocalAccount(s) {
			t.Errorf("isLocalAccount(%q) = true, want false (IdP-managed)", s)
		}
	}
}
