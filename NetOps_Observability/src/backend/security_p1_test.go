package main

import "testing"

// TestEnsureSigningSecret covers the SR-017 fail-closed boot guard: with no
// JWT_SECRET the process must refuse to start unless dev mode is opted into.
func TestEnsureSigningSecret(t *testing.T) {
	t.Run("explicit secret is allowed", func(t *testing.T) {
		t.Setenv("JWT_SECRET", "a-real-configured-secret")
		t.Setenv("ALLOW_DEV_SECRETS", "")
		if err := ensureSigningSecret(); err != nil {
			t.Fatalf("configured JWT_SECRET must pass: %v", err)
		}
	})
	t.Run("missing secret fails closed", func(t *testing.T) {
		t.Setenv("JWT_SECRET", "")
		t.Setenv("ALLOW_DEV_SECRETS", "")
		if err := ensureSigningSecret(); err == nil {
			t.Fatal("missing JWT_SECRET must fail closed without ALLOW_DEV_SECRETS")
		}
	})
	t.Run("dev opt-in allows the fallback", func(t *testing.T) {
		t.Setenv("JWT_SECRET", "")
		t.Setenv("ALLOW_DEV_SECRETS", "true")
		if err := ensureSigningSecret(); err != nil {
			t.Fatalf("ALLOW_DEV_SECRETS=true must permit dev fallback: %v", err)
		}
	})
}
