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

// TestLDAPTLSConfig covers SR-014: TLS is routed through the hardened tlsconfig
// package and cert verification can no longer be silently disabled.
func TestLDAPTLSConfig(t *testing.T) {
	t.Run("default verifies against system roots", func(t *testing.T) {
		cfg, err := ldapConfig{Host: "ldap.example.com"}.tlsConfig()
		if err != nil {
			t.Fatalf("default LDAP TLS config: %v", err)
		}
		if cfg.InsecureSkipVerify {
			t.Error("default LDAP TLS must verify the server certificate")
		}
		if cfg.ServerName != "ldap.example.com" {
			t.Errorf("ServerName = %q, want hostname verification against the LDAP host", cfg.ServerName)
		}
	})
	t.Run("insecure-skip-verify refused without dev opt-in", func(t *testing.T) {
		t.Setenv("ALLOW_DEV_SECRETS", "")
		if _, err := (ldapConfig{Host: "h", InsecureSkipVerify: true}).tlsConfig(); err == nil {
			t.Fatal("LDAP_INSECURE_SKIP_VERIFY must be refused without ALLOW_DEV_SECRETS")
		}
	})
	t.Run("insecure-skip-verify allowed only with dev opt-in", func(t *testing.T) {
		t.Setenv("ALLOW_DEV_SECRETS", "true")
		cfg, err := (ldapConfig{Host: "h", InsecureSkipVerify: true}).tlsConfig()
		if err != nil {
			t.Fatalf("dev opt-in must permit insecure LDAP TLS: %v", err)
		}
		if !cfg.InsecureSkipVerify {
			t.Error("dev opt-in should honor InsecureSkipVerify")
		}
	})
}
