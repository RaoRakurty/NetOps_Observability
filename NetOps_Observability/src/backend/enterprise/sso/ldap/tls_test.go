// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
//
// COMMERCIAL ADD-ON MODULE. This package implements the `ldap` entitlement
// (Enterprise tier) and is NOT Apache-2.0 core. See the LICENSE notice file in
// this directory, ../../../../../LICENSING.md, and LICENSES/Correlix-Enterprise.txt.

package ldap

import (
	"testing"
)

// TestLDAPTLSConfig covers SR-014: TLS is routed through the hardened tlsconfig
// package and cert verification can no longer be silently disabled.
func TestLDAPTLSConfig(t *testing.T) {
	t.Run("default verifies against system roots", func(t *testing.T) {
		cfg, err := Config{Host: "ldap.example.com"}.tlsConfig()
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
		if _, err := (Config{Host: "h", InsecureSkipVerify: true}).tlsConfig(); err == nil {
			t.Fatal("LDAP_INSECURE_SKIP_VERIFY must be refused without ALLOW_DEV_SECRETS")
		}
	})
	t.Run("insecure-skip-verify allowed only with dev opt-in", func(t *testing.T) {
		t.Setenv("ALLOW_DEV_SECRETS", "true")
		cfg, err := (Config{Host: "h", InsecureSkipVerify: true}).tlsConfig()
		if err != nil {
			t.Fatalf("dev opt-in must permit insecure LDAP TLS: %v", err)
		}
		if !cfg.InsecureSkipVerify {
			t.Error("dev opt-in should honor InsecureSkipVerify")
		}
	})
}
