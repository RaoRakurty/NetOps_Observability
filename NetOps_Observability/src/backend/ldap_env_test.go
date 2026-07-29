package main

// ldap_env_test.go — the LDAP_* env constructor stays in main (env reads live
// in the entrypoint); its tests moved here when the protocol core went to
// internal/ldap (Phase-2 W1.8).

import (
	"testing"

	"netops/backend/internal/ldap"
)

func TestNewLDAPConfigFromEnv(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
	t.Setenv("LDAP_HOST", "ad.example.com")
	t.Setenv("LDAP_PORT", "636")
	t.Setenv("LDAP_USE_TLS", "true")
	t.Setenv("LDAP_START_TLS", "false")
	t.Setenv("LDAP_BIND_DN", "cn=svc,dc=example,dc=com")
	t.Setenv("LDAP_BIND_PASSWORD", "svcpass")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("LDAP_USER_FILTER", "(sAMAccountName=%s)")
	t.Setenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=example,dc=com")
	t.Setenv("LDAP_GROUP_FILTER", "(member=%s)")
	t.Setenv("LDAP_DEFAULT_ROLE", "operator")
	t.Setenv("LDAP_DEFAULT_TENANT", "acme")
	t.Setenv("LDAP_INSECURE_SKIP_VERIFY", "true")
	t.Setenv("LDAP_ROLE_MAP", "cn=admins,ou=groups,dc=example,dc=com=super-admin;cn=netops,ou=groups,dc=example,dc=com=operator")

	c := newLDAPConfig()
	if !c.Enabled {
		t.Fatal("expected enabled")
	}
	if c.Host != "ad.example.com" || c.Port != 636 || !c.UseTLS || c.StartTLS {
		t.Errorf("transport fields wrong: %+v", c)
	}
	if c.BindDN != "cn=svc,dc=example,dc=com" || c.BindPassword != "svcpass" {
		t.Errorf("bind fields wrong: %+v", c)
	}
	if c.BaseDN != "dc=example,dc=com" || c.UserFilter != "(sAMAccountName=%s)" {
		t.Errorf("base/filter wrong: %+v", c)
	}
	if c.GroupBaseDN != "ou=groups,dc=example,dc=com" || c.GroupFilter != "(member=%s)" {
		t.Errorf("group fields wrong: %+v", c)
	}
	if c.DefaultRole != "operator" || c.DefaultTenant != "acme" || !c.InsecureSkipVerify {
		t.Errorf("defaults wrong: %+v", c)
	}
	if len(c.RoleMappings) != 2 {
		t.Fatalf("role map parse: got %d mappings: %+v", len(c.RoleMappings), c.RoleMappings)
	}
	if c.RoleMappings[0].Group != "cn=admins,ou=groups,dc=example,dc=com" || c.RoleMappings[0].Role != "super-admin" {
		t.Errorf("role map[0] wrong: %+v", c.RoleMappings[0])
	}
	if c.RoleMappings[1].Role != "operator" {
		t.Errorf("role map[1] wrong: %+v", c.RoleMappings[1])
	}

	// Resolving a role over the parsed mappings should respect precedence.
	role := ldap.RoleFor([]string{"cn=admins,ou=groups,dc=example,dc=com", "cn=netops,ou=groups,dc=example,dc=com"}, c.RoleMappings, c.DefaultRole)
	if role != "super-admin" {
		t.Errorf("resolved role = %q, want %q", role, "super-admin")
	}
}

// LDAP_ENABLED=false (or no host) must yield a disabled config.
func TestNewLDAPConfigDisabled(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "false")
	t.Setenv("LDAP_HOST", "ad.example.com")
	if newLDAPConfig().Enabled {
		t.Error("LDAP must be disabled when LDAP_ENABLED!=true")
	}
	t.Setenv("LDAP_ENABLED", "true")
	t.Setenv("LDAP_HOST", "")
	if newLDAPConfig().Enabled {
		t.Error("LDAP must be disabled when LDAP_HOST is empty")
	}
}
