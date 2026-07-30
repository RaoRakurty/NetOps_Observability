package backend

import (
	"os"
	"testing"
)

// TestLDAPLiveForumsys exercises the native LDAP path end-to-end against the
// public Forum Systems test directory (ldap.forumsys.com). Skipped unless
// NETOPS_LDAP_LIVE=1 so the normal/offline suite stays hermetic. Validates a
// real service bind + user search + user bind (the actual credential check) and
// that a wrong password is rejected.
func TestLDAPLiveForumsys(t *testing.T) {
	if os.Getenv("NETOPS_LDAP_LIVE") != "1" {
		t.Skip("set NETOPS_LDAP_LIVE=1 to run against ldap.forumsys.com")
	}
	cfg := ldapConfig{
		Enabled:      true,
		Host:         "ldap.forumsys.com",
		Port:         389,
		BindDN:       "cn=read-only-admin,dc=example,dc=com",
		BindPassword: "password",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
		DefaultRole:  RoleReadOnly,
	}

	id, err := cfg.Authenticate("tesla", "password")
	if err != nil {
		t.Fatalf("expected successful bind for tesla: %v", err)
	}
	if id == nil || id.DN == "" {
		t.Fatalf("expected a resolved identity with DN, got %+v", id)
	}
	t.Logf("OK login: user=%s dn=%s email=%s groups=%v", id.Username, id.DN, id.Email, id.Groups)

	if _, err := cfg.Authenticate("tesla", "wrong-password"); err == nil {
		t.Fatal("expected wrong password to be rejected")
	}
	if _, err := cfg.Authenticate("nobody-here", "password"); err == nil {
		t.Fatal("expected unknown user to be rejected")
	}
}
