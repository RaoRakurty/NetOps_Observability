package main

import (
	"bytes"
	"testing"
)

func TestBERLength(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}},
		{65535, []byte{0x82, 0xff, 0xff}},
	}
	for _, c := range cases {
		if got := berLength(c.n); !bytes.Equal(got, c.want) {
			t.Errorf("berLength(%d)=%v want %v", c.n, got, c.want)
		}
	}
}

func TestReadLengthRoundTrip(t *testing.T) {
	for _, n := range []int{0, 5, 127, 128, 300, 70000} {
		enc := berLength(n)
		got, consumed, err := readLength(enc)
		if err != nil {
			t.Fatalf("readLength(%v): %v", enc, err)
		}
		if got != n {
			t.Errorf("readLength round-trip: got %d want %d", got, n)
		}
		if consumed != len(enc) {
			t.Errorf("readLength consumed %d want %d", consumed, len(enc))
		}
	}
}

func TestBERInt(t *testing.T) {
	cases := []struct {
		v    int
		want []byte
	}{
		{0, []byte{0x02, 0x01, 0x00}},
		{3, []byte{0x02, 0x01, 0x03}},
		{127, []byte{0x02, 0x01, 0x7f}},
		{128, []byte{0x02, 0x02, 0x00, 0x80}}, // high bit set -> pad to stay positive
		{256, []byte{0x02, 0x02, 0x01, 0x00}},
	}
	for _, c := range cases {
		if got := berInt(tagInteger, c.v); !bytes.Equal(got, c.want) {
			t.Errorf("berInt(%d)=%v want %v", c.v, got, c.want)
		}
	}
}

func TestParseFilterEquality(t *testing.T) {
	got, err := parseFilter("(uid=jdoe)")
	if err != nil {
		t.Fatal(err)
	}
	// [a3 LEN [04 03 uid] [04 04 jdoe]]
	want := []byte{0xa3, 0x0b, 0x04, 0x03, 'u', 'i', 'd', 0x04, 0x04, 'j', 'd', 'o', 'e'}
	if !bytes.Equal(got, want) {
		t.Errorf("equality filter:\n got %v\nwant %v", got, want)
	}
}

func TestParseFilterPresence(t *testing.T) {
	got, err := parseFilter("(objectClass=*)")
	if err != nil {
		t.Fatal(err)
	}
	// present [7] primitive (0x87), content = "objectClass"
	want := append([]byte{tagFilterPresent, byte(len("objectClass"))}, []byte("objectClass")...)
	if !bytes.Equal(got, want) {
		t.Errorf("presence filter:\n got %v\nwant %v", got, want)
	}
}

func TestParseFilterSubstring(t *testing.T) {
	got, err := parseFilter("(cn=a*b*c)")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0] != tagFilterSubstrings {
		t.Fatalf("expected substrings tag 0x%02x, got %v", tagFilterSubstrings, got)
	}
	// Should contain initial 'a' [0x80], any 'b' [0x81], final 'c' [0x82].
	if !bytes.Contains(got, []byte{0x80, 0x01, 'a'}) ||
		!bytes.Contains(got, []byte{0x81, 0x01, 'b'}) ||
		!bytes.Contains(got, []byte{0x82, 0x01, 'c'}) {
		t.Errorf("substring components missing in %v", got)
	}
}

func TestParseFilterAndOrNot(t *testing.T) {
	got, err := parseFilter("(&(objectClass=person)(uid=jdoe))")
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != tagFilterAnd {
		t.Errorf("expected AND tag, got 0x%02x", got[0])
	}

	got, err = parseFilter("(|(uid=a)(uid=b))")
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != tagFilterOr {
		t.Errorf("expected OR tag, got 0x%02x", got[0])
	}

	got, err = parseFilter("(!(uid=a))")
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != tagFilterNot {
		t.Errorf("expected NOT tag, got 0x%02x", got[0])
	}
}

func TestParseFilterErrors(t *testing.T) {
	bad := []string{"", "uid=jdoe", "(uid=jdoe", "(&)", "()", "(uid=jdoe))"}
	for _, f := range bad {
		if _, err := parseFilter(f); err == nil {
			t.Errorf("expected error for filter %q", f)
		}
	}
}

func TestLDAPEscapeFilterValue(t *testing.T) {
	// LDAP injection attempt must be neutralized.
	got := ldapEscapeFilterValue("*)(uid=*))(|(uid=*")
	for _, ch := range []string{"(", ")", "*"} {
		if bytes.ContainsAny([]byte(got), ch) {
			t.Errorf("escaped value still contains %q: %s", ch, got)
		}
	}
	if got != `\2a\29\28uid=\2a\29\29\28|\28uid=\2a` {
		t.Errorf("unexpected escape: %s", got)
	}
}

func TestParseSearchEntryRoundTrip(t *testing.T) {
	// Build a SearchResultEntry content: objectName + PartialAttributeList.
	mail := berTLV(tagSequence, concat(
		berTLV(tagOctetString, []byte("mail")),
		berTLV(tagSequence, berTLV(tagOctetString, []byte("jdoe@example.com"))), // SET OF reuses SEQUENCE tag here for the test
	))
	memberOf := berTLV(tagSequence, concat(
		berTLV(tagOctetString, []byte("memberOf")),
		berTLV(tagSequence, concat(
			berTLV(tagOctetString, []byte("cn=netops,ou=groups,dc=example,dc=com")),
			berTLV(tagOctetString, []byte("cn=admins,ou=groups,dc=example,dc=com")),
		)),
	))
	content := concat(
		berTLV(tagOctetString, []byte("uid=jdoe,ou=people,dc=example,dc=com")),
		berTLV(tagSequence, concat(mail, memberOf)),
	)
	e, err := parseSearchEntry(content)
	if err != nil {
		t.Fatal(err)
	}
	if e.dn != "uid=jdoe,ou=people,dc=example,dc=com" {
		t.Errorf("dn=%q", e.dn)
	}
	if first(e.attr("mail")) != "jdoe@example.com" {
		t.Errorf("mail=%v", e.attr("mail"))
	}
	groups := e.attr("memberof") // case-insensitive
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %v", groups)
	}
}

func TestParseLDAPResult(t *testing.T) {
	// LDAPResult: resultCode ENUMERATED, matchedDN, errorMessage
	content := concat(
		berInt(tagEnumerated, 49), // invalidCredentials
		berTLV(tagOctetString, []byte("")),
		berTLV(tagOctetString, []byte("bad password")),
	)
	rc, msg := parseLDAPResult(content)
	if rc != 49 {
		t.Errorf("rc=%d want 49", rc)
	}
	if msg != "bad password" {
		t.Errorf("msg=%q", msg)
	}
}

func TestLDAPRoleForPrecedence(t *testing.T) {
	mappings := []ldapRoleMapping{
		{Group: "cn=netops,ou=groups,dc=example,dc=com", Role: RoleOperator},
		{Group: "cn=admins,ou=groups,dc=example,dc=com", Role: RoleSuperAdmin},
		{Group: "cn=viewers,ou=groups,dc=example,dc=com", Role: RoleReadOnly},
	}

	// single match -> that role
	if r := ldapRoleFor([]string{"cn=netops,ou=groups,dc=example,dc=com"}, mappings, RoleReadOnly); r != RoleOperator {
		t.Errorf("single match: got %q want %q", r, RoleOperator)
	}

	// multiple matches -> most privileged wins (super-admin > operator)
	groups := []string{
		"cn=netops,ou=groups,dc=example,dc=com",
		"cn=admins,ou=groups,dc=example,dc=com",
	}
	if r := ldapRoleFor(groups, mappings, RoleReadOnly); r != RoleSuperAdmin {
		t.Errorf("precedence: got %q want %q", r, RoleSuperAdmin)
	}

	// match on a bare cn (group value carries no DN) against a full-DN mapping
	if r := ldapRoleFor([]string{"netops"}, mappings, RoleReadOnly); r != RoleOperator {
		t.Errorf("bare cn match: got %q want %q", r, RoleOperator)
	}

	// case-insensitive
	if r := ldapRoleFor([]string{"CN=Admins,OU=Groups,DC=example,DC=com"}, mappings, RoleReadOnly); r != RoleSuperAdmin {
		t.Errorf("case-insensitive: got %q want %q", r, RoleSuperAdmin)
	}

	// no match -> default role
	if r := ldapRoleFor([]string{"cn=other,dc=x"}, mappings, RoleOperator); r != RoleOperator {
		t.Errorf("no match: got %q want default %q", r, RoleOperator)
	}

	// no match + empty default -> read-only
	if r := ldapRoleFor([]string{"cn=other,dc=x"}, mappings, ""); r != RoleReadOnly {
		t.Errorf("empty default: got %q want %q", r, RoleReadOnly)
	}
}

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
	t.Setenv("LDAP_DEFAULT_ROLE", RoleOperator)
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
	if c.DefaultRole != RoleOperator || c.DefaultTenant != "acme" || !c.InsecureSkipVerify {
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
	role := ldapRoleFor([]string{"cn=admins,ou=groups,dc=example,dc=com", "cn=netops,ou=groups,dc=example,dc=com"}, c.RoleMappings, c.DefaultRole)
	if role != RoleSuperAdmin {
		t.Errorf("resolved role = %q, want %q", role, RoleSuperAdmin)
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

// authenticate must reject empty credentials before any network I/O (the
// empty-password LDAP unauthenticated-bind bypass).
func TestLDAPAuthenticateRejectsEmptyCreds(t *testing.T) {
	lc := ldapConfig{Enabled: true, Host: "ldap.invalid", BaseDN: "dc=x"}
	if _, err := lc.authenticate("", "pw"); err == nil {
		t.Error("empty username must be rejected")
	}
	if _, err := lc.authenticate("user", ""); err == nil {
		t.Error("empty password must be rejected (unauthenticated-bind bypass)")
	}
}
