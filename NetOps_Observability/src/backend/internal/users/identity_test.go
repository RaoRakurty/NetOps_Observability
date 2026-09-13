// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// identity_test.go — the key material of tracker 300, pinned.
//
// These are GOLDEN VECTORS, not round-trips: fixed inputs → fixed output
// strings. That matters more here than almost anywhere else in the codebase,
// because an accidental change to the issuer normalisation or the id derivation
// does not fail loudly — it RE-NAMESPACES every account minted under the old
// rule. The next sign-in misses the tuple, provisions a fresh account with a
// default role, and the user's bindings, sessions and audit trail are orphaned.
// If one of these literals has to change, it is a migration, not an edit.

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeIssuerGoldenVectors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// Scheme and host fold; the PATH KEEPS ITS CASE (a Keycloak realm name is
		// case-sensitive — folding it would fuse two realms into one namespace).
		{"https://KC.Example.COM/realms/Correlix/", "https://kc.example.com/realms/Correlix"},
		{"HTTPS://kc.example.com:8443/realms/x//", "https://kc.example.com:8443/realms/x"},
		// Query and fragment are dropped rather than keyed on: an issuer has
		// neither, and a redirect-shaped variant must not mint a second namespace.
		{"  https://kc.example.com/realms/a?x=1#f  ", "https://kc.example.com/realms/a"},
		// Our own non-URL namespaces are already canonical.
		{"local", "local"},
		{"LOCAL", "local"},
		{"ldap:dir.example.com:389", "ldap:dir.example.com:389"},
		{"not a url", "not a url"},
		{"", ""},
		{"   ", ""},
	} {
		if got := NormalizeIssuer(tc.in); got != tc.want {
			t.Errorf("NormalizeIssuer(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLDAPIssuerGoldenVectors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The base DN is not part of the namespace, and the default port is
		// supplied so ldap://dir and ldap://dir:389 are ONE namespace.
		{"ldap://Dir.Example.COM/dc=example,dc=com", "ldap:dir.example.com:389"},
		{"ldaps://dir.example.com", "ldap:dir.example.com:636"},
		{"dir.example.com:3268", "ldap:dir.example.com:3268"},
		// A bind DN in the URL is never keyed on — and never logged.
		{"ldap://bind%40x:pw@dir.example.com:389", "ldap:dir.example.com:389"},
		{"ldap://[::1]", "ldap:[::1]:389"},
		{"", ""},
	} {
		if got := LDAPIssuer(tc.in); got != tc.want {
			t.Errorf("LDAPIssuer(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTACACSIssuerGoldenVectors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"TAC1.example.com", "tacacs:tac1.example.com:49"},
		{"tac1.example.com:4949", "tacacs:tac1.example.com:4949"},
		{"[2001:db8::1]", "tacacs:[2001:db8::1]:49"},
		{"", ""},
	} {
		if got := TACACSIssuer(tc.in); got != tc.want {
			t.Errorf("TACACSIssuer(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Two directories are two namespaces even when they hand out identical login
// names — the whole reason the issuer is in the key.
func TestIssuerNamespacesAreDisjoint(t *testing.T) {
	got := map[string]string{
		"local":  LocalIssuer,
		"ldap":   LDAPIssuer("ldap://dir.example.com"),
		"ldap2":  LDAPIssuer("ldap://other.example.com"),
		"tacacs": TACACSIssuer("tac1.example.com"),
		"oidc":   NormalizeIssuer("https://kc.example.com/realms/correlix"),
	}
	seen := map[string]string{}
	for name, iss := range got {
		if prev, dup := seen[iss]; dup {
			t.Fatalf("issuer %q is shared by %s and %s — the namespaces are not disjoint", iss, prev, name)
		}
		seen[iss] = name
	}
}

func TestTenantFragmentGoldenVectors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "global"},       // no tenant = the platform realm
		{"global", "global"}, // the global tenant is named, not hashed
		{"GLOBAL", "global"},
		{"t_aaaaaaaabbbb", "aaaaaaa"}, // first 7 after the "t_" prefix
		{"t_ab", "ab"},
		{"t_9f8e7d6c5b4a", "9f8e7d6"},
		{"acme-prod", "acmepro"}, // a legacy slug-shaped id keeps its id-safe chars
		{"t_...", "tenant"},      // nothing representable; the hash still separates it
	} {
		if got := TenantFragment(tc.in); got != tc.want {
			t.Errorf("TenantFragment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The frozen derivation of §2.4. Changing any literal below re-namespaces live
// accounts; see this file's header.
func TestFederatedIDGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		tenant, issuer, subject string
		wantShort, wantFull     string
	}{
		{
			"global", "local", "admin",
			"fed_global_dzw5vaa324wegcqqbsw5gnjfct",
			"fed_global_dzw5vaa324wegcqqbsw5gnjfctp4x3ycbaho7dmjkqcxl2f56qaa",
		},
		{
			"t_aaaaaaaabbbbbbbbccccccccdddddddd", "local", "admin",
			"fed_aaaaaaa_trhpkbsa6tf4sh5le6wsy25sgu",
			"fed_aaaaaaa_trhpkbsa6tf4sh5le6wsy25sgu3yzf4dedppygnygdjcytll75ea",
		},
		{
			"t_aaaaaaaabbbbbbbbccccccccdddddddd", "https://kc.example.com/realms/correlix",
			"3f0a1b2c-dead-beef-0000-111122223333",
			"fed_aaaaaaa_5urkn67a64nlqunhq24seeutyy",
			"fed_aaaaaaa_5urkn67a64nlqunhq24seeutyy3qm7h6hddc6vd4qe7pyulaat5q",
		},
		{
			"global", "https://kc.example.com/realms/correlix",
			"3f0a1b2c-dead-beef-0000-111122223333",
			"fed_global_2s6rgr43wuxvux5bayt2cxafod",
			"fed_global_2s6rgr43wuxvux5bayt2cxafodib55q7yimxxqf6zg7p4zcpjmdq",
		},
		{
			"t_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ldap:dir.example.com:389",
			"cn=jdoe,ou=people,dc=example,dc=com",
			"fed_bbbbbbb_meagq6mtuvsef4vo3cbiow7243",
			"fed_bbbbbbb_meagq6mtuvsef4vo3cbiow7243jze3ufxpgg7eoms2tycwsbt3oq",
		},
		{
			"global", "tacacs:tac1.example.com:49", "jdoe",
			"fed_global_vo6a4wkkoljlino3tjljphkbiw",
			"fed_global_vo6a4wkkoljlino3tjljphkbiwe3pr4bh3tj7aib7mm5peviqzha",
		},
	} {
		if got := FederatedID(tc.tenant, tc.issuer, tc.subject); got != tc.wantShort {
			t.Errorf("FederatedID(%q, %q, %q) = %q, want %q", tc.tenant, tc.issuer, tc.subject, got, tc.wantShort)
		}
		if got := FederatedIDExtended(tc.tenant, tc.issuer, tc.subject); got != tc.wantFull {
			t.Errorf("FederatedIDExtended(%q, %q, %q) = %q, want %q", tc.tenant, tc.issuer, tc.subject, got, tc.wantFull)
		}
	}
}

// Widths and shape: 26 base32 chars = 130 bits, 52 = the whole SHA-256.
func TestFederatedIDShape(t *testing.T) {
	id := FederatedID("t_abcdef0123", "https://kc/realms/r", "sub-1")
	if !strings.HasPrefix(id, "fed_") {
		t.Fatalf("id %q has no fed_ prefix", id)
	}
	parts := strings.SplitN(strings.TrimPrefix(id, "fed_"), "_", 2)
	if len(parts) != 2 {
		t.Fatalf("id %q is not fed_<fragment>_<hash>", id)
	}
	if len(parts[1]) != fedHashShort {
		t.Errorf("hash length = %d, want %d", len(parts[1]), fedHashShort)
	}
	ext := FederatedIDExtended("t_abcdef0123", "https://kc/realms/r", "sub-1")
	if got := len(strings.SplitN(strings.TrimPrefix(ext, "fed_"), "_", 2)[1]); got != fedHashFull {
		t.Errorf("extended hash length = %d, want %d", got, fedHashFull)
	}
	// The extended form must EXTEND the short one, not replace it: a re-derivation
	// after a collision has to stay recognisably the same identity.
	if !strings.HasPrefix(ext, id) {
		t.Errorf("extended id %q is not a prefix-extension of %q", ext, id)
	}
}

// Deterministic: a JIT race and a re-run migration must converge on ONE id.
func TestFederatedIDIsDeterministic(t *testing.T) {
	a := FederatedID("t_x", "https://kc/realms/r", "sub-1")
	for i := 0; i < 100; i++ {
		if got := FederatedID("t_x", "https://kc/realms/r", "sub-1"); got != a {
			t.Fatalf("FederatedID is not deterministic: %q then %q", a, got)
		}
	}
}

// DOMAIN SEPARATION. Without the 0x00 separators, ("a","bc") and ("ab","c")
// would hash alike and two distinct principals could share an id. This is the
// test that would catch someone "simplifying" the digest into a concatenation.
func TestIdentityDigestIsDomainSeparated(t *testing.T) {
	pairs := [][3]string{
		{"t_a", "bc", "s"},
		{"t_ab", "c", "s"},
		{"t_a", "b", "cs"},
		{"t_a", "bc", "s "},
	}
	seen := map[string][3]string{}
	for _, p := range pairs {
		d := identityDigest(p[0], p[1], p[2])
		if prev, dup := seen[d]; dup {
			t.Fatalf("digest collision between %v and %v — the tuple is not domain-separated", prev, p)
		}
		seen[d] = p
	}
	// And every field participates: change one, the id changes.
	base := FederatedID("t_a", "iss", "sub")
	for _, other := range []string{
		FederatedID("t_b", "iss", "sub"),
		FederatedID("t_a", "iss2", "sub"),
		FederatedID("t_a", "iss", "sub2"),
	} {
		if other == base {
			t.Fatalf("id %q did not change when a key field changed", base)
		}
	}
}

// A federated id must never be mistakable for a local one, in either direction.
func TestFederatedAndLocalIDNamespacesDoNotOverlap(t *testing.T) {
	fed := FederatedID("global", "https://kc/realms/r", "sub")
	if strings.HasPrefix(fed, "u_") || legacyUserID("admin") == fed {
		t.Fatalf("federated id %q collides with the local id namespace", fed)
	}
	if !strings.HasPrefix(fed, "fed_") {
		t.Fatalf("federated id %q lost its prefix", fed)
	}
}

func TestIdentityNormalizationKeepsOIDCSubjectCase(t *testing.T) {
	// An OIDC `sub` is case-sensitive per spec: folding it could fuse two
	// principals into one account.
	i := Identity{TenantID: " T_ABC ", Issuer: "HTTPS://KC.Example.com/realms/R/", Subject: " AbC-123 ", Protocol: "OIDC"}
	got := i.normalized()
	if got.TenantID != "t_abc" {
		t.Errorf("tenant = %q, want %q", got.TenantID, "t_abc")
	}
	if got.Issuer != "https://kc.example.com/realms/R" {
		t.Errorf("issuer = %q, want the host folded and the path preserved", got.Issuer)
	}
	if got.Subject != "AbC-123" {
		t.Errorf("subject = %q — an OIDC sub must be trimmed but NEVER case-folded", got.Subject)
	}
	if got.Protocol != "oidc" {
		t.Errorf("protocol = %q, want %q", got.Protocol, "oidc")
	}
	// The one subject the store owns rather than receives IS folded.
	local := Identity{Issuer: LocalIssuer, Subject: "  Admin ", Protocol: ProtocolLocal}.normalized()
	if local.Subject != "admin" {
		t.Errorf("local subject = %q, want %q", local.Subject, "admin")
	}
}

func TestIdentityValidateMirrorsTheDatabaseChecks(t *testing.T) {
	for name, i := range map[string]Identity{
		"no issuer":   {Subject: "s", Protocol: "oidc"},
		"no subject":  {Issuer: "i", Protocol: "oidc"},
		"no protocol": {Issuer: "i", Subject: "s"},
	} {
		if err := i.validate(); err == nil {
			t.Errorf("%s: validate() = nil, want the same refusal migration 0049's CHECKs give", name)
		}
	}
	if err := (Identity{Issuer: "i", Subject: "s", Protocol: "oidc"}).validate(); err != nil {
		t.Errorf("a complete tuple was refused: %v", err)
	}
}

// The §2.6 conditions as a PURE table — the six written-down rules, one failing
// field at a time, plus the fail-closed reading of an unknown epoch. The
// cross-backend contract proves the same rules end-to-end; this proves the
// predicate itself, including the case no backend can reach once it has written
// its marker.
func TestLegacyBindPermittedConditions(t *testing.T) {
	epoch := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	ok := func(mod func(*User, *Assertion, *Realm, *time.Time, *bool, *string)) (User, Assertion, Realm, time.Time, bool, string) {
		// The all-conditions-hold baseline: a pre-epoch, active, unbound LDAP
		// account in t_a, and an LDAP assertion naming it by its legacy username.
		u := User{ID: "jdoe", Username: "jdoe", AuthSource: ProtocolLDAP, TenantID: "t_a",
			Status: "active", CreatedAt: epoch.Add(-time.Hour)}
		a := Assertion{
			Identity:       Identity{TenantID: "t_a", Issuer: "ldap:dir:389", Subject: "cn=jdoe", Protocol: ProtocolLDAP},
			LegacyUsername: "JDoe", // case-insensitive by design: condition 4 folds it
		}
		rl := realmOf("t_a")
		marker := epoch
		has := false
		identityTenant := "t_a"
		if mod != nil {
			mod(&u, &a, &rl, &marker, &has, &identityTenant)
		}
		return u, a, rl, marker, has, identityTenant
	}

	if u, a, rl, m, has, it := ok(nil); !legacyBindPermitted(u, a, rl, m, has, it) {
		t.Fatal("the baseline (every condition satisfied) was refused — the rest of this table is meaningless")
	}

	for name, mod := range map[string]func(*User, *Assertion, *Realm, *time.Time, *bool, *string){
		"1 already bound": func(_ *User, _ *Assertion, _ *Realm, _ *time.Time, has *bool, _ *string) {
			*has = true
		},
		"2 different auth source": func(u *User, _ *Assertion, _ *Realm, _ *time.Time, _ *bool, _ *string) {
			u.AuthSource = ProtocolOIDC
		},
		"2 local account": func(u *User, _ *Assertion, _ *Realm, _ *time.Time, _ *bool, _ *string) {
			u.AuthSource = ProtocolLocal
		},
		"2 legacy empty auth source reads as local": func(u *User, _ *Assertion, _ *Realm, _ *time.Time, _ *bool, _ *string) {
			u.AuthSource = ""
		},
		"3 created after the epoch": func(u *User, _ *Assertion, _ *Realm, m *time.Time, _ *bool, _ *string) {
			u.CreatedAt = m.Add(time.Hour)
		},
		"3 created exactly at the epoch": func(u *User, _ *Assertion, _ *Realm, m *time.Time, _ *bool, _ *string) {
			u.CreatedAt = *m
		},
		"3 unknown epoch fails closed": func(_ *User, _ *Assertion, _ *Realm, m *time.Time, _ *bool, _ *string) {
			*m = time.Time{}
		},
		"4 no legacy username": func(_ *User, a *Assertion, _ *Realm, _ *time.Time, _ *bool, _ *string) {
			a.LegacyUsername = ""
		},
		"4 legacy username names another account": func(_ *User, a *Assertion, _ *Realm, _ *time.Time, _ *bool, _ *string) {
			a.LegacyUsername = "someone-else"
		},
		"5a realm does not reach the account's tenant": func(_ *User, _ *Assertion, rl *Realm, _ *time.Time, _ *bool, _ *string) {
			*rl = realmOf("t_b")
		},
		"5b the identity row would land in another tenant": func(_ *User, _ *Assertion, _ *Realm, _ *time.Time, _ *bool, it *string) {
			*it = "t_b"
		},
		"6 disabled": func(u *User, _ *Assertion, _ *Realm, _ *time.Time, _ *bool, _ *string) {
			u.Status = "disabled"
		},
	} {
		u, a, rl, m, has, it := ok(mod)
		if legacyBindPermitted(u, a, rl, m, has, it) {
			t.Errorf("%s: the lazy bind was PERMITTED — every one of the §2.6 conditions must hold", name)
		}
	}
}
