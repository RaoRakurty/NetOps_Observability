// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ssoidp

// ssoidp_test.go — unit tests for the desired-state domain: normalization
// defaults, validation invariants (including the SR-025 platform-owner guard),
// write-only secret preservation, sealed persistence + reload, and removal.
// The HTTP boundary and the Keycloak apply path are tested in package main.

import (
	"errors"
	"strings"
	"testing"
)

func validOIDC() Config {
	return Config{
		Alias: "okta-oidc", Protocol: "oidc", Enabled: true,
		DiscoveryURL: "https://okta.example.com/.well-known/openid-configuration",
		ClientID:     "cid", ClientSecret: "sec",
	}
}

func validSAML() Config {
	return Config{
		Alias: "okta-saml", Protocol: "saml", Enabled: true,
		MetadataXML: `<EntityDescriptor entityID="https://okta.example.com"/>`,
	}
}

func TestNormalizeDefaults(t *testing.T) {
	c := Config{Alias: " Okta-SAML ", Protocol: " SAML "}.Normalize()
	if c.Alias != "okta-saml" || c.Protocol != "saml" {
		t.Fatalf("normalize: %+v", c)
	}
	if c.GroupsAttr != "groups" {
		t.Fatalf("groups_attr default missing: %q", c.GroupsAttr)
	}
	if c.DisplayName != "okta-saml" {
		t.Fatalf("display_name should default to alias: %q", c.DisplayName)
	}
}

func TestValidate(t *testing.T) {
	roleOK := func(r string) bool { return r == "operator" || r == "super-admin" || r == "read-only" }
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // "" = valid
	}{
		{"valid oidc", func(c *Config) {}, ""},
		{"bad alias", func(c *Config) { c.Alias = "Bad_Alias!" }, "alias"},
		{"alias too short", func(c *Config) { c.Alias = "a" }, "alias"},
		{"bad protocol", func(c *Config) { c.Protocol = "ldap" }, "protocol"},
		{"oidc missing discovery", func(c *Config) { c.DiscoveryURL = "" }, "discovery_url"},
		{"oidc missing client id", func(c *Config) { c.ClientID = "" }, "client_id"},
		{"oidc non-http discovery", func(c *Config) { c.DiscoveryURL = "ftp://x/y" }, "http(s)"},
		{"unknown role", func(c *Config) {
			c.RoleMappings = []RoleMapping{{Value: "g", Role: "warlord"}}
		}, "unknown role"},
		{"empty mapping value", func(c *Config) {
			c.RoleMappings = []RoleMapping{{Value: "", Role: "operator"}}
		}, "need a value"},
		{"blank attr mapping", func(c *Config) {
			c.AttrMappings = []AttrMapping{{IdPAttr: "", UserAttr: "email"}}
		}, "attr_mappings"},
		{"super-admin guard", func(c *Config) {
			c.RoleMappings = []RoleMapping{{Value: "admins", Role: "super-admin"}}
		}, "FEDERATION_ALLOW_PLATFORM_OWNER"},
	}
	for _, tc := range cases {
		c := validOIDC()
		tc.mutate(&c)
		err := c.Normalize().Validate(roleOK, false)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err %v does not mention %q", tc.name, err, tc.wantErr)
		}
	}

	// The guard message must explain the silent SR-025 downgrade, and the
	// explicit opt-in must lift it.
	c := validOIDC()
	c.RoleMappings = []RoleMapping{{Value: "admins", Role: "super-admin"}}
	err := c.Validate(roleOK, false)
	if err == nil || !strings.Contains(err.Error(), "DOWNGRADED") || !strings.Contains(err.Error(), "guardFederatedRole") {
		t.Fatalf("guard message must explain the downgrade: %v", err)
	}
	if err := c.Validate(roleOK, true); err != nil {
		t.Fatalf("opt-in should accept the mapping: %v", err)
	}
}

func TestValidateSAMLMetadataSources(t *testing.T) {
	c := validSAML()
	c.MetadataURL = "https://okta.example.com/metadata"
	if err := c.Validate(nil, false); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("both sources: %v", err)
	}
	c = validSAML()
	c.MetadataXML = ""
	if err := c.Validate(nil, false); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("no source: %v", err)
	}
	c = validSAML()
	c.MetadataXML = strings.Repeat("x", MetadataXMLMax+1)
	if err := c.Validate(nil, false); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize metadata: %v", err)
	}
}

func TestPublicRedactsSecret(t *testing.T) {
	p := validOIDC().Public()
	if !p.ClientSecretSet {
		t.Fatal("client_secret_set should be true")
	}
	// The Public shape has no secret field at all — compile-time guarantee; here
	// we just confirm the flag flips with the secret.
	c := validOIDC()
	c.ClientSecret = ""
	if c.Public().ClientSecretSet {
		t.Fatal("client_secret_set should be false")
	}
}

func TestStoreSecretPreservedAndSealedAtRest(t *testing.T) {
	path := t.TempDir() + "/sso.json"
	deps := Deps{
		Seal: func(v string) (string, error) {
			if v == "" {
				return "", nil
			}
			return "sealed:" + v, nil
		},
		Open: func(v string) (string, error) {
			if v == "" {
				return "", nil
			}
			if !strings.HasPrefix(v, "sealed:") {
				return "", errors.New("not sealed")
			}
			return strings.TrimPrefix(v, "sealed:"), nil
		},
	}
	st := NewStore(path, deps)
	if _, err := st.Set(validOIDC()); err != nil {
		t.Fatalf("set: %v", err)
	}
	// Redacted round-trip: blank secret preserves the stored one.
	in := validOIDC()
	in.ClientSecret = ""
	in.DisplayName = "v2"
	out, err := st.Set(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.ClientSecret != "sec" || out.DisplayName != "v2" {
		t.Fatalf("secret not preserved across redacted save: %+v", out.Public())
	}
	// Reload: the persisted secret round-trips through the seal/open transforms.
	st2 := NewStore(path, deps)
	got, ok := st2.Get("okta-oidc")
	if !ok || got.ClientSecret != "sec" || got.GroupsAttr != "groups" {
		t.Fatalf("reload lost data: %+v", got)
	}
}

func TestStoreRemove(t *testing.T) {
	st := NewStore(t.TempDir()+"/sso.json", Deps{})
	if _, err := st.Set(validSAML()); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("okta-saml"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, ok := st.Get("okta-saml"); ok {
		t.Fatal("record still present after remove")
	}
	if err := st.Remove("okta-saml"); err == nil {
		t.Fatal("second remove should report absence")
	}
	if got := st.List(); len(got) != 0 {
		t.Fatalf("list = %+v, want empty", got)
	}
}
