package backend

import (
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/oidc"
	"netops/backend/internal/platformdb"

	"time"
)

func TestOIDCConfigStoreSetEffectiveAndReload(t *testing.T) {
	path := t.TempDir() + "/oidc.json"
	st := newOIDCConfigStore(path, nil)

	in := oidcConfig{
		Enabled:      true,
		Issuer:       "https://idp.example.com/realms/netops/",
		ClientID:     "netops",
		ClientSecret: "s3cret",
		Scopes:       "openid email",
	}
	out, err := st.set(in)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	// Issuer trailing slash should be trimmed by normalize.
	if out.Issuer != "https://idp.example.com/realms/netops" {
		t.Fatalf("issuer not normalized: %q", out.Issuer)
	}
	if eff := st.effective(); !eff.Enabled || eff.ClientID != "netops" {
		t.Fatalf("effective mismatch: %+v", eff)
	}

	// A fresh store reading the same path must reload the persisted overlay.
	st2 := newOIDCConfigStore(path, nil)
	eff := st2.effective()
	if !eff.Enabled || eff.Issuer != "https://idp.example.com/realms/netops" || eff.ClientSecret != "s3cret" {
		t.Fatalf("reload mismatch: %+v", eff)
	}
}

func TestOIDCConfigSecretPreservedOnEmptyUpdate(t *testing.T) {
	st := newOIDCConfigStore(t.TempDir()+"/oidc.json", nil)
	if _, err := st.set(oidcConfig{Enabled: true, Issuer: "https://idp/", ClientID: "a", ClientSecret: "keepme"}); err != nil {
		t.Fatal(err)
	}
	// Update without a secret (the redacted form) must preserve the stored one.
	out, err := st.set(oidcConfig{Enabled: true, Issuer: "https://idp/", ClientID: "a", Scopes: "openid"})
	if err != nil {
		t.Fatal(err)
	}
	if out.ClientSecret != "keepme" {
		t.Fatalf("secret not preserved: %q", out.ClientSecret)
	}
}

func TestOIDCPublicNeverLeaksSecret(t *testing.T) {
	c := oidcConfig{Enabled: true, Issuer: "https://idp", ClientID: "a", ClientSecret: "topsecret"}
	pub := c.Public()
	if !pub.ClientSecretSet {
		t.Fatal("client_secret_set should be true")
	}
	b, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "topsecret") {
		t.Fatalf("public JSON leaked the client secret: %s", b)
	}
	if strings.Contains(string(b), "client_secret\"") {
		t.Fatalf("public JSON carries a client_secret field: %s", b)
	}
}

func TestOIDCConfigValidate(t *testing.T) {
	st := newOIDCConfigStore(t.TempDir()+"/oidc.json", nil)
	if _, err := st.set(oidcConfig{Enabled: true, ClientID: "a"}); err == nil {
		t.Fatal("expected error: enabled without issuer")
	}
	if _, err := st.set(oidcConfig{Enabled: true, Issuer: "https://idp"}); err == nil {
		t.Fatal("expected error: enabled without client_id")
	}
	// Disabled config needs no issuer/client_id.
	if _, err := st.set(oidcConfig{Enabled: false}); err != nil {
		t.Fatalf("disabled config should validate: %v", err)
	}
}

func TestOIDCSetRebuildsAndSwapsProvider(t *testing.T) {
	srv := &server{}
	srv.oidc.Store(oidc.NewProviderFromConfig(oidcConfig{}, 10*time.Minute)) // disabled initial provider
	st := newOIDCConfigStore(t.TempDir()+"/oidc.json", srv)

	if srv.oidcProvider().Ready() {
		t.Fatal("provider should not be ready before config")
	}
	if _, err := st.set(oidcConfig{
		Enabled:  true,
		Issuer:   "https://idp.example.com/realms/netops",
		ClientID: "netops",
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	p := srv.oidcProvider()
	if !p.Ready() {
		t.Fatalf("provider not ready after valid config: %+v", p)
	}
	if p.Issuer() != "https://idp.example.com/realms/netops" || p.ClientID() != "netops" {
		t.Fatalf("provider not rebuilt from config: %+v", p)
	}
}

// A stored record that nobody ever filled in must NOT override the OIDC_* env.
//
// This is the defect that made SSO unbringable-up: a blank, disabled document
// sits in the kv store, and `load()` treated "the key exists" as "an operator
// configured this". A fully correct .env was parsed and then discarded, so
// /api/auth/sso/config answered {"enabled":false} and every SSO route 404'd,
// with nothing logged to explain it. docker-compose.yml documents the env path
// as THE way to enable SSO, so the env has to win over a blank.
func TestOIDCBlankStoredConfigFallsBackToEnv(t *testing.T) {
	path := t.TempDir() + "/oidc.json"
	// Exactly the shape found in the field: default-constructed, never edited.
	blank := []byte(`{"enabled":false,"issuer":"","client_id":"","scopes":"openid email profile",` +
		`"redirect_url":"","post_login_url":"/","default_role":"read-only",` +
		`"default_tenant":"global","admin_roles":"","operator_roles":"","providers":""}`)
	if err := platformdb.Save(path, blank); err != nil {
		t.Fatalf("seed blank config: %v", err)
	}

	t.Setenv("OIDC_ENABLED", "true")
	t.Setenv("OIDC_ISSUER", "https://kc.example.com/auth/realms/correlix")
	t.Setenv("OIDC_CLIENT_ID", "netops")
	t.Setenv("OIDC_DEFAULT_TENANT", "t_homedepot")

	got := newOIDCConfigStore(path, nil).effective()
	if !got.Enabled {
		t.Fatal("blank stored config overrode OIDC_ENABLED=true — SSO cannot be enabled from the environment")
	}
	if got.Issuer != "https://kc.example.com/auth/realms/correlix" {
		t.Errorf("issuer = %q, want the env value", got.Issuer)
	}
	if got.ClientID != "netops" {
		t.Errorf("client_id = %q, want the env value", got.ClientID)
	}
	if got.DefaultTenant != "t_homedepot" {
		t.Errorf("default_tenant = %q, want the env value", got.DefaultTenant)
	}
}

// The fall-through is narrow ON PURPOSE: a record an operator genuinely saved
// still wins, INCLUDING a deliberately disabled one. "SSO is turned off here"
// is a real decision and must not be silently undone by a stale env var.
func TestOIDCDeliberatelyDisabledStoredConfigStillOverridesEnv(t *testing.T) {
	path := t.TempDir() + "/oidc.json"
	saved := []byte(`{"enabled":false,"issuer":"https://kc.example.com/auth/realms/correlix",` +
		`"client_id":"netops","scopes":"openid email profile","post_login_url":"/"}`)
	if err := platformdb.Save(path, saved); err != nil {
		t.Fatalf("seed saved config: %v", err)
	}

	t.Setenv("OIDC_ENABLED", "true")
	t.Setenv("OIDC_ISSUER", "https://SHOULD-NOT-WIN.example.com")

	got := newOIDCConfigStore(path, nil).effective()
	if got.Enabled {
		t.Error("env re-enabled SSO that an operator had explicitly turned off")
	}
	if got.Issuer == "https://SHOULD-NOT-WIN.example.com" {
		t.Error("env issuer overrode a genuinely stored configuration")
	}
}

func TestOIDCNeverConfiguredPredicate(t *testing.T) {
	cases := []struct {
		name string
		cfg  oidcConfig
		want bool
	}{
		{"zero value", oidcConfig{}, true},
		{"blank with cosmetic defaults", oidcConfig{Scopes: "openid email profile", PostLoginURL: "/"}, true},
		{"whitespace only", oidcConfig{Issuer: "   ", ClientID: "\t"}, true},
		{"disabled but has issuer", oidcConfig{Issuer: "https://kc/realms/x"}, false},
		{"disabled but has client id", oidcConfig{ClientID: "netops"}, false},
		{"enabled", oidcConfig{Enabled: true}, false},
	}
	for _, tc := range cases {
		if got := tc.cfg.NeverConfigured(); got != tc.want {
			t.Errorf("%s: NeverConfigured() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
