package main

import (
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/oidc"

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
