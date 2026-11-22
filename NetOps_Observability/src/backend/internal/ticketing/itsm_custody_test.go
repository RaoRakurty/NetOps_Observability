// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// itsm_custody_test.go — tracker 456: the ITSM connector secrets are sealed at
// rest under the owning tenant's key, a plaintext store migrates once, a sealed
// store that cannot be opened is never overwritten. The custody here is a fake
// with the vault's shape (prefix, AAD = tenant|field); the real vault is
// exercised in the root package (itsm_custody_vault_test.go).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/platformdb"
)

const fakePrefix = "v1:"

// fakeCustody seals by binding tenant|field into the blob, so a value moved to
// another tenant or field does not open — the property the vault's AAD gives.
func fakeCustody(active bool) SecretCustody {
	return SecretCustody{
		Seal: func(tenant, field, pt string) (string, error) {
			if !active || pt == "" {
				return pt, nil
			}
			return fakePrefix + base64.StdEncoding.EncodeToString([]byte(tenant+"|"+field+"|"+pt)), nil
		},
		Open: func(tenant, field, stored string) (string, error) {
			if !strings.HasPrefix(stored, fakePrefix) {
				return stored, nil
			}
			if !active {
				return "", errors.New("encrypted secret present but custody is not configured")
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, fakePrefix))
			if err != nil {
				return "", err
			}
			want := tenant + "|" + field + "|"
			if !strings.HasPrefix(string(raw), want) {
				return "", errors.New("wrong tenant/field")
			}
			return strings.TrimPrefix(string(raw), want), nil
		},
		Active: func() bool { return active },
	}
}

// fiveSecrets is one tenant's config carrying every write-only secret, each
// distinct per tenant so a leak names its owner.
func fiveSecrets(tag string) ITSMConfig {
	return ITSMConfig{
		ServiceNow: ServiceNowConfig{Enabled: true, InstanceURL: "https://" + tag + ".service-now.com", User: "u", Password: "snpw-" + tag},
		Jira:       JiraConfig{Enabled: true, BaseURL: "https://" + tag + ".atlassian.net", Email: "e@x", APIToken: "jira-" + tag, ProjectKey: "OPS"},
		PagerDuty:  PagerDutyRCAConfig{Enabled: true, RoutingKey: "pdkey-" + tag},
		Slack:      SlackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/slack-" + tag},
		Teams:      TeamsRCAConfig{Enabled: true, WebhookURL: "https://example.webhook.office.com/teams-" + tag},
	}
}

func secretsOf(c ITSMConfig) []string {
	return []string{c.ServiceNow.Password, c.Jira.APIToken, c.PagerDuty.RoutingKey, c.Slack.WebhookURL, c.Teams.WebhookURL}
}

func writeEnvelope(t *testing.T, path string, version int, tenants map[string]ITSMConfig) {
	t.Helper()
	b, err := json.Marshal(itsmConfigFile{Version: version, Tenants: tenants})
	if err != nil {
		t.Fatal(err)
	}
	if err := platformdb.Save(path, b); err != nil {
		t.Fatal(err)
	}
}

func readEnvelope(t *testing.T, path string) (itsmConfigFile, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f itsmConfigFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("stored envelope unreadable: %v", err)
	}
	return f, raw
}

func openStore(t *testing.T, path string, c SecretCustody) *ITSMConfigStore {
	t.Helper()
	return NewITSMConfigStore(path,
		func() ITSMConfig { return ITSMConfig{} },
		func(system, tenant string) string { return filepath.Join(t.TempDir(), system+"_"+tenant+".json") },
		func() bool { return false }, c)
}

func assertNoPlaintext(t *testing.T, raw []byte, tags ...string) {
	t.Helper()
	for _, tag := range tags {
		for _, s := range secretsOf(fiveSecrets(tag)) {
			if bytes.Contains(raw, []byte(s)) {
				t.Fatalf("secret %q stored in plaintext:\n%s", s, raw)
			}
		}
	}
}

func assertOpened(t *testing.T, st *ITSMConfigStore, tenant, tag string) {
	t.Helper()
	got, ok := st.ConfigFor(tenant)
	if !ok {
		t.Fatalf("tenant %q missing after reload", tenant)
	}
	want := secretsOf(fiveSecrets(tag))
	for i, s := range secretsOf(got) {
		if s != want[i] {
			t.Fatalf("tenant %q secret %d = %q, want %q", tenant, i, s, want[i])
		}
	}
}

// A save with custody active writes v3 with every secret sealed; a reopen
// gives the connectors their plaintext back.
func TestITSMSecretsSealedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "itsm.json")
	st := openStore(t, path, fakeCustody(true))
	st.SetConfigForTest("acme", fiveSecrets("acme"))
	st.SetConfigForTest("", fiveSecrets("global"))
	st.mu.Lock()
	err := st.persist()
	st.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// A real setter goes through the same path.
	if err := st.SetPagerDutyRCA("acme", PagerDutyRCAConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}

	f, raw := readEnvelope(t, path)
	if f.Version != itsmFileVersionSealed {
		t.Fatalf("version = %d, want %d", f.Version, itsmFileVersionSealed)
	}
	assertNoPlaintext(t, raw, "acme", "global")
	for tenant, cfg := range f.Tenants {
		for i, s := range secretsOf(cfg) {
			if !strings.HasPrefix(s, fakePrefix) {
				t.Fatalf("tenant %q secret %d not sealed: %q", tenant, i, s)
			}
		}
	}

	re := openStore(t, path, fakeCustody(true))
	assertOpened(t, re, "acme", "acme")
	assertOpened(t, re, "", "global")
}

// A v2 (plaintext-era) store found while custody is active is rewritten sealed
// at construction, once: the next open writes nothing.
func TestITSMPlaintextStoreMigratesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "itsm.json")
	writeEnvelope(t, path, itsmFileVersionPlain, map[string]ITSMConfig{"acme": fiveSecrets("acme"), "": fiveSecrets("global")})

	st := openStore(t, path, fakeCustody(true))
	assertOpened(t, st, "acme", "acme")
	f, raw := readEnvelope(t, path)
	if f.Version != itsmFileVersionSealed {
		t.Fatalf("migration did not seal: version %d", f.Version)
	}
	assertNoPlaintext(t, raw, "acme", "global")

	info1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	re := openStore(t, path, fakeCustody(true))
	assertOpened(t, re, "acme", "acme")
	assertOpened(t, re, "", "global")
	_, raw2 := readEnvelope(t, path)
	info2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) || !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatal("a sealed store was rewritten on reopen — the migration is not idempotent")
	}
}

// The pre-envelope single-object format migrates under "" and is sealed too.
func TestITSMLegacyFormatMigratesSealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "itsm.json")
	b, err := json.Marshal(fiveSecrets("global"))
	if err != nil {
		t.Fatal(err)
	}
	if err := platformdb.Save(path, b); err != nil {
		t.Fatal(err)
	}
	st := openStore(t, path, fakeCustody(true))
	assertOpened(t, st, "", "global")
	f, raw := readEnvelope(t, path)
	if f.Version != itsmFileVersionSealed {
		t.Fatalf("legacy store not sealed: version %d", f.Version)
	}
	assertNoPlaintext(t, raw, "global")
}

// Dormant custody (no SEAL_PROVIDER, or a nil vault) keeps today's plaintext v2
// envelope and never rewrites a store on open.
func TestITSMDormantCustodyStaysPlaintext(t *testing.T) {
	for name, c := range map[string]SecretCustody{"zero": {}, "dormant": fakeCustody(false)} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "itsm.json")
			writeEnvelope(t, path, itsmFileVersionPlain, map[string]ITSMConfig{"acme": fiveSecrets("acme")})
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			st := openStore(t, path, c)
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("dormant custody rewrote the store on open")
			}
			if err := st.SetPagerDutyRCA("acme", PagerDutyRCAConfig{Enabled: true}); err != nil {
				t.Fatal(err)
			}
			if f, _ := readEnvelope(t, path); f.Version != itsmFileVersionPlain {
				t.Fatalf("dormant save wrote version %d, want %d", f.Version, itsmFileVersionPlain)
			}
			assertOpened(t, openStore(t, path, c), "acme", "acme")
		})
	}
}

// A sealed value is bound to its tenant: moved under another tenant's key it
// does not open, and the store then refuses every save, leaving the stored
// bytes untouched and no tenant's secret readable under the wrong key.
func TestITSMSealedSecretBoundToTenant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "itsm.json")
	writeEnvelope(t, path, itsmFileVersionPlain, map[string]ITSMConfig{"acme": fiveSecrets("acme")})
	_ = openStore(t, path, fakeCustody(true)) // seals it

	f, _ := readEnvelope(t, path)
	writeEnvelope(t, path, itsmFileVersionSealed, map[string]ITSMConfig{"beta": f.Tenants["acme"]})
	tampered, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	st := openStore(t, path, fakeCustody(true))
	if cfg, ok := st.ConfigFor("beta"); ok && cfg.PagerDuty.RoutingKey != "" {
		t.Fatalf("acme's sealed key opened under beta: %q", cfg.PagerDuty.RoutingKey)
	}
	assertRefusesSaves(t, st, path, tampered)
}

// A sealed store opened without custody (SEAL_PROVIDER removed) runs on the env
// defaults and refuses saves — it never overwrites credentials it cannot read.
func TestITSMSealedStoreWithoutCustodyRefusesSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "itsm.json")
	writeEnvelope(t, path, itsmFileVersionPlain, map[string]ITSMConfig{"acme": fiveSecrets("acme")})
	_ = openStore(t, path, fakeCustody(true))
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]SecretCustody{"dormant": fakeCustody(false), "unwired": {}} {
		t.Run(name, func(t *testing.T) {
			st := openStore(t, path, c)
			if _, ok := st.ConfigFor("acme"); ok {
				t.Fatal("a sealed tenant config was served without opening it")
			}
			assertRefusesSaves(t, st, path, sealed)
		})
	}
}

func assertRefusesSaves(t *testing.T, st *ITSMConfigStore, path string, want []byte) {
	t.Helper()
	saves := map[string]func() error{
		"Set":             func() error { return st.Set("acme", ITSMConfig{}) },
		"SetPagerDutyRCA": func() error { return st.SetPagerDutyRCA("acme", PagerDutyRCAConfig{Enabled: true, RoutingKey: "new"}) },
		"SetSlackRCA":     func() error { return st.SetSlackRCA("acme", SlackRCAConfig{}) },
		"SetTeamsRCA":     func() error { return st.SetTeamsRCA("acme", TeamsRCAConfig{}) },
	}
	for name, save := range saves {
		if err := save(); err == nil || !strings.Contains(err.Error(), "not overwritten") {
			t.Fatalf("%s on an unopenable sealed store: err = %v, want a refusal", name, err)
		}
	}
	if cfg, ok := st.ConfigFor("acme"); ok && cfg.PagerDuty.RoutingKey == "new" {
		t.Fatal("a refused save still changed the in-memory config")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("a refused save rewrote the stored config")
	}
}
