// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/platformdb"
	"netops/backend/internal/ticketing"
	"netops/backend/internal/vault"
)

// TestITSMSecretsSealedWithRealVault (tracker 456): with an active vault the
// production wiring (newITSMConfigStore) seals every ITSM connector secret at
// rest under its tenant's DEK — a plaintext store from before the change is
// migrated at boot — and a reopen gives the connectors the plaintext back.
// Without custody, a sealed store refuses saves instead of being overwritten.
func TestITSMSecretsSealedWithRealVault(t *testing.T) {
	v, err := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	path := filepath.Join(t.TempDir(), "itsm.json")

	cfg := func(tag string) ticketing.ITSMConfig {
		return ticketing.ITSMConfig{
			ServiceNow: ticketing.ServiceNowConfig{Enabled: true, InstanceURL: "https://" + tag + ".service-now.com", User: "u", Password: "snpw-" + tag},
			Jira:       ticketing.JiraConfig{Enabled: true, BaseURL: "https://" + tag + ".atlassian.net", Email: "e@x", APIToken: "jira-" + tag, ProjectKey: "OPS"},
			PagerDuty:  ticketing.PagerDutyRCAConfig{Enabled: true, RoutingKey: "pdkey-" + tag},
			Slack:      ticketing.SlackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/slack-" + tag},
			Teams:      ticketing.TeamsRCAConfig{Enabled: true, WebhookURL: "https://example.webhook.office.com/teams-" + tag},
		}
	}
	secrets := func(c ticketing.ITSMConfig) []string {
		return []string{c.ServiceNow.Password, c.Jira.APIToken, c.PagerDuty.RoutingKey, c.Slack.WebhookURL, c.Teams.WebhookURL}
	}
	// A pre-456 store: version 2, every secret in the clear.
	plain, err := json.Marshal(map[string]any{"version": 2, "tenants": map[string]ticketing.ITSMConfig{"acme": cfg("acme"), "": cfg("global")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := platformdb.Save(path, plain); err != nil {
		t.Fatal(err)
	}

	st := newITSMConfigStore(v, path)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"acme", "global"} {
		for _, s := range secrets(cfg(tag)) {
			if strings.Contains(string(raw), s) {
				t.Fatalf("secret %q still plaintext at rest after boot:\n%s", s, raw)
			}
		}
	}
	if !strings.Contains(string(raw), vault.VersionPrefix) {
		t.Fatal("expected vault ciphertext at rest")
	}
	if got, _ := st.ConfigFor("acme"); got.PagerDuty.RoutingKey != "pdkey-acme" {
		t.Fatalf("in-memory secret lost: %q", got.PagerDuty.RoutingKey)
	}

	// Reopen with the same vault: every secret opens to its tenant's plaintext.
	re := newITSMConfigStore(v, path)
	for tenant, tag := range map[string]string{"acme": "acme", "": "global"} {
		got, ok := re.ConfigFor(tenant)
		if !ok {
			t.Fatalf("tenant %q missing after reopen", tenant)
		}
		want := secrets(cfg(tag))
		for i, s := range secrets(got) {
			if s != want[i] {
				t.Fatalf("tenant %q secret %d = %q, want %q", tenant, i, s, want[i])
			}
		}
	}

	// Custody removed (dormant vault): the sealed store is not served and not
	// overwritten.
	dormant := newITSMConfigStore(vault.Dormant(), path)
	if _, ok := dormant.ConfigFor("acme"); ok {
		t.Fatal("sealed tenant config served without custody")
	}
	if err := dormant.SetPagerDutyRCA("acme", ticketing.PagerDutyRCAConfig{Enabled: true, RoutingKey: "x"}); err == nil {
		t.Fatal("a save over an unopenable sealed store was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(raw) {
		t.Fatal("the sealed store was rewritten without custody")
	}
}
