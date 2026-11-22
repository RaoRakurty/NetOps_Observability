// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// itsm_custody_pg_test.go — tracker 456 on the Postgres backend: a sealed ITSM
// store written on the file backend crosses the one-time file→Postgres cutover
// (rows_import_files: itsm_config.json is a blob key) byte-for-byte, still
// sealed, and opens on Postgres; a save on Postgres writes it sealed again.
// Gated on DATABASE_URL_TEST like every pg-integration test in this package.

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

func TestITSMSealedConfigSurvivesCutoverPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	v, err := vault.NewWithProvider(ctx, &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	const key = "/data/itsm_config.json"

	// 1. On the file backend, a plaintext pre-456 store is sealed at boot.
	dir := t.TempDir()
	filePath := filepath.Join(dir, filepath.Base(key))
	plain, err := json.Marshal(map[string]any{"version": 2, "tenants": map[string]ticketing.ITSMConfig{
		"acme": {PagerDuty: ticketing.PagerDutyRCAConfig{Enabled: true, RoutingKey: "pdkey-acme"},
			Slack: ticketing.SlackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/slack-acme"}},
		"beta": {Teams: ticketing.TeamsRCAConfig{Enabled: true, WebhookURL: "https://example.webhook.office.com/teams-beta"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = newITSMConfigStore(v, filePath)
	sealedFile, err := os.ReadFile(filePath) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	plaintexts := []string{"pdkey-acme", "slack-acme", "teams-beta"}
	for _, s := range plaintexts {
		if strings.Contains(string(sealedFile), s) {
			t.Fatalf("file backend: %q still plaintext", s)
		}
	}

	// 2. The cutover moves the same sealed bytes into Postgres.
	appDSN := provisionAppRole(ctx, t, adminDSN)
	t.Setenv("IMPORT_FILE_STATE_DIR", dir)
	ps, err := platformdb.NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("pg store (with blob import): %v", err)
	}
	defer ps.DB().Close()
	restore := platformdb.SwapBackendForTest(ps)
	defer restore()

	row, err := platformdb.Load(key)
	if err != nil {
		t.Fatalf("load imported row: %v", err)
	}
	for _, s := range plaintexts {
		if strings.Contains(string(row), s) {
			t.Fatalf("postgres row: %q plaintext after cutover", s)
		}
	}
	if !strings.Contains(string(row), vault.VersionPrefix) {
		t.Fatal("postgres row: expected vault ciphertext")
	}

	// 3. It opens on Postgres, per tenant, and a save stays sealed.
	st := newITSMConfigStore(v, key)
	if c, _ := st.ConfigFor("acme"); c.PagerDuty.RoutingKey != "pdkey-acme" || c.Slack.WebhookURL != "https://hooks.slack.com/services/slack-acme" {
		t.Fatalf("acme did not open on postgres: %+v", c)
	}
	if c, _ := st.ConfigFor("beta"); c.Teams.WebhookURL != "https://example.webhook.office.com/teams-beta" {
		t.Fatalf("beta did not open on postgres: %+v", c.Teams)
	}
	if c, _ := st.ConfigFor("beta"); c.PagerDuty.RoutingKey != "" {
		t.Fatal("acme's routing key surfaced under beta")
	}
	if err := st.SetPagerDutyRCA("beta", ticketing.PagerDutyRCAConfig{Enabled: true, RoutingKey: "pdkey-beta"}); err != nil {
		t.Fatalf("save on postgres: %v", err)
	}
	row2, err := platformdb.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(row2), "pdkey-beta") || strings.Contains(string(row2), "pdkey-acme") {
		t.Fatalf("postgres save wrote plaintext:\n%s", row2)
	}
	if c, _ := newITSMConfigStore(v, key).ConfigFor("beta"); c.PagerDuty.RoutingKey != "pdkey-beta" {
		t.Fatalf("beta's saved key did not reopen: %q", c.PagerDuty.RoutingKey)
	}
}
