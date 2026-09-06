// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// rows_import_legacy_pg_test.go — the boot-clobber regression.
//
// importLegacy re-imports the pre-normalization netops_kv blob snapshot, and
// saveRows applies it as DELETE-then-insert of the WHOLE table under platform
// scope. The only guard against that destroying live data is the "is the target
// already populated?" check.
//
// That check used to ask the BARE POOL for `SELECT count(*) FROM <table>`. With
// no tenant GUC set, a FORCE-RLS table filters every row out, so a FULL table
// answered 0. The guard read "empty", the DELETE ran under cross-tenant scope
// (which DOES see the rows), and the cutover-era snapshot replaced live state —
// on EVERY BOOT of an upgraded install, logging only "imported legacy blob
// app-state". NewPGStore's own comment called the import "idempotent"; it was
// describing an intent the guard did not implement.
//
// This test MUST run as a NON-SUPERUSER: superusers and BYPASSRLS roles ignore
// RLS entirely, so the bug is invisible to them. provisionAppRole gives us that
// role, exactly as TestPgStoreRLSIsolation does.
//
// Skipped unless DATABASE_URL_TEST is set (CI's pg-integration leg supplies it),
// so the default offline suite is unaffected.
func TestPgStoreImportLegacyDoesNotClobberLiveRows(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the legacy-import clobber regression")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)

	ps, err := NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}

	// --- live state: what an operator created AFTER the cutover ---------------
	live := []map[string]any{{
		"username": "alice", "tenant_id": "acme", "role": "admin", "status": "active",
	}}
	liveJSON, err := json.Marshal(live)
	if err != nil {
		t.Fatalf("marshal live: %v", err)
	}
	if err := ps.Save("kv://users", liveJSON); err != nil {
		t.Fatalf("save live users: %v", err)
	}

	// --- a stale legacy snapshot still sitting in netops_kv -------------------
	stale := []map[string]any{{
		"username": "cutover-era", "tenant_id": "acme", "role": "read-only", "status": "active",
	}}
	staleJSON, err := json.Marshal(stale)
	if err != nil {
		t.Fatalf("marshal stale: %v", err)
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS netops_kv (key text PRIMARY KEY, data bytea NOT NULL)`,
		`GRANT SELECT ON netops_kv TO netops_app_test`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed netops_kv (%s): %v", stmt, err)
		}
	}
	if _, err := admin.Exec(ctx,
		`INSERT INTO netops_kv (key, data) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data`,
		"kv://users", staleJSON); err != nil {
		t.Fatalf("insert stale snapshot: %v", err)
	}

	// --- reboot: NewPGStore runs importLegacy again ---------------------------
	if _, err := NewPGStore(ctx, appDSN); err != nil {
		t.Fatalf("reboot newPgStore: %v", err)
	}

	got, err := ps.Load("kv://users")
	if err != nil {
		t.Fatalf("load users after reboot: %v", err)
	}
	var after []map[string]any
	if err := json.Unmarshal(got, &after); err != nil {
		t.Fatalf("unmarshal users after reboot: %v (raw %s)", err, got)
	}
	if len(after) != 1 {
		t.Fatalf("expected the 1 live user to survive the boot import, got %d: %s", len(after), got)
	}
	if id, _ := after[0]["username"].(string); id != "alice" {
		t.Fatalf("BOOT CLOBBER: live user was replaced by the legacy snapshot — id=%q, want \"alice\". "+
			"importLegacy's populated-target guard must count through targetEmpty "+
			"(WithTenant), never the bare pool, or RLS reports a full table as empty.", id)
	}

	// A second reboot must be equally harmless — the import claims idempotency,
	// so pin it rather than trusting the comment.
	if _, err := NewPGStore(ctx, appDSN); err != nil {
		t.Fatalf("second reboot newPgStore: %v", err)
	}
	got2, err := ps.Load("kv://users")
	if err != nil {
		t.Fatalf("load users after second reboot: %v", err)
	}
	var after2 []map[string]any
	if err := json.Unmarshal(got2, &after2); err != nil {
		t.Fatalf("unmarshal after second reboot: %v", err)
	}
	if len(after2) != 1 {
		t.Fatalf("second boot changed the table: %d rows, want 1: %s", len(after2), got2)
	}
	if id, _ := after2[0]["username"].(string); id != "alice" {
		t.Fatalf("second boot clobbered live state: id=%q, want \"alice\"", id)
	}
}
