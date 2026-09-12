// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
)

// rows_import_markers_test.go — the M5/M6 regressions.
//
// M5: "already imported" used to be inferred from row COUNT (targetEmpty), so
// deleting a collection's last row made the target look never-imported and the
// next boot resurrected the deleted data from the frozen snapshot. The
// authoritative signal is now the explicit import marker, written in the same
// transaction as the import.
//
// M6: an import failure used to warn-and-continue, letting boot proceed to
// SeedAdmin against a store whose real users were still in the un-imported
// snapshot (silent identity reset). NewPGStore now fails fast.
//
// The PG-backed tests are gated on DATABASE_URL_TEST like their neighbours; the
// marker-key predicate is pure and always runs.

func TestImportMarkerKeyNormalizesKeyShapes(t *testing.T) {
	// The legacy blob key shape and the file key shape target the same table,
	// so they must share ONE marker — one import decision per collection.
	if a, b := importMarkerKey("kv://users"), importMarkerKey("/data/users.json"); a != b {
		t.Errorf("key shapes must share a marker: %q vs %q", a, b)
	}
	if a, b := importMarkerKey("/data/users.json"), importMarkerKey("/data/roles.json"); a == b {
		t.Errorf("distinct collections must not share a marker: %q", a)
	}
	if got := importMarkerKey("/data/users.json"); got != "import:done:users" {
		t.Errorf("importMarkerKey = %q, want import:done:users", got)
	}
}

func TestPgStoreImportFileStateDoesNotResurrectDeletedRows(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the import-resurrection regression")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	dir := t.TempDir()
	snapshot := `[{"username":"alice","tenant_id":"acme","role":"admin"}]`
	if err := os.WriteFile(filepath.Join(dir, "users.json"), []byte(snapshot), 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	// Cutover boot: the snapshot imports into the empty target.
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("first import: %v", err)
	}
	got, err := ps.Load("kv://users")
	if err != nil {
		t.Fatalf("load after import: %v", err)
	}
	var users []map[string]any
	if err := json.Unmarshal(got, &users); err != nil || len(users) != 1 {
		t.Fatalf("expected 1 imported user, got %s (err %v)", got, err)
	}

	// The operator deletes the last user (whole-collection flush of []).
	if err := ps.Save("kv://users", []byte("[]")); err != nil {
		t.Fatalf("delete last user: %v", err)
	}

	// Reboot: the import must NOT resurrect alice from the frozen snapshot —
	// the count-based guard read the emptied table as "never imported".
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("reboot import: %v", err)
	}
	got, err = ps.Load("kv://users")
	if err != nil {
		t.Fatalf("load after reboot: %v", err)
	}
	users = nil
	if err := json.Unmarshal(got, &users); err != nil {
		t.Fatalf("unmarshal after reboot: %v (raw %s)", err, got)
	}
	if len(users) != 0 {
		t.Fatalf("RESURRECTION: deleted collection re-imported from the snapshot on reboot: %s", got)
	}
}

func TestPgStoreImportLegacyDoesNotResurrectDeletedRows(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the legacy-import resurrection regression")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)
	ps, err := NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	// A legacy netops_kv snapshot appears (upgraded install).
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
		"kv://users", []byte(`[{"username":"cutover-era","tenant_id":"acme"}]`)); err != nil {
		t.Fatalf("insert legacy snapshot: %v", err)
	}

	// Boot: legacy snapshot imports into the empty target (and records marker).
	if _, err := NewPGStore(ctx, appDSN); err != nil {
		t.Fatalf("boot with legacy snapshot: %v", err)
	}

	// The operator deletes the last user, then the process reboots.
	if err := ps.Save("kv://users", []byte("[]")); err != nil {
		t.Fatalf("delete last user: %v", err)
	}
	if _, err := NewPGStore(ctx, appDSN); err != nil {
		t.Fatalf("reboot: %v", err)
	}
	got, err := ps.Load("kv://users")
	if err != nil {
		t.Fatalf("load after reboot: %v", err)
	}
	var users []map[string]any
	if err := json.Unmarshal(got, &users); err != nil {
		t.Fatalf("unmarshal after reboot: %v (raw %s)", err, got)
	}
	if len(users) != 0 {
		t.Fatalf("RESURRECTION: legacy import re-imported the deleted collection on reboot: %s", got)
	}
}

func TestPgStoreImportFailureFailsBoot(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the import fail-fast regression")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)

	// tenants.json is fine; users.json is malformed. The import must abort the
	// BOOT (NewPGStore error), not warn-and-continue into a store where users
	// never arrived and SeedAdmin would mint a fresh admin (identity reset).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tenants.json"), []byte(`[{"id":"acme"}]`), 0o600); err != nil {
		t.Fatalf("write tenants: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users.json"), []byte(`{not json`), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	t.Setenv("IMPORT_FILE_STATE_DIR", dir)
	if _, err := NewPGStore(ctx, appDSN); err == nil {
		t.Fatal("a failing import key must fail NewPGStore (fail-fast), got nil error")
	}

	// And the failure is recoverable: fix the file, boot again, import lands.
	if err := os.WriteFile(filepath.Join(dir, "users.json"),
		[]byte(`[{"username":"alice","tenant_id":"acme"}]`), 0o600); err != nil {
		t.Fatalf("fix users: %v", err)
	}
	ps, err := NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("boot after fix: %v", err)
	}
	defer ps.db.Close()
	got, err := ps.Load("kv://users")
	if err != nil {
		t.Fatalf("load users: %v", err)
	}
	var users []map[string]any
	if err := json.Unmarshal(got, &users); err != nil || len(users) != 1 {
		t.Fatalf("expected the fixed import to land 1 user, got %s (err %v)", got, err)
	}
}

// TestPgStoreImportsCustodyMaterial — tracker 245. A file-backend install with
// TLS and sealing carries two things a cutover cannot re-create: the sealing
// vault's wrapped keys and the internal mesh CA. Before they were importable, a
// switch to Postgres silently minted a NEW CA (breaking every issued SVID on a
// fail-closed mesh) and orphaned every sealed value. They round-trip under BARE
// keys — identical on both backends — and, like every other collection, import
// at most once and never over live custody.
func TestPgStoreImportsCustodyMaterial(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the custody-import test")
	}
	ctx := context.Background()
	dsn := provisionAppRole(ctx, t, adminDSN)
	ps, err := NewPGStore(ctx, dsn)
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}

	dir := t.TempDir()
	custody := map[string]string{
		"secrets_wrapped_keys.json": `{"v1":"wrapped-dek-bytes"}`,
		"tls_internal_ca_cert.pem":  "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
		"tls_internal_ca_key.enc":   "sealed-ca-key-bytes",
	}
	for name, body := range custody {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("import: %v", err)
	}
	for name, want := range custody {
		got, err := ps.Load(name)
		if err != nil {
			t.Fatalf("load %s after import: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s round-tripped as %q", name, got)
		}
	}

	// A later boot must not overwrite custody that has since been rotated in
	// Postgres — the marker, not the content, decides.
	rotated := []byte("rotated-in-postgres")
	if err := ps.Save("tls_internal_ca_key.enc", rotated); err != nil {
		t.Fatalf("save rotated: %v", err)
	}
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("second import: %v", err)
	}
	got, err := ps.Load("tls_internal_ca_key.enc")
	if err != nil || string(got) != string(rotated) {
		t.Fatalf("a re-run clobbered rotated custody: %q %v", got, err)
	}
	ps.db.Close()
}
