// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// import_file_state_pg_test.go — the one-time file→Postgres cutover, end to end
// (tracker 245, the 2026-09-06 importer extension).
//
// The mechanism's own regressions live in internal/platformdb; what is proved
// HERE is the thing an operator actually depends on: the WIRED list — every
// domain collection main registers — moves a real file into real rows,
// preserving ids, owners and timestamps, exactly once, and fails the boot
// naming the collection when a file is malformed.
//
// PG-backed cases are gated on DATABASE_URL_TEST like every pg-integration test
// in this package; the wiring guards are pure and always run.

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// ---- wiring guards (no database) ------------------------------------------

// TestDomainImportCollectionsDoNotCollideWithBlobKeys — a domain collection
// whose name matches a blob key's basename would SHARE that key's import
// marker, and the second of the two would silently never run. The failure is
// invisible: the boot log says "imported", and one of the two collections is
// simply empty for ever.
func TestDomainImportCollectionsDoNotCollideWithBlobKeys(t *testing.T) {
	blob := map[string]string{}
	for _, k := range platformdb.FileStateBlobKeys() {
		blob[strings.TrimSuffix(filepath.Base(k), ".json")] = k
	}
	seen := map[string]bool{}
	for _, c := range domainImportCollections(nil) {
		if k, clash := blob[c.Name]; clash {
			t.Errorf("domain collection %q shares an import marker with blob key %q", c.Name, k)
		}
		if seen[c.Name] {
			t.Errorf("domain collection %q is registered twice", c.Name)
		}
		seen[c.Name] = true
		if c.Count == nil || c.Import == nil || c.File == "" {
			t.Errorf("domain collection %q is incomplete (file=%q count=%v import=%v)",
				c.Name, c.File, c.Count != nil, c.Import != nil)
		}
		if filepath.IsAbs(c.File) || strings.Contains(c.File, "..") {
			t.Errorf("domain collection %q: file %q must be relative to the import dir", c.Name, c.File)
		}
	}
}

// TestEveryFileBackedPGPairIsImported — the registry of file↔Postgres store
// pairs. Every one of them is a collection the api reads from FILES on the file
// backend and from a DOMAIN TABLE on Postgres, so every one of them is empty
// after a cutover unless it is imported. Adding a pair without an importer is
// the defect this guard exists to catch; the list is the same one
// docs/DEPLOY_POSTGRES_APPSTATE.md publishes.
func TestEveryFileBackedPGPairIsImported(t *testing.T) {
	want := []string{
		"bgp_alert_policy", "bgp_watchlist", "config_backup_versions", "config_drift_state",
		"dem_experience", "dem_targets", "iris_investigations", "maintenance_windows",
		"metering_daily", "pcap_captures", "pipeline_processors", "rca_feedback",
		"security_control_plane", "security_frameworks", "tac_templates",
	}
	have := map[string]bool{}
	for _, c := range domainImportCollections(nil) {
		have[c.Name] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("collection %q has a Postgres store but no importer — a cutover leaves it EMPTY", w)
		}
	}
	if len(have) != len(want) {
		t.Errorf("the wired list has %d collections, the guard knows %d — update both together "+
			"(and the coverage list in docs/DEPLOY_POSTGRES_APPSTATE.md)", len(have), len(want))
	}
}

// ---- end-to-end: files in, rows out ---------------------------------------

// importFixtures is one fixture per WIRED domain collection: the exact on-disk
// shape its file store writes, and how many rows it must become.
type importFixture struct {
	collection string
	file       string
	body       string
	wantRows   int
}

func domainImportFixtures() []importFixture {
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	return []importFixture{
		{"dem_targets", "dem_targets.json", `{"acme":[
			{"id":"t1","tenant_id":"acme","name":"portal","kind":"http","host":"https://portal.example.com","interval_sec":60,"created_at":"` + now + `","updated_at":"` + now + `"},
			{"id":"t2","tenant_id":"acme","name":"dns","kind":"dns","host":"example.com","interval_sec":60,"created_at":"` + now + `","updated_at":"` + now + `"}],
			"globex":[{"id":"t3","tenant_id":"globex","name":"ping","kind":"icmp","host":"10.0.0.1","interval_sec":60,"created_at":"` + now + `","updated_at":"` + now + `"}]}`, 3},
		{"dem_experience", "dem_experience.json", `{"journeys":{},"changes":{}}`, 0},
		{"iris_investigations", "iris_investigations.json", `[
			{"tenant_id":"acme","id":"11111111-1111-4111-8111-111111111111","device_name":"spine1","skills":["bgp"],"verdict":"peer flapped","citations":["c1"],"outcome":"confirmed","created_at":"` + now + `","resolved_at":"` + now + `"}]`, 1},
		{"config_backup_versions", "config_backup_versions.json", `[
			{"tenant_id":"acme","device_id":"d1","sha":"` + strings.Repeat("a", 64) + `","captured_at":"` + now + `","size_bytes":10,"status":"ok","golden":true},
			{"tenant_id":"acme","device_id":"d1","sha":"` + strings.Repeat("b", 64) + `","captured_at":"` + now + `","size_bytes":11,"status":"ok"}]`, 2},
		{"config_drift_state", "config_drift_state.json", `[
			{"tenant_id":"acme","device_id":"d1","state":"in_sync","last_sha":"` + strings.Repeat("a", 64) + `","updated_at":"` + now + `"}]`, 1},
		{"security_control_plane", "security_control_plane.json", `{"rules":[
			{"tenant_id":"acme","rule_id":"r1","enabled":false,"updated_by":"a@acme","updated_at":"` + now + `"}],
			"views":[{"tenant_id":"acme","id":"22222222-2222-4222-8222-222222222222","name":"mine","filters":{"severity":"high"},"created_by":"a@acme","created_at":"` + now + `"}]}`, 2},
		{"security_frameworks", "security_frameworks.json", `{"frameworks":[
			{"tenant_id":"acme","framework_id":"pci-dss-v4","enabled":true,"updated_by":"a@acme","updated_at":"` + now + `"},
			{"tenant_id":"acme","framework_id":"hipaa-security-rule","enabled":false,"updated_by":"a@acme","updated_at":"` + now + `"}]}`, 2},
		{"bgp_watchlist", "bgp_watchlist.json", `{"acme":[
			{"resource":"193.0.0.0/21","kind":"prefix","note":"ours","added_by":"a@acme","created_at":"` + now + `"}]}`, 1},
		{"bgp_alert_policy", "bgp_alert_policy.json", `{"acme":{"default":{"expected_origins":[3333],"min_visibility":0.5,"min_vantages":3},"updated_by":"a@acme","updated_at":"` + now + `"}}`, 1},
		{"maintenance_windows", "maintenance_windows.json", `[]`, 0},
		{"pcap_captures", "pcap_captures.json", `[]`, 0},
		{"pipeline_processors", "pipeline_processors.json", `{"rules":[],"versions":[]}`, 0},
		{"rca_feedback", "rca_feedback.json", `[]`, 0},
		{"tac_templates", "tac_templates.json", `{}`, 0},
		{"metering_daily", "api/metering.json", `{"records":[
			{"day":"2026-09-01","tenant_id":"acme","samples":24,"updated_at":"` + now + `","meters":{}},
			{"day":"2026-09-01","tenant_id":"","samples":24,"updated_at":"` + now + `","meters":{}}]}`, 2},
	}
}

func writeImportFixtures(t *testing.T, dir string, fx []importFixture) {
	t.Helper()
	for _, f := range fx {
		p := filepath.Join(dir, filepath.FromSlash(f.file))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("mkdir for %s: %v", f.collection, err)
		}
		if err := os.WriteFile(p, []byte(f.body), 0o600); err != nil {
			t.Fatalf("write %s: %v", f.collection, err)
		}
	}
}

// collectionsByName indexes the wired list so a test can drive one collection.
func collectionsByName(db *platformdb.DB) map[string]platformdb.Collection {
	out := map[string]platformdb.Collection{}
	for _, c := range domainImportCollections(db) {
		out[c.Name] = c
	}
	return out
}

// TestDomainCollectionsImportFromFilesPG is the round trip: every wired
// collection's file fixture becomes exactly the rows it describes, a second run
// is a no-op (skipped by the marker), and nothing is clobbered.
func TestDomainCollectionsImportFromFilesPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()

	dir := t.TempDir()
	fx := domainImportFixtures()
	writeImportFixtures(t, dir, fx)

	cols := domainImportCollections(ps.DB())
	if err := platformdbImport(ctx, ps, dir, cols); err != nil {
		t.Fatalf("import: %v", err)
	}
	byName := collectionsByName(ps.DB())
	for _, f := range fx {
		c, ok := byName[f.collection]
		if !ok {
			t.Errorf("%s: not wired", f.collection)
			continue
		}
		got, cerr := c.Count(ctx)
		if cerr != nil {
			t.Errorf("%s: count: %v", f.collection, cerr)
			continue
		}
		if got != f.wantRows {
			t.Errorf("%s: %d rows after import, want %d", f.collection, got, f.wantRows)
		}
	}

	// Second boot: the marker stops every one of them, even though the files
	// are still there. Re-importing would duplicate rows (or fail a primary key).
	if err := platformdbImport(ctx, ps, dir, cols); err != nil {
		t.Fatalf("second import must be a silent no-op, got: %v", err)
	}
	for _, f := range fx {
		got, cerr := byName[f.collection].Count(ctx)
		if cerr != nil {
			t.Errorf("%s: recount: %v", f.collection, cerr)
			continue
		}
		if got != f.wantRows {
			t.Errorf("%s: %d rows after the SECOND import, want %d — the collection was imported twice",
				f.collection, got, f.wantRows)
		}
	}
}

// platformdbImport runs the collection import against a specific store,
// bypassing the process-wide backend selection the production wiring uses.
func platformdbImport(ctx context.Context, ps *platformdb.PGStore, dir string, cols []platformdb.Collection) error {
	restore := platformdb.SwapBackendForTest(ps)
	defer restore()
	return platformdb.ImportCollections(ctx, dir, cols)
}

// TestDomainCollectionsPreserveIdentityPG — a cutover is a MOVE, not a
// re-creation: ids, owning tenants and timestamps come across unchanged. The
// stores' own Create paths mint fresh ids and stamp now(), so an importer built
// on them would silently rewrite every one of these.
func TestDomainCollectionsPreserveIdentityPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()

	dir := t.TempDir()
	writeImportFixtures(t, dir, domainImportFixtures())
	if err := platformdbImport(ctx, ps, dir, domainImportCollections(ps.DB())); err != nil {
		t.Fatalf("import: %v", err)
	}

	type check struct {
		what  string
		query string
		args  []any
		want  string
	}
	checks := []check{
		{"dem target id+owner", `SELECT tenant_id||'/'||target_id FROM dem_targets WHERE target_id='t1'`, nil, "acme/t1"},
		{"dem target owner of the other tenant", `SELECT tenant_id FROM dem_targets WHERE target_id='t3'`, nil, "globex"},
		{"iris row id", `SELECT id::text FROM iris_investigations`, nil, "11111111-1111-4111-8111-111111111111"},
		{"iris owner", `SELECT tenant_id FROM iris_investigations`, nil, "acme"},
		{"golden mark", `SELECT version_sha FROM config_backup_versions WHERE golden`, nil, strings.Repeat("a", 64)},
		{"saved view id", `SELECT id::text FROM security_saved_views`, nil, "22222222-2222-4222-8222-222222222222"},
		{"rule override stays DISABLED", `SELECT enabled::text FROM security_rule_state WHERE rule_id='r1'`, nil, "false"},
		{"framework selection", `SELECT enabled::text FROM security_framework_state WHERE framework_id='pci-dss-v4'`, nil, "true"},
		{"watched prefix", `SELECT resource FROM bgp_watchlist`, nil, "193.0.0.0/21"},
		{"metering installation row", `SELECT day FROM metering_daily WHERE tenant_id=''`, nil, "2026-09-01"},
	}
	for _, c := range checks {
		var got string
		err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, c.query, c.args...).Scan(&got)
		})
		if err != nil {
			t.Errorf("%s: %v", c.what, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.what, got, c.want)
		}
	}

	// Timestamps travel: the imported target's created_at is the file's, not now().
	var created time.Time
	if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT created_at FROM dem_targets WHERE target_id='t1'`).Scan(&created)
	}); err != nil {
		t.Fatalf("read created_at: %v", err)
	}
	if time.Since(created) < 0 || created.IsZero() {
		t.Errorf("created_at %v is not the file's value", created)
	}
	var body []byte
	if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT data FROM dem_targets WHERE target_id='t1'`).Scan(&body)
	}); err != nil {
		t.Fatalf("read data: %v", err)
	}
	var tgt map[string]any
	if err := json.Unmarshal(body, &tgt); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if tgt["created_at"] != created.UTC().Format(time.RFC3339) {
		t.Errorf("the row's data column (%v) disagrees with its created_at column (%v)",
			tgt["created_at"], created.UTC().Format(time.RFC3339))
	}
}

// TestDomainCollectionImportFailureNamesTheCollection — a malformed file must
// abort the boot AND say which collection it was, or an operator is left
// bisecting a data volume by hand. It must also leave no marker: a failure that
// recorded "done" would freeze the loss in place.
func TestDomainCollectionImportFailureNamesTheCollection(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()

	for _, tc := range []struct{ collection, file, body string }{
		{"dem_targets", "dem_targets.json", `{not json`},
		{"dem_targets", "dem_targets.json", `{"*":[{"id":"t1","name":"x","kind":"icmp","host":"10.0.0.1","interval_sec":60}]}`},
		{"iris_investigations", "iris_investigations.json", `[{"id":"x","verdict":"v"}]`},
		{"config_backup_versions", "config_backup_versions.json", `[{"tenant_id":"acme","sha":"aa","status":"ok"}]`},
		{"security_control_plane", "security_control_plane.json", `{"rules":[{"tenant_id":"acme","enabled":false}]}`},
		{"metering_daily", "api/metering.json", `{"records":[{"day":"nope","tenant_id":"acme"}]}`},
	} {
		dir := t.TempDir()
		p := filepath.Join(dir, filepath.FromSlash(tc.file))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		only := []platformdb.Collection{collectionsByName(ps.DB())[tc.collection]}
		err := platformdbImport(ctx, ps, dir, only)
		if err == nil {
			t.Errorf("%s: a malformed file must fail the boot (body %.40s)", tc.collection, tc.body)
			continue
		}
		if !strings.Contains(err.Error(), tc.collection) {
			t.Errorf("%s: the failure must name the collection, got %v", tc.collection, err)
		}
		var marked bool
		if qerr := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_kv WHERE key=$1)`,
				"import:done:"+tc.collection).Scan(&marked)
		}); qerr != nil {
			t.Fatalf("check marker: %v", qerr)
		}
		if marked {
			t.Errorf("%s: a FAILED import recorded a done-marker — the loss would be frozen in place", tc.collection)
		}
	}
}

// TestDomainCollectionImportSkipsPopulatedTargetPG — live rows written after a
// cutover must never be replaced by the frozen snapshot on a later boot.
func TestDomainCollectionImportSkipsPopulatedTargetPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()

	// A row already exists (created through the api after the cutover).
	if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO bgp_watchlist (tenant_id, resource, kind, note, added_by)
		    VALUES ('acme','2001:db8::/32','prefix','live','a@acme')`)
		return e
	}); err != nil {
		t.Fatalf("seed live row: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bgp_watchlist.json"),
		[]byte(`{"acme":[{"resource":"193.0.0.0/21","kind":"prefix"}]}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	only := []platformdb.Collection{collectionsByName(ps.DB())["bgp_watchlist"]}
	if err := platformdbImport(ctx, ps, dir, only); err != nil {
		t.Fatalf("import: %v", err)
	}
	var n int
	var res string
	if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM bgp_watchlist`).Scan(&n); e != nil {
			return e
		}
		return tx.QueryRow(ctx, `SELECT resource FROM bgp_watchlist`).Scan(&res)
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n != 1 || res != "2001:db8::/32" {
		t.Errorf("the live watchlist was replaced by the snapshot: %d rows, first %q", n, res)
	}
}

// TestImportRehearsalAgainstACopiedDataDir is the LAB REHEARSAL harness: point
// it at a COPY of a real /data (never the live one) and it runs BOTH import
// phases against a throwaway database, then prints the per-collection
// file→rows table the cutover runbook asks for. It counts rows; it never
// prints a stored value, because these files hold sealed material and tokens.
//
// Skipped unless IMPORT_REHEARSAL_DIR is set, so it never runs in CI.
func TestImportRehearsalAgainstACopiedDataDir(t *testing.T) {
	dir := strings.TrimSpace(os.Getenv("IMPORT_REHEARSAL_DIR"))
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if dir == "" || adminDSN == "" {
		t.Skip("set IMPORT_REHEARSAL_DIR (a COPY of /data) and DATABASE_URL_TEST to run the cutover rehearsal")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)

	// Phase 1 — the blob/rowSpec collections, run exactly as a real boot runs
	// them: NewPGStore imports them when IMPORT_FILE_STATE_DIR is set.
	t.Setenv("IMPORT_FILE_STATE_DIR", dir)
	ps, err := platformdb.NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("REHEARSAL FAILED (blob phase): %v", err)
	}
	defer ps.DB().Close()
	restore := platformdb.SwapBackendForTest(ps)
	defer restore()

	// Phase 2 — the domain collections, through the wired list.
	cols := domainImportCollections(ps.DB())
	if err := platformdb.ImportCollections(ctx, dir, cols); err != nil {
		t.Fatalf("REHEARSAL FAILED (domain phase): %v", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n%-34s %-30s %10s %10s  %s\n", "COLLECTION", "FILE", "FILE", "PG", "VERDICT")
	for _, key := range platformdb.FileStateBlobKeys() {
		base := filepath.Base(key)
		raw, rerr := os.ReadFile(filepath.Join(dir, base)) // #nosec G304 -- the rehearsal's own copied data dir
		subtree := countTreeFiles(filepath.Join(dir, base+".d"))
		if rerr != nil && subtree == 0 {
			continue // absent on this install
		}
		// A blob collection's record count is its SHAPE: array elements, or 1
		// for a singleton document (a config object, a PEM, a sealed key). The
		// per-record subtree (devices) is counted separately and added, because
		// those are separate rows on both backends.
		want := platformdb.FileRecordCountForTest(raw) + subtree
		got, cerr := ps.StoredRecordCountForTest(ctx, key)
		if cerr == nil && subtree > 0 {
			recs, lerr := ps.LoadPrefix(key + ".d/")
			if lerr != nil {
				cerr = lerr
			} else {
				got += len(recs)
			}
		}
		verdict := "OK"
		switch {
		case cerr != nil:
			verdict = "COUNT FAILED: " + cerr.Error()
			t.Errorf("%s: count: %v", key, cerr)
		case got != want:
			verdict = "MISMATCH"
			t.Errorf("%s: file holds %d records, Postgres holds %d", key, want, got)
		}
		fmt.Fprintf(&b, "%-34s %-30s %10d %10d  %s\n", strings.TrimSuffix(base, ".json"), base, want, got, verdict)
	}
	// Domain collections: a file's ROW count is not derivable from its shape
	// (one JSON object can be five rows), so the file column says only whether
	// the file was there. The row count is the importer's own verified answer.
	for _, c := range cols {
		n, cerr := c.Count(ctx)
		if cerr != nil {
			t.Errorf("%s: count: %v", c.Name, cerr)
			continue
		}
		src := "absent"
		if _, rerr := os.Stat(filepath.Join(dir, filepath.FromSlash(c.File))); rerr == nil {
			src = "present"
		}
		fmt.Fprintf(&b, "%-34s %-30s %10s %10d  %s\n", c.Name, c.File, src, n, "OK")
	}
	t.Log(b.String())
}

// countTreeFiles counts the committed records under a per-record subtree (the
// device store's "<key>.d/"), skipping in-flight atomic-write temporaries. Zero
// for a subtree that does not exist.
func countTreeFiles(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error { // best-effort: an absent subtree is zero records, not a failure
		if err != nil || d == nil || d.IsDir() || strings.HasSuffix(p, ".tmp") {
			return nil //nolint:nilerr // an unreadable entry is not counted; the import itself would fail loudly
		}
		n++
		return nil
	})
	return n
}
