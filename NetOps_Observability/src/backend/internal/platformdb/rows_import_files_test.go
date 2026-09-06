package platformdb

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// rows_import_files_test.go — the 2026-09-06 importer extension (tracker 245).
//
// The properties under test are the ones a cutover's correctness rests on:
// every blob-seam collection is in the inventory, the per-record device subtree
// travels with its parent, an unreadable file fails the boot instead of reading
// as empty, and a populated target is recorded skipped-populated rather than
// clobbered. The pure ones run everywhere; the rest are gated on
// DATABASE_URL_TEST like their neighbours.

func TestFileStateBlobKeysAreUniqueAndAnchored(t *testing.T) {
	keys := FileStateBlobKeys()
	if len(keys) < 40 {
		t.Fatalf("the inventory shrank to %d keys — a removed collection is a collection that "+
			"is silently empty after a backend switch", len(keys))
	}
	seenKey := map[string]bool{}
	seenMarker := map[string]string{}
	for _, k := range keys {
		if seenKey[k] {
			t.Errorf("duplicate key %q in the import inventory", k)
		}
		seenKey[k] = true
		// Two keys that normalize to the same marker share ONE import decision:
		// the second would silently never run.
		m := importMarkerKey(k)
		if prev, ok := seenMarker[m]; ok {
			t.Errorf("keys %q and %q share the import marker %q — one of them would never import", prev, k, m)
		}
		seenMarker[m] = k
	}
	for _, k := range fileStatePrefixKeys() {
		if !seenKey[k] {
			t.Errorf("prefix key %q has no parent blob key — its subtree would never be imported", k)
		}
	}
}

// TestEveryRowSpecCollectionIsImported — a normalized table this package can
// write itself but never imports is a table that stays empty after a cutover.
// audit_events was exactly that until 2026-09-06: the trail restarted at zero.
func TestEveryRowSpecCollectionIsImported(t *testing.T) {
	inventory := map[string]bool{}
	for _, k := range FileStateBlobKeys() {
		inventory[strings.TrimSuffix(filepath.Base(k), ".json")] = true
	}
	for base := range rowSpecs {
		if !inventory[base] {
			t.Errorf("rowSpecs collection %q has a normalized table but is not in the import "+
				"inventory — a cutover would leave %s empty", base, rowSpecs[base].table)
		}
	}
}

func TestBlobRecordCountReadsShapeNotValues(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"empty", "", 0},
		{"blank", "   \n", 0},
		{"empty array", "[]", 0},
		{"array", `[{"a":1},{"a":2},{"a":3}]`, 3},
		{"object is one document", `{"enabled":true}`, 1},
		{"pem is one document", "-----BEGIN CERTIFICATE-----\nx\n", 1},
		{"malformed array is still one stored document", `[{"a":`, 1},
	}
	for _, c := range cases {
		if got := blobRecordCount([]byte(c.in)); got != c.want {
			t.Errorf("%s: blobRecordCount = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestReadImportFileRefusesEscapingPaths(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{"../outside.json", "a/../../outside.json", "/etc/passwd"} {
		if _, err := readImportFile(dir, rel); err == nil {
			t.Errorf("readImportFile(%q) must be refused", rel)
		}
	}
	// An absent file is "nothing to import", not an error.
	b, err := readImportFile(dir, "absent.json")
	if err != nil || b != nil {
		t.Errorf("absent file: got (%q, %v), want (nil, nil)", b, err)
	}
}

func TestCollectPrefixRecordsSkipsTemporariesAndMissingSubtree(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "devices.json.d", "manual")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "aaa"), []byte(`{"id":"a"}`), 0o600); err != nil {
		t.Fatalf("write record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "bbb.tmp"), []byte(`partial`), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "devices.json.d", "migrated"), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	got, err := collectPrefixRecords(filepath.Join(dir, "devices.json.d"))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	names := make([]string, 0, len(got))
	for k := range got {
		names = append(names, k)
	}
	sort.Strings(names)
	want := []string{"manual/aaa", "migrated"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("records = %v, want %v (an in-flight .tmp is not a committed record)", names, want)
	}
	// A subtree that does not exist is an empty collection, not a failure.
	none, err := collectPrefixRecords(filepath.Join(dir, "absent.json.d"))
	if err != nil || len(none) != 0 {
		t.Errorf("absent subtree: got (%v, %v), want (empty, nil)", none, err)
	}
}

// ---- PG-backed: the cutover behaviours themselves -------------------------

func TestPgStoreImportsDeviceRecordSubtree(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the device-subtree import test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	dir := t.TempDir()
	// The legacy whole-fleet blob plus the per-record subtree the device store
	// actually writes today. Both must arrive: an install newer than the
	// per-record switch keeps EVERY device in the subtree.
	if err := os.WriteFile(filepath.Join(dir, "devices.json"), []byte(`[]`), 0o600); err != nil {
		t.Fatalf("write devices blob: %v", err)
	}
	for _, rel := range []string{"manual/aaa", "manual/bbb", "suppressed/ccc", "migrated"} {
		p := filepath.Join(dir, "devices.json.d", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(`{"id":"`+filepath.Base(rel)+`"}`), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("import: %v", err)
	}
	recs, err := ps.LoadPrefix("/data/devices.json.d/")
	if err != nil {
		t.Fatalf("load prefix: %v", err)
	}
	for _, want := range []string{
		"/data/devices.json.d/manual/aaa",
		"/data/devices.json.d/manual/bbb",
		"/data/devices.json.d/suppressed/ccc",
		"/data/devices.json.d/migrated",
	} {
		if _, ok := recs[want]; !ok {
			t.Errorf("per-device record %q did not survive the cutover (got %d records)", want, len(recs))
		}
	}
}

// TestPgStoreImportFailsOnUnreadableFile — a file that EXISTS but cannot be
// read must fail the boot naming the collection. The pre-2026-09-06 code folded
// the read error into "nothing to import" (`err != nil || len(data) == 0`) and
// a permissions fault therefore migrated an install to an EMPTY collection with
// nothing said about it.
func TestPgStoreImportFailsOnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0000 file is still readable, so the fault cannot be simulated")
	}
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the unreadable-file regression")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "orgs.json")
	if err := os.WriteFile(path, []byte(`[{"id":"o1"}]`), 0o600); err != nil {
		t.Fatalf("write orgs: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) }) // best-effort: TempDir cleanup needs it readable
	err = ps.importFileState(ctx, dir)
	if err == nil {
		t.Fatal("an unreadable collection file must FAIL the import, not import as empty")
	}
	if !strings.Contains(err.Error(), "orgs.json") {
		t.Errorf("the failure must name the collection, got %v", err)
	}
}

func TestPgStoreImportCollectionsIsOneTimeAndVerified(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Collection-seam import test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "widgets.json"), []byte(`[1,2,3]`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	rows := 0
	imports := 0
	col := Collection{
		Name: "widgets", File: "widgets.json",
		Count: func(context.Context) (int, error) { return rows, nil },
		Import: func(_ context.Context, raw []byte) (int, error) {
			var xs []int
			if err := json.Unmarshal(raw, &xs); err != nil {
				return 0, err
			}
			imports++
			rows = len(xs)
			return rows, nil
		},
	}
	if err := ps.importCollections(ctx, dir, []Collection{col}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if imports != 1 || rows != 3 {
		t.Fatalf("first import: imports=%d rows=%d, want 1/3", imports, rows)
	}
	// Second boot: the marker, not the row count, is what stops it — even after
	// the operator empties the collection deliberately.
	rows = 0
	if err := ps.importCollections(ctx, dir, []Collection{col}); err != nil {
		t.Fatalf("second import: %v", err)
	}
	if imports != 1 {
		t.Errorf("RESURRECTION: the collection was imported again after being emptied (imports=%d)", imports)
	}
}

func TestPgStoreImportCollectionsSkipsPopulatedTarget(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the skipped-populated test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "widgets.json"), []byte(`[1,2,3]`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	imported := false
	col := Collection{
		Name: "widgets", File: "widgets.json",
		Count:  func(context.Context) (int, error) { return 7, nil }, // live rows already there
		Import: func(context.Context, []byte) (int, error) { imported = true; return 3, nil },
	}
	if err := ps.importCollections(ctx, dir, []Collection{col}); err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported {
		t.Fatal("a populated target must NEVER be clobbered by the snapshot")
	}
	// app_kv.data is BYTEA (the blob backend's contract), so the marker is read
	// as bytes and decoded here rather than with a JSONB operator.
	var raw []byte
	if err := ps.db.pool.QueryRow(ctx, `SELECT data FROM app_kv WHERE key=$1`,
		importMarkerKey("widgets")).Scan(&raw); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	var marker struct {
		Import string `json:"import"`
	}
	if err := json.Unmarshal(raw, &marker); err != nil {
		t.Fatalf("decode marker %q: %v", raw, err)
	}
	if marker.Import != "skipped-populated" {
		t.Errorf("marker records %q, want skipped-populated", marker.Import)
	}
}

// TestPgStoreImportCollectionsVerifiesRowCount — an importer that reports more
// rows than actually landed (an ON CONFLICT collapse, an RLS refusal) must FAIL
// rather than have the shortfall frozen in place by a "done" marker.
func TestPgStoreImportCollectionsVerifiesRowCount(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the import verification test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "widgets.json"), []byte(`[1,2,3]`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	col := Collection{
		Name: "widgets", File: "widgets.json",
		Count:  func(context.Context) (int, error) { return 1, nil }, // only one landed
		Import: func(context.Context, []byte) (int, error) { return 3, nil },
	}
	// Count returns 1 BEFORE the import too, which is the populated path — use a
	// counter that starts empty and stays short instead.
	calls := 0
	col.Count = func(context.Context) (int, error) {
		calls++
		if calls == 1 {
			return 0, nil
		}
		return 1, nil
	}
	err = ps.importCollections(ctx, dir, []Collection{col})
	if err == nil {
		t.Fatal("a short import must fail the boot")
	}
	if !strings.Contains(err.Error(), "widgets") {
		t.Errorf("the failure must name the collection, got %v", err)
	}
	// And it must NOT have recorded the import as done.
	var present bool
	if err := ps.db.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_kv WHERE key=$1)`,
		importMarkerKey("widgets")).Scan(&present); err != nil {
		t.Fatalf("check marker: %v", err)
	}
	if present {
		t.Error("a failed import must not be marked done — the loss would be frozen in place")
	}
}

func TestImportCollectionValidationRefusesIncompleteEntries(t *testing.T) {
	bad := []Collection{
		{File: "x.json", Count: func(context.Context) (int, error) { return 0, nil },
			Import: func(context.Context, []byte) (int, error) { return 0, nil }},
		{Name: "x", Count: func(context.Context) (int, error) { return 0, nil },
			Import: func(context.Context, []byte) (int, error) { return 0, nil }},
		{Name: "x", File: "x.json"},
	}
	for i, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("case %d: an incomplete collection must be refused", i)
		}
	}
	ok := Collection{Name: "x", File: "x.json",
		Count:  func(context.Context) (int, error) { return 0, nil },
		Import: func(context.Context, []byte) (int, error) { return 0, nil }}
	if err := ok.validate(); err != nil {
		t.Errorf("a complete collection must validate: %v", err)
	}
}

// TestStoredRowCountReadsNormalizedTablesUnderPlatformScope guards the RLS trap
// that made the original importer clobber live data: a bare-pool count of a
// FORCE-RLS table reads a FULL table as empty.
func TestStoredRowCountReadsNormalizedTablesUnderPlatformScope(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the platform-scope count test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	if err := ps.Save("/data/users.json",
		[]byte(`[{"username":"alice","tenant_id":"acme"},{"username":"bob","tenant_id":"beta"}]`)); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	n, err := ps.storedRowCount(ctx, "/data/users.json")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("storedRowCount = %d, want 2 — a FORCE-RLS table counted outside the '*' scope reads as empty", n)
	}
	// A bare pool query is the trap: it must NOT be what the importer uses.
	var bare int
	if err := ps.db.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&bare); err != nil {
		t.Fatalf("bare count: %v", err)
	}
	if bare != 0 {
		t.Logf("note: the bare-pool count saw %d rows (RLS bypass?) — the guard above is what matters", bare)
	}
}

// TestPgStoreImportSubtreeWithoutLegacyBlob — an install newer than the device
// store's per-record switch may have NO devices.json at all, only the subtree.
// The subtree is then ALL of the fleet, and a blob-only importer would migrate
// it to an empty device inventory without a word.
func TestPgStoreImportSubtreeWithoutLegacyBlob(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the subtree-only import test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json.d", "manual", "aaa")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(`{"id":"aaa"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// No devices.json — only the subtree.
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("import: %v", err)
	}
	var data []byte
	if err := ps.db.pool.QueryRow(ctx, `SELECT data FROM app_kv WHERE key=$1`,
		"/data/devices.json.d/manual/aaa").Scan(&data); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("the per-record row is missing: a subtree-only install migrated to an EMPTY inventory")
		}
		t.Fatalf("read record: %v", err)
	}
	if string(data) != `{"id":"aaa"}` {
		t.Errorf("record bytes changed in transit: %s", data)
	}

	// And a second boot does not re-import it, even after the row is deleted.
	if err := ps.Delete("/data/devices.json.d/manual/aaa"); err != nil {
		t.Fatalf("delete record: %v", err)
	}
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("second import: %v", err)
	}
	var present bool
	if err := ps.db.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_kv WHERE key=$1)`,
		"/data/devices.json.d/manual/aaa").Scan(&present); err != nil {
		t.Fatalf("check: %v", err)
	}
	if present {
		t.Error("RESURRECTION: a deleted device record came back from the snapshot")
	}
}

// TestTargetEmptySeesPerRecordRows — the guard that stops a stale snapshot
// overwriting a live fleet. A target holding device RECORDS but no legacy blob
// row is NOT empty, and reading it as empty would upsert every stale record
// back over the live ones.
func TestTargetEmptySeesPerRecordRows(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the per-record targetEmpty test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	empty, err := ps.targetEmpty(ctx, "/data/devices.json")
	if err != nil {
		t.Fatalf("targetEmpty: %v", err)
	}
	if !empty {
		t.Fatal("a fresh database must read as empty")
	}
	if err := ps.Save("/data/devices.json.d/manual/live", []byte(`{"id":"live"}`)); err != nil {
		t.Fatalf("seed live record: %v", err)
	}
	empty, err = ps.targetEmpty(ctx, "/data/devices.json")
	if err != nil {
		t.Fatalf("targetEmpty: %v", err)
	}
	if empty {
		t.Error("a target holding per-record device rows read as EMPTY — a stale snapshot would overwrite the live fleet")
	}
}
