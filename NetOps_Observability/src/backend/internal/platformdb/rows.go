package platformdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// pgstore.go — the normalized Postgres backend (M0).
//
// It implements the same blob-shaped Backend the stores already call
// (Load/Save a JSON blob per key), so NO store logic and NO HTTP API changes —
// exactly the "swap to Postgres with no API-surface change" promise in
// kvstore.go. The difference is underneath: instead of dumping each store's
// whole collection as one opaque blob (the old pgkv.go), PGStore EXPLODES the
// blob into one row per element in a normalized, RLS-protected table on Save and
// REASSEMBLES those rows back into the array on Load. The element is stored
// verbatim in a JSONB `data` column (lossless), with id/tenant/type/ts lifted
// into typed columns so Row-Level Security and indexes can act on them.
//
// This is the M0 foundation for database-enforced tenant isolation
// (docs/design/postgres-rls.md): the schema, tenant_id columns, and RLS policies
// now live in the database. The app still loads each collection whole at startup
// (operating as platform owner '*'), so RLS is the *backstop* under the app-layer
// Authorize() chokepoint today; it becomes per-request enforcing once store reads
// are scoped to the caller's tenant — a later milestone. Stores not yet
// normalized (singleton configs, refresh tokens, report runs) fall back to a
// verbatim blob in app_kv.
//
// pgx is an allowlisted, vendored dependency (CLAUDE.md §6), so the offline image
// build is unaffected; this path is used only when STORE_BACKEND=postgres.

// rowSpec maps a logical store (keyed by its file basename without ".json") to a
// normalized table and tells the exploder which JSON fields to lift into typed
// columns. Table names come only from this hardcoded registry — never from user
// input — so the `"... "+spec.table` concatenations below carry no injection risk.
type rowSpec struct {
	table       string
	idField     string // JSON field used as the primary key
	lowerID     bool   // lowercase the id (the user store keys case-insensitively)
	tenantField string // JSON field → tenant_id column ("" = global table, no tenant scope)
	selfTenant  bool   // tenant_id is a generated column (tenants); never write it
	typeField   string // JSON field → type column ("" = none)
	tsField     string // JSON field → ts column ("" = none; default now())
}

// rowSpecs is the normalized-table registry. Keys are store basenames. The
// tenant-scoped tables (RLS on) carry tenant_id; roles/snmp_profiles are global
// reference data. Note audit uses JSON "tenant"/"time", not "tenant_id"/"ts".
var rowSpecs = map[string]rowSpec{
	"users":            {table: "users", idField: "username", lowerID: true, tenantField: "tenant_id"},
	"tenants":          {table: "tenants", idField: "id", selfTenant: true},
	"apikeys":          {table: "api_keys", idField: "id", tenantField: "tenant_id"},
	"saved":            {table: "saved_objects", idField: "id", tenantField: "tenant_id", typeField: "type"},
	"snmp_credentials": {table: "snmp_credentials", idField: "id", tenantField: "tenant_id"},
	"audit":            {table: "audit_events", idField: "id", tenantField: "tenant", tsField: "time"},
	"roles":            {table: "roles", idField: "id"},
	"snmp_profiles":    {table: "snmp_profiles", idField: "id"},
}

// specFor resolves the registry entry for a backend key by its basename, so both
// the production path ("/data/users.json") and the test seam ("kv://users")
// resolve to the same spec.
func specFor(key string) (rowSpec, bool) {
	base := strings.TrimSuffix(filepath.Base(key), ".json")
	s, ok := rowSpecs[base]
	return s, ok
}

// DB exposes the RLS transaction machinery (the seam every extracted
// package's DB interface is satisfied by).
func (p *PGStore) DB() *DB { return p.db }

type PGStore struct {
	db *DB
}

// NewPGStore connects (running migrations via NewDB) and imports any legacy
// blob app-state left by the old pgkv.go backend. Fails fast on a bad DSN.
func NewPGStore(ctx context.Context, dsn string) (*PGStore, error) {
	db, err := NewDB(ctx, dsn)
	if err != nil {
		return nil, err
	}
	ps := &PGStore{db: db}
	// Import failures FAIL THE BOOT (M6). The old warn-and-continue left the
	// worst possible state standing: an early failing key aborted the rest of
	// the import, the process came up anyway, and SeedAdmin — which runs after
	// store selection in main — saw an empty users table and minted a fresh
	// bootstrap admin over an install whose real identities were still sitting
	// in the un-imported snapshot (a silent identity reset). UsePostgres already
	// fails fast on a NewPGStore error, so returning here is what keeps
	// SeedAdmin from ever running against a half-imported store.
	if err := ps.importLegacy(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("legacy blob import: %w", err)
	}
	// One-time file→Postgres cutover: import the file-backend /data/*.json
	// collections when IMPORT_FILE_STATE_DIR points at them (idempotent via
	// per-collection import markers — never clobbers or resurrects state).
	if dir := os.Getenv("IMPORT_FILE_STATE_DIR"); dir != "" {
		if err := ps.importFileState(ctx, dir); err != nil {
			db.Close()
			return nil, fmt.Errorf("file-state import: %w", err)
		}
	}
	return ps, nil
}

// ---- one-time import bookkeeping (M5) --------------------------------------
//
// "Has this collection been imported?" used to be answered by row count
// (targetEmpty). Count is a proxy that lies in one direction: an operator who
// deletes the LAST row of a collection makes the target look never-imported,
// and the next boot resurrects the deleted data from the frozen snapshot. The
// authoritative signal is an explicit marker row in app_kv, written in the SAME
// transaction as the import itself so a crash can never separate the two.
// targetEmpty stays as the pre-marker fallback: a populated target without a
// marker (an install imported before markers existed, or live data written
// before any import ran) is recorded as done-without-importing.

// importMarkerKey normalizes a backend key to its marker row key. Basename
// normalization (mirroring specFor) makes the legacy blob key shape
// ("kv://users") and the file key shape ("/data/users.json") share one marker —
// they target the same table, so one import decision covers both.
func importMarkerKey(key string) string {
	return "import:done:" + strings.TrimSuffix(filepath.Base(key), ".json")
}

// importDone reports whether the one-time import decision for key is recorded.
// app_kv carries no RLS, so the bare pool sees the marker.
func (p *PGStore) importDone(ctx context.Context, key string) (bool, error) {
	var present bool
	err := p.db.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM app_kv WHERE key=$1)`, importMarkerKey(key)).Scan(&present)
	return present, err
}

// markImportedTx records the import decision inside the import's own
// transaction (atomic with the rows it covers).
func markImportedTx(ctx context.Context, tx pgx.Tx, key, how string) error {
	_, err := tx.Exec(ctx, `INSERT INTO app_kv (key, data, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
		importMarkerKey(key), []byte(`{"import":"`+how+`"}`))
	return err
}

// markImported records the decision outside any import write — the
// "target already populated, never import" case. A failure is returned (and
// fails the boot) rather than swallowed: an unrecorded skip plus a later
// row-deletion is exactly the resurrection path the marker exists to close.
func (p *PGStore) markImported(ctx context.Context, key, how string) error {
	_, err := p.db.pool.Exec(ctx, `INSERT INTO app_kv (key, data, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
		importMarkerKey(key), []byte(`{"import":"`+how+`"}`))
	return err
}

// importKey writes one collection's imported data AND its marker in a single
// transaction (normalized rows under platform scope, or an app_kv blob).
//
// `records` is the optional PER-RECORD subtree that belongs to the SAME
// collection (the device store's "<key>.d/…" rows). It travels in this
// transaction, not a later one, because it is not a separate collection: one
// decision, one marker, one commit. A crash cannot leave a marked-done
// collection with half its records — which for devices would be half a fleet.
func (p *PGStore) importKey(ctx context.Context, key string, data []byte, records map[string][]byte) error {
	if spec, ok := specFor(key); ok {
		if len(records) > 0 {
			// Structurally impossible today (per-record keys are hash-named and
			// never collide with the rowSpecs registry) — refused rather than
			// silently dropped, because dropping them would lose data.
			return fmt.Errorf("collection %s is normalized and cannot carry per-record rows", spec.table)
		}
		rows, err := explode(spec, data)
		if err != nil {
			return fmt.Errorf("explode %s: %w", spec.table, err)
		}
		return p.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			if err := replaceRowsTx(ctx, tx, spec, rows); err != nil {
				return err
			}
			return markImportedTx(ctx, tx, key, "rows")
		})
	}
	tx, err := p.db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // best-effort: deferred rollback is a no-op after Commit
	const upsert = `INSERT INTO app_kv (key, data, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`
	if len(data) > 0 {
		if _, err := tx.Exec(ctx, upsert, key, data); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(records) { // deterministic order: a failure reproduces
		if _, err := tx.Exec(ctx, upsert, key+".d/"+name, records[name]); err != nil {
			return fmt.Errorf("per-record row %s: %w", name, err)
		}
	}
	if err := markImportedTx(ctx, tx, key, "blob"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// sortedKeys returns a map's keys in byte order.
func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// importFileState migrates the file-backend app-state (the /data/*.json
// collections) into the normalized tables / app_kv. Each collection is imported
// AT MOST ONCE, gated on the import marker (see importDone) — never on row
// count, which reads a deliberately-emptied collection as "never imported" and
// resurrects the frozen snapshot on the next boot (M5).
//
// The inventory lives in rows_import_files.go (fileStateBlobKeys), which also
// explains the three classes of collection and why the always-file ones are
// deliberately absent from it. Collections whose Postgres target is a DOMAIN
// table are imported separately, through the Collection seam, because their row
// shape belongs to the owning package (ImportCollections).
//
// Transient state (sessions, refresh tokens, rendered report artifacts) is
// intentionally NOT imported — it rebuilds, and everyone re-logs in. What this
// list does NOT cover is documented collection by collection in
// docs/DEPLOY_POSTGRES_APPSTATE.md — an operator must be able to SEE the gap
// rather than discover it after the switch (tracker 245).
func (p *PGStore) importFileState(ctx context.Context, dir string) error {
	prefixed := map[string]bool{}
	for _, k := range fileStatePrefixKeys() {
		prefixed[k] = true
	}
	imported := 0
	for _, key := range fileStateBlobKeys() {
		path := filepath.Join(dir, filepath.Base(key))
		// #nosec G304 G703 -- `path` is filepath.Base of a COMPILED-IN key
		// (fileStateBlobKeys) joined under the operator-configured
		// IMPORT_FILE_STATE_DIR. No request, tenant or caller string reaches
		// it, and Base() strips any separator, so there is nothing here for a
		// traversal to traverse; gosec's taint analysis cannot see that the
		// directory came from the process environment.
		data, err := os.ReadFile(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			data = nil // never written on this install; a per-record subtree may still exist
		case err != nil:
			// A file that EXISTS but cannot be read is a FAILURE, not an empty
			// collection. Folding the two together (the pre-2026-09-06
			// `err != nil || len(data) == 0`) is how a permissions or IO fault
			// silently turns a cutover into data loss (§10).
			return fmt.Errorf("import %s: read %s: %w", key, path, err)
		}
		// The PER-RECORD subtree is part of the same collection. It is read
		// here, before any decision, because on an install newer than the
		// device store's per-record switch the legacy blob may not exist at all
		// and the subtree is ALL of the data (tracker 245, 2026-09-06).
		var records map[string][]byte
		if prefixed[key] {
			records, err = collectPrefixRecords(path + ".d")
			if err != nil {
				return fmt.Errorf("import %s: per-record subtree: %w", key, err)
			}
		}
		if len(data) == 0 && len(records) == 0 {
			continue // nothing on disk for this collection
		}
		done, err := p.importDone(ctx, key)
		if err != nil {
			return err
		}
		if done {
			continue // decision already recorded — one-time means one-time
		}
		empty, err := p.targetEmpty(ctx, key)
		if err != nil {
			return err
		}
		if !empty {
			// Live rows with no marker (pre-marker install, or writes that beat
			// the import): record done-without-importing so a later deliberate
			// emptying can never re-trigger the import. Never clobber.
			if err := p.markImported(ctx, key, "skipped-populated"); err != nil {
				return err
			}
			logInfo("db", "skipped file-backend collection (target already populated)",
				map[string]any{"key": key})
			continue
		}
		if err := p.importKey(ctx, key, data, records); err != nil {
			return fmt.Errorf("import %s: %w", key, err)
		}
		// Per-collection verification: count what actually landed and compare
		// it with what the file held. A silently short import (an explode that
		// dropped elements, an insert that collapsed on conflict) would
		// otherwise be recorded as done and frozen in place.
		want := blobRecordCount(data)
		got, err := p.storedRowCount(ctx, key)
		if err != nil {
			return fmt.Errorf("import %s: verify: %w", key, err)
		}
		if got != want {
			return fmt.Errorf("import %s: the file holds %d records but the target holds %d after the import", key, want, got)
		}
		imported++
		logInfo("db", "imported file-backend collection",
			map[string]any{"key": key, "rows": got, "records": len(records)})
	}
	if imported > 0 {
		logInfo("db", "imported file-backend app-state into Postgres", map[string]any{"collections": imported})
	}
	return nil
}

// targetEmpty reports whether the Postgres target for a backend key has no data
// (so an import won't overwrite live state). The count MUST run under the
// platform ('*') tenant scope — the tables are FORCE-RLS, and a bare pool query
// carries no app.tenant_id, so every row is invisible and a populated table
// reads as empty. That exact blindness made the "idempotent" import re-clobber
// live api_keys/saved/snmp_profiles with the stale pre-cutover file on EVERY
// boot (any key minted since the cutover vanished on the next restart).
func (p *PGStore) targetEmpty(ctx context.Context, key string) (bool, error) {
	if spec, ok := specFor(key); ok {
		var n int
		err := p.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+spec.table).Scan(&n)
		})
		if err != nil {
			return false, err
		}
		return n == 0, nil
	}
	var present bool
	if err := p.db.pool.QueryRow(ctx,
		// The per-record subtree counts as data for this collection: a target
		// holding device records but no legacy blob is NOT empty, and importing
		// a stale snapshot over it would resurrect deleted devices.
		`SELECT EXISTS (SELECT 1 FROM app_kv WHERE key = $1 OR key LIKE $2 ESCAPE '\')`,
		key, escapeLike(key+".d/")+"%").Scan(&present); err != nil {
		return false, err
	}
	return !present, nil
}

// Load reassembles a normalized collection into the JSON array the store expects,
// or reads a verbatim blob for non-normalized keys. A missing blob returns
// os.ErrNotExist (the Backend contract); an empty collection returns "[]".
func (p *PGStore) Load(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if spec, ok := specFor(key); ok {
		return p.loadRows(ctx, spec)
	}
	return p.loadBlob(ctx, key)
}

// Save explodes a collection blob into normalized rows, or writes a verbatim blob
// for non-normalized keys.
func (p *PGStore) Save(key string, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if spec, ok := specFor(key); ok {
		return p.saveRows(ctx, spec, data)
	}
	return p.saveBlob(ctx, key, data)
}

func (p *PGStore) loadRows(ctx context.Context, spec rowSpec) ([]byte, error) {
	var datas [][]byte
	// Platform scope ('*'): the app holds and serves all tenants from one
	// process today, so a full read is correct. RLS still scopes any future
	// per-tenant connection.
	err := p.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT data FROM "+spec.table+" ORDER BY id")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d []byte
			if err := rows.Scan(&d); err != nil {
				return err
			}
			datas = append(datas, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return assemble(datas), nil
}

func (p *PGStore) saveRows(ctx context.Context, spec rowSpec, data []byte) error {
	rows, err := explode(spec, data)
	if err != nil {
		return fmt.Errorf("explode %s: %w", spec.table, err)
	}
	// The store flushes the whole collection (all tenants), so a delete+insert
	// of the entire table under platform scope is the correct, simplest sync and
	// handles deletions for free — same whole-collection rewrite the file backend
	// already does, just transactional.
	return p.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return replaceRowsTx(ctx, tx, spec, rows)
	})
}

// replaceRowsTx is the whole-table rewrite shared by saveRows and importKey —
// split out so an import can pair it with its marker in ONE transaction.
func replaceRowsTx(ctx context.Context, tx pgx.Tx, spec rowSpec, rows []rowValue) error {
	if _, err := tx.Exec(ctx, "DELETE FROM "+spec.table); err != nil {
		return err
	}
	for _, r := range rows {
		if err := insertRow(ctx, tx, spec, r); err != nil {
			return err
		}
	}
	return nil
}

func (p *PGStore) loadBlob(ctx context.Context, key string) ([]byte, error) {
	var data []byte
	err := p.db.pool.QueryRow(ctx, `SELECT data FROM app_kv WHERE key = $1`, key).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, os.ErrNotExist // mirror the file backend's "absent" signal
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (p *PGStore) saveBlob(ctx context.Context, key string, data []byte) error {
	_, err := p.db.pool.Exec(ctx, `INSERT INTO app_kv (key, data, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, key, data)
	return err
}

// rowValue is one exploded collection element: the verbatim JSON plus the fields
// lifted into typed columns.
type rowValue struct {
	id     string
	tenant string
	typ    string
	ts     *time.Time
	data   json.RawMessage
}

// explode parses a store's JSON-array blob into one rowValue per element,
// extracting the columns the spec names. Pure (no I/O) so it is unit-testable
// without a database.
func explode(spec rowSpec, blob []byte) ([]rowValue, error) {
	if len(strings.TrimSpace(string(blob))) == 0 {
		return nil, nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(blob, &elems); err != nil {
		return nil, err
	}
	out := make([]rowValue, 0, len(elems))
	for _, e := range elems {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(e, &fields); err != nil {
			return nil, err
		}
		id, err := strField(fields, spec.idField)
		if err != nil {
			return nil, fmt.Errorf("element missing required id field %q", spec.idField)
		}
		if spec.lowerID {
			id = strings.ToLower(id)
		}
		rv := rowValue{id: id, data: e}
		if spec.tenantField != "" && !spec.selfTenant {
			t, _ := strField(fields, spec.tenantField) // discard: absent/empty → "" (global)
			// Normalize to match withTenant's GUC (lower+trim) so the tenant_id
			// column compares equal to the RLS session tenant; the verbatim object
			// (original casing) is preserved in the data column.
			rv.tenant = strings.ToLower(strings.TrimSpace(t))
		}
		if spec.typeField != "" {
			rv.typ, _ = strField(fields, spec.typeField) // best-effort: absent/malformed field leaves it empty
		}
		if spec.tsField != "" {
			if raw, ok := fields[spec.tsField]; ok {
				var ts time.Time
				if json.Unmarshal(raw, &ts) == nil && !ts.IsZero() {
					rv.ts = &ts
				}
			}
		}
		out = append(out, rv)
	}
	return out, nil
}

// insertRow writes one exploded element, matching each table's column shape.
func insertRow(ctx context.Context, tx pgx.Tx, spec rowSpec, r rowValue) error {
	switch {
	case spec.selfTenant: // tenants — tenant_id is generated from id
		_, err := tx.Exec(ctx, "INSERT INTO "+spec.table+" (id, data) VALUES ($1, $2)", r.id, []byte(r.data))
		return err
	case spec.tsField != "": // audit_events (id, tenant_id, ts, data)
		ts := time.Now().UTC()
		if r.ts != nil {
			ts = *r.ts
		}
		_, err := tx.Exec(ctx, "INSERT INTO "+spec.table+" (id, tenant_id, ts, data) VALUES ($1, $2, $3, $4)", r.id, r.tenant, ts, []byte(r.data))
		return err
	case spec.typeField != "": // saved_objects (id, tenant_id, type, data)
		_, err := tx.Exec(ctx, "INSERT INTO "+spec.table+" (id, tenant_id, type, data) VALUES ($1, $2, $3, $4)", r.id, r.tenant, r.typ, []byte(r.data))
		return err
	case spec.tenantField != "": // users, api_keys, snmp_credentials (id, tenant_id, data)
		_, err := tx.Exec(ctx, "INSERT INTO "+spec.table+" (id, tenant_id, data) VALUES ($1, $2, $3)", r.id, r.tenant, []byte(r.data))
		return err
	default: // roles, snmp_profiles (id, data)
		_, err := tx.Exec(ctx, "INSERT INTO "+spec.table+" (id, data) VALUES ($1, $2)", r.id, []byte(r.data))
		return err
	}
}

// assemble concatenates row JSON back into a single array blob. Empty → "[]" so
// an unpopulated table loads as an empty (not missing) collection, letting the
// store seed its defaults exactly as it would over an empty file.
func assemble(datas [][]byte) []byte {
	if len(datas) == 0 {
		return []byte("[]")
	}
	out := make([]byte, 0, 2+len(datas)*64)
	out = append(out, '[')
	for i, d := range datas {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, d...)
	}
	return append(out, ']')
}

// strField extracts a string-valued JSON field; reports absence so callers can
// distinguish a required id (error) from an optional tenant (treated as global).
func strField(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", errors.New("field absent")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

// importLegacy is a one-time, idempotent migration of app-state written by the
// old blob backend (pgkv.go's netops_kv table) into the normalized tables /
// app_kv. It only fills empty targets, so re-running it (every boot) is a no-op
// once data has moved.
func (p *PGStore) importLegacy(ctx context.Context) error {
	var exists bool
	if err := p.db.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'netops_kv')`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	rows, err := p.db.pool.Query(ctx, `SELECT key, data FROM netops_kv`)
	if err != nil {
		return err
	}
	type kv struct {
		key  string
		data []byte
	}
	var items []kv
	for rows.Next() {
		var it kv
		if err := rows.Scan(&it.key, &it.data); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	imported := 0
	for _, it := range items {
		// Two guards stand between a stale legacy snapshot and live data,
		// because importKey below is DELETE-then-insert of the whole table under
		// platform scope:
		//
		// 1. The import marker (M5): once the decision for a key is recorded,
		//    the snapshot is never consulted again — row count cannot re-open
		//    the question, so deleting a collection's last row no longer
		//    resurrects the cutover-era data on the next boot.
		// 2. For pre-marker installs, targetEmpty — which MUST count inside
		//    WithTenant(ctx, "", true, …). Asking the bare pool instead — as
		//    this once did — runs with no tenant GUC set, so a FORCE-RLS table
		//    filters every row out and a FULL table counts 0. The guard then
		//    read "empty", the DELETE ran under cross-tenant scope (which DOES
		//    see the rows) and the snapshot replaced live state on EVERY BOOT,
		//    silently destroying every user, API key, role binding and
		//    dashboard created since cutover.
		done, err := p.importDone(ctx, it.key)
		if err != nil {
			return err
		}
		if done {
			continue
		}
		empty, err := p.targetEmpty(ctx, it.key)
		if err != nil {
			return err
		}
		if !empty {
			// Populated but unmarked (imported before markers existed, or live
			// writes preceded this import): record the decision, never clobber.
			if err := p.markImported(ctx, it.key, "skipped-populated"); err != nil {
				return err
			}
			continue
		}
		if err := p.importKey(ctx, it.key, it.data, nil); err != nil {
			return fmt.Errorf("import %s: %w", it.key, err)
		}
		imported++
	}
	if imported > 0 {
		logInfo("db", "imported legacy blob app-state into normalized tables", map[string]any{"keys": imported})
	}
	return nil
}
