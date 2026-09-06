package platformdb

// rows_import_files.go — WHAT the one-time file→Postgres cutover moves, and the
// seam for the collections this package cannot write itself.
//
// rows.go owns the MECHANISM (the marker gate, the skipped-populated decision,
// the fail-the-boot contract). This file owns the INVENTORY, because the
// inventory is the part an operator has to be able to read and audit:
// docs/DEPLOY_POSTGRES_APPSTATE.md restates it, and a collection missing from
// here is a collection that is silently empty after a backend switch.
//
// Three classes of collection exist, and the difference is decided entirely by
// how the owning store persists:
//
//  1. BLOB-SEAM collections — the store calls platformdb.Load/Save with its
//     configured path. On the file backend that path is a file; on Postgres it
//     is an app_kv row key. Importing one is a verbatim byte move under the same
//     key, so identity, tenant ownership and timestamps are preserved by
//     construction. fileStateBlobKeys lists them.
//
//  2. NORMALIZED collections — the store has a DOMAIN table (dem_targets,
//     iris_investigations, …) selected by main's ActivePG() switch, and the file
//     JSON is never read on Postgres. Importing one needs the owning package's
//     row shape, which this package must not import (those packages import
//     platformdb — the dependency runs the other way). They arrive through the
//     Collection seam below, injected by the composition root.
//     rowSpecs collections (users/tenants/…/audit) are the special case this
//     package CAN write itself, so they stay in the blob key list and are
//     exploded by importKey.
//
//  3. ALWAYS-FILE collections — the store reads its own file with os.ReadFile
//     and is not selected by STORE_BACKEND at all (the licence document, the
//     backup/verify reports, the derived enrichment exports). A backend switch
//     does not touch them, so importing them would be wrong, not merely
//     unnecessary. They are listed in the deployment doc, never here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"
)

// fileStateBlobKeys is class 1 (plus the rowSpecs collections, which importKey
// explodes into their normalized tables under the same marker).
//
// The key IS the store's default path, because the key is what the store asks
// the backend for. A deployment that overrode a store's path with its own env
// knob is out of scope by construction: the importer reads <dir>/<basename> and
// writes the DEFAULT key, which is the key a default-configured store reads
// back. That is the same contract the original sixteen keys have always had.
func fileStateBlobKeys() []string {
	return []string{
		// ---- identity, access and platform-global configuration (the original
		// tracker-245 set; normalized tables via rowSpecs where one exists) ----
		"/data/tenants.json", "/data/roles.json", "/data/users.json",
		"/data/snmp_credentials.json", "/data/snmp_profiles.json",
		"/data/apikeys.json", "/data/saved.json", "/data/contact_points.json",
		"/data/notify_config.json", "/data/oidc_config.json", "/data/ldap_config.json",
		"/data/sso_idp_config.json",
		"/data/tacacs_config.json", "/data/token_policy.json", "/data/copilot_config.json",
		"/data/export_policy.json",
		// The AUDIT TRAIL. It has a normalized table (audit_events, rowSpecs)
		// and was NOT imported before, so a cutover started the trail again from
		// zero — losing the evidence an audit trail exists to keep. It is
		// imported like any other collection: the ring is bounded on the file
		// backend, so the volume is bounded too.
		"/data/audit.json",
		// ---- org / tenant structure and access bindings --------------------
		"/data/orgs.json", "/data/role_bindings.json",
		"/data/tenant_display.json", "/data/tenant_governance.json",
		// ---- inventory and its operator-owned annotations ------------------
		// devices.json is the legacy whole-fleet blob; the per-device records
		// live under the "<key>.d/" prefix and are imported by importPrefixTree
		// (see fileStatePrefixKeys).
		"/data/devices.json",
		"/data/device_locations.json", "/data/device_sites.json",
		"/data/device_monitoring.json", "/data/sites.json",
		"/data/discovery_config.json", "/data/netbox_config.json",
		// ---- alerting / notification runtime state -------------------------
		"/data/alert_episodes.json", "/data/alert_notify_state.json",
		"/data/user_rules.json",
		// ---- RCA -----------------------------------------------------------
		"/data/rca_promotions.json", "/data/rca_report_revisions.json",
		"/data/rca_action_items.json",
		// ---- security posture (the tenant-facing settings; the CTEM control
		// plane and framework selection are normalized Collections) ----------
		"/data/security_settings.json", "/data/security_policies.json",
		"/data/ssh_known_hosts.json",
		// ---- integrations, AI and verification ------------------------------
		"/data/itsm_config.json", "/data/tac_connectors.json",
		"/data/ai_tenant_config.json",
		"/data/cloud_monitors.json", "/data/cloud_slos.json",
		"/data/verify_config.json", "/data/verify_runs.json",
		"/data/wan_policy.json",
		// ---- BARE keys (relative on the file backend, anchored on DATA_DIR;
		// a row key here, so they must round-trip unchanged) ------------------
		//
		// CUSTODY, not configuration — the reason a TLS/sealed install could not
		// be cut over at all before (tracker 245):
		//   secrets_wrapped_keys.json — the vault's WRAPPED data-encryption keys.
		//     Without them every value sealed on the file backend (SNMP
		//     credentials, connector secrets) is undecryptable after a cutover.
		//   tls_internal_ca_*         — the internal mesh CA. Without them the api
		//     mints a NEW CA and every SVID issued by the old one stops being
		//     trusted, which on a fail-closed mesh is a stack outage.
		//   cloud_workload_issuer_key.enc — the cloud-connector workload issuer
		//     key. Without it every workload identity it signed stops verifying.
		// All are already encrypted/sealed at rest; this moves the same bytes
		// between the platform's own stores, once, under the same marker gate.
		"secrets_wrapped_keys.json",
		"tls_internal_ca_cert.pem", "tls_internal_ca_key.enc",
		"cloud_workload_issuer_key.enc",
		// The incident time-intelligence backfill cursor. Rebuildable, but
		// re-deriving it means re-walking the whole history, so it travels.
		"timeintel_backfill_cursor.json",
	}
}

// FileStateBlobKeys exposes the inventory for the wiring guard (the composition
// root must not register a Collection whose name collides with one of these —
// they would share an import marker and the second one would never run).
func FileStateBlobKeys() []string { return fileStateBlobKeys() }

// fileStatePrefixKeys names the blob keys that ALSO have a per-record subtree
// ("<key>.d/…"). The device store persists one record per device there, and a
// cutover that moved only the legacy blob would lose every device onboarded
// since the store switched to per-record persistence — which, on any install
// newer than that switch, is all of them.
func fileStatePrefixKeys() []string { return []string{"/data/devices.json"} }

// Collection is one file-backed collection whose Postgres target is a domain
// table this package cannot write (class 2 above). The owning package supplies
// Count and Import; the composition root supplies the list.
//
// Contract for Import:
//   - it MUST preserve ids, tenant ownership and timestamps exactly as the file
//     holds them (a cutover is a move, not a re-creation);
//   - it MUST return an error for a malformed file rather than importing a
//     subset — a partial import that boots looks exactly like a complete one;
//   - it returns the number of rows it wrote, which the importer verifies
//     against Count.
type Collection struct {
	// Name is the collection's identity: the import marker key and the label in
	// the boot log. Must not collide with a fileStateBlobKeys basename.
	Name string
	// File is the path under the import dir, relative ("dem_targets.json",
	// "api/metering.json"). Absent file → nothing to import.
	File string
	// Count reports how many rows the Postgres target already holds. It decides
	// the skipped-populated case and verifies the import afterwards.
	Count func(ctx context.Context) (int, error)
	// Import parses raw and writes the rows, returning how many it wrote.
	Import func(ctx context.Context, raw []byte) (int, error)
}

// ImportCollections runs the marker-gated one-time import for class-2
// collections. It is a no-op unless the active backend is Postgres — on the
// file backend the files ARE the store, and on memory there is nothing durable
// to import into.
//
// Every failure is returned, and main aborts the boot on it: a half-imported
// control plane that comes up looks identical to a complete one.
func ImportCollections(ctx context.Context, dir string, cols []Collection) error {
	ps, ok := ActivePG()
	if !ok {
		return nil
	}
	return ps.importCollections(ctx, dir, cols)
}

func (p *PGStore) importCollections(ctx context.Context, dir string, cols []Collection) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	imported := 0
	for _, c := range cols {
		if err := c.validate(); err != nil {
			return err
		}
		raw, err := readImportFile(dir, c.File)
		if err != nil {
			return fmt.Errorf("import %s: %w", c.Name, err)
		}
		if len(raw) == 0 {
			continue // absent or empty file → nothing to import
		}
		done, err := p.importDone(ctx, c.Name)
		if err != nil {
			return fmt.Errorf("import %s: %w", c.Name, err)
		}
		if done {
			continue // one-time means one-time
		}
		have, err := c.Count(ctx)
		if err != nil {
			return fmt.Errorf("import %s: count target: %w", c.Name, err)
		}
		if have > 0 {
			// Live rows with no marker: record done-without-importing so a
			// later deliberate emptying can never re-trigger the import.
			if err := p.markImported(ctx, c.Name, "skipped-populated"); err != nil {
				return fmt.Errorf("import %s: %w", c.Name, err)
			}
			logInfo("db", "skipped file-backend collection (target already populated)",
				map[string]any{"collection": c.Name, "rows": have})
			continue
		}
		wrote, err := c.Import(ctx, raw)
		if err != nil {
			return fmt.Errorf("import %s: %w", c.Name, err)
		}
		// VERIFY, then mark. Counting the target after the write is the only
		// check that catches an importer whose INSERT silently landed fewer
		// rows than it parsed (an ON CONFLICT collapse, an RLS refusal that
		// affected zero rows). Marking a wrong import "done" would freeze the
		// loss in place, so the marker is written only once the count agrees.
		//
		// The marker is NOT in the importer's transaction (it belongs to the
		// owning package, which owns its own transaction). A crash in the gap
		// leaves rows imported and unmarked, and the next boot then reads the
		// target as POPULATED and records skipped-populated — the same
		// end state, reached honestly. The gap can duplicate nothing.
		got, err := c.Count(ctx)
		if err != nil {
			return fmt.Errorf("import %s: verify: %w", c.Name, err)
		}
		if got != wrote {
			return fmt.Errorf("import %s: wrote %d rows but the target holds %d — refusing to record the import as done", c.Name, wrote, got)
		}
		if err := p.markImported(ctx, c.Name, "rows"); err != nil {
			return fmt.Errorf("import %s: %w", c.Name, err)
		}
		imported++
		logInfo("db", "imported file-backend collection",
			map[string]any{"collection": c.Name, "file": c.File, "rows": got})
	}
	if imported > 0 {
		logInfo("db", "imported file-backend domain collections into Postgres",
			map[string]any{"collections": imported})
	}
	return nil
}

func (c Collection) validate() error {
	switch {
	case strings.TrimSpace(c.Name) == "":
		return errors.New("import collection: empty name")
	case strings.TrimSpace(c.File) == "":
		return fmt.Errorf("import collection %s: empty file", c.Name)
	case c.Count == nil || c.Import == nil:
		return fmt.Errorf("import collection %s: Count and Import are required", c.Name)
	}
	return nil
}

// readImportFile reads dir/rel, refusing a relative path that escapes dir. The
// paths are compiled-in constants, so this is defence in depth (§3) rather than
// an input boundary. An absent file is (nil, nil) — "nothing to import".
func readImportFile(dir, rel string) ([]byte, error) {
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return nil, fmt.Errorf("import file %q must be a relative path inside the import dir", rel)
	}
	full := filepath.Join(dir, filepath.Clean(rel))
	// #nosec G304 G703 -- `rel` is a COMPILED-IN relative path (the wired
	// Collection list), rejected above if it is absolute or contains "..", and
	// joined under the operator-configured IMPORT_FILE_STATE_DIR. No request,
	// tenant or caller string reaches it.
	b, err := os.ReadFile(full)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		// A file that EXISTS but cannot be read is a failure, never "absent":
		// treating a permission error as an empty collection is how a cutover
		// silently drops data (§10).
		return nil, err
	}
	return b, nil
}

// collectPrefixRecords reads the per-record subtree into slash-separated
// relative names → bytes. In-flight atomic-write temporaries are skipped, the
// same ".tmp" suffix rule FileKV.LoadPrefix applies. The walk is root-scoped so
// a symlink planted in the subtree cannot pull the read outside it.
func collectPrefixRecords(srcDir string) (map[string][]byte, error) {
	root, err := os.OpenRoot(srcDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // no subtree = nothing to import
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", srcDir, err)
	}
	defer func() { _ = root.Close() }() // read-only handle; Close cannot lose data
	rfs := root.FS()
	out := map[string][]byte{}
	walkErr := fs.WalkDir(rfs, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasSuffix(p, ".tmp") {
			return nil
		}
		b, rerr := fs.ReadFile(rfs, p)
		if rerr != nil {
			return rerr
		}
		out[p] = b
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("scan %s: %w", srcDir, walkErr)
	}
	return out, nil
}

// blobRecordCount is the honest "how many records did this collection hold"
// for the verification log line: the element count of a JSON array, or 1 for a
// singleton document (a config object, a PEM, a sealed key). It never parses
// the VALUES — only the shape.
func blobRecordCount(data []byte) int {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return 0
	}
	if trimmed[0] != '[' {
		return 1
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(data, &elems); err != nil {
		return 1 // not an array after all; it is still one stored document
	}
	return len(elems)
}

// storedRowCount reports how many rows the Postgres target for key holds after
// an import: table rows for a normalized collection, the stored blob's record
// count for an app_kv one.
func (p *PGStore) storedRowCount(ctx context.Context, key string) (int, error) {
	if spec, ok := specFor(key); ok {
		var n int
		err := p.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+spec.table).Scan(&n)
		})
		return n, err
	}
	data, err := p.loadBlob(ctx, key)
	if errors.Is(err, os.ErrNotExist) {
		// No blob row. That is a real answer — zero records — and it is the
		// normal state for a prefixed collection whose per-record subtree is
		// all it has (an install newer than the device store's per-record
		// switch has no devices.json at all).
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return blobRecordCount(data), nil
}
