package backend

import (
	"errors"
	"netops/backend/internal/platformdb"
	"os"
	"strings"
)

// kv_legacy_migrate.go — heal the store keys that F-63's fix orphaned.
//
// WHAT HAPPENED. Seven settings stores returned RELATIVE kv keys
// ("tenant_governance.json"). That was a real defect on the FILE backend, where
// a relative key resolves against the API container's WORKDIR (/home/nonroot)
// rather than the /data mount, so the write silently never landed. The fix
// prefixed all seven with /data/.
//
// But the key is backend-dependent, and the fix was not. On the POSTGRES
// backend a kv key is just a row key with no filesystem semantics, so the
// relative key had been working perfectly — and repointing the code at
// "/data/tenant_governance.json" orphaned every row written under the old name.
// On a live install that reads as sudden, total data loss: per-tenant required
// tags, RCA windows, seam owners, time-display preferences, RCA promotions and
// the RCA revision register all read back empty, while the rows sat untouched
// in app_kv under their old keys.
//
// The original defect was backend-conditional; so was its fix, in the opposite
// direction. Neither is visible from the other's environment, which is exactly
// why this needs a migration rather than a code review.
//
// WHAT THIS DOES. At startup, before any store is constructed: for each renamed
// key, if the new key has no value and the legacy key does, copy legacy -> new.
// COPY, never move — the legacy row stays as a backup, so this is reversible and
// safe to run against a store that was already migrated by hand. Idempotent: a
// second run finds the new key populated and does nothing.
//
// On the file backend the legacy key is an unwritable relative path, so the read
// simply fails and the migration no-ops — correct, because there was never any
// data there to recover.

// legacyKVKeys maps each store's CURRENT key to the relative key it used before
// the F-63 fix. Add an entry here whenever a store's key changes; changing a
// key without one silently strands whatever the old key held.
func legacyKVKeys() map[string]string {
	return map[string]string{
		tenantGovernancePath(): "tenant_governance.json",
		tenantDisplayPath():    "tenant_display.json",
		rcaPromotionsPath():    "rca_promotions.json",
		rcaRevisionsPath():     "rca_report_revisions.json",
		rcaActionItemsPath():   "rca_action_items.json",
		cloudSLOPath():         "cloud_slos.json",
		cloudMonitorsPath():    "cloud_monitors.json",
	}
}

// migrateLegacyKVKeys copies any orphaned legacy-key value onto its current key.
// Returns the keys it recovered, for the caller to log. Never fatal: a store
// that cannot be migrated still starts (empty), which is the pre-migration
// behaviour — this only ever adds data back.
func migrateLegacyKVKeys() []string {
	var recovered []string
	for current, legacy := range legacyKVKeys() {
		// Only migrate an actual rename. A store whose key never had a /data
		// prefix, or that somehow maps to itself, is not a candidate.
		if current == legacy || !strings.HasPrefix(current, "/") {
			continue
		}
		// Never overwrite live data: if the current key already holds anything,
		// it is authoritative and the legacy row is stale history.
		if b, err := platformdb.Load(current); err == nil && len(b) > 0 {
			continue
		}
		b, err := platformdb.Load(legacy)
		if err != nil {
			// os.ErrNotExist is the normal case (fresh install, or the file
			// backend where the relative path was never writable).
			if !errors.Is(err, os.ErrNotExist) {
				logWarn("store", "legacy kv key unreadable during migration",
					map[string]any{"legacy": legacy, "err": err.Error()})
			}
			continue
		}
		if len(b) == 0 {
			continue
		}
		if err := platformdb.Save(current, b); err != nil {
			logError("store", "could not recover legacy kv key — settings written under the old key stay invisible",
				map[string]any{"legacy": legacy, "current": current, "err": err.Error()})
			continue
		}
		recovered = append(recovered, current)
	}
	return recovered
}
