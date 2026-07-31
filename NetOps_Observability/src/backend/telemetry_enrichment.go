package backend

import (
	"context"
	"encoding/csv"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"netops/backend/models"
)

// telemetry_enrichment.go — exports the device→tenant map so the ingest tier
// (Vector aggregator, correlation) can stamp a tenant_id onto every telemetry
// record at the source. This is the Phase 1 substrate of #20 (multi-tenant
// telemetry isolation); see docs/design/multitenant-telemetry-isolation.md.
//
// The Go API's discovery is the source of truth for Device.TenantID, but the
// aggregator has no inventory access — so we periodically write a small CSV
// keyed by the device-identity values that telemetry carries (the device NAME,
// which appears as syslog `hostname`, and the management ADDRESS, which appears
// as the flows `sampler_address`/`src/dst_addr`). The aggregator loads it as a
// Vector enrichment table and looks each event up by that identity.
//
// Reads do NOT depend on this file — they still use the live read-time device
// matcher (tenancy.go). The exported tag is defense-in-depth groundwork that
// Phase 2 promotes into database-enforced row policies / DLS.

const enrichmentFileName = "device_tenant.csv"

// enrichmentRow is one (identity, tenant) mapping. identity is either a device
// name or a management address; tenant is the normalized owning tenant ("" for
// global/unassigned, which is platform-only under the strict model).
type enrichmentRow struct {
	Identity string
	Tenant   string
}

// buildEnrichmentRows projects the device inventory onto the identity→tenant
// rows the ingest tier looks up. Pure (no IO) so it is unit-testable.
//
// Rules:
//   - one row per distinct non-empty device NAME and per distinct ADDRESS;
//   - tenant is the device's normalized TenantID ("" = global/platform);
//   - an identity that maps to MORE THAN ONE distinct tenant is AMBIGUOUS and is
//     omitted entirely (fail-safe: it stays untagged → "" → platform-only, never
//     leaked to a wrong tenant). NAT can collapse several devices onto one
//     address, so this guard matters.
//
// Rows are returned sorted by identity for deterministic output (stable file,
// clean diffs, reproducible tests).
func buildEnrichmentRows(devices []models.Device) []enrichmentRow {
	// identity -> set of distinct tenants seen for it.
	seen := map[string]map[string]bool{}
	add := func(identity, tenant string) {
		if identity == "" {
			return
		}
		if seen[identity] == nil {
			seen[identity] = map[string]bool{}
		}
		seen[identity][tenant] = true
	}
	for _, d := range devices {
		t := deviceTenant(d)
		add(d.Name, t)
		add(d.Address, t)
	}

	rows := make([]enrichmentRow, 0, len(seen))
	for identity, tenants := range seen {
		if len(tenants) != 1 {
			continue // ambiguous identity — omit (fail-safe).
		}
		for t := range tenants {
			rows = append(rows, enrichmentRow{Identity: identity, Tenant: t})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Identity < rows[j].Identity })
	return rows
}

// writeEnrichmentCSV atomically writes the rows as a headered CSV to
// dir/device_tenant.csv (temp file + rename, so a reader never sees a partial
// file). Header is `identity,tenant_id` — matched by the Vector enrichment
// table and the correlation loader.
func writeEnrichmentCSV(dir string, rows []enrichmentRow) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".device_tenant-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename.

	w := csv.NewWriter(tmp)
	if err := w.Write([]string{"identity", "tenant_id"}); err != nil {
		tmp.Close()
		return err
	}
	for _, r := range rows {
		if err := w.Write([]string{r.Identity, r.Tenant}); err != nil {
			tmp.Close()
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// os.CreateTemp creates 0600, but this file IS the shared cross-service plane:
	// the Vector aggregator and the correlation engine (different uids) must read
	// it. 0600 left them with PermissionError → silently empty tenant maps.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, enrichmentFileName))
}

// startTenantEnrichment runs the export loop until ctx is cancelled. It is a
// no-op unless TENANT_ENRICHMENT_DIR is set (so the file backend / dev builds
// without the shared volume are unaffected). It writes once immediately, then
// on every TENANT_ENRICHMENT_INTERVAL tick (default 60s).
func (s *server) startTenantEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" {
		return
	}
	interval := 60 * time.Second
	if v := os.Getenv("TENANT_ENRICHMENT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	write := func() {
		rows := buildEnrichmentRows(s.discovery.Devices())
		if err := writeEnrichmentCSV(dir, rows); err != nil {
			log.Printf("tenant-enrichment: write %s: %v", dir, err)
			return
		}
		log.Printf("tenant-enrichment: wrote %d identity rows to %s/%s", len(rows), dir, enrichmentFileName)
	}
	go func() {
		write()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
}
