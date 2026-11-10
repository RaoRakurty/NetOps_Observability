// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"context"
	"encoding/csv"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/internal/invfacts"
	"netops/backend/internal/vendorprofile"
	"netops/backend/models"
	"netops/backend/nms"
)

// telemetry_enrichment.go — exports the device→tenant map so the ingest tier
// (Vector aggregator, correlation) can stamp a tenant_id onto every telemetry
// record at the source. This is the Phase 1 substrate of #20 (multi-tenant
// telemetry isolation); see docs/design/multitenant-telemetry-isolation.md.
//
// The Go API's discovery is the source of truth for Device.TenantID, but the
// aggregator has no inventory access — so we periodically write a small CSV
// keyed by EVERY device-identity value that telemetry carries:
//
//   - the inventory device ID — what the in-API collectors stamp as `device`
//     (SNMP traps — collectors/snmptrap.go attributeDevice sets Target.ID —,
//     SNMP metrics, the C7.1 entity-resolver trap rescue). For an SNMP-scanned
//     device that is discovery.ScanDeviceID(sysName, addr), e.g.
//     "vedge-20-1e95f00f", which equals NEITHER the name nor the address;
//   - the device NAME, which appears as syslog `hostname`;
//   - the management ADDRESS, which appears as the flows
//     `sampler_address`/`src/dst_addr` and the trap source `host`.
//
// The aggregator loads it as a Vector enrichment table and looks each event up
// by that identity; the correlation engine's verified_tenant reads the same
// file. (2026-10-25 lab defect: the ID row was missing, so every trap from an
// SNMP-discovered device — whose `device` is its scan id — was a registry MISS
// on the registry-anchored trap lane: quarantined as identity_unattributable
// and never correlated, while its metrics silently fell to the platform tenant.)
//
// Reads do NOT depend on this file — they still use the live read-time device
// matcher (tenancy.go). The exported tag is defense-in-depth groundwork that
// Phase 2 promotes into database-enforced row policies / DLS.
//
// INVENTORY FACTS (tracker 387, telemetry plan §6a layer 2). The same row also
// carries what the inventory knows about the device behind the identity: device
// id, vendor, model, site, role. They arrive on the existing O(1) lookup and the
// existing reload, so the vendor on a syslog line or a trap comes from discovery
// rather than from a guess at its text. identity and tenant_id stay the FIRST TWO
// columns: the engine reads them by position (main.py _tenant_registry).
//
// A fact can never cross a tenant. Facts are collected per identity and the row is
// emitted only when the identity has one owner, so an identity two tenants claim
// is omitted whole, facts included. Facts are never used to attribute anything:
// the tenant on a record is exactly what it was before these columns existed.

const enrichmentFileName = "device_tenant.csv"

// enrichmentCSVHeader is the file's contract with both readers. New columns go on
// the END: the engine reads the first two by position.
var enrichmentCSVHeader = []string{"identity", "tenant_id", "device_id", "vendor", "model", "site", "role"}

// maxEnrichmentCellRunes bounds one fact. It lands on every record of the device,
// so an inventory field somebody pasted a paragraph into must not ride along.
const maxEnrichmentCellRunes = invfacts.MaxCellRunes

// enrichmentRow is one identity's row. Identity is a device id, name or management
// address; Tenant is the normalized owning tenant ("" for global/unassigned, which
// is platform-only under the strict model). The rest are inventory facts; "" means
// the inventory does not state one, or the devices behind the identity disagree.
type enrichmentRow struct {
	Identity string
	Tenant   string
	DeviceID string
	Vendor   string
	Model    string
	Site     string
	Role     string
}

// cleanEnrichmentCell makes one inventory value safe to stamp on telemetry: no
// control characters, no surrounding space, bounded. Inventory text is written by
// operators and importers, so it is treated as input like any other (§3).
func cleanEnrichmentCell(v string) string { return invfacts.CleanCell(v) }

// enrichmentSite is the device's site for telemetry, in the precedence the geomap
// uses: the operator's device-to-site binding, then the inventory's own label. The
// binding map is the DEVICE'S OWN tenant's, so another tenant's binding on a
// same-named device is unreachable. The annotation store behind the location editor
// is deliberately not read here: it is keyed by identity token with no tenant, so
// reading it could put one tenant's site on another's record.
func enrichmentSite(d models.Device, bindings map[string]string) string {
	if slug := sotSiteFor(d, bindings); slug != "" {
		return slug
	}
	return d.Labels["location"]
}

// identityFacts gathers the facts of every device claiming one identity.
type identityFacts struct {
	deviceIDs, vendors, models, sites, roles map[string]bool
}

func newIdentityFacts() *identityFacts {
	return &identityFacts{
		deviceIDs: map[string]bool{}, vendors: map[string]bool{}, models: map[string]bool{},
		sites: map[string]bool{}, roles: map[string]bool{},
	}
}

// soleFact returns the one value the devices behind an identity agree on, or "".
// A device that states nothing does not disagree: the same box found by two sources
// often has the vendor on only one of them. Two different values is a conflict,
// and a conflict is left blank rather than settled by a guess.
func soleFact(values map[string]bool) string { return invfacts.Sole(values) }

// buildEnrichmentRows projects the device inventory onto the identity→tenant
// rows the ingest tier looks up. Pure (no IO) so it is unit-testable.
//
// Rules:
//   - one row per distinct non-empty device ID, device NAME and ADDRESS — the
//     three identities share ONE namespace, because a lane's lookup key is a
//     bare string that does not say which of the three it is;
//   - tenant is the device's normalized TenantID ("" = global/platform);
//   - an identity that maps to MORE THAN ONE distinct tenant is AMBIGUOUS and is
//     omitted entirely (fail-safe: it is a registry MISS — quarantined on the
//     registry-anchored lanes, never leaked to a wrong tenant). NAT can collapse
//     several devices onto one address, and one device's id can equal another
//     tenant's device name, so this guard matters across all three kinds.
//
// Rows are returned sorted by identity for deterministic output (stable file,
// clean diffs, reproducible tests).
func buildEnrichmentRows(devices []models.Device) []enrichmentRow {
	return buildEnrichmentRowsWith(devices, nil)
}

// buildEnrichmentRowsWith is buildEnrichmentRows with a per-tenant source of the
// operator's device-to-site bindings. It is called with the device's own tenant
// only; nil means no bindings are available.
func buildEnrichmentRowsWith(devices []models.Device, siteBindings func(tenant string) map[string]string) []enrichmentRow {
	rows, _ := buildEnrichmentRowsFacts(devices, siteBindings, nil)
	return rows
}

// buildEnrichmentRowsFacts is buildEnrichmentRowsWith with the NMS's votes on
// model, site and role (inventory_facts.go), keyed by (owner, device id). It
// also returns how each fact of each exported device was settled. nmsFacts nil
// is "no NMS facts": the rows are exactly what they were before PR 13a.
func buildEnrichmentRowsFacts(devices []models.Device, siteBindings func(tenant string) map[string]string, nmsFacts map[invfacts.Key]*invfacts.Votes) ([]enrichmentRow, map[invfacts.StatKey]int) {
	stats := map[invfacts.StatKey]int{}
	// identity -> set of distinct tenants seen for it.
	seen := map[string]map[string]bool{}
	facts := map[string]*identityFacts{}
	bindingsByTenant := map[string]map[string]string{}
	bindingsFor := func(tenant string) map[string]string {
		if siteBindings == nil {
			return nil
		}
		b, ok := bindingsByTenant[tenant]
		if !ok {
			b = siteBindings(tenant)
			bindingsByTenant[tenant] = b
		}
		return b
	}
	add := func(identity, tenant string, d models.Device, vendor, model, site, role string) {
		if identity == "" {
			return
		}
		if seen[identity] == nil {
			seen[identity] = map[string]bool{}
			facts[identity] = newIdentityFacts()
		}
		seen[identity][tenant] = true
		f := facts[identity]
		for _, c := range []struct {
			into  map[string]bool
			value string
		}{
			{f.deviceIDs, d.ID}, {f.vendors, vendor}, {f.models, model}, {f.sites, site}, {f.roles, role},
		} {
			if v := cleanEnrichmentCell(c.value); v != "" {
				c.into[v] = true
			}
		}
	}
	reg := vendorprofile.Default()
	for _, d := range devices {
		// A controller-ONLY device is left out: its events already carry the
		// integration's tenant, and its name/address (a vManage edge reported
		// to RETAIL and also found by the platform's SNMP scan) would make the
		// other owner's identity ambiguous here — and an ambiguous identity is
		// dropped, which would cost that owner its attribution.
		if d.Source == devmon.SourceController {
			continue
		}
		t := deviceTenant(d)
		vendor, _ := reg.InventoryVendorID(d.Vendor) // "" = the inventory states none
		// The NMS votes are keyed by the device's OWN owner: another tenant's
		// controller can only ever have voted on its own devices.
		facts := invfacts.Resolve(d, enrichmentSite(d, bindingsFor(t)), nmsFacts[invfacts.KeyFor(t, d.ID)])
		invfacts.Count(stats, facts)
		model, site, role := facts.Model.Value, facts.Site.Value, facts.Role.Value
		add(d.ID, t, d, vendor, model, site, role)
		add(d.Name, t, d, vendor, model, site, role)
		add(d.Address, t, d, vendor, model, site, role)
	}

	rows := make([]enrichmentRow, 0, len(seen))
	for identity, tenants := range seen {
		if len(tenants) != 1 {
			continue // ambiguous identity — omit (fail-safe).
		}
		f := facts[identity]
		for t := range tenants {
			rows = append(rows, enrichmentRow{
				Identity: identity, Tenant: t,
				DeviceID: soleFact(f.deviceIDs), Vendor: soleFact(f.vendors), Model: soleFact(f.models),
				Site: soleFact(f.sites), Role: soleFact(f.roles),
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Identity < rows[j].Identity })
	return rows, stats
}

// writeEnrichmentCSV atomically writes the rows as a headered CSV to
// dir/device_tenant.csv (temp file + rename, so a reader never sees a partial
// file). The header is enrichmentCSVHeader — matched by the Vector enrichment
// tables and the correlation loader.
//
// F-10: it reports whether the file actually CHANGED, and it skips the rename
// when the bytes are identical to what is already on disk. The Vector-side
// reload wrapper (cx-enrichment-reload.sh) keys off this file — before this
// guard, the every-60s export tick bumped the mtime with identical content,
// which would have translated into a Vector reload a minute, forever.
func writeEnrichmentCSV(dir string, rows []enrichmentRow) (bool, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(enrichmentCSVHeader); err != nil {
		return false, err
	}
	for _, r := range rows {
		if err := w.Write([]string{r.Identity, r.Tenant, r.DeviceID, r.Vendor, r.Model, r.Site, r.Role}); err != nil {
			return false, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return false, err
	}

	final := filepath.Join(dir, enrichmentFileName)
	// Unreadable/missing existing file → treat as changed and write; the write
	// path below surfaces any real error.
	if prev, err := os.ReadFile(final); err == nil && bytes.Equal(prev, buf.Bytes()) {
		return false, nil
	}

	tmp, err := os.CreateTemp(dir, ".device_tenant-*.tmp")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename.

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	// os.CreateTemp creates 0600, but this file IS the shared cross-service plane:
	// the Vector aggregator and the correlation engine (different uids) must read
	// it. 0600 left them with PermissionError → silently empty tenant maps.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, final); err != nil {
		return false, err
	}
	return true, nil
}

// writeTenantEnrichmentOnce is one export tick. It reports whether it wrote.
//
// NOT-READY HOLD (tracker 366). Until the SNMP scanner's inventory is complete
// — its memory restored at boot, or one sweep finished — the previous file is
// left exactly as it stands. Writing earlier would publish every scanned
// device that has not been re-found yet as unattributed, and the ingest tier
// and correlation would stamp its telemetry platform-only for the minutes (or,
// with an unreadable store and a down network, the hours) until it answered.
// A stale map is right about everything it lists; a premature one is wrong
// about exactly the devices an outage is about.
func (s *server) writeTenantEnrichmentOnce(dir string) bool {
	if !s.discovery.Ready("snmp") {
		log.Printf("tenant-enrichment: SNMP inventory not complete yet (scan memory unread and no sweep finished) — %s/%s left as it stands", dir, enrichmentFileName)
		return false
	}
	rows := s.enrichmentRowsFor(s.discovery.Devices())
	changed, err := writeEnrichmentCSV(dir, rows)
	if err != nil {
		log.Printf("tenant-enrichment: write %s: %v", dir, err)
		return false
	}
	if changed {
		// The mtime bump is the signal the Vector-side reload wrapper
		// (F-10) keys off — log it so a reload has a visible cause here.
		log.Printf("tenant-enrichment: wrote %d identity rows to %s/%s (changed — vector tiers will reload)", len(rows), dir, enrichmentFileName)
	}
	return changed
}

// enrichmentRowsFor builds the export from the server's stores. Each device's site
// bindings are read for its own tenant, non-cross, so another tenant's are
// unreachable however the identity tokens collide.
func (s *server) enrichmentRowsFor(devices []models.Device) []enrichmentRow {
	s.refreshInventoryFacts()
	rows, stats := buildEnrichmentRowsFacts(devices, func(tenant string) map[string]string {
		return s.deviceSites.Assignments(tenant, false)
	}, s.invFacts.Current())
	s.invFacts.SetStats(stats)
	return rows
}

// refreshInventoryFacts is the registry export's facts step (internal/invfacts):
// bounded, logged on failure, never fatal to the export.
func (s *server) refreshInventoryFacts() {
	if s.invFacts == nil || s.nms == nil || s.nmsResolver == nil {
		return
	}
	var store nms.EnabledLister = s.nms.Store()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.invFacts.Refresh(ctx, store, s.nmsResolver.Peek); err != nil {
		logWarn("tenant-enrichment", "NMS inventory facts unread: the registry keeps the previous model/site/role facts this cycle",
			map[string]any{"error": err.Error()})
	}
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
	write := func() { s.writeTenantEnrichmentOnce(dir) }
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
