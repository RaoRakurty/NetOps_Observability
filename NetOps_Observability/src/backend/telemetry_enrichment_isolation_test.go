// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// telemetry_enrichment_isolation_test.go — §3a isolation for the inventory facts
// on the registry (tracker 387 PR 12; template: org_isolation_test.go).
//
// The registry has no read route of its own: what reaches a tenant is the record
// the facts land on. So the assertions are on the file both readers load, and
// they are the same three the template makes, in this surface's terms:
//
//   - own-only: a row carries only facts of devices its own tenant owns;
//   - cross-tenant: an identity two tenants claim is a MISS, facts included, and
//     another tenant's site binding on a same-named device is unreachable;
//   - no attribution through the side door: the facts change no tenant.

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"netops/backend/internal/devmon"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

const (
	isoTenantA = "t_acme"
	isoTenantB = "t_globex"
)

// isoDevices is two tenants and the platform, with the collisions NAT and shared
// naming produce in real estates. Every fact is distinct per owner so that a leak
// reads as a wrong value rather than a coincidence.
func isoDevices() []models.Device {
	return []models.Device{
		{ID: "acme-1", Name: "edge-1", Address: "10.0.0.1", TenantID: isoTenantA,
			Vendor: "arista", Model: "ACME-MODEL", Type: "switch",
			Labels: map[string]string{"role": "acme-role", "site": "acme-label-site"}},
		{ID: "globex-1", Name: "edge-1", Address: "10.0.0.2", TenantID: isoTenantB,
			Vendor: "juniper", Model: "GLOBEX-MODEL", Type: "router",
			Labels: map[string]string{"role": "globex-role"}},
		// Both tenants' boxes behind one NAT address.
		{ID: "acme-2", Name: "acme-only", Address: "192.0.2.9", TenantID: isoTenantA,
			Vendor: "cisco", Model: "ACME-NAT"},
		{ID: "globex-2", Name: "globex-only", Address: "192.0.2.9", TenantID: isoTenantB,
			Vendor: "nokia", Model: "GLOBEX-NAT"},
		{ID: "plat-1", Name: "platform-box", Address: "10.9.9.9", Vendor: "cisco", Model: "PLATFORM-MODEL"},
		// A controller's report of tenant B's view of the platform box: it stays out
		// entirely, so its facts cannot land on the platform's row.
		{ID: "plat-1", Name: "platform-box", Address: "10.9.9.9", TenantID: isoTenantB,
			Vendor: "paloalto", Model: "CONTROLLER-MODEL", Source: devmon.SourceController},
	}
}

// isoExport writes the file through the real writer and returns it by identity.
func isoExport(t *testing.T, rows []enrichmentRow) map[string]map[string]string {
	t.Helper()
	dir := t.TempDir()
	if _, err := writeEnrichmentCSV(dir, rows); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := os.Open(filepath.Join(dir, enrichmentFileName))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	recs, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	head := recs[0]
	out := map[string]map[string]string{}
	for _, rec := range recs[1:] {
		row := map[string]string{}
		for i, col := range head {
			row[col] = rec[i]
		}
		out[row["identity"]] = row
	}
	return out
}

func TestEnrichmentFactsNeverCrossATenant(t *testing.T) {
	store, err := newDeviceSiteStore(filepath.Join(t.TempDir(), "device_sites.json"))
	if err != nil {
		t.Fatal(err)
	}
	devices := isoDevices()
	// Each tenant binds ITS device, and the identity tokens collide on the shared
	// name "edge-1". A map built across tenants would let one overwrite the other.
	for _, b := range []struct {
		tenant, id, site string
		dev              models.Device
	}{
		{isoTenantA, "acme-1", "acme-bound-site", devices[0]},
		{isoTenantB, "globex-1", "globex-bound-site", devices[1]},
	} {
		if err := store.Set(DeviceSiteBinding{
			TenantID: b.tenant, DeviceID: b.id, Site: b.site, Tokens: discovery.DeviceIdentities(b.dev),
		}); err != nil {
			t.Fatal(err)
		}
	}
	s := &server{deviceSites: store}
	got := isoExport(t, s.enrichmentRowsFor(devices))

	// own-only: every row states its own owner's facts.
	for identity, want := range map[string]map[string]string{
		"acme-1":      {"tenant_id": isoTenantA, "device_id": "acme-1", "vendor": "arista", "model": "ACME-MODEL", "site": "acme-bound-site", "role": "acme-role"},
		"10.0.0.1":    {"tenant_id": isoTenantA, "device_id": "acme-1", "vendor": "arista", "model": "ACME-MODEL", "site": "acme-bound-site", "role": "acme-role"},
		"globex-1":    {"tenant_id": isoTenantB, "device_id": "globex-1", "vendor": "juniper", "model": "GLOBEX-MODEL", "site": "globex-bound-site", "role": "globex-role"},
		"10.0.0.2":    {"tenant_id": isoTenantB, "device_id": "globex-1", "vendor": "juniper", "model": "GLOBEX-MODEL", "site": "globex-bound-site", "role": "globex-role"},
		"acme-only":   {"tenant_id": isoTenantA, "device_id": "acme-2", "vendor": "cisco", "model": "ACME-NAT"},
		"globex-only": {"tenant_id": isoTenantB, "device_id": "globex-2", "vendor": "nokia", "model": "GLOBEX-NAT"},
		"plat-1":      {"tenant_id": "", "device_id": "plat-1", "vendor": "cisco", "model": "PLATFORM-MODEL"},
	} {
		row, ok := got[identity]
		if !ok {
			t.Fatalf("identity %q has no row", identity)
		}
		for col, v := range want {
			if row[col] != v {
				t.Errorf("identity %q column %q = %q, want %q", identity, col, row[col], v)
			}
		}
	}

	// cross-tenant: both shared identities are a miss, not a blank row. A reader
	// that found a row would attribute it.
	for _, shared := range []string{"edge-1", "192.0.2.9"} {
		if row, ok := got[shared]; ok {
			t.Errorf("identity %q is claimed by two tenants and must be omitted whole, got %v", shared, row)
		}
	}

	// And nothing of B's anywhere on a row A owns, by value, whatever the column.
	for identity, row := range got {
		for col, v := range row {
			switch row["tenant_id"] {
			case isoTenantA:
				if strings.Contains(strings.ToLower(v), "globex") {
					t.Errorf("tenant A row %q column %q carries tenant B data: %q", identity, col, v)
				}
			case isoTenantB:
				if strings.Contains(strings.ToLower(v), "acme") {
					t.Errorf("tenant B row %q column %q carries tenant A data: %q", identity, col, v)
				}
			case "":
				if strings.Contains(v, "CONTROLLER") {
					t.Errorf("platform row %q column %q carries a controller-only device's fact: %q", identity, col, v)
				}
			}
		}
	}
}

// The real store, and the case that can actually leak. Device identity tokens carry
// the address first, so a device with its own binding never reaches a colliding name
// token. A device with NO binding does: if the bindings were read across tenants, this
// unbound box would take another tenant's site through its shared name.
func TestAnUnboundDeviceNeverInheritsAnotherTenantsSiteByName(t *testing.T) {
	store, err := newDeviceSiteStore(filepath.Join(t.TempDir(), "device_sites.json"))
	if err != nil {
		t.Fatal(err)
	}
	bound := models.Device{ID: "acme-1", Name: "edge-1", Address: "10.0.0.1", TenantID: isoTenantA}
	unbound := models.Device{ID: "globex-1", Name: "edge-1", Address: "10.0.0.2", TenantID: isoTenantB}
	if err := store.Set(DeviceSiteBinding{
		TenantID: isoTenantA, DeviceID: bound.ID, Site: "acme-bound-site", Tokens: discovery.DeviceIdentities(bound),
	}); err != nil {
		t.Fatal(err)
	}
	s := &server{deviceSites: store}
	got := isoExport(t, s.enrichmentRowsFor([]models.Device{bound, unbound}))
	if site := got["acme-1"]["site"]; site != "acme-bound-site" {
		t.Fatalf("premise: the bound device must read its own binding, got %q", site)
	}
	for _, identity := range []string{"globex-1", "10.0.0.2"} {
		if site := got[identity]["site"]; site != "" {
			t.Errorf("tenant B's %q took tenant A's site %q through a shared name", identity, site)
		}
	}
}

// The binding source is asked for the device's OWN tenant and nothing else, so
// the cross-tenant case above cannot depend on what a store happens to return.
func TestEnrichmentSiteBindingsAreReadPerOwningTenant(t *testing.T) {
	asked := map[string]bool{}
	rows := buildEnrichmentRowsWith(isoDevices(), func(tenant string) map[string]string {
		asked[tenant] = true
		return map[string]string{"name:edge-1": "bound-for-" + tenant}
	})
	if want := map[string]bool{isoTenantA: true, isoTenantB: true, "": true}; !reflect.DeepEqual(asked, want) {
		t.Fatalf("bindings asked for %v, want each owner once: %v", asked, want)
	}
	for _, r := range rows {
		if r.Identity == "acme-1" && r.Site != "bound-for-"+isoTenantA {
			t.Errorf("tenant A device read site %q", r.Site)
		}
		if r.Identity == "globex-1" && r.Site != "bound-for-"+isoTenantB {
			t.Errorf("tenant B device read site %q", r.Site)
		}
	}
}

// Metamorphic: strip every fact from the inventory and the (identity, tenant)
// pairs must not move. Tenant stays channel-derived (owner decision 2026-11-01):
// these columns are carried by the row, they never decide it.
func TestEnrichmentFactsDoNotChangeAttribution(t *testing.T) {
	full := isoDevices()
	bare := make([]models.Device, len(full))
	for i, d := range full {
		bare[i] = models.Device{ID: d.ID, Name: d.Name, Address: d.Address, TenantID: d.TenantID, Source: d.Source}
	}
	got, want := identityTenants(buildEnrichmentRows(full)), identityTenants(buildEnrichmentRows(bare))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("facts moved attribution:\n with=%v\n bare=%v", got, want)
	}
}

// Within one tenant a conflict is blank rather than settled by a guess, and a
// device that states nothing does not count as disagreeing.
func TestEnrichmentFactsOnASharedIdentityInOneTenant(t *testing.T) {
	rows := buildEnrichmentRows([]models.Device{
		{ID: "a", Name: "a", Address: "10.1.1.1", TenantID: "acme", Vendor: "cisco", Model: "M1"},
		{ID: "b", Name: "b", Address: "10.1.1.1", TenantID: "acme", Vendor: "arista", Model: "M1"},
		{ID: "c", Name: "c", Address: "10.2.2.2", TenantID: "acme", Vendor: "cisco"},
		{ID: "d", Name: "d", Address: "10.2.2.2", TenantID: "acme"},
	})
	by := map[string]enrichmentRow{}
	for _, r := range rows {
		by[r.Identity] = r
	}
	if r := by["10.1.1.1"]; r.Tenant != "acme" || r.Vendor != "" || r.DeviceID != "" || r.Model != "M1" {
		t.Errorf("conflicting vendor and device id must be blank, the agreed model kept: %+v", r)
	}
	if r := by["10.2.2.2"]; r.Vendor != "cisco" || r.DeviceID != "" {
		t.Errorf("one stated vendor stands, two devices still mean no device id: %+v", r)
	}
}

// The vendor column speaks the catalogue's vocabulary, whatever the inventory
// wrote, for every vendor and never as a guess.
func TestEnrichmentVendorIsTheProfileID(t *testing.T) {
	for inventory, want := range map[string]string{
		"cisco":                      "cisco",
		"Arista Networks":            "arista",
		"Juniper Networks, Inc.":     "juniper",
		"Hewlett Packard Enterprise": "hp",
		"sonic":                      "sonic",
		"net-snmp":                   "", // names the agent, not the box
		"linux":                      "",
		"generic":                    "",
		"Definitely Not A Vendor":    "",
		"":                           "",
	} {
		rows := buildEnrichmentRows([]models.Device{{ID: "x", Vendor: inventory}})
		if len(rows) != 1 || rows[0].Vendor != want {
			t.Errorf("inventory vendor %q exported as %+v, want %q", inventory, rows, want)
		}
	}
}

func TestEnrichmentCellsAreBoundedAndClean(t *testing.T) {
	rows := buildEnrichmentRows([]models.Device{{
		ID: "x", Model: "line\nbreak\tand\x00nul", Labels: map[string]string{"role": strings.Repeat("r", 500)},
	}})
	if len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}
	if rows[0].Model != "linebreakandnul" {
		t.Errorf("control characters survived: %q", rows[0].Model)
	}
	if n := len([]rune(rows[0].Role)); n != maxEnrichmentCellRunes {
		t.Errorf("role is %d runes, want the %d bound", n, maxEnrichmentCellRunes)
	}
}
