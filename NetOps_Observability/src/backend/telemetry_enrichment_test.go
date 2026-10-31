// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

func TestBuildEnrichmentRows(t *testing.T) {
	devices := []models.Device{
		{ID: "d1", Name: "leaf1", Address: "10.0.0.1", TenantID: "Acme"}, // tenant normalized to lower
		{ID: "d2", Name: "leaf2", Address: "10.0.0.2", TenantID: "acme"},
		{ID: "d3", Name: "spine1", Address: "10.0.0.3", TenantID: ""}, // global
		{ID: "d4", Name: "", Address: ""},                             // empty name/address skipped; the id still names it
		{ID: "", Name: "", Address: ""},                               // no identity at all → no row
	}
	got := buildEnrichmentRows(devices)
	want := []enrichmentRow{
		{"10.0.0.1", "acme"},
		{"10.0.0.2", "acme"},
		{"10.0.0.3", ""},
		{"d1", "acme"},
		{"d2", "acme"},
		{"d3", ""},
		{"d4", ""},
		{"leaf1", "acme"},
		{"leaf2", "acme"},
		{"spine1", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestBuildEnrichmentRows_AmbiguousIdentityOmitted(t *testing.T) {
	// Two devices share an address but belong to different tenants (NAT/collision).
	// The shared address is fail-safe omitted; the distinct names survive.
	devices := []models.Device{
		{ID: "d1", Name: "r1", Address: "10.0.0.9", TenantID: "acme"},
		{ID: "d2", Name: "r2", Address: "10.0.0.9", TenantID: "globex"},
	}
	got := buildEnrichmentRows(devices)
	want := []enrichmentRow{
		{"d1", "acme"},
		{"d2", "globex"},
		{"r1", "acme"},
		{"r2", "globex"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ambiguous address should be omitted:\n got=%v\nwant=%v", got, want)
	}
}

func TestBuildEnrichmentRows_SameTenantDuplicateAddressKept(t *testing.T) {
	// Same address, same tenant (e.g. two interfaces of one device) is NOT
	// ambiguous — it collapses to a single row.
	devices := []models.Device{
		{ID: "d1", Name: "a", Address: "10.0.0.5", TenantID: "acme"},
		{ID: "d2", Name: "b", Address: "10.0.0.5", TenantID: "acme"},
	}
	got := buildEnrichmentRows(devices)
	want := []enrichmentRow{
		{"10.0.0.5", "acme"},
		{"a", "acme"},
		{"b", "acme"},
		{"d1", "acme"},
		{"d2", "acme"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("same-tenant duplicate address mismatch:\n got=%v\nwant=%v", got, want)
	}
}

// 2026-10-25 lab regression: an SNMP-scanned device's inventory id is
// discovery.ScanDeviceID(sysName, addr) — e.g. "vedge-20-1e95f00f" — which is
// neither its name ("vEdge-20") nor its address. The trap receiver stamps that
// id as the trap's `device` (attributeDevice → Target.ID) and both the Vector
// aggregator and the correlation engine look the trap up by it. The registry
// carried only name + address rows, so every such trap was a registry MISS on
// a registry-anchored lane and was quarantined as identity_unattributable. The
// id must be a row of its own, owned by the device's tenant.
func TestBuildEnrichmentRows_ScanDeviceIDIsAnIdentity(t *testing.T) {
	devices := []models.Device{
		{ID: discovery.ScanDeviceID("vEdge-20", "192.168.222.20"), Name: "vEdge-20", Address: "192.168.222.20", TenantID: ""},
		{ID: discovery.ScanDeviceID("cEDGE-81", "192.168.222.81"), Name: "cEDGE-81", Address: "192.168.222.81", TenantID: "Retail"},
		// Vendor-neutral: the id form is derived from sysName, whatever the vendor.
		{ID: discovery.ScanDeviceID("mx480-core#1", "10.20.0.1"), Name: "mx480-core#1", Address: "10.20.0.1", TenantID: "acme"},
	}
	byIdentity := map[string]string{}
	for _, r := range buildEnrichmentRows(devices) {
		byIdentity[r.Identity] = r.Tenant
	}
	for _, d := range devices {
		if d.ID == d.Name || d.ID == d.Address {
			t.Fatalf("fixture premise broken: scan id %q must differ from name and address", d.ID)
		}
		want := deviceTenant(d)
		for _, identity := range []string{d.ID, d.Name, d.Address} {
			got, ok := byIdentity[identity]
			if !ok {
				t.Fatalf("identity %q of device %q has no registry row — a lane keyed on it is a registry MISS", identity, d.ID)
			}
			if got != want {
				t.Fatalf("identity %q attributed to %q, want the device's own tenant %q", identity, got, want)
			}
		}
	}
	if len(byIdentity) != 3*len(devices) {
		t.Fatalf("want exactly 3 identities per device, got %d: %v", len(byIdentity), byIdentity)
	}
}

// §3a: id, name and address share ONE lookup namespace (a lane's key is a bare
// string that does not say which kind it is), so a string that is one tenant's
// device id and another tenant's device name is ambiguous and must be omitted —
// never resolved to either owner. The devices' unshared identities keep their
// attribution.
func TestBuildEnrichmentRows_IDCollidingAcrossTenantsIsOmitted(t *testing.T) {
	devices := []models.Device{
		{ID: "core-1", Name: "acme-core", Address: "10.0.0.1", TenantID: "acme"},
		{ID: "globex-dev-7", Name: "core-1", Address: "10.0.0.2", TenantID: "globex"},
	}
	got := buildEnrichmentRows(devices)
	want := []enrichmentRow{
		{"10.0.0.1", "acme"},
		{"10.0.0.2", "globex"},
		{"acme-core", "acme"},
		{"globex-dev-7", "globex"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("an id shared across tenants must be omitted:\n got=%v\nwant=%v", got, want)
	}
}

// A device whose id IS its name (static/operator inventory) yields one row,
// not a self-collision.
func TestBuildEnrichmentRows_IDEqualToNameIsOneRow(t *testing.T) {
	devices := []models.Device{{ID: "edge1", Name: "edge1", Address: "10.0.0.7", TenantID: "acme"}}
	got := buildEnrichmentRows(devices)
	want := []enrichmentRow{{"10.0.0.7", "acme"}, {"edge1", "acme"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("id==name mismatch:\n got=%v\nwant=%v", got, want)
	}
}

// A controller-only device stays out entirely — its id included — so it can
// never make an SNMP-discovered twin's identities ambiguous.
func TestBuildEnrichmentRows_ControllerOnlyDeviceIDNotExported(t *testing.T) {
	devices := []models.Device{
		{ID: "vedge-20-1e95f00f", Name: "vEdge-20", Address: "192.168.222.20", TenantID: ""},
		{ID: "vedge-20-1e95f00f", Name: "vEdge-20", Address: "192.168.222.20", TenantID: "retail", Source: devmon.SourceController},
	}
	got := buildEnrichmentRows(devices)
	want := []enrichmentRow{{"192.168.222.20", ""}, {"vEdge-20", ""}, {"vedge-20-1e95f00f", ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("controller-only device must not reach the registry:\n got=%v\nwant=%v", got, want)
	}
}

func TestWriteEnrichmentCSV_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	rows := []enrichmentRow{
		{"10.0.0.1", "acme"},
		{"spine1", ""},
	}
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
	want := [][]string{
		{"identity", "tenant_id"},
		{"10.0.0.1", "acme"},
		{"spine1", ""},
	}
	if !reflect.DeepEqual(recs, want) {
		t.Fatalf("csv mismatch:\n got=%v\nwant=%v", recs, want)
	}
	// No leftover temp files from the atomic write.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected only the final file, got %d entries: %v", len(entries), entries)
	}
	// The file is read by OTHER uids (Vector, correlation) — os.CreateTemp's 0600
	// must not survive the rename, or their tenant maps go silently empty.
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("enrichment csv must be world-readable (0644), got %o", perm)
	}
}

// F-10 (TLS assurance step-3 e2e): the export loop rewrote the CSV every tick
// even when NOTHING changed, so the file's mtime churned every 60s and could
// never mean "the tenant map changed". The Vector-side reload wrapper keys off
// the file, so an unconditional rewrite would force a reload a minute — the
// writer must skip the rename when the bytes are identical.
func TestWriteEnrichmentCSV_UnchangedContentDoesNotRewrite(t *testing.T) {
	dir := t.TempDir()
	rows := []enrichmentRow{{"10.0.0.1", "acme"}, {"spine1", "globex"}}

	changed, err := writeEnrichmentCSV(dir, rows)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if !changed {
		t.Fatal("first write must report changed=true (the file did not exist)")
	}

	// Pin the mtime into the past; an identical rewrite must LEAVE it there
	// (a rename would bump it — that is the every-60s churn this kills).
	path := filepath.Join(dir, enrichmentFileName)
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	changed, err = writeEnrichmentCSV(dir, rows)
	if err != nil {
		t.Fatalf("identical rewrite: %v", err)
	}
	if changed {
		t.Fatal("identical content must report changed=false")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.ModTime().Equal(past) {
		t.Fatalf("identical content still rewrote the file (mtime bumped %v -> %v) — "+
			"the reload wrapper would HUP Vector every export tick (F-10)",
			past, info.ModTime())
	}

	// A REAL change must write and report it.
	rows[1].Tenant = "initech"
	changed, err = writeEnrichmentCSV(dir, rows)
	if err != nil {
		t.Fatalf("changed rewrite: %v", err)
	}
	if !changed {
		t.Fatal("changed content must report changed=true")
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.ModTime().Equal(past) {
		t.Fatal("changed content did not actually rewrite the file")
	}
}
