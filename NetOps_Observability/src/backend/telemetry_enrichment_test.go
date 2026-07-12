package main

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"netops/backend/models"
)

func TestBuildEnrichmentRows(t *testing.T) {
	devices := []models.Device{
		{ID: "d1", Name: "leaf1", Address: "10.0.0.1", TenantID: "Acme"}, // tenant normalized to lower
		{ID: "d2", Name: "leaf2", Address: "10.0.0.2", TenantID: "acme"},
		{ID: "d3", Name: "spine1", Address: "10.0.0.3", TenantID: ""}, // global
		{ID: "d4", Name: "", Address: ""},                            // empty identities → skipped
	}
	got := buildEnrichmentRows(devices)
	want := []enrichmentRow{
		{"10.0.0.1", "acme"},
		{"10.0.0.2", "acme"},
		{"10.0.0.3", ""},
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
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("same-tenant duplicate address mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestWriteEnrichmentCSV_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	rows := []enrichmentRow{
		{"10.0.0.1", "acme"},
		{"spine1", ""},
	}
	if err := writeEnrichmentCSV(dir, rows); err != nil {
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
