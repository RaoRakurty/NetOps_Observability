// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/models"
)

// Owner rule 2026-11-23: a device is shown by its hostname, never its address. The
// registry row carries the device's display name on every one of its identities, so
// the ingest tier can title a frame that arrived with only a source address
// (rfc3164 IOS writes no hostname) with "cEDGE-40" instead of "192.168.222.107".
func TestEnrichmentRowsCarryTheDisplayNameOnEveryIdentity(t *testing.T) {
	devs := []models.Device{
		{ID: "cedge-40-fdf7b64f", Name: "cEDGE-40", Address: "192.168.222.107", TenantID: "t_acme"},
	}
	rows := buildEnrichmentRows(devs)
	if len(rows) != 3 {
		t.Fatalf("want id, name and address rows, got %+v", rows)
	}
	for _, r := range rows {
		if r.Name != "cEDGE-40" {
			t.Fatalf("identity %q: Name = %q, want cEDGE-40", r.Identity, r.Name)
		}
	}
}

// Two devices claiming one address in ONE tenant (NAT) disagree on the name: the
// row states none rather than picking one — the same rule as every other fact.
func TestEnrichmentDisplayNameConflictIsLeftBlank(t *testing.T) {
	devs := []models.Device{
		{ID: "a-id", Name: "edge-a", Address: "10.9.9.9", TenantID: "t_acme"},
		{ID: "b-id", Name: "edge-b", Address: "10.9.9.9", TenantID: "t_acme"},
	}
	found := false
	for _, r := range buildEnrichmentRows(devs) {
		if r.Identity == "10.9.9.9" {
			found = true
			if r.Name != "" {
				t.Fatalf("a shared address must not name either device, got %q", r.Name)
			}
		}
	}
	if !found {
		t.Fatal("the shared address (one tenant) must still have its tenant row")
	}
}

// An address two TENANTS claim is omitted whole (fail-safe), so no name can cross.
func TestEnrichmentDisplayNameNeverCrossesTenants(t *testing.T) {
	devs := []models.Device{
		{ID: "a-id", Name: "edge-a", Address: "10.9.9.9", TenantID: "t_a"},
		{ID: "b-id", Name: "edge-b", Address: "10.9.9.9", TenantID: "t_b"},
	}
	for _, r := range buildEnrichmentRows(devs) {
		if r.Identity == "10.9.9.9" {
			t.Fatalf("an address two tenants claim must have no row, got %+v", r)
		}
	}
}
