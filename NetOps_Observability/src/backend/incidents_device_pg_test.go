// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"os"
	"strings"
	"testing"

	"netops/backend/internal/incident"
	"netops/backend/internal/platformdb"
)

// TestIncidentDeviceColumnPG proves migration 0080 against real Postgres
// (tracker 438): the device round-trips, a dedup fold never flips it, an
// oversized id is dropped rather than refused, and RLS keeps the device-stamped
// row out of another tenant's Get and List. Gated on DATABASE_URL_TEST like the
// rest of the incident PG corpus.
func TestIncidentDeviceColumnPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres incident device test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	store := incident.NewPGStore(ps.DB())

	in := IncidentInput{TenantID: "acme-where", Title: "Gi1 down", Severity: "high",
		SourceType: "alert", SourceID: "InterfaceDown", DedupKey: "alert:where-1", Actor: "alert-engine",
		DeviceID: "edge-1-ab12"}
	inc, created, err := store.Ingest(ctx, in)
	if err != nil || !created {
		t.Fatalf("ingest: err=%v created=%v", err, created)
	}
	if inc.DeviceID != "edge-1-ab12" {
		t.Fatalf("device_id = %q, want edge-1-ab12", inc.DeviceID)
	}

	// A fold carrying another device keeps the first one.
	other := in
	other.DeviceID = "edge-2-cd34"
	folded, created, err := store.Ingest(ctx, other)
	if err != nil || created || folded.ID != inc.ID {
		t.Fatalf("fold: err=%v created=%v id=%s", err, created, folded.ID)
	}
	if folded.DeviceID != "edge-1-ab12" {
		t.Fatalf("a dedup fold flipped the device to %q", folded.DeviceID)
	}

	// A device-less first detection takes the device a later fold brings.
	blank := IncidentInput{TenantID: "acme-where", Title: "BGP down", Severity: "high",
		SourceType: "alert", DedupKey: "alert:where-2", Actor: "alert-engine"}
	b1, _, err := store.Ingest(ctx, blank)
	if err != nil || b1.DeviceID != "" {
		t.Fatalf("device-less ingest: err=%v device=%q", err, b1.DeviceID)
	}
	blank.DeviceID = "edge-3-ef56"
	if b2, _, err := store.Ingest(ctx, blank); err != nil || b2.DeviceID != "edge-3-ef56" {
		t.Fatalf("fold onto an empty device: err=%v device=%q", err, b2.DeviceID)
	}

	// An id the CHECK would refuse is dropped, never a failed ingest.
	big := IncidentInput{TenantID: "acme-where", Title: "x", Severity: "low", SourceType: "alert",
		DedupKey: "alert:where-3", DeviceID: strings.Repeat("d", incident.MaxDeviceIDLen+1)}
	if g, _, err := store.Ingest(ctx, big); err != nil || g.DeviceID != "" {
		t.Fatalf("oversized device id: err=%v device len=%d", err, len(g.DeviceID))
	}

	// §3a: RLS keeps the device-stamped row from another tenant.
	if _, _, found, _ := store.Get(ctx, "globex-where", false, inc.ID); found {
		t.Fatal("CROSS-TENANT LEAK: globex-where read acme-where's device incident by id")
	}
	list, err := store.List(ctx, "globex-where", false, IncidentQuery{})
	if err != nil {
		t.Fatalf("globex list: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: globex-where listed %d of acme-where's incidents", len(list))
	}
	own, err := store.List(ctx, "acme-where", false, IncidentQuery{})
	if err != nil {
		t.Fatalf("acme list: %v", err)
	}
	seen := false
	for _, r := range own {
		if r.ID == inc.ID {
			seen = r.DeviceID == "edge-1-ab12"
		}
	}
	if !seen {
		t.Fatalf("acme-where's own list does not carry the device: %+v", own)
	}
}
