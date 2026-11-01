// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
	"netops/backend/nms"
)

// TestPgControllerSessionsKeepIdentityAndAreTenantIsolated proves migration
// 0061 (tunnel/peer/colours on controller sessions) and the tenant-scoped
// session writer on Postgres, as the non-superuser app role:
//   - the tunnel identity round-trips;
//   - a tenant's overlay read returns only its own sessions, even when another
//     tenant has the SAME tunnel id;
//   - UpsertStates filing a row under another tenant is refused by RLS
//     WITH CHECK (it used to write as the cross-tenant '*' reader);
//   - the read is bounded and says when it was truncated.
//
// Gated on DATABASE_URL_TEST.
func TestPgControllerSessionsKeepIdentityAndAreTenantIsolated(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres controller-session isolation test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := nms.NewPGStore(ps.DB(), nil)
	t0 := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	tid := nms.CanonicalTunnelID("10.255.255.20", "mpls", "10.255.255.51", "mpls")
	sess := func(dev, peer string, at time.Time) nms.StateRecord {
		return nms.StateRecord{EntityKey: dev + "-mpls-" + peer + "-mpls-ipsec", StateKind: "bfd", CurrentState: "up",
			FirstSeen: at, LastSeen: at, DeviceID: dev, TunnelID: tid, PeerID: peer, LocalColor: "mpls", RemoteColor: "mpls"}
	}

	if err := st.UpsertStates(ctx, "t_retail", "int-r", []nms.StateRecord{
		sess("10.255.255.20", "10.255.255.51", t0), sess("10.255.255.51", "10.255.255.20", t0.Add(time.Second)),
		{EntityKey: "10.255.255.20", StateKind: "reachability", CurrentState: "reachable", FirstSeen: t0, LastSeen: t0, DeviceID: "10.255.255.20"},
	}); err != nil {
		t.Fatalf("UpsertStates retail: %v", err)
	}
	// Another tenant, the same overlay addressing, the same tunnel id.
	if err := st.UpsertStates(ctx, "t_acme", "int-a", []nms.StateRecord{sess("10.255.255.20", "10.255.255.51", t0)}); err != nil {
		t.Fatalf("UpsertStates acme: %v", err)
	}

	got, truncated, err := st.OverlaySessions(ctx, "t_retail", t0.Add(-time.Hour), 10)
	if err != nil || truncated || len(got) != 2 {
		t.Fatalf("retail overlay read: err=%v truncated=%v %+v", err, truncated, got)
	}
	for _, r := range got {
		if r.TunnelID != tid || r.IntegrationID != "int-r" || r.LocalColor != "mpls" || r.RemoteColor != "mpls" || r.PeerID == "" {
			t.Fatalf("identity did not round-trip: %+v", r)
		}
	}
	if got[0].DeviceID != "10.255.255.51" {
		t.Fatalf("newest first: %+v", got)
	}
	acme, _, err := st.OverlaySessions(ctx, "t_acme", t0.Add(-time.Hour), 10)
	if err != nil || len(acme) != 1 || acme[0].IntegrationID != "int-a" {
		t.Fatalf("CROSS-TENANT: acme must read exactly its own session: %v %+v", err, acme)
	}
	if none, _, err := st.OverlaySessions(ctx, "t_retail", t0.Add(time.Hour), 10); err != nil || len(none) != 0 {
		t.Fatalf("since must bound the read: %v %+v", err, none)
	}
	one, truncated, err := st.OverlaySessions(ctx, "t_retail", t0.Add(-time.Hour), 1)
	if err != nil || len(one) != 1 || !truncated {
		t.Fatalf("limit 1 of 2 must say truncated: %v %v %+v", err, truncated, one)
	}

	// The writer itself is tenant-scoped now: a row filed under another tenant
	// is refused by the database, not merely avoided by the caller.
	err = ps.DB().WithTenant(ctx, "t_acme", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO controller_state_current (tenant_id, integration_id, entity_key, state_kind, current_state)
			VALUES ('t_retail','int-r','x','bfd','up')`)
		return e
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a session write into another tenant must be RLS-denied (42501); got %v", err)
	}

	// Re-polling the same session updates it in place (idempotent upsert).
	moved := sess("10.255.255.20", "10.255.255.51", t0.Add(time.Minute))
	moved.CurrentState = "down"
	if err := st.UpsertStates(ctx, "t_retail", "int-r", []nms.StateRecord{moved}); err != nil {
		t.Fatal(err)
	}
	again, _, _ := st.OverlaySessions(ctx, "t_retail", t0.Add(-time.Hour), 10)
	if len(again) != 2 || again[0].CurrentState != "down" {
		t.Fatalf("re-poll must update, not duplicate: %+v", again)
	}
}
