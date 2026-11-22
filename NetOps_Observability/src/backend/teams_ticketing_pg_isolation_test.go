// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// teams_ticketing_pg_isolation_test.go — the Teams problem destination against
// a real Postgres (FORCE RLS on incident_policies and correlix_ticket_links,
// migrations 0016/0021). A Teams policy and a Teams ticket link are one
// tenant's rows: another tenant neither sees nor overwrites them, a forged
// owner is refused by the policy's WITH CHECK, and the one-enabled invariant
// holds per (tenant, "teams"). Runs in CI's pgintegration leg.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
	"netops/backend/internal/ticketing"
)

func TestTeamsTicketingRLSIsolationPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()
	st := ticketing.NewPGStore(ps.DB())

	policy := func(tenant, id string, enabled bool) ticketing.IncidentPolicy {
		return ticketing.IncidentPolicy{TenantID: tenant, ID: id, Name: "teams " + id, ExternalSystem: "teams",
			Enabled: enabled, MinVerdict: "suspected", DefaultImpact: 2, DefaultUrgency: 2}
	}
	for _, p := range []ticketing.IncidentPolicy{policy("acme", "t1", true), policy("globex", "t1", true)} {
		if err := ticketing.ValidateIncidentPolicy(p); err != nil {
			t.Fatalf("a Teams policy must validate: %v", err)
		}
		if err := st.PutPolicy(ctx, p); err != nil {
			t.Fatalf("put %s/%s: %v", p.TenantID, p.ID, err)
		}
	}
	// One enabled Teams policy per tenant — a second one is the typed conflict,
	// and globex's enabled Teams policy does not count against acme.
	if err := st.PutPolicy(ctx, policy("acme", "t2", true)); !errors.Is(err, ticketing.ErrPolicyConflict) {
		t.Fatalf("a second enabled Teams policy for acme = %v, want ErrPolicyConflict", err)
	}
	acme, err := st.ListPolicies(ctx, "acme", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(acme) != 1 || acme[0].TenantID != "acme" || acme[0].ExternalSystem != "teams" {
		t.Fatalf("RLS LEAK or no round trip: acme's policies = %+v", acme)
	}
	if _, found, _ := st.GetPolicy(ctx, "globex", false, "t1"); !found {
		t.Fatal("globex's own Teams policy is missing")
	}
	if ok, err := st.DeletePolicy(ctx, "acme", false, "t1"); err != nil || !ok {
		t.Fatalf("acme's own delete: ok=%v err=%v", ok, err)
	}
	if _, found, _ := st.GetPolicy(ctx, "globex", false, "t1"); !found {
		t.Fatal("acme's delete of its t1 reached globex's t1")
	}

	// The ticket link a Teams delivery writes: fixed non-secret origin, the
	// dedupe key as identity, one row per (tenant, corr object, "teams").
	now := time.Now().UTC()
	link := ticketing.Link{TenantID: "acme", CorrObjectID: "corr-1", ExternalSystem: "teams",
		InstanceURL: ticketing.TeamsOrigin, TicketNumber: "T-1", SysID: ticketing.DedupeKey("acme", "corr-1", "teams"),
		DedupeKey: ticketing.DedupeKey("acme", "corr-1", "teams"), Status: "open", LastSyncedAt: &now}
	if err := st.PutLink(ctx, link); err != nil {
		t.Fatal(err)
	}
	got, found, err := st.GetLink(ctx, "acme", false, "corr-1", "teams")
	if err != nil || !found || got.InstanceURL != ticketing.TeamsOrigin || got.Status != "open" {
		t.Fatalf("acme's Teams link round trip: %+v found=%v err=%v", got, found, err)
	}
	if _, found, err := st.GetLink(ctx, "globex", false, "corr-1", "teams"); err != nil || found {
		t.Fatalf("RLS LEAK: globex sees acme's Teams link (found=%v err=%v)", found, err)
	}
	// globex filing for the same correlation id is its own row, not an overwrite.
	other := link
	other.TenantID, other.TicketNumber, other.Status = "globex", "T-9", "pending"
	if err := st.PutLink(ctx, other); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := st.GetLink(ctx, "acme", false, "corr-1", "teams"); got.TicketNumber != "T-1" || got.Status != "open" {
		t.Fatalf("globex's link overwrote acme's: %+v", got)
	}

	// A forged owner inside acme's scoped transaction is refused by the policy.
	err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO correlix_ticket_links (tenant_id, corr_object_id, external_system, status)
            VALUES ('globex', 'corr-forged', 'teams', 'open')`)
		return execErr
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", err)
	}
}
