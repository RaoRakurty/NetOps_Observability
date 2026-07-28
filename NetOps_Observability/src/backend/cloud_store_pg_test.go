package main

// cloud_store_pg_test.go — CROSS-TENANT isolation for the Postgres cloud inventory
// store (CLAUDE.md §3a.5, REQUIRED with the feature). Drives cloud.PGStore as two
// scoped tenants through withTenant, run as the non-superuser app role so FORCE ROW
// LEVEL SECURITY actually bites — the storage-layer backstop even if a handler authz
// check were bypassed. Asserts: own-only list/query, cross-tenant query no-leak,
// cross-tenant get-by-id → not found (never revealed), a per-tenant refresh cannot
// clobber another tenant's inventory, a scoped tenant cannot forge a row into another
// tenant's namespace (RLS WITH CHECK), filters+pagination hold under RLS, and the
// platform cross view sees both. Gated on DATABASE_URL_TEST.

import (
	"context"
	"errors"
	"netops/backend/internal/platformdb"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"netops/backend/cloud"
)

func acmeInventory() []cloud.CloudResource {
	return []cloud.CloudResource{
		{ResourceID: "acme-r1", Provider: cloud.AWS, AccountID: "111", Region: "us-east-1", ResourceType: "ec2", Confidence: cloud.Confirmed, Tags: map[string]string{"env": "prod"}},
		{ResourceID: "acme-r2", Provider: cloud.AWS, AccountID: "111", Region: "us-west-2", ResourceType: "ec2", Confidence: cloud.Unknown},
		{ResourceID: "acme-r3", Provider: cloud.Azure, AccountID: "sub-9", Region: "eastus", ResourceType: "vm", Confidence: cloud.Strong, Tags: map[string]string{"env": "prod"}},
	}
}

func TestCloudStorePgCrossTenantIsolation(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres cloud-inventory isolation test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := cloud.NewPGStore(ps.DB())

	// acme + globex each load their own inventory (per-tenant full refresh).
	if err := st.ReplaceInventory(ctx, "acme", acmeInventory(),
		[]cloud.CloudIdentityMapping{{MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.0.0.1", AppID: "billing"}}); err != nil {
		t.Fatalf("acme ReplaceInventory: %v", err)
	}
	if err := st.ReplaceInventory(ctx, "globex",
		[]cloud.CloudResource{{ResourceID: "globex-r1", Provider: cloud.GCP, AccountID: "proj-z", Region: "us-central1", ResourceType: "gce", Confidence: cloud.Weak}}, nil); err != nil {
		t.Fatalf("globex ReplaceInventory: %v", err)
	}

	// 1) own-only list/query: acme sees exactly its 3, globex exactly its 1.
	if rs, _ := st.ListResources(ctx, "acme", false); len(rs) != 3 {
		t.Fatalf("acme should see exactly its 3 resources, got %d", len(rs))
	}
	page, err := st.QueryResources(ctx, "acme", false, cloud.ResourceFilter{})
	if err != nil || len(page.Resources) != 3 {
		t.Fatalf("acme QueryResources: got %d err=%v, want 3", len(page.Resources), err)
	}
	if maps, _ := st.ListMappings(ctx, "acme", false); len(maps) != 1 {
		t.Fatalf("acme should see exactly its 1 mapping, got %d", len(maps))
	}

	// 2) globex sees NEITHER acme's resources nor its mapping — no cross-tenant leak.
	if page, err := st.QueryResources(ctx, "globex", false, cloud.ResourceFilter{}); err != nil || len(page.Resources) != 1 || page.Resources[0].ResourceID != "globex-r1" {
		t.Fatalf("globex must see only its own resource: %+v err=%v", page.Resources, err)
	}
	if maps, err := st.ListMappings(ctx, "globex", false); err != nil || len(maps) != 0 {
		t.Fatalf("globex must see zero acme mappings, got %d err=%v", len(maps), err)
	}

	// 3) cross-tenant get-by-id → not found (never reveal another tenant's id).
	if _, ok, err := st.GetResource(ctx, "globex", false, "acme-r1"); err != nil || ok {
		t.Fatalf("globex GetResource of acme's id must be not-found: ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.GetResource(ctx, "acme", false, "acme-r1"); err != nil || !ok {
		t.Fatalf("acme GetResource of its own id must be found: ok=%v err=%v", ok, err)
	}

	// 4) filters + keyset pagination hold under RLS (scoped scan).
	if page, err := st.QueryResources(ctx, "acme", false, cloud.ResourceFilter{Provider: "aws"}); err != nil || len(page.Resources) != 2 {
		t.Fatalf("acme provider=aws: got %d err=%v, want 2", len(page.Resources), err)
	}
	if page, err := st.QueryResources(ctx, "acme", false, cloud.ResourceFilter{Tag: "env=prod"}); err != nil || len(page.Resources) != 2 {
		t.Fatalf("acme tag env=prod: got %d err=%v, want 2", len(page.Resources), err)
	}
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		p, err := st.QueryResources(ctx, "acme", false, cloud.ResourceFilter{Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("acme paged query: %v", err)
		}
		for _, r := range p.Resources {
			if r.TenantID != "acme" {
				t.Fatalf("paged query leaked a non-acme row: %+v", r)
			}
			seen[r.ResourceID] = true
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if len(seen) != 3 {
		t.Fatalf("acme pagination visited %d rows, want 3", len(seen))
	}

	// 5) a per-tenant refresh cannot clobber another tenant: acme reloading its own
	// inventory leaves globex's row intact (DELETE is RLS-scoped to acme).
	if err := st.ReplaceInventory(ctx, "acme", acmeInventory()[:1], nil); err != nil {
		t.Fatalf("acme refresh: %v", err)
	}
	if rs, _ := st.ListResources(ctx, "acme", false); len(rs) != 1 {
		t.Fatalf("acme refresh should leave 1 row, got %d", len(rs))
	}
	if rs, _ := st.ListResources(ctx, "globex", false); len(rs) != 1 {
		t.Fatalf("globex inventory must survive acme's refresh, got %d", len(rs))
	}

	// 6) RLS WITH CHECK backstop: a scoped tenant cannot forge a row directly into
	// another tenant's namespace even talking to the DB (42501 = insufficient_privilege).
	rlsDenied := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "42501"
	}
	err = ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO cloud_resources (tenant_id, resource_id) VALUES ('acme', 'forged')`)
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("globex forging a row into acme's namespace must be RLS-denied (42501); got %v", err)
	}

	// 7) platform cross view sees both tenants' rows (control).
	if all, err := st.QueryResources(ctx, "*", true, cloud.ResourceFilter{}); err != nil || len(all.Resources) != 2 {
		t.Fatalf("platform cross view should see both tenants' rows (1+1), got %d err=%v", len(all.Resources), err)
	}
}
