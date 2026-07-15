package main

// cloud_query_test.go — server-side filter + keyset-pagination + get-by-id for the
// cloud inventory store (WAVE 1 #1, rev #2). Exercises the in-memory backend (no DB
// required, runs in CI) and asserts the filter/paging semantics the pg backend
// mirrors in SQL. Tenant isolation of these same paths under FORCE-RLS is proven in
// cloud_store_pg_test.go.

import (
	"context"
	"testing"

	"netops/backend/cloud"
)

func seedCloudInventory(t *testing.T) cloudStore {
	t.Helper()
	st := newCloudStore() // mem backend (no STORE_BACKEND=postgres in unit tests)
	res := []cloud.CloudResource{
		{ResourceID: "r-aws-1", Provider: cloud.AWS, AccountID: "111", Region: "us-east-1", ResourceType: "ec2", Confidence: cloud.Confirmed, Tags: map[string]string{"env": "prod", "app": "billing"}},
		{ResourceID: "r-aws-2", Provider: cloud.AWS, AccountID: "111", Region: "us-west-2", ResourceType: "ec2", Confidence: cloud.Unknown, Tags: map[string]string{"env": "dev"}},
		{ResourceID: "r-azure-1", Provider: cloud.Azure, AccountID: "sub-9", Region: "eastus", ResourceType: "vm", Confidence: cloud.Strong, Tags: map[string]string{"env": "prod"}},
		{ResourceID: "r-gcp-1", Provider: cloud.GCP, AccountID: "proj-x", Region: "us-central1", ResourceType: "gce", Confidence: cloud.Suspected},
	}
	if err := st.ReplaceInventory(context.Background(), "org-a", res, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return st
}

func TestCloudQueryFilters(t *testing.T) {
	ctx := context.Background()
	st := seedCloudInventory(t)

	cases := []struct {
		name string
		f    cloudResourceFilter
		want int
	}{
		{"provider aws", cloudResourceFilter{Provider: "aws"}, 2},
		{"provider case-insensitive", cloudResourceFilter{Provider: "AWS"}, 2},
		{"account", cloudResourceFilter{Account: "111"}, 2},
		{"region", cloudResourceFilter{Region: "eastus"}, 1},
		{"type vm", cloudResourceFilter{Type: "vm"}, 1},
		{"attribution unknown", cloudResourceFilter{Attribution: "unknown"}, 1},
		{"attribution attributed", cloudResourceFilter{Attribution: "attributed"}, 3},
		{"attribution unattributed", cloudResourceFilter{Attribution: "unattributed"}, 1},
		{"attribution strong", cloudResourceFilter{Attribution: "strong"}, 1},
		{"tag has env", cloudResourceFilter{Tag: "env"}, 3},
		{"tag env=prod", cloudResourceFilter{Tag: "env=prod"}, 2},
		{"tag app=billing", cloudResourceFilter{Tag: "app=billing"}, 1},
		{"combined aws prod", cloudResourceFilter{Provider: "aws", Tag: "env=prod"}, 1},
		{"no filter", cloudResourceFilter{}, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			page, err := st.QueryResources(ctx, "org-a", false, c.f)
			if err != nil {
				t.Fatalf("QueryResources: %v", err)
			}
			if len(page.Resources) != c.want {
				t.Fatalf("filter %+v: got %d resources, want %d", c.f, len(page.Resources), c.want)
			}
		})
	}
}

func TestCloudQueryPagination(t *testing.T) {
	ctx := context.Background()
	st := seedCloudInventory(t)

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := st.QueryResources(ctx, "org-a", false, cloudResourceFilter{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		if len(page.Resources) > 2 {
			t.Fatalf("page %d exceeded limit: %d", pages, len(page.Resources))
		}
		for _, r := range page.Resources {
			if seen[r.ResourceID] {
				t.Fatalf("duplicate across pages: %s", r.ResourceID)
			}
			seen[r.ResourceID] = true
		}
		pages++
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 4 {
		t.Fatalf("pagination visited %d resources, want 4", len(seen))
	}
	if pages != 2 {
		t.Fatalf("4 resources at limit 2 should be 2 pages, got %d", pages)
	}
}

func TestCloudQueryBadCursor(t *testing.T) {
	st := seedCloudInventory(t)
	if _, err := st.QueryResources(context.Background(), "org-a", false, cloudResourceFilter{Cursor: "!!!not-base64!!!"}); err == nil {
		t.Fatal("a malformed cursor must be rejected, got nil error")
	}
}

func TestCloudGetResource(t *testing.T) {
	ctx := context.Background()
	st := seedCloudInventory(t)

	// own resource is found
	r, ok, err := st.GetResource(ctx, "org-a", false, "r-aws-1")
	if err != nil || !ok || r.ResourceID != "r-aws-1" {
		t.Fatalf("own GetResource: ok=%v err=%v r=%+v", ok, err, r)
	}
	// another tenant cannot get org-a's resource by id → not found (never revealed)
	if _, ok, err := st.GetResource(ctx, "org-b", false, "r-aws-1"); err != nil || ok {
		t.Fatalf("cross-tenant GetResource must be not-found: ok=%v err=%v", ok, err)
	}
	// missing id → not found
	if _, ok, err := st.GetResource(ctx, "org-a", false, "nope"); err != nil || ok {
		t.Fatalf("missing GetResource must be not-found: ok=%v err=%v", ok, err)
	}
}

func TestCloudQueryTenantScoped(t *testing.T) {
	ctx := context.Background()
	st := seedCloudInventory(t)
	// org-b has no inventory → an own-only query returns nothing (no leak of org-a).
	page, err := st.QueryResources(ctx, "org-b", false, cloudResourceFilter{})
	if err != nil || len(page.Resources) != 0 {
		t.Fatalf("org-b must see zero resources, got %d err=%v", len(page.Resources), err)
	}
	// platform cross view sees org-a's rows.
	all, err := st.QueryResources(ctx, "", true, cloudResourceFilter{})
	if err != nil || len(all.Resources) != 4 {
		t.Fatalf("cross view should see 4, got %d err=%v", len(all.Resources), err)
	}
}
