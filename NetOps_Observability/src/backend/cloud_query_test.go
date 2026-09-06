// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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

func seedCloudInventory(t *testing.T) cloud.Store {
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
		f    cloud.ResourceFilter
		want int
	}{
		{"provider aws", cloud.ResourceFilter{Provider: "aws"}, 2},
		{"provider case-insensitive", cloud.ResourceFilter{Provider: "AWS"}, 2},
		{"account", cloud.ResourceFilter{Account: "111"}, 2},
		{"region", cloud.ResourceFilter{Region: "eastus"}, 1},
		{"type vm", cloud.ResourceFilter{Type: "vm"}, 1},
		{"attribution unknown", cloud.ResourceFilter{Attribution: "unknown"}, 1},
		{"attribution attributed", cloud.ResourceFilter{Attribution: "attributed"}, 3},
		{"attribution unattributed", cloud.ResourceFilter{Attribution: "unattributed"}, 1},
		{"attribution strong", cloud.ResourceFilter{Attribution: "strong"}, 1},
		{"tag has env", cloud.ResourceFilter{Tag: "env"}, 3},
		{"tag env=prod", cloud.ResourceFilter{Tag: "env=prod"}, 2},
		{"tag app=billing", cloud.ResourceFilter{Tag: "app=billing"}, 1},
		{"combined aws prod", cloud.ResourceFilter{Provider: "aws", Tag: "env=prod"}, 1},
		{"no filter", cloud.ResourceFilter{}, 4},
		// Multi-value OR sets (Wave 2 #5 scope bar): comma-separated values OR
		// within a dimension, AND across dimensions.
		{"providers aws,azure", cloud.ResourceFilter{Provider: "aws,azure"}, 3},
		{"providers all three", cloud.ResourceFilter{Provider: "aws,azure,gcp"}, 4},
		{"accounts 111,sub-9", cloud.ResourceFilter{Account: "111,sub-9"}, 3},
		{"regions us-east-1,eastus", cloud.ResourceFilter{Region: "us-east-1,eastus"}, 2},
		{"multi-provider AND region", cloud.ResourceFilter{Provider: "aws,azure", Region: "us-west-2"}, 1},
		{"multi with stray spaces/commas", cloud.ResourceFilter{Provider: " aws , azure ,"}, 3},
		{"multi no match", cloud.ResourceFilter{Account: "111", Region: "eastus"}, 0},
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
		page, err := st.QueryResources(ctx, "org-a", false, cloud.ResourceFilter{Limit: 2, Cursor: cursor})
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
	if _, err := st.QueryResources(context.Background(), "org-a", false, cloud.ResourceFilter{Cursor: "!!!not-base64!!!"}); err == nil {
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
	page, err := st.QueryResources(ctx, "org-b", false, cloud.ResourceFilter{})
	if err != nil || len(page.Resources) != 0 {
		t.Fatalf("org-b must see zero resources, got %d err=%v", len(page.Resources), err)
	}
	// platform cross view sees org-a's rows.
	all, err := st.QueryResources(ctx, "", true, cloud.ResourceFilter{})
	if err != nil || len(all.Resources) != 4 {
		t.Fatalf("cross view should see 4, got %d err=%v", len(all.Resources), err)
	}
}
