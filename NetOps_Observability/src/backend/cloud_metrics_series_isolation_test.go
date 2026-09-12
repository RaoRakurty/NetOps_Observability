// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_metrics_series_isolation_test.go — CROSS-ORG isolation for
// GET /api/cloud/metrics/series (CLAUDE.md §3a rule 5). Through the real
// router + auth middleware: a tenant can chart ONLY its own inventory's
// resource ids; another tenant's id is 404 (indistinguishable from absent),
// an as_tenant override into a foreign org changes nothing, and the PromQL
// selector sent upstream never names a foreign resource.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"netops/backend/cloud"
)

func TestCloudMetricSeriesIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloud = newCloudStore()
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	onboardOrg := func(org, tenant, slug string) onboardResponse {
		st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
			"org_name": org, "tenant_name": tenant, "tenant_slug": slug,
		})
		if st != 201 {
			t.Fatalf("onboard %s: %d %s", org, st, b)
		}
		var r onboardResponse
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	acme := onboardOrg("Acme Corp", "Acme Prod", "acme-prod")
	globex := onboardOrg("Globex Inc", "Globex Prod", "globex-prod")

	mkUser := func(name, tenantID string) string {
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": name, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		return login(t, srv, name, "Passw0rd!2345").Token
	}
	alice := mkUser("alice-metrics", acme.Tenant.ID)
	bob := mkUser("bob-metrics", globex.Tenant.ID)

	seedCloudResource(t, s, acme.Tenant.ID, "i-acme1", "acme-web-1")
	seedCloudResource(t, s, globex.Tenant.ID, "i-globex1", "globex-db-1")

	// The fake store returns data for BOTH ids — isolation must come from the
	// handler, never from the store happening to be empty.
	vm, queries := fakeVM(t, `[
		{"metric":{"resource_id":"i-acme1"},"values":[[1000,"1"]]},
		{"metric":{"resource_id":"i-globex1"},"values":[[1000,"2"]]}
	]`)
	t.Setenv("VM_QUERY_URL", vm.URL)

	get := func(token, path string) (int, []byte) { return do(t, srv, "GET", path, token, nil) }

	// 1) Own resource → 200 with exactly the own series.
	st, b := get(alice, "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-acme1")
	if st != 200 {
		t.Fatalf("alice own resource: want 200, got %d %s", st, b)
	}
	var resp struct {
		Series []struct {
			ResourceID string             `json:"resource_id"`
			Points     []cloudSeriesPoint `json:"points"`
		} `json:"series"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Series) != 1 || resp.Series[0].ResourceID != "i-acme1" {
		t.Fatalf("alice must see only her series: %+v", resp.Series)
	}

	// 2) Another tenant's id → 404 (never revealed, never charted).
	if st, _ := get(alice, "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-globex1"); st != 404 {
		t.Fatalf("cross-tenant id: want 404, got %d", st)
	}
	// 2b) Mixed own+foreign → 404 too (no partial leak).
	if st, _ := get(alice, "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-acme1&resource=i-globex1"); st != 404 {
		t.Fatalf("mixed own+foreign: want 404, got %d", st)
	}

	// 3) as_tenant into another org is ignored for a scoped user — still only
	// her own tenant's view, foreign id still 404.
	if st, _ := get(alice, "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-globex1&as_tenant="+globex.Tenant.ID); st != 404 {
		t.Fatalf("as_tenant override must not leak: got %d", st)
	}

	// 4) Bob symmetrically sees only his own.
	if st, _ := get(bob, "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-acme1"); st != 404 {
		t.Fatalf("bob reading acme id: want 404, got %d", st)
	}

	// 5) The upstream selector never named a foreign resource on a scoped call.
	for _, q := range *queries {
		if strings.Contains(q, "i-globex1") && !strings.Contains(q, "i-acme1") {
			continue // bob's own query
		}
		if strings.Contains(q, "i-acme1") && strings.Contains(q, "i-globex1") {
			t.Fatalf("a single upstream query mixed both tenants' ids: %s", q)
		}
	}

	// 6) The platform owner (cross) may read any tenant's resource.
	if st, _ := get(admin, "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-globex1"); st != 200 {
		t.Fatal("platform owner must be able to read any tenant's series")
	}
}

// seedCloudResource loads one resource into a tenant's inventory (stamped by
// the store from the tenant argument, mirroring the real ingest path).
func seedCloudResource(t *testing.T, s *server, tenantID, resourceID, name string) {
	t.Helper()
	existing, err := s.cloud.ListResources(context.Background(), tenantID, false)
	if err != nil {
		t.Fatal(err)
	}
	res := append(existing, cloud.CloudResource{
		ResourceID: resourceID, ResourceName: name, Provider: "aws",
		AccountID: "123456789012", Region: "us-west-2",
	})
	if err := s.cloud.ReplaceInventory(context.Background(), tenantID, res, nil); err != nil {
		t.Fatal(fmt.Errorf("seed %s: %w", resourceID, err))
	}
}
