package main

// cloud_network_overview_test.go — the MANDATED cross-tenant isolation test for
// the Cloud Network Overview roll-up surface (CLAUDE.md §3a step 5), exercised
// through the REAL router + auth middleware: two tenants hold inventories with
// look-alike VPC ids, and each caller's overview must contain ONLY its own
// tenant's network — the other tenant's VPCs, seams and regions never appear,
// and an `as_tenant` override into the other org is ignored for a non-owner.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netops/backend/cloud"
)

type overviewFixture struct {
	tenantID, token string
}

func seedOverviewTenant(t *testing.T, s *server, tenant, vpc, region, seamID string) {
	t.Helper()
	now := time.Now().UTC()
	res := []cloud.CloudResource{
		{
			Provider: cloud.AWS, Region: region, VpcID: vpc,
			ResourceID: "i-" + tenant, ResourceName: "web-" + tenant,
			ResourceType: "ec2:instance", Status: "healthy", StatusReason: "running",
			LastSeenAt: now,
		},
		{
			Provider: cloud.AWS, Region: region, VpcID: vpc,
			ResourceID: "alb-" + tenant, ResourceName: "edge-" + tenant,
			ResourceType: "elbv2:loadbalancer", Status: "degraded",
			StatusReason: "targets 1/2 healthy", LastSeenAt: now,
		},
		{
			Provider: cloud.AWS, Region: region,
			ResourceID: seamID, ResourceName: seamID,
			ResourceType: "ec2:vpnconnection", Status: "down",
			StatusReason: "0/2 tunnels up", AttachedVpcIDs: []string{vpc},
			LastSeenAt: now,
		},
	}
	if err := s.cloud.ReplaceInventory(context.Background(), tenant, res, nil); err != nil {
		t.Fatalf("seed %s: %v", tenant, err)
	}
}

func TestCloudNetworkOverviewCrossTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloud = newCloudStore() // the shared harness doesn't wire the cloud store

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*overviewFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tid := idOf(t, b)
		user := "ov-op-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tid,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &overviewFixture{tenantID: tid, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// Same-shaped estates, DIFFERENT identifiers per tenant.
	seedOverviewTenant(t, s, a.tenantID, "vpc-alpha", "us-west-2", "vpn-alpha")
	seedOverviewTenant(t, s, b.tenantID, "vpc-bravo", "eu-central-1", "vpn-bravo")

	type overviewResp struct {
		Providers []cloud.ProviderOverview `json:"providers"`
		Seams     []cloud.SeamOverview     `json:"seams"`
	}
	fetch := func(token, path string) (overviewResp, string) {
		st, body := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		var out overviewResp
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode overview: %v", err)
		}
		return out, string(body)
	}

	// (1) Own-only view: A sees exactly its own VPC and seam...
	ovA, rawA := fetch(a.token, "/api/cloud/network/overview")
	if len(ovA.Providers) != 1 || len(ovA.Providers[0].Regions) != 1 {
		t.Fatalf("A overview shape: %+v", ovA.Providers)
	}
	regA := ovA.Providers[0].Regions[0]
	if regA.Region != "us-west-2" || len(regA.VPCs) != 1 || regA.VPCs[0].VpcID != "vpc-alpha" {
		t.Fatalf("A must see only vpc-alpha in us-west-2, got %+v", regA)
	}
	if len(ovA.Seams) != 1 || ovA.Seams[0].Devices[0].ResourceID != "vpn-alpha" {
		t.Fatalf("A must see only its own seam, got %+v", ovA.Seams)
	}
	// ...and NOTHING of B leaks anywhere in the payload.
	for _, leak := range []string{"vpc-bravo", "vpn-bravo", "eu-central-1", b.tenantID} {
		if strings.Contains(rawA, leak) {
			t.Fatalf("tenant B identifier %q leaked into A's overview", leak)
		}
	}

	// (2) Symmetric for B.
	_, rawB := fetch(b.token, "/api/cloud/network/overview")
	for _, leak := range []string{"vpc-alpha", "vpn-alpha", "us-west-2", a.tenantID} {
		if strings.Contains(rawB, leak) {
			t.Fatalf("tenant A identifier %q leaked into B's overview", leak)
		}
	}

	// (3) as_tenant into the other org is IGNORED for a non-owner: A still gets
	// A's view, never B's.
	ovAs, rawAs := fetch(a.token, "/api/cloud/network/overview?as_tenant="+b.tenantID)
	if len(ovAs.Providers) != 1 || ovAs.Providers[0].Regions[0].VPCs[0].VpcID != "vpc-alpha" {
		t.Fatalf("as_tenant must not widen a non-owner: %+v", ovAs.Providers)
	}
	if strings.Contains(rawAs, "vpc-bravo") || strings.Contains(rawAs, "vpn-bravo") {
		t.Fatal("as_tenant into another org leaked that org's network")
	}

	// (4) The platform owner's cross-tenant view still works (sees both) — the
	// isolation is scoping, not data loss.
	_, rawAdmin := fetch(admin, "/api/cloud/network/overview")
	if !strings.Contains(rawAdmin, "vpc-alpha") || !strings.Contains(rawAdmin, "vpc-bravo") {
		t.Fatal("platform owner cross-tenant view must include both tenants")
	}
}
