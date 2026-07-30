package backend

// cloud_topology_isolation_test.go — CROSS-ORG isolation for GET /api/topology/cloud
// (CLAUDE.md §3a, required regression guard). The discovered cloud topology fixtures
// are provider-global, owned by CLOUD_FIXTURE_TENANT. We assert, through the REAL
// router + auth middleware, that ONLY the owner tenant (and the cross-tenant platform
// owner) can read them — every other tenant gets an honest empty view, and neither an
// as_tenant override nor a narrowed owner view can leak another tenant's network.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"netops/backend/topology"
)

func writeTopologyFixture(t *testing.T, dir string) {
	t.Helper()
	fixture := map[string]any{
		"provider": "aws", "account_id": "123456789012", "region": "us-west-2",
		"vpcs":    []map[string]any{{"id": "vpc-1", "cidr": "10.60.0.0/16", "name": "prod"}},
		"subnets": []map[string]any{{"id": "subnet-app", "cidr": "10.60.10.0/24", "name": "app-a"}},
		"nodes":   []map[string]any{{"id": "igw-1", "kind": "internet_gateway", "name": "prod-igw"}},
		"edges": []map[string]any{{
			"from_subnet": "subnet-app", "to": "igw-1", "to_kind": "internet_gateway",
			"destination": "0.0.0.0/0", "state": "active", "route_table_name": "rt-app",
		}},
	}
	b, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aws-topology.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCloudTopologyIsolation(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	onboard := func(org, tenant, slug string) onboardResponse {
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
	owner := onboard("Acme Corp", "Acme Prod", "acme-prod")      // owns the fixtures
	other := onboard("Globex Inc", "Globex Prod", "globex-prod") // must never see them

	mkUser := func(name, tenantID string) string {
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": name, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		return login(t, srv, name, "Passw0rd!2345").Token
	}
	alice := mkUser("alice", owner.Tenant.ID) // scoped to the owner tenant
	bob := mkUser("bob", other.Tenant.ID)     // scoped to the other tenant

	// Point the endpoint at a real fixtures dir owned by the owner tenant.
	dir := t.TempDir()
	writeTopologyFixture(t, dir)
	t.Setenv("CLOUD_FIXTURES_DIR", dir)
	t.Setenv("CLOUD_FIXTURE_TENANT", owner.Tenant.ID)

	get := func(token, path string) topology.View {
		st, b := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, b)
		}
		var v topology.View
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("decode view: %v (%s)", err, b)
		}
		return v
	}

	// 1) The OWNER tenant sees the real topology (the VPC group + its nodes).
	own := get(alice, "/api/topology/cloud")
	if len(own.Nodes) == 0 || len(own.Groups) == 0 {
		t.Fatalf("owner tenant saw an empty topology: %+v", own)
	}
	var sawVPC bool
	for _, g := range own.Groups {
		if g.ID == "vpc-1" {
			sawVPC = true
		}
	}
	if !sawVPC {
		t.Fatalf("owner tenant missing vpc-1 group: %+v", own.Groups)
	}
	// Every node/group is stamped with the CALLER's scope, never the fixture's.
	if own.Scope.TenantID != owner.Tenant.ID {
		t.Fatalf("view scope = %q, want owner tenant %q", own.Scope.TenantID, owner.Tenant.ID)
	}

	// 2) A DIFFERENT tenant gets an honest EMPTY view — never the owner's network.
	if got := get(bob, "/api/topology/cloud"); len(got.Nodes) != 0 || len(got.Groups) != 0 {
		t.Fatalf("cross-tenant leak: bob saw %d nodes / %d groups", len(got.Nodes), len(got.Groups))
	}

	// 3) bob cannot WIDEN into the owner tenant via ?as_tenant= (override ignored).
	if got := get(bob, "/api/topology/cloud?as_tenant="+owner.Tenant.ID); len(got.Nodes) != 0 {
		t.Fatalf("as_tenant leak: bob?as_tenant=owner saw %d nodes", len(got.Nodes))
	}

	// 4) The platform owner (cross-tenant Global) sees the topology.
	if got := get(admin, "/api/topology/cloud"); len(got.Nodes) == 0 {
		t.Fatalf("platform owner saw an empty topology")
	}

	// 5) The platform owner NARROWED to the other tenant sees empty (the override
	//    only ever narrows — it must not reveal the owner tenant's fixtures).
	if got := get(admin, "/api/topology/cloud?as_tenant="+other.Tenant.ID); len(got.Nodes) != 0 {
		t.Fatalf("narrowed owner leak: admin?as_tenant=other saw %d nodes", len(got.Nodes))
	}
}
