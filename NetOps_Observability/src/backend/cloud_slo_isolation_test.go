package backend

// cloud_slo_isolation_test.go — CROSS-ORG isolation for /api/cloud/slos
// (CLAUDE.md §3a rule 5). Each tenant reads/writes ONLY its own SLO list; a
// scoped admin's as_tenant override into a foreign org is ignored; a non-admin
// cannot write.

import (
	"encoding/json"
	"testing"
)

func TestCloudSLOIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloud = newCloudStore()
	s.cloudSLOs = newCloudSLOStore("") // in-memory
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
	acme := onboardOrg("Acme Corp", "Acme Prod", "acme-slo")
	globex := onboardOrg("Globex Inc", "Globex Prod", "globex-slo")

	mkUser := func(name, role, tenantID string) string {
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": name, "password": "Passw0rd!2345", "role": role, "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		return login(t, srv, name, "Passw0rd!2345").Token
	}
	aliceAdmin := mkUser("alice-slo", "admin", acme.Tenant.ID)
	bobAdmin := mkUser("bob-slo", "admin", globex.Tenant.ID)
	caroOp := mkUser("caro-slo", "operator", acme.Tenant.ID)

	put := func(token, app string, extraQS string) (int, []byte) {
		return do(t, srv, "PUT", "/api/cloud/slos"+extraQS, token, map[string]any{
			"slos": []map[string]any{{"app_name": app, "target_pct": 99.9, "window_days": 7}},
		})
	}
	listApps := func(token, extraQS string) []string {
		st, b := do(t, srv, "GET", "/api/cloud/slos"+extraQS, token, nil)
		if st != 200 {
			t.Fatalf("GET slos: %d %s", st, b)
		}
		var r struct {
			SLOs []struct {
				AppName string `json:"app_name"`
			} `json:"slos"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(r.SLOs))
		for _, s := range r.SLOs {
			out = append(out, s.AppName)
		}
		return out
	}

	// Each tenant admin defines its own SLO.
	if st, b := put(aliceAdmin, "acme-shop", ""); st != 200 {
		t.Fatalf("alice PUT: %d %s", st, b)
	}
	if st, b := put(bobAdmin, "globex-crm", ""); st != 200 {
		t.Fatalf("bob PUT: %d %s", st, b)
	}

	// 1) Own-only list.
	if got := listApps(aliceAdmin, ""); len(got) != 1 || got[0] != "acme-shop" {
		t.Fatalf("alice leak: %v", got)
	}
	if got := listApps(bobAdmin, ""); len(got) != 1 || got[0] != "globex-crm" {
		t.Fatalf("bob leak: %v", got)
	}

	// 2) as_tenant into another org is ignored for a scoped admin — she still
	// reads/writes her OWN tenant's list, never Globex's.
	if got := listApps(aliceAdmin, "?as_tenant="+globex.Tenant.ID); len(got) != 1 || got[0] != "acme-shop" {
		t.Fatalf("alice as_tenant read leaked: %v", got)
	}
	if st, _ := put(aliceAdmin, "sneaky-app", "?as_tenant="+globex.Tenant.ID); st != 200 {
		t.Fatal("alice as_tenant write should land in her own tenant (not error)")
	}
	if got := listApps(bobAdmin, ""); len(got) != 1 || got[0] != "globex-crm" {
		t.Fatalf("alice's as_tenant write reached globex: %v", got)
	}
	if got := listApps(aliceAdmin, ""); len(got) != 1 || got[0] != "sneaky-app" {
		t.Fatalf("alice's write went somewhere unexpected: %v", got)
	}

	// 3) A non-admin cannot write (403), but can read its tenant's list.
	if st, _ := put(caroOp, "nope", ""); st != 403 {
		t.Fatalf("operator PUT must be 403, got %d", st)
	}
	if got := listApps(caroOp, ""); len(got) != 1 || got[0] != "sneaky-app" {
		t.Fatalf("operator read wrong list: %v", got)
	}

	// 4) Unauthenticated → 401.
	if st, _ := do(t, srv, "GET", "/api/cloud/slos", "", nil); st != 401 {
		t.Fatal("unauthenticated must be refused")
	}
}
