package backend

// dem_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for the
// Digital Experience surfaces, exercised through the REAL router + auth
// middleware and the REAL s.demAuthz gate mapping (org_isolation_test.go
// template), because the gate CHOICE is half of what §3a rule 3 is about.
//
// Proven here:
//   - own-only list: org A never sees org B's targets, and vice versa;
//   - the owner is stamped from the TOKEN — a tenant_id in the body is refused
//     outright rather than silently re-owned;
//   - cross-tenant GET / PUT / DELETE of a foreign target id → 404 (an id is
//     never confirmed to exist), and the victim's row survives;
//   - an `as_tenant` selector into another org is ignored (it can only NARROW);
//   - the platform owner in the Global view is REFUSED rather than served every
//     tenant's rows;
//   - the experience score is per tenant and is HONEST when nothing was
//     measured — never an empty table that reads as "all well".

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"netops/backend/internal/dem"
)

func demFixtures(t *testing.T) (srv *httptest.Server, s *server, a, b *orgFixture) {
	t.Helper()
	hs, st := newTestServerState(t)
	st.demMetrics = dem.NewMetrics()
	st.demTargets = dem.NewFileStore(filepath.Join(t.TempDir(), "dem_targets.json"))
	api, err := st.buildDEMAPI(st.demTargets)
	if err != nil {
		t.Fatalf("buildDEMAPI: %v", err)
	}
	st.demAPI = api

	admin := login(t, hs, "admin", "Passw0rd!2345").Token
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		code, body := do(t, hs, "POST", "/api/orgs", admin, map[string]any{"name": "DEM Org " + name})
		if code != 201 {
			t.Fatalf("create org %s: %d %s", name, code, body)
		}
		orgID := idOf(t, body)
		code, body = do(t, hs, "POST", "/api/tenants", admin, map[string]any{"name": "DEM Tenant " + name, "org_id": orgID})
		if code != 201 {
			t.Fatalf("create tenant %s: %d %s", name, code, body)
		}
		tenantID := idOf(t, body)
		user := "dem-user-" + name
		code, body = do(t, hs, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if code != 201 {
			t.Fatalf("create user %s: %d %s", name, code, body)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, hs, user, "Passw0rd!2345").Token}
	}
	return hs, st, fix["A"], fix["B"]
}

func demCreate(t *testing.T, srv *httptest.Server, token, name, host string) dem.Target {
	t.Helper()
	code, body := do(t, srv, "POST", "/api/dem/targets", token, map[string]any{
		"name": name, "kind": "icmp", "host": host, "site": "dc1", "app": "core",
	})
	if code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", name, code, body)
	}
	var out dem.Target
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return out
}

func demList(t *testing.T, srv *httptest.Server, token, path string) []dem.Target {
	t.Helper()
	code, body := do(t, srv, "GET", path, token, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, code, body)
	}
	var resp struct {
		Targets []dem.Target `json:"targets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return resp.Targets
}

func TestDEMTargetsCrossOrgIsolation(t *testing.T) {
	srv, s, a, b := demFixtures(t)

	ta := demCreate(t, srv, a.token, "A spine", "10.70.245.11")
	tb := demCreate(t, srv, b.token, "B spine", "10.70.245.12")

	// §3a rule 2: the owner comes from the token.
	if ta.TenantID != a.tenantID || tb.TenantID != b.tenantID {
		t.Fatalf("owner not stamped from the token: %q %q", ta.TenantID, tb.TenantID)
	}

	// Own-only list.
	listA := demList(t, srv, a.token, "/api/dem/targets")
	if len(listA) != 1 || listA[0].ID != ta.ID {
		t.Fatalf("org A sees %d targets: %+v", len(listA), listA)
	}
	listB := demList(t, srv, b.token, "/api/dem/targets")
	if len(listB) != 1 || listB[0].ID != tb.ID {
		t.Fatalf("org B sees %d targets: %+v", len(listB), listB)
	}

	// Cross-tenant get / put / delete → 404, and B's row survives.
	if code, body := do(t, srv, "GET", "/api/dem/targets/"+tb.ID, a.token, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET → %d %s (an id must never be confirmed to exist)", code, body)
	}
	if code, _ := do(t, srv, "PUT", "/api/dem/targets/"+tb.ID, a.token, map[string]any{"paused": true}); code != http.StatusNotFound {
		t.Fatalf("cross-tenant PUT → %d", code)
	}
	if code, _ := do(t, srv, "DELETE", "/api/dem/targets/"+tb.ID, a.token, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant DELETE → %d", code)
	}
	if got := demList(t, srv, b.token, "/api/dem/targets"); len(got) != 1 || got[0].Paused {
		t.Fatalf("org B's target was mutated by org A: %+v", got)
	}

	// The as_tenant selector can only NARROW: A pointing it at B's tenant still
	// sees only A's rows.
	got := demList(t, srv, a.token, "/api/dem/targets?as_tenant="+b.tenantID)
	if len(got) != 1 || got[0].ID != ta.ID {
		t.Fatalf("as_tenant into another org widened the view: %+v", got)
	}
	if s.reachesTenant(a.user, b.tenantID) {
		t.Fatal("org A's operator reaches org B's tenant")
	}

	// A tenant in the CREATE body cannot be expressed at all: the wire type has
	// no such field and unknown fields are refused.
	if code, _ := do(t, srv, "POST", "/api/dem/targets", a.token, map[string]any{
		"name": "sneaky", "kind": "icmp", "host": "10.0.0.1", "tenant_id": b.tenantID,
	}); code != http.StatusBadRequest {
		t.Fatalf("a tenant claim in the body returned %d", code)
	}

	// The platform owner in the Global (cross-tenant) view is REFUSED, not
	// served every tenant's rows.
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if code, body := do(t, srv, "GET", "/api/dem/targets", admin, nil); code != http.StatusBadRequest {
		t.Fatalf("cross-tenant principal was served the catalogue: %d %s", code, body)
	}
	// …and scoping in with the switcher works.
	if got := demList(t, srv, admin, "/api/dem/targets?as_tenant="+b.tenantID); len(got) != 1 || got[0].ID != tb.ID {
		t.Fatalf("platform owner scoped into org B saw %+v", got)
	}
}

// The experience score is per tenant, and with nothing measured it must say so
// rather than render an empty table that reads as "all well".
func TestDEMExperienceIsScopedAndHonest(t *testing.T) {
	srv, _, a, b := demFixtures(t)
	ta := demCreate(t, srv, a.token, "A spine", "10.70.245.11")
	demCreate(t, srv, b.token, "B spine", "10.70.245.12")

	code, body := do(t, srv, "GET", "/api/dem/experience", a.token, nil)
	if code != http.StatusOK {
		t.Fatalf("experience: %d %s", code, body)
	}
	var resp dem.ExperienceResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if len(resp.Targets) != 1 || resp.Targets[0].Subject != ta.ID {
		t.Fatalf("org A's experience view holds %+v", resp.Targets)
	}
	if resp.Targets[0].Tenant != a.tenantID {
		t.Fatalf("result carries tenant %q", resp.Targets[0].Tenant)
	}
	if resp.Measured || resp.Reason == "" || resp.Note == "" {
		t.Fatalf("an unmeasured window was not explained: %+v", resp)
	}
	for _, r := range resp.Targets {
		if r.Score != nil {
			t.Fatalf("an unmeasured target carried a score: %+v", r)
		}
	}
	// A cross-tenant principal is refused here too.
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if code, _ := do(t, srv, "GET", "/api/dem/experience", admin, nil); code != http.StatusBadRequest {
		t.Fatalf("cross-tenant principal was served an experience score: %d", code)
	}
}

// The route registrations in main.go are LITERALS so the route-isolation
// ledger's scanner can see them; this pins that they still match the module's
// exported constants.
func TestDEMRouteLiteralsMatchTheModuleConstants(t *testing.T) {
	if dem.TargetsPath != "/api/dem/targets" ||
		dem.TargetItemPath != "/api/dem/targets/" ||
		dem.ExperiencePath != "/api/dem/experience" {
		t.Fatalf("route constants drifted from the registered literals: %q %q %q",
			dem.TargetsPath, dem.TargetItemPath, dem.ExperiencePath)
	}
}
