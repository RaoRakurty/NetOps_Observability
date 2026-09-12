// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// operator-visibility restriction (Tenant.OperatorRestricted) on the CLOUD plane.
//
// The cloud plane is the customer's provider estate: the resources and their
// names, the accounts they sit in, the identity map that names its apps, the flow
// pairs between them, and the daily figures the provider BILLED that tenant. The
// billed costs matter on their own: an account id plus an amount is what the
// customer spends, and it is commercially sensitive whether or not anything else
// leaks with it.
//
// The plane reads through TWO storage models, so both are exercised here: the
// inventory store, asked for a (tenant, cross) pair, and ClickHouse, whose row
// policies enforce on a tenant_scope SETTING that the platform owner deliberately
// unlocks with '__all__'. The ClickHouse stand-in below APPLIES the strict row
// policy and the handler's exclusion predicate to seeded rows, so a leak shows up
// as the tenant's own bytes in the response rather than as a missing substring.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/cloud"
	"netops/backend/cloudconn"
	"netops/backend/internal/discovery"
)

// The identifiers and figures that must never cross. Named here so every
// assertion below says WHICH field leaked.
const (
	acmeAccountID   = "111122223333" // the AWS account acme is billed under
	acmeCostAmount  = "48211.57"     // what the provider billed acme that day
	acmeCostService = "Amazon Elastic Compute Cloud - Compute"
	acmeResourceID  = "i-0acmepay01"
	acmeResName     = "acme-payments-api"
	acmePrivateIP   = "10.50.1.10"
	acmeConnectorID = "ccn_acme01"
)

// ── a ClickHouse that enforces the policy, so a leak is visible as bytes ─────

// chPolicyRow is one seeded ClickHouse row. tenant_id is what the STRICT row
// policy compares against tenant_scope; every other key is a projected column.
type chPolicyRow map[string]any

// chScopeOf reads the tenant_scope literal out of the emitted SETTINGS clause.
func chScopeOf(sql string) string {
	_, rest, ok := strings.Cut(sql, "tenant_scope = '")
	if !ok {
		return ""
	}
	scope, _, _ := strings.Cut(rest, "'")
	return scope
}

// chExcludedOf reads the tenant ids out of the handler's exclusion predicate.
func chExcludedOf(sql string) map[string]bool {
	out := map[string]bool{}
	_, rest, ok := strings.Cut(sql, "tenant_id NOT IN (")
	if !ok {
		return out
	}
	list, _, _ := strings.Cut(rest, ")")
	for _, part := range strings.Split(list, ",") {
		if v := strings.Trim(strings.TrimSpace(part), "'"); v != "" {
			out[v] = true
		}
	}
	return out
}

// cloudPolicyCH stands in for ClickHouse on the cloud plane. It models the two
// things that actually decide what a cloud read returns:
//
//   - the STRICT tenant row policy — a row is visible only to its own tenant, or
//     to a caller that asked for '__all__'. No untagged-shared escape.
//   - the handler's own tenant_id exclusion, which is the only way to hide a
//     tenant from a caller reading at '__all__'.
//
// Rows are keyed by the netops table they belong to; the SQL's FROM clause picks
// the set. Projection is not modelled: the seeded row IS the projected row, which
// is what the decoding wire types read.
func cloudPolicyCH(t *testing.T, tables map[string][]chPolicyRow) (queries *[]string) {
	t.Helper()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<20)
		n, _ := r.Body.Read(buf)
		sql := string(buf[:n])
		got = append(got, sql)

		// The scope reaches ClickHouse one of two ways: inside the SQL as a
		// SETTINGS clause, or as the tenant_scope request setting the streaming
		// proxy sends. Both are the same rule, so the stand-in reads both and the
		// recorded query carries whichever was used.
		scope := chScopeOf(sql)
		if scope == "" {
			scope = r.URL.Query().Get("tenant_scope")
			sql += "\n SETTINGS tenant_scope = '" + scope + "'"
			got[len(got)-1] = sql
		}
		excluded := chExcludedOf(sql)
		var rows []chPolicyRow
		for table, seeded := range tables {
			if !strings.Contains(sql, table) {
				continue
			}
			for _, row := range seeded {
				owner, _ := row["tenant_id"].(string)
				if scope != "__all__" && owner != scope {
					continue // the STRICT row policy
				}
				if excluded[owner] {
					continue // the handler's exclusion
				}
				rows = append(rows, row)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(sql, "FORMAT JSONEachRow"):
			for _, row := range rows {
				b, err := json.Marshal(row)
				if err != nil {
					t.Errorf("marshal seeded row: %v", err)
					return
				}
				_, _ = w.Write(append(b, '\n'))
			}
		default: // FORMAT JSON / TSV surfaces this test does not seed
			_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return &got
}

// ── the fixture ─────────────────────────────────────────────────────────────

type restrictedCloudFixture struct {
	t         *testing.T
	s         *server
	acme      string
	globex    string
	chQueries *[]string
}

func newRestrictedCloudFixture(t *testing.T) *restrictedCloudFixture {
	t.Helper()
	dir := t.TempDir()
	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}

	queries := cloudPolicyCH(t, map[string][]chPolicyRow{
		// The billed costs. Both tenants have a bill; only acme's must vanish.
		"netops.cloud_costs": {
			{"tenant_id": acme.ID, "day": "2026-09-09", "provider": "aws",
				"account": acmeAccountID, "service": acmeCostService,
				"amount": 48211.57, "currency": "USD"},
			{"tenant_id": globex.ID, "day": "2026-09-09", "provider": "azure",
				"account": "sub-globex", "service": "Virtual Machines",
				"amount": 902.10, "currency": "USD"},
		},
		// The observed flow pairs behind the service map.
		"netops.corr_signals": {
			{"tenant_id": acme.ID, "src": acmePrivateIP, "dst": "10.50.9.9",
				"bytes": 987654321.0, "obs": 12, "providers": []string{"aws"}},
			{"tenant_id": globex.ID, "src": "10.60.1.10", "dst": "10.60.9.9",
				"bytes": 4242.0, "obs": 3, "providers": []string{"azure"}},
		},
	})

	s := &server{
		discovery: discovery.NewDiscoveryAggregator(),
		roles:     roles,
		tenants:   ts,
		cloud:     cloud.NewMemStore(),
	}
	s.governance = newTenantGovernanceStore(filepath.Join(dir, "governance.json"))
	s.cloudApp = newCloudAppResolver(s.cloud)
	s.cloudConn = cloudconn.NewMemStore()
	mustCreateConnector(t, s, acme.ID, acmeConnectorID, "Acme billing", acmeAccountID, "Acme Production Account")
	mustCreateConnector(t, s, globex.ID, "ccn_globex01", "Globex billing", "sub-globex", "Globex Production Sub")

	seed := func(tenant, resourceID, name, account, ip, app string) {
		if err := s.cloud.ReplaceInventory(context.Background(), tenant, []cloud.CloudResource{{
			Provider: cloud.AWS, AccountID: account, Region: "us-east-1",
			ResourceID: resourceID, ResourceType: "ec2_instance", ResourceName: name,
			PrivateIPs: []string{ip}, AppID: app, AppName: app, Confidence: cloud.Confirmed,
		}}, []cloud.CloudIdentityMapping{{
			MatchKeyType: cloud.MatchPrivateIP, MatchKey: ip, AppID: app, AppName: app,
			Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed,
		}}); err != nil {
			t.Fatalf("seed %s inventory: %v", tenant, err)
		}
	}
	seed(acme.ID, acmeResourceID, acmeResName, acmeAccountID, acmePrivateIP, "acme-payments")
	seed(globex.ID, "i-0globex01", "globex-shop-api", "sub-globex", "10.60.1.10", "globex-shop")

	return &restrictedCloudFixture{t: t, s: s, acme: acme.ID, globex: globex.ID, chQueries: queries}
}

// get runs one cloud read and returns the status and the raw body — a leak test
// must be able to grep bytes, not only decoded fields.
func (f *restrictedCloudFixture) get(path string, claims jwtClaims) (int, string) {
	f.t.Helper()
	w := httptest.NewRecorder()
	r := req(http.MethodGet, path, "", claims)
	switch {
	case path == "/api/cloud/costs":
		f.s.handleCloudCosts(w, r)
	case path == "/api/cloud/resources":
		f.s.handleCloudResources(w, r)
	case path == "/api/cloud/identity-map":
		f.s.handleCloudIdentityMap(w, r)
	case path == "/api/cloud/apps":
		f.s.handleCloudApps(w, r)
	case path == "/api/cloud/service-map":
		f.s.handleCloudServiceMap(w, r)
	case path == "/api/cloud/connectors":
		f.s.handleCloudConnectors(w, r)
	case strings.HasPrefix(path, "/api/cloud/connectors/"):
		f.s.handleCloudConnectorByID(w, r)
	case strings.HasPrefix(path, "/api/cloud/resources/"):
		f.s.handleCloudResourceByID(w, r)
	default:
		f.t.Fatalf("no handler wired for %s", path)
	}
	return w.Code, w.Body.String()
}

// cloudReadPaths are the surfaces this test drives. Each one either reads the
// inventory store, ClickHouse, or both.
var cloudReadPaths = []string{
	"/api/cloud/costs",
	"/api/cloud/resources",
	"/api/cloud/identity-map",
	"/api/cloud/apps",
	"/api/cloud/service-map",
	"/api/cloud/connectors",
}

// TestCloudPlaneHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test.
// Both halves: the platform owner's Global view, and the owner scoped into the
// restricted tenant with ?as_tenant.
func TestCloudPlaneHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedCloudFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// Baseline: before anything is restricted the owner reads acme's estate AND
	// its bill, so this test cannot pass by serving nothing.
	if _, body := f.get("/api/cloud/costs", owner); !strings.Contains(body, acmeAccountID) ||
		!strings.Contains(body, acmeCostAmount) {
		t.Fatalf("baseline: the owner's Global cost view does not carry acme's bill: %s", body)
	}
	if _, body := f.get("/api/cloud/resources", owner); !strings.Contains(body, acmeResourceID) {
		t.Fatalf("baseline: the owner's Global inventory does not carry acme's resource: %s", body)
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the Global view. Acme is gone from every cloud surface; globex
	// is intact, so the fix is a filter and not a blanket.
	*f.chQueries = nil
	for _, path := range cloudReadPaths {
		st, body := f.get(path, owner)
		if st != http.StatusOK {
			t.Fatalf("GET %s (owner) = %d: %s", path, st, body)
		}
		for _, leak := range []string{
			acmeAccountID,             // the billed account id
			acmeCostAmount,            // the cost figure itself
			acmeCostService,           // what the spend was on
			acmeResourceID,            // the resource id
			acmeResName,               // the resource name
			acmePrivateIP,             // the address it answers on
			"acme-payments",           // the application it serves
			"Acme Production Account", // the onboarded account's display name
		} {
			if strings.Contains(body, leak) {
				t.Errorf("RESTRICTION LEAK: %s returned acme's %q to the platform owner: %s", path, leak, body)
			}
		}
	}
	// Globex keeps its own on the two surfaces that name it.
	if _, body := f.get("/api/cloud/costs", owner); !strings.Contains(body, "sub-globex") || !strings.Contains(body, "902.1") {
		t.Errorf("restricting acme also hid globex's bill: %s", body)
	}
	if _, body := f.get("/api/cloud/resources", owner); !strings.Contains(body, "i-0globex01") {
		t.Errorf("restricting acme also hid globex's inventory: %s", body)
	}

	// Every ClickHouse read in the Global view carries the exclusion, naming the
	// restricted tenant's OPAQUE id — the row policies cannot express this,
	// because '__all__' unlocks every tenant by design.
	if len(*f.chQueries) == 0 {
		t.Fatal("the Global view issued no ClickHouse read at all")
	}
	for _, sql := range *f.chQueries {
		if !strings.Contains(sql, "tenant_id NOT IN ('"+f.acme+"')") {
			t.Errorf("RESTRICTION LEAK: a Global cloud read does not exclude the restricted tenant.\nSQL: %s", sql)
		}
		if strings.Contains(sql, f.globex) {
			t.Errorf("a Global cloud read excluded globex, which is not restricted.\nSQL: %s", sql)
		}
	}

	// ── half 2: ?as_tenant into the restricted tenant. Nothing, on every
	// surface, and every ClickHouse read runs at a scope no row carries.
	scoped := ownerActing(owner, f.acme)
	*f.chQueries = nil
	for _, path := range cloudReadPaths {
		st, body := f.get(path, scoped)
		if st != http.StatusOK {
			t.Fatalf("GET %s (owner→acme) = %d: %s", path, st, body)
		}
		for _, leak := range []string{acmeAccountID, acmeCostAmount, acmeResourceID, acmeResName, acmePrivateIP} {
			if strings.Contains(body, leak) {
				t.Errorf("RESTRICTION LEAK: %s returned acme's %q to the owner scoped into acme: %s", path, leak, body)
			}
		}
	}
	for _, sql := range *f.chQueries {
		if !strings.Contains(sql, "tenant_scope = '"+cloudDeniedCHScope+"'") {
			t.Errorf("RESTRICTION LEAK: an owner→acme cloud read did not run at the denied scope.\nSQL: %s", sql)
		}
	}

	// A connector BY ID is a 404 in both halves, for the same reason.
	for name, claims := range map[string]jwtClaims{"Global": owner, "owner→acme": scoped} {
		st, body := f.get("/api/cloud/connectors/"+acmeConnectorID, claims)
		if st != http.StatusNotFound {
			t.Errorf("RESTRICTION LEAK: %s GET acme's connector by id = %d, want 404: %s", name, st, body)
		}
		if strings.Contains(body, acmeAccountID) {
			t.Errorf("RESTRICTION LEAK: %s connector-by-id body names acme's account %q: %s", name, acmeAccountID, body)
		}
	}

	// A resource BY ID is a 404 in both halves — the same answer an id that does
	// not exist gets, so the operator never learns acme has one (§3a.1).
	for name, claims := range map[string]jwtClaims{"Global": owner, "owner→acme": scoped} {
		st, body := f.get("/api/cloud/resources/"+acmeResourceID, claims)
		if st != http.StatusNotFound {
			t.Errorf("RESTRICTION LEAK: %s GET acme's resource by id = %d, want 404: %s", name, st, body)
		}
		if strings.Contains(body, acmeResName) {
			t.Errorf("RESTRICTION LEAK: %s resource-by-id body names acme's %q: %s", name, acmeResName, body)
		}
	}

	// The owner scoped into the UNRESTRICTED tenant still reads it, bill included.
	if _, body := f.get("/api/cloud/costs", ownerActing(owner, f.globex)); !strings.Contains(body, "sub-globex") {
		t.Errorf("owner→globex lost globex's own bill: %s", body)
	}

	// And acme's OWN user is never restricted from acme's own estate — the switch
	// hides a tenant from the PLATFORM, never from itself.
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleSuperAdmin, Tenant: f.acme}
	if _, body := f.get("/api/cloud/costs", acmeUser); !strings.Contains(body, acmeAccountID) ||
		!strings.Contains(body, acmeCostAmount) {
		t.Fatalf("acme's own user lost its own bill: %s", body)
	}
	st, body := f.get("/api/cloud/resources/"+acmeResourceID, acmeUser)
	if st != http.StatusOK || !strings.Contains(body, acmeResName) {
		t.Fatalf("acme's own user lost its own resource: %d %s", st, body)
	}
	if st, body = f.get("/api/cloud/connectors/"+acmeConnectorID, acmeUser); st != http.StatusOK ||
		!strings.Contains(body, acmeAccountID) {
		t.Fatalf("acme's own user lost its own connector: %d %s", st, body)
	}
}

// ── every remaining ClickHouse read on the plane ────────────────────────────

// cloudSignalSurfaces are the rest of the cloud plane's ClickHouse reads. The
// test above proves the rule by BYTES on the surfaces whose rows it seeds; this
// one proves it reaches every remaining read, including the second-tier ones a
// handler only issues once it has picked some objects.
var cloudSignalSurfaces = []struct {
	name string
	path string
	call func(*server, http.ResponseWriter, *http.Request)
}{
	{"health", "/api/cloud/health", (*server).handleCloudHealth},
	{"changes", "/api/cloud/changes", (*server).handleCloudChanges},
	{"evidence", "/api/cloud/evidence", (*server).handleCloudEvidence},
	{"security", "/api/cloud/security", (*server).handleCloudSecurity},
	{"provider events", "/api/cloud/provider-events", (*server).handleCloudProviderEvents},
	{"seam telemetry", "/api/cloud/seam-telemetry", (*server).handleCloudSeamTelemetry},
	{"network overview", "/api/cloud/network/overview", (*server).handleCloudNetworkOverview},
	{"ingestion", "/api/cloud/ingestion", (*server).handleCloudIngestion},
	{"app rca", "/api/cloud/app-rca?app=acme-payments", (*server).handleCloudAppRca},
	{"investigation changes",
		"/api/cloud/investigations/11111111-2222-3333-4444-555555555555/changes",
		(*server).handleCloudInvestigationChanges},
}

// TestCloudSignalSurfacesCarryTheOperatorVisibilityRestriction walks the rest of
// the plane and pins the two things the restriction has to do to a ClickHouse
// read: exclude the restricted tenant by tenant_id in the operator's Global view
// (the row policies cannot, because '__all__' unlocks everything by design), and
// run at a scope no row carries when the operator has scoped INTO that tenant.
func TestCloudSignalSurfacesCarryTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedCloudFixture(t)
	// Seed the object + archive tables so the SECOND-TIER reads fire: the
	// evidence ledger's signal join and its total count, and the overview's
	// evidence-handle read, only run once a first read has picked some ids.
	*f.chQueries = nil
	queries := cloudPolicyCH(t, map[string][]chPolicyRow{
		"netops.corr_current": {
			{"tenant_id": f.acme, "cid": "11111111-2222-3333-4444-555555555555",
				"state_s": "open", "window_start_s": "2026-09-09T00:00:00Z",
				"top_hypothesis": "acme payments path degraded", "affected": `{"apps":["acme-payments"],"cloud_resources":["` + acmeResourceID + `"]}`},
		},
		"netops.corr_signals_archive": {
			{"tenant_id": f.acme, "cid": "11111111-2222-3333-4444-555555555555",
				"signal_id_s": "sig-acme-1", "kind": "cloud_change", "entity_id": acmeResourceID,
				"ts_s": "2026-09-09T00:05:00Z", "attrs": `{"resource_id":"` + acmeResourceID + `"}`},
		},
	})

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	run := func(claims jwtClaims, name, path string, call func(*server, http.ResponseWriter, *http.Request)) []string {
		t.Helper()
		*queries = nil
		w := httptest.NewRecorder()
		call(f.s, w, req(http.MethodGet, path, "", claims))
		if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
			t.Fatalf("%s: GET %s = %d (%s)", name, path, w.Code, w.Body.String())
		}
		if len(*queries) == 0 {
			t.Fatalf("%s: issued no ClickHouse read, so this surface proves nothing", name)
		}
		out := make([]string, len(*queries))
		copy(out, *queries)
		return out
	}

	// ── half 1: the Global view excludes the restricted tenant, by opaque id.
	for _, tc := range cloudSignalSurfaces {
		for _, sql := range run(owner, tc.name, tc.path, tc.call) {
			if !strings.Contains(sql, "tenant_id NOT IN ('"+f.acme+"')") {
				t.Errorf("RESTRICTION LEAK: the %s read does not exclude the restricted tenant.\nSQL: %s", tc.name, sql)
			}
			if strings.Contains(sql, f.globex) {
				t.Errorf("the %s read excluded globex, which is not restricted.\nSQL: %s", tc.name, sql)
			}
		}
	}

	// ── half 2: ?as_tenant into the restricted tenant reads at a denied scope.
	scoped := ownerActing(owner, f.acme)
	for _, tc := range cloudSignalSurfaces {
		for _, sql := range run(scoped, tc.name, tc.path, tc.call) {
			if !strings.Contains(sql, "tenant_scope = '"+cloudDeniedCHScope+"'") {
				t.Errorf("RESTRICTION LEAK: the %s read did not run at the denied scope for owner→acme.\nSQL: %s", tc.name, sql)
			}
		}
	}

	// The owner scoped into the UNRESTRICTED tenant reads that tenant normally —
	// no denial, no exclusion.
	for _, tc := range cloudSignalSurfaces {
		for _, sql := range run(ownerActing(owner, f.globex), tc.name, tc.path, tc.call) {
			if !strings.Contains(sql, "tenant_scope = '"+f.globex+"'") {
				t.Errorf("owner→globex %s read did not run at globex's own scope.\nSQL: %s", tc.name, sql)
			}
			if strings.Contains(sql, "tenant_id NOT IN") {
				t.Errorf("owner→globex %s read carries an exclusion it should not.\nSQL: %s", tc.name, sql)
			}
		}
	}
}
