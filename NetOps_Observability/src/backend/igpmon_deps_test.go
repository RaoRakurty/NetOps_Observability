package backend

// igpmon_deps_test.go — the CLAUDE.md §3a rule-5 cross-org test for the OSPF /
// IS-IS monitoring subtree (internal/igpmon), exercised through the REAL
// wiring: the module is assembled by s.buildIGPMon() itself, so the gate under
// test is the production s.igpmonAuthz mapping, the device boundary is the
// production s.igpmonLookupDevice + igpmonCanSee pair, the ClickHouse scope is
// the production chTenantScope and the metrics filters are the production
// s.igpmonScopeFilters. A fixture that re-implemented any of those would prove
// nothing about the deployed surface.
//
// Only the two OUTBOUND stores are swapped for recorders — the module cannot
// reach ClickHouse or VictoriaMetrics in a unit test, and recording what was
// SENT is the point: an isolation property observable only through the response
// body is one that can silently rot.
//
// Proven here:
//   - tenant A cannot see tenant B's device: 404, byte-identical to the answer
//     for a device that does not exist (no existence oracle);
//   - a scoped principal's ClickHouse read carries ITS OWN tenant scope, and a
//     principal with no tenant reads nothing at all (the "__none__" sentinel
//     short-circuits before the DB is touched);
//   - every VictoriaMetrics read carries that tenant's device boundary as
//     extra_filters[], and a tenant with no visible device gets the
//     match-nothing sentinel rather than an unfiltered fleet read;
//   - ?as_tenant= into another org is ignored for a non-owner;
//   - the platform owner is the ONLY principal that reads cross-tenant, and a
//     tenant admin holding full administration:admin is NOT that principal;
//   - a read-only principal is admitted (these are reads) and an
//     unauthenticated one is refused before any store is touched.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/igpmon"
	"netops/backend/models"
)

// igpCall records one outbound store read.
type igpCall struct {
	scope   string
	sql     string
	query   string
	filters []string
}

// igpFixture is a server with two tenants' devices and a recording igpmon API
// built from the PRODUCTION Deps (only CHQuery/VMQuery are swapped).
type igpFixture struct {
	s   *server
	api *igpmon.API
	ch  []igpCall
	vm  []igpCall
}

func newIGPFixture(t *testing.T) *igpFixture {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "gx-edge", Address: "10.2.0.1", TenantID: "globex"})
	d.Upsert(models.Device{ID: "shared-dns", Name: "shared-dns", Address: "10.9.0.1"}) // platform-owned

	f := &igpFixture{s: &server{roles: roles, discovery: d}}

	// The production Deps, with ONLY the two stores replaced by recorders. Every
	// isolation-bearing collaborator (Authz, Scope, LookupDevice, CanSee,
	// ScopeFilters) is the deployed one.
	prod, err := f.s.buildIGPMon()
	if err != nil {
		t.Fatalf("buildIGPMon: %v", err)
	}
	if prod == nil {
		t.Fatal("buildIGPMon returned a nil API")
	}
	api, err := igpmon.New(igpmon.Deps{
		Now:          time.Now,
		Authz:        f.s.igpmonAuthz,
		LookupDevice: f.s.igpmonLookupDevice,
		CanSee:       igpmonCanSee,
		Scope:        chTenantScope,
		ScopeFilters: f.s.igpmonScopeFilters,
		CHQuery: func(_ context.Context, scope, sql string) ([]map[string]any, error) {
			f.ch = append(f.ch, igpCall{scope: scope, sql: sql})
			return nil, nil
		},
		VMQuery: func(_ context.Context, q string, filters []string) ([]igpmon.Sample, error) {
			f.vm = append(f.vm, igpCall{query: q, filters: append([]string(nil), filters...)})
			return nil, nil
		},
		Metrics:    igpmon.NewMetrics(),
		WriteJSON:  writeJSON,
		WriteError: writeError,
		LogWarn:    func(string, map[string]any) {},
	})
	if err != nil {
		t.Fatalf("igpmon.New: %v", err)
	}
	f.api = api
	return f
}

// get runs one request through the module's real dispatcher.
func (f *igpFixture) get(path string, claims jwtClaims) *httptest.ResponseRecorder {
	f.ch, f.vm = nil, nil
	w := httptest.NewRecorder()
	f.api.Handler()(w, req(http.MethodGet, path, "", claims))
	return w
}

// igpPaths is every route the subtree serves, with the ?device= the caller owns.
func igpPaths(device string) []string {
	var out []string
	for _, proto := range []string{"ospf", "isis"} {
		out = append(out,
			"/api/protocols/"+proto+"/adjacencies?device="+device,
			"/api/protocols/"+proto+"/summary",
			"/api/protocols/"+proto+"/health?device="+device,
		)
	}
	return out
}

// igpRoutes names all six registered routes LITERALLY. They are spelled out
// rather than composed so this file is the searchable proof, for the §3a
// route-isolation coverage guard and for a human, that every one of them was
// exercised cross-tenant here:
//
//	/api/protocols/ospf/adjacencies  /api/protocols/isis/adjacencies
//	/api/protocols/ospf/summary      /api/protocols/isis/summary
//	/api/protocols/ospf/health       /api/protocols/isis/health
var igpRoutes = []struct{ path, deviceParam string }{
	{"/api/protocols/ospf/adjacencies", "?device="},
	{"/api/protocols/ospf/summary", ""},
	{"/api/protocols/ospf/health", "?device="},
	{"/api/protocols/isis/adjacencies", "?device="},
	{"/api/protocols/isis/summary", ""},
	{"/api/protocols/isis/health", "?device="},
}

// TestIgpmonEveryRegisteredRouteIsOwnTenantOnly walks all six routes: the
// caller's own device answers, another org's device is a 404 indistinguishable
// from an absent one, and the ClickHouse read never leaves the caller's scope.
func TestIgpmonEveryRegisteredRouteIsOwnTenantOnly(t *testing.T) {
	f := newIGPFixture(t)
	for _, rt := range igpRoutes {
		own := rt.path
		if rt.deviceParam != "" {
			own += rt.deviceParam + "acme-core"
		}
		w := f.get(own, acme())
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s (own) = %d (%s)", own, w.Code, w.Body.String())
		}
		if len(f.ch) != 1 || f.ch[0].scope != "acme" {
			t.Errorf("GET %s did not read at the caller's tenant scope: %+v", own, f.ch)
		}
		if strings.Contains(w.Body.String(), "globex") || strings.Contains(w.Body.String(), "gx-edge") {
			t.Errorf("GET %s leaked another org's data: %s", own, w.Body.String())
		}
		if rt.deviceParam == "" {
			continue
		}
		foreign := f.get(rt.path+rt.deviceParam+"globex-core", acme())
		absent := f.get(rt.path+rt.deviceParam+"no-such-device", acme())
		if foreign.Code != http.StatusNotFound || absent.Code != http.StatusNotFound {
			t.Errorf("GET %s cross-tenant = %d, absent = %d, want 404/404", rt.path, foreign.Code, absent.Code)
		}
		if foreign.Body.String() != absent.Body.String() {
			t.Errorf("GET %s reveals existence: %q vs %q", rt.path, foreign.Body.String(), absent.Body.String())
		}
		// as_tenant into another org is ignored for a non-owner.
		if w := f.get(rt.path+rt.deviceParam+"globex-core&as_tenant=globex", acme()); w.Code != http.StatusNotFound {
			t.Errorf("GET %s with as_tenant into another org = %d, want 404", rt.path, w.Code)
		}
	}
}

// TestIgpmonForeignDeviceIsIndistinguishableFromAnAbsentOne — §3a rule 1.
func TestIgpmonForeignDeviceIsIndistinguishableFromAnAbsentOne(t *testing.T) {
	f := newIGPFixture(t)
	for _, proto := range []string{"ospf", "isis"} {
		for _, op := range []string{"adjacencies", "health"} {
			base := "/api/protocols/" + proto + "/" + op + "?device="

			own := f.get(base+"acme-core", acme())
			if own.Code != http.StatusOK {
				t.Fatalf("%s/%s own device = %d (%s)", proto, op, own.Code, own.Body.String())
			}

			foreign := f.get(base+"globex-core", acme())
			foreignBody := foreign.Body.String()
			foreignStores := len(f.ch) + len(f.vm)

			absent := f.get(base+"no-such-device", acme())
			absentBody := absent.Body.String()

			if foreign.Code != http.StatusNotFound || absent.Code != http.StatusNotFound {
				t.Fatalf("%s/%s foreign=%d absent=%d, want 404/404", proto, op, foreign.Code, absent.Code)
			}
			if foreignBody != absentBody {
				t.Errorf("%s/%s EXISTENCE ORACLE: foreign %q != absent %q", proto, op, foreignBody, absentBody)
			}
			if strings.Contains(foreignBody, "globex") || strings.Contains(foreignBody, "gx-edge") {
				t.Errorf("%s/%s leaked the foreign device: %s", proto, op, foreignBody)
			}
			if foreignStores != 0 {
				t.Errorf("%s/%s read a store for a device the caller cannot see", proto, op)
			}

			// The platform-owned (untagged) device is NOT a tenant's to read.
			shared := f.get(base+"shared-dns", acme())
			if shared.Code != http.StatusNotFound {
				t.Errorf("%s/%s tenant read a platform-owned device: %d", proto, op, shared.Code)
			}
			// …but the platform owner reads it, and globex's, cross-tenant.
			if w := f.get(base+"shared-dns", platformOwner()); w.Code != http.StatusOK {
				t.Errorf("%s/%s platform owner on the shared device = %d", proto, op, w.Code)
			}
			if w := f.get(base+"globex-core", platformOwner()); w.Code != http.StatusOK {
				t.Errorf("%s/%s platform owner cross-tenant = %d", proto, op, w.Code)
			}
			// A tenant ADMIN holding full administration:admin is still NOT the
			// platform owner (§3a rule 3).
			if w := f.get(base+"globex-core", tAdmin("acme")); w.Code != http.StatusNotFound {
				t.Errorf("%s/%s a tenant admin reached another tenant's device: %d", proto, op, w.Code)
			}
		}
	}
}

// TestIgpmonClickHouseReadCarriesTheCallersScopeOnly — §3a rule 4.
func TestIgpmonClickHouseReadCarriesTheCallersScopeOnly(t *testing.T) {
	f := newIGPFixture(t)
	cases := []struct {
		name   string
		claims jwtClaims
		device string
		scope  string
	}{
		{"acme", acme(), "acme-core", "acme"},
		{"globex", globex(), "globex-core", "globex"},
		{"platform owner", platformOwner(), "shared-dns", "__all__"},
	}
	for _, c := range cases {
		for _, p := range igpPaths(c.device) {
			w := f.get(p, c.claims)
			if w.Code != http.StatusOK {
				t.Fatalf("%s GET %s = %d (%s)", c.name, p, w.Code, w.Body.String())
			}
			if len(f.ch) != 1 {
				t.Fatalf("%s GET %s issued %d ClickHouse reads, want 1", c.name, p, len(f.ch))
			}
			if f.ch[0].scope != c.scope {
				t.Errorf("%s GET %s ClickHouse scope = %q, want %q", c.name, p, f.ch[0].scope, c.scope)
			}
			// The other tenant's id must never appear in the SQL.
			for _, foreign := range []string{"globex-core", "acme-core"} {
				if foreign != c.device && strings.Contains(f.ch[0].sql, "'"+foreign+"'") {
					t.Errorf("%s GET %s SQL carried a foreign device id: %s", c.name, p, f.ch[0].sql)
				}
			}
		}
	}
}

// TestIgpmonTenantlessPrincipalReadsNothing — the fail-closed sentinel. A
// principal with no tenant resolves to "__none__", which short-circuits BEFORE
// ClickHouse is touched.
func TestIgpmonTenantlessPrincipalReadsNothing(t *testing.T) {
	f := newIGPFixture(t)
	tenantless := jwtClaims{Sub: "nobody", Role: RoleOperator} // no Tenant
	for _, p := range []string{"/api/protocols/ospf/summary", "/api/protocols/isis/summary"} {
		w := f.get(p, tenantless)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", p, w.Code, w.Body.String())
		}
		if chTenantScope(req(http.MethodGet, p, "", tenantless)) != "__none__" {
			t.Fatalf("a tenantless principal did not resolve to the __none__ sentinel")
		}
		if len(f.ch) != 0 {
			t.Errorf("GET %s reached ClickHouse with a scope that admits nothing: %+v", p, f.ch)
		}
		// And its metrics reads are bounded by the match-nothing sentinel, never
		// unfiltered.
		for _, c := range f.vm {
			if len(c.filters) == 0 {
				t.Errorf("GET %s issued an UNFILTERED metrics read: %q", p, c.query)
			}
		}
	}
}

// TestIgpmonEveryMetricsReadCarriesTheTenantDeviceBoundary — §3a rule 4 for the
// time-series lane. A scoped principal ALWAYS carries at least one matcher; the
// unrestricted platform owner legitimately carries none.
func TestIgpmonEveryMetricsReadCarriesTheTenantDeviceBoundary(t *testing.T) {
	f := newIGPFixture(t)

	for _, p := range igpPaths("acme-core") {
		if w := f.get(p, acme()); w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", p, w.Code)
		}
		if len(f.vm) == 0 {
			t.Fatalf("GET %s issued no metrics read", p)
		}
		for _, c := range f.vm {
			joined := strings.Join(c.filters, " ")
			if joined == "" {
				t.Fatalf("GET %s issued an UNSCOPED metrics read: %q", p, c.query)
			}
			if !strings.Contains(joined, "acme-core") {
				t.Errorf("GET %s filters do not bound the read to acme's devices: %v", p, c.filters)
			}
			if strings.Contains(joined, "globex-core") || strings.Contains(joined, "gx-edge") {
				t.Errorf("GET %s filters admitted another tenant's device: %v", p, c.filters)
			}
		}
	}

	// A tenant with NO visible device gets the match-nothing sentinel, not an
	// unfiltered read.
	empty := jwtClaims{Sub: "u@nowhere", Role: RoleOperator, Tenant: "nowhere"}
	if w := f.get("/api/protocols/ospf/summary", empty); w.Code != http.StatusOK {
		t.Fatalf("empty-tenant summary = %d", w.Code)
	}
	if len(f.vm) == 0 {
		t.Fatal("empty-tenant summary issued no metrics read")
	}
	for _, c := range f.vm {
		if !strings.Contains(strings.Join(c.filters, " "), "__netops_no_visible_device__") {
			t.Errorf("a device-less tenant was not bounded by the match-nothing sentinel: %v", c.filters)
		}
	}

	// The unrestricted platform owner has nothing to restrict.
	if w := f.get("/api/protocols/ospf/summary", platformOwner()); w.Code != http.StatusOK {
		t.Fatalf("owner summary = %d", w.Code)
	}
	for _, c := range f.vm {
		if len(c.filters) != 0 {
			t.Errorf("the platform owner's read was restricted: %v", c.filters)
		}
	}
}

// TestIgpmonAsTenantIntoAnotherOrgIsIgnored — the switcher can only NARROW, and
// only for a principal that reaches the target.
func TestIgpmonAsTenantIntoAnotherOrgIsIgnored(t *testing.T) {
	f := newIGPFixture(t)

	// A non-owner's ?as_tenant= is not honoured by principalTenant, so the scope
	// stays its own and the foreign device stays a 404.
	w := f.get("/api/protocols/ospf/health?device=globex-core&as_tenant=globex", acme())
	if w.Code != http.StatusNotFound {
		t.Fatalf("acme with ?as_tenant=globex reached globex's device: %d (%s)", w.Code, w.Body.String())
	}
	w = f.get("/api/protocols/ospf/summary?as_tenant=globex", acme())
	if w.Code != http.StatusOK {
		t.Fatalf("acme summary = %d", w.Code)
	}
	if len(f.ch) != 1 || f.ch[0].scope != "acme" {
		t.Fatalf("?as_tenant= widened a non-owner's ClickHouse scope: %+v", f.ch)
	}
	for _, c := range f.vm {
		if strings.Contains(strings.Join(c.filters, " "), "globex-core") {
			t.Errorf("?as_tenant= widened a non-owner's metrics boundary: %v", c.filters)
		}
	}
}

// TestIgpmonGateIsRequirePermInfrastructureRead — the right gate, before any
// store is touched (§3a rule 3).
func TestIgpmonGateIsRequirePermInfrastructureRead(t *testing.T) {
	f := newIGPFixture(t)

	// Unauthenticated: 401, and nothing was read.
	w := httptest.NewRecorder()
	f.ch, f.vm = nil, nil
	f.api.Handler()(w, httptest.NewRequest(http.MethodGet, "/api/protocols/ospf/summary", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", w.Code)
	}
	if len(f.ch) != 0 || len(f.vm) != 0 {
		t.Fatal("an unauthenticated request reached a store")
	}

	// A read-only principal is admitted — every route here is a READ.
	if w := f.get("/api/protocols/isis/summary", tViewer("acme")); w.Code != http.StatusOK {
		t.Errorf("read-only principal = %d, want 200 (%s)", w.Code, w.Body.String())
	}

	// There is no write surface: every other method is refused.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		w := httptest.NewRecorder()
		f.api.Handler()(w, req(m, "/api/protocols/ospf/summary", "", tAdmin("acme")))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", m, w.Code)
		}
	}
}

// TestIgpmonProductionDepsAreComplete — buildIGPMon must produce a module that
// igpmon.New accepts, on a bare server. A missing collaborator is a 500-shaped
// wiring bug that this catches at build time instead of at 3am.
func TestIgpmonProductionDepsAreComplete(t *testing.T) {
	s := &server{}
	api, err := s.buildIGPMon()
	if err != nil {
		t.Fatalf("buildIGPMon on a bare server: %v", err)
	}
	if api == nil {
		t.Fatal("buildIGPMon returned nil without an error")
	}
	// With no inventory at all, a device lookup fails closed rather than panics.
	if _, ok := s.igpmonLookupDevice("anything"); ok {
		t.Error("a device resolved against an absent inventory")
	}
	// And an unmapped gate is refused rather than defaulted to read.
	w := httptest.NewRecorder()
	if _, ok := s.igpmonAuthz(w, req(http.MethodGet, "/x", "", platformOwner()), igpmon.Gate(99)); ok {
		t.Error("an unknown gate was authorized")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("unknown gate = %d, want 403", w.Code)
	}
}

// TestIgpmonCanSeeMatchesTheCentralDevicePolicy — igpmonCanSee must agree with
// canSeeDevice for every (device tenant, principal) pair, or the module's 404
// boundary would drift from the rest of the platform's.
func TestIgpmonCanSeeMatchesTheCentralDevicePolicy(t *testing.T) {
	devices := []models.Device{
		{ID: "a", TenantID: "acme"},
		{ID: "b", TenantID: "globex"},
		{ID: "c"}, // untagged / platform-owned
	}
	principals := []struct {
		tenant string
		cross  bool
	}{{"acme", false}, {"globex", false}, {"", false}, {TenantGlobal, true}}
	for _, d := range devices {
		for _, p := range principals {
			want := canSeeDevice(d, p.tenant, p.cross)
			got := igpmonCanSee(
				igpmon.Device{ID: d.ID, TenantID: deviceTenant(d)},
				igpmon.Principal{Tenant: p.tenant, Cross: p.cross},
			)
			if got != want {
				t.Errorf("device %q (tenant %q) / principal %q cross=%v: igpmonCanSee=%v, canSeeDevice=%v",
					d.ID, d.TenantID, p.tenant, p.cross, got, want)
			}
		}
	}
}

// TestIgpmonResponseNeverFabricatesAZero — the honesty contract, asserted at the
// wiring level: with both stores returning nothing, the live counts serialize as
// JSON null and the coverage block says so.
func TestIgpmonResponseNeverFabricatesAZero(t *testing.T) {
	f := newIGPFixture(t)
	w := f.get("/api/protocols/ospf/health?device=acme-core", acme())
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d (%s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	for _, k := range []string{"neighbor_count", "adjacencies_up", "adjacencies_down"} {
		if v, ok := body[k]; !ok || v != nil {
			t.Errorf("%s = %v, want null — an uncollected source must never render as 0", k, v)
		}
	}
	cov, _ := body["coverage"].(map[string]any)
	if cov == nil || cov["live_series"] != false || cov["lsdb"] != false {
		t.Errorf("coverage = %v, want live_series/lsdb false", body["coverage"])
	}
}
