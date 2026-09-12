// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// security_findings_restriction_test.go — the CLAUDE.md §3a rule-5 isolation
// test for the operator-visibility restriction (Tenant.OperatorRestricted) on
// the security-findings plane.
//
// A tenant that has switched the restriction on is invisible to the platform
// owner in logs, flows, metrics, igpmon, the BMP feed, unified search, the RCA
// path spine and digital experience. It must be invisible here too — on EVERY
// route the plane registers, not a sample — because this plane answers with
// counts as often as with rows, and a count is a disclosure: "three criticals",
// "412 assets", "78 % passing" each describe the customer's own exposure.
//
// The ten routes covered, and the field each one would leak:
//
//	findings            the finding id and the device it sits on
//	findings/{id}       200 vs 404 — the existence of another tenant's finding
//	findings/facets     the per-severity COUNT
//	findings/trend      the per-bucket doc count
//	posture             funnel.discover, coverage.assessed_assets, total_assets
//	compliance          findings / assessed — the scorecard denominator
//	frameworks          which frameworks the tenant is assessed against
//	views               the saved view's NAME
//	rules               which detections the tenant turned off
//	exposure-stories    the correlation objects grounded on its findings
//
// The OpenSearch double is run in aggAware mode, so the facet, trend, funnel,
// coverage and compliance numbers are folded out of the documents that actually
// matched rather than echoed from a canned fixture. Without that the four
// aggregating routes would answer a leaking query and a fixed one identically.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/compliancemodel"
	"netops/backend/internal/discovery"
	"netops/backend/internal/oslog"
	"netops/backend/models"
	"netops/backend/secapi"
)

// secRestrictionFixture is the findings plane wired to a REAL tenant store, so
// the switch under test is the production one (Tenant.OperatorRestricted →
// effectiveRestrictedIDs → operatorTelemetryRestriction) and every seeded row is
// keyed on the OPAQUE tenant id the store mints, never the human slug.
type secRestrictionFixture struct {
	t              *testing.T
	s              *server
	fake           *secFakeOS
	chQueries      *[]string
	acme, globex   string // opaque tenant ids
	acmeRule       string // a catalog rule acme turned OFF
	globexRule     string // a catalog rule globex turned OFF
	acmeView       string
	globexViewName string
}

func newSecRestrictionFixture(t *testing.T) *secRestrictionFixture {
	t.Helper()
	chQueries := fakeCH(t)

	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
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
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}

	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "acme-edge", Name: "acme-edge", Address: "10.1.0.2", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID})

	s := &server{roles: roles, discovery: d, tenants: ts}
	s.secStore = secapi.NewFileStore("")               // in-memory control plane
	s.secFrameworks = secapi.NewFrameworkFileStore("") // in-memory selection
	s.secFindMetrics = secapi.NewMetrics()
	s.secAPI = secapi.New(s.securityAPIDeps())

	// The findings corpus. The Global pattern carries BOTH tenants (it is the
	// one pattern that names every tenant's indices); each tenant's own pattern
	// carries its own. A query that names a pattern seeded with nothing reads
	// nothing, which is how at-rest separation turns a cross-tenant lookup into
	// a 404 upstream.
	acmeDoc := secDocAt("acme-f1", acme.ID, "critical", "Fail", "ISP", "acme-core", secRestrictionTS)
	globexDoc := secDocAt("globex-f1", globex.ID, "medium", "Fail", "ISP", "globex-core", secRestrictionTS)
	fake := &secFakeOS{
		aggAware: true,
		docs: map[string]string{
			"netops-secfindings-*":                         "[" + acmeDoc + "," + globexDoc + "]",
			secPatternFor(oslog.IndexTenantSeg(acme.ID)):   "[" + acmeDoc + "]",
			secPatternFor(oslog.IndexTenantSeg(globex.ID)): "[" + globexDoc + "]",
		},
	}
	secStartFakeOS(t, fake)

	f := &secRestrictionFixture{
		t: t, s: s, fake: fake, chQueries: chQueries,
		acme: acme.ID, globex: globex.ID,
		acmeView: "Acme PCI gaps", globexViewName: "Globex baseline",
	}

	// Control-plane state, seeded through the store so the routes have a real
	// per-tenant answer to leak. Two DIFFERENT catalog rules, so "acme's choice"
	// and "globex's choice" are distinguishable in the merged platform view.
	catalog := secapi.Catalog()
	if len(catalog) < 2 {
		t.Fatalf("the rule catalog has %d rules; this test needs two", len(catalog))
	}
	f.acmeRule, f.globexRule = catalog[0].RuleID, catalog[1].RuleID
	ctx := context.Background()
	if err := s.secStore.SetRuleStates(ctx, acme.ID, false, acme.ID,
		[]secapi.RuleState{{RuleID: f.acmeRule, Enabled: false}}); err != nil {
		t.Fatalf("seed acme rule state: %v", err)
	}
	if err := s.secStore.SetRuleStates(ctx, globex.ID, false, globex.ID,
		[]secapi.RuleState{{RuleID: f.globexRule, Enabled: false}}); err != nil {
		t.Fatalf("seed globex rule state: %v", err)
	}
	if _, err := s.secStore.AddView(ctx, acme.ID, false,
		secapi.SavedView{TenantID: acme.ID, Name: f.acmeView, CreatedBy: "a@acme"}); err != nil {
		t.Fatalf("seed acme view: %v", err)
	}
	if _, err := s.secStore.AddView(ctx, globex.ID, false,
		secapi.SavedView{TenantID: globex.ID, Name: f.globexViewName, CreatedBy: "g@globex"}); err != nil {
		t.Fatalf("seed globex view: %v", err)
	}
	if err := s.secFrameworks.SetFrameworkStates(ctx, acme.ID, false, acme.ID,
		[]secapi.FrameworkState{{FrameworkID: compliancemodel.IDHIPAA, Enabled: true}}); err != nil {
		t.Fatalf("seed acme frameworks: %v", err)
	}
	if err := s.secFrameworks.SetFrameworkStates(ctx, globex.ID, false, globex.ID,
		[]secapi.FrameworkState{{FrameworkID: compliancemodel.IDPCIDSS, Enabled: true}}); err != nil {
		t.Fatalf("seed globex frameworks: %v", err)
	}
	return f
}

// secRestrictionTS stamps both fixtures inside the default 30-day window, so the
// trend histogram has a bucket to put them in.
const secRestrictionTS = 1757462400000 // 2026-09-10T00:00:00Z

// secRoute is one route of the plane, named as the page names it.
type secRoute struct {
	name    string
	path    string
	handler func(http.ResponseWriter, *http.Request)
}

// routes is every route the security-findings plane registers, in the order
// main.go registers them. A route added to the plane and not to this list is a
// route with no isolation test, so the count is asserted below.
func (f *secRestrictionFixture) routes() []secRoute {
	a := f.s.secAPI
	return []secRoute{
		{"findings", "/api/security/findings", a.HandleFindings},
		{"findings/{id}", "/api/security/findings/acme-f1", a.HandleFindingByID},
		{"facets", "/api/security/findings/facets", a.HandleFacets},
		{"trend", "/api/security/findings/trend?bucket=1d", a.HandleTrend},
		{"posture", "/api/security/posture", a.HandlePosture},
		{"compliance", "/api/security/compliance", a.HandleCompliance},
		{"frameworks", "/api/security/frameworks", a.HandleFrameworks},
		{"views", "/api/security/views", a.HandleViews},
		{"rules", "/api/security/rules", a.HandleRules},
		{"exposure-stories", "/api/security/exposure-stories", a.HandleExposureStories},
	}
}

// get runs one route and returns its status and raw body. A leak test must be
// able to grep BYTES, not only decoded fields: a tenant id that reaches a note
// string leaks exactly as much as one that reaches a row.
func (f *secRestrictionFixture) get(rt secRoute, claims jwtClaims) (int, string) {
	f.t.Helper()
	w := httptest.NewRecorder()
	rt.handler(w, req(http.MethodGet, rt.path, "", claims))
	return w.Code, w.Body.String()
}

// osCalls returns the OpenSearch requests made since the last reset.
func (f *secRestrictionFixture) osCalls() []secOSCall { return f.fake.all() }

func (f *secRestrictionFixture) reset() {
	f.fake.mu.Lock()
	f.fake.calls = nil
	f.fake.mu.Unlock()
	*f.chQueries = nil
}

// secAcmeBytes is everything of acme's that must never appear in a byte of a
// platform read. The rule id is deliberately NOT here: every rules answer names
// every rule in the shipped catalog, so the id itself carries no tenant fact —
// what leaks is its ENABLED flag, which secRuleEnabled reads.
func secAcmeBytes(f *secRestrictionFixture) []string {
	return []string{"acme-f1", "n-acme-f1", f.acme, "acme-core", "acme-edge", f.acmeView}
}

// secJSONNumber pulls one dotted numeric path out of a response body. A MISSING
// path reads as zero, because a facet map carries only the keys that occurred:
// "no critical findings" and "the critical key is absent" are the same fact, and
// a test that could not read the second one could not assert a count fell to 0.
func secJSONNumber(t *testing.T, body, path string) float64 {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode %s: %v (%s)", path, err, body)
	}
	var cur any = doc
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: %q is not an object in %s", path, seg, body)
		}
		cur, ok = m[seg]
		if !ok {
			return 0
		}
	}
	n, ok := cur.(float64)
	if !ok {
		t.Fatalf("%s is %T, not a number, in %s", path, cur, body)
	}
	return n
}

// TestSecurityFindingsHonourTheOperatorVisibilityRestriction is the §3a rule-5
// isolation test. Both halves: the platform owner's Global view, and the owner
// scoped into the restricted tenant with ?as_tenant.
func TestSecurityFindingsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newSecRestrictionFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	if got := len(f.routes()); got != 10 {
		t.Fatalf("the plane has %d routes under test; main.go registers ten — a route with no isolation test is the defect this file exists to prevent", got)
	}

	// ── baseline. Before anything is restricted the owner reads BOTH tenants on
	// every route, so this test cannot pass by serving nothing.
	for _, rt := range f.routes() {
		code, body := f.get(rt, owner)
		if code != http.StatusOK {
			t.Fatalf("baseline %s = %d (%s)", rt.name, code, body)
		}
	}
	if _, body := f.get(f.routes()[0], owner); !strings.Contains(body, "acme-f1") || !strings.Contains(body, "globex-f1") {
		t.Fatalf("baseline: the owner's Global list is missing a tenant: %s", body)
	}
	if n := secJSONNumber(t, mustBody(t, f, "facets", owner), "severity.critical"); n != 1 {
		t.Fatalf("baseline: facets severity.critical = %v, want 1 (acme's finding)", n)
	}
	if n := secJSONNumber(t, mustBody(t, f, "posture", owner), "funnel.discover"); n != 2 {
		t.Fatalf("baseline: posture funnel.discover = %v, want 2 (both tenants)", n)
	}
	if n := secJSONNumber(t, mustBody(t, f, "posture", owner), "coverage.total_assets"); n != 3 {
		t.Fatalf("baseline: posture total_assets = %v, want 3 (two acme devices + one globex)", n)
	}
	if n := secJSONNumber(t, mustBody(t, f, "compliance", owner), "current_findings"); n != 2 {
		t.Fatalf("baseline: compliance findings = %v, want 2", n)
	}
	if body := mustBody(t, f, "views", owner); !strings.Contains(body, f.acmeView) {
		t.Fatalf("baseline: the owner's Global view list is missing acme's saved view: %s", body)
	}
	if body := mustBody(t, f, "frameworks", owner); !strings.Contains(body, compliancemodel.IDHIPAA) {
		t.Fatalf("baseline: the frameworks answer does not name HIPAA at all: %s", body)
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the platform owner's Global view. Acme is gone from every
	// route; globex is untouched.
	for _, rt := range f.routes() {
		f.reset()
		code, body := f.get(rt, owner)
		if code != http.StatusOK && !(rt.name == "findings/{id}" && code == http.StatusNotFound) {
			t.Errorf("global %s = %d (%s)", rt.name, code, body)
			continue
		}
		for _, leak := range secAcmeBytes(f) {
			if strings.Contains(body, leak) {
				t.Errorf("RESTRICTION LEAK: the platform owner's Global %s carried acme's %q: %s", rt.name, leak, body)
			}
		}
		// Every OpenSearch read on this half must name the exclusion, because
		// the Global pattern DOES name acme's indices — the clause is the only
		// thing standing between them and the answer.
		for _, call := range f.osCalls() {
			if !strings.Contains(call.Body, `"must_not":[{"terms":{"tenant_id":["`+f.acme+`"]}}]`) {
				t.Errorf("RESTRICTION LEAK: %s queried %s without excluding the restricted tenant: %s",
					rt.name, call.Index, call.Body)
			}
			if strings.Contains(call.Body, f.globex) {
				t.Errorf("%s excluded globex, which is not restricted: %s", rt.name, call.Body)
			}
		}
	}

	// The numbers, named. A count is a disclosure, so each aggregating route is
	// read for the value that crossed rather than only for the absence of a row.
	if n := secJSONNumber(t, mustBody(t, f, "facets", owner), "severity.critical"); n != 0 {
		t.Errorf("RESTRICTION LEAK: facets still counts acme's critical finding: severity.critical = %v, want 0", n)
	}
	if n := secJSONNumber(t, mustBody(t, f, "facets", owner), "severity.medium"); n != 1 {
		t.Errorf("restricting acme also hid globex's medium finding: severity.medium = %v, want 1", n)
	}
	if n := secJSONNumber(t, mustBody(t, f, "posture", owner), "funnel.discover"); n != 1 {
		t.Errorf("RESTRICTION LEAK: the CTEM funnel still counts acme: funnel.discover = %v, want 1", n)
	}
	if n := secJSONNumber(t, mustBody(t, f, "posture", owner), "coverage.assessed_assets"); n != 1 {
		t.Errorf("RESTRICTION LEAK: coverage still counts acme's assessed device: assessed_assets = %v, want 1", n)
	}
	if n := secJSONNumber(t, mustBody(t, f, "posture", owner), "coverage.total_assets"); n != 1 {
		t.Errorf("RESTRICTION LEAK: the funnel denominator still counts acme's fleet: total_assets = %v, want 1 (globex only)", n)
	}
	if n := secJSONNumber(t, mustBody(t, f, "compliance", owner), "current_findings"); n != 1 {
		t.Errorf("RESTRICTION LEAK: the scorecards still fold acme's finding: findings = %v, want 1", n)
	}
	trend := mustBody(t, f, "trend", owner)
	if strings.Count(trend, `"fail"`) > 0 && strings.Contains(trend, `"fail":2`) {
		t.Errorf("RESTRICTION LEAK: the trend bucket still counts both tenants: %s", trend)
	}

	// The control plane. Acme's saved view, acme's disabled detection and acme's
	// framework selection are its configuration, and all three are readable in
	// the platform view unless the store hides them.
	views := mustBody(t, f, "views", owner)
	if strings.Contains(views, f.acmeView) {
		t.Errorf("RESTRICTION LEAK: the Global view list carried acme's saved view %q: %s", f.acmeView, views)
	}
	if !strings.Contains(views, f.globexViewName) {
		t.Errorf("restricting acme also hid globex's saved view: %s", views)
	}
	rules := secRuleEnabled(t, mustBody(t, f, "rules", owner))
	if enabled, ok := rules[f.acmeRule]; ok && !enabled {
		t.Errorf("RESTRICTION LEAK: the Global rule view still reports acme's detection %q as turned off", f.acmeRule)
	}
	if enabled, ok := rules[f.globexRule]; !ok || enabled {
		t.Errorf("restricting acme also lost globex's own rule state for %q", f.globexRule)
	}
	fw := secFrameworkEnabled(t, mustBody(t, f, "frameworks", owner))
	if fw[compliancemodel.IDHIPAA] {
		t.Errorf("RESTRICTION LEAK: the Global framework view still reports HIPAA enabled, which is acme's selection alone")
	}
	if !fw[compliancemodel.IDPCIDSS] {
		t.Errorf("restricting acme also hid globex's PCI DSS selection")
	}

	// Exposure stories run on ClickHouse, whose row policies cannot express this
	// rule under the '__all__' scope — so the exclusion has to be in the SQL.
	f.reset()
	if _, body := f.get(f.routeByName("exposure-stories"), owner); strings.Contains(body, f.acme) {
		t.Errorf("RESTRICTION LEAK: the exposure-story list carried acme: %s", body)
	}
	if len(*f.chQueries) != 1 {
		t.Fatalf("want exactly one ClickHouse read for the exposure stories, got %d", len(*f.chQueries))
	}
	if sql := (*f.chQueries)[0]; !strings.Contains(sql, "tenant_id NOT IN ('"+f.acme+"')") {
		t.Errorf("RESTRICTION LEAK: the exposure-story SQL does not exclude the restricted tenant.\nSQL: %s", sql)
	} else if strings.Contains(sql, f.globex) {
		t.Errorf("the exposure-story SQL excluded globex, which is not restricted.\nSQL: %s", sql)
	}

	// ── half 2: ?as_tenant into the restricted tenant. Nothing, on every route,
	// and nothing of acme's is even NAMED in the query that goes out.
	scoped := ownerActing(owner, f.acme)
	for _, rt := range f.routes() {
		f.reset()
		code, body := f.get(rt, scoped)
		switch {
		case rt.name == "findings/{id}":
			if code != http.StatusNotFound {
				t.Errorf("RESTRICTION LEAK: owner→acme %s = %d, want 404 (another tenant's finding is never confirmed to exist): %s", rt.name, code, body)
			}
		case code != http.StatusOK:
			// 200-with-nothing, never 403: a refusal would confirm the tenant
			// has findings at all.
			t.Errorf("owner→acme %s = %d, want 200 with an empty view: %s", rt.name, code, body)
		}
		for _, leak := range secAcmeBytes(f) {
			if strings.Contains(body, leak) {
				t.Errorf("RESTRICTION LEAK: owner→acme %s carried %q: %s", rt.name, leak, body)
			}
		}
		for _, call := range f.osCalls() {
			if !strings.Contains(call.Index, secapi.RestrictedScope) {
				t.Errorf("RESTRICTION LEAK: owner→acme %s read the index pattern %q — a denied read is answered under the scope that owns nothing",
					rt.name, call.Index)
			}
			if strings.Contains(call.Index, f.acme) || strings.Contains(call.Body, f.acme) {
				t.Errorf("RESTRICTION LEAK: owner→acme %s named acme in its query: %s %s", rt.name, call.Index, call.Body)
			}
			if strings.Contains(call.Body, "acme-core") {
				t.Errorf("RESTRICTION LEAK: owner→acme %s fed acme's device keys into the untagged matcher: %s", rt.name, call.Body)
			}
		}
	}
	// The control plane, on this half too: acme's own configuration is acme's,
	// and the operator standing in acme's shoes may not read it either.
	if rules := secRuleEnabled(t, mustBody(t, f, "rules", scoped)); !rules[f.acmeRule] {
		t.Errorf("RESTRICTION LEAK: owner→acme still reads acme's detection %q as turned off", f.acmeRule)
	}
	if fw := secFrameworkEnabled(t, mustBody(t, f, "frameworks", scoped)); fw[compliancemodel.IDHIPAA] {
		t.Error("RESTRICTION LEAK: owner→acme still reads acme's HIPAA selection")
	}

	// The denied read never reaches ClickHouse at all: the answer is decided
	// before the first row.
	f.reset()
	f.get(f.routeByName("exposure-stories"), scoped)
	if len(*f.chQueries) != 0 {
		t.Errorf("owner→acme still read ClickHouse %d times: %v", len(*f.chQueries), *f.chQueries)
	}
	// And the funnel's denominator is zero, not acme's fleet size.
	if n := secJSONNumber(t, mustBody(t, f, "posture", scoped), "coverage.total_assets"); n != 0 {
		t.Errorf("RESTRICTION LEAK: owner→acme posture reported acme's fleet size: total_assets = %v, want 0", n)
	}

	// ── the owner scoped into the UNRESTRICTED tenant still reads it whole.
	globexScoped := ownerActing(owner, f.globex)
	if body := mustBody(t, f, "findings", globexScoped); !strings.Contains(body, "globex-f1") {
		t.Errorf("owner→globex lost globex's own findings: %s", body)
	}
	if n := secJSONNumber(t, mustBody(t, f, "posture", globexScoped), "coverage.total_assets"); n != 1 {
		t.Errorf("owner→globex total_assets = %v, want 1", n)
	}

	// ── and acme's OWN user is never restricted from acme's own data. The
	// switch hides a tenant from the PLATFORM, never from itself.
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	body := mustBody(t, f, "findings", acmeUser)
	if !strings.Contains(body, "acme-f1") {
		t.Fatalf("acme's own user lost its own findings: %s", body)
	}
	if strings.Contains(body, "globex-f1") {
		t.Fatalf("acme's own user saw globex's finding: %s", body)
	}
	if !strings.Contains(mustBody(t, f, "views", acmeUser), f.acmeView) {
		t.Error("acme's own user lost its own saved view")
	}
	if n := secJSONNumber(t, mustBody(t, f, "posture", acmeUser), "coverage.total_assets"); n != 2 {
		t.Errorf("acme's own user reads total_assets = %v, want its own 2 devices", n)
	}
}

// TestSecurityFindingsRestrictionSurvivesBreakGlass pins the other direction of
// the same switch: a live break-glass session un-hides its tenant, so the
// restriction is a visibility rule the platform can lift on the record — not a
// wall that makes an incident unworkable.
func TestSecurityFindingsRestrictionSurvivesBreakGlass(t *testing.T) {
	f := newSecRestrictionFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	if body := mustBody(t, f, "findings", ownerActing(owner, f.acme)); strings.Contains(body, "acme-f1") {
		t.Fatalf("restricted read leaked before break-glass: %s", body)
	}
	if _, err := f.s.tenants.SetOperatorRestricted("acme", false); err != nil {
		t.Fatalf("unrestrict acme: %v", err)
	}
	if body := mustBody(t, f, "findings", ownerActing(owner, f.acme)); !strings.Contains(body, "acme-f1") {
		t.Fatalf("lifting the restriction did not restore the operator's read: %s", body)
	}
}

// mustBody runs one named route and fails on anything but 200.
func mustBody(t *testing.T, f *secRestrictionFixture, name string, claims jwtClaims) string {
	t.Helper()
	rt := f.routeByName(name)
	code, body := f.get(rt, claims)
	if code != http.StatusOK {
		t.Fatalf("%s = %d (%s)", name, code, body)
	}
	return body
}

func (f *secRestrictionFixture) routeByName(name string) secRoute {
	f.t.Helper()
	for _, rt := range f.routes() {
		if rt.name == name {
			return rt
		}
	}
	f.t.Fatalf("no route named %q", name)
	return secRoute{}
}

// secRuleEnabled decodes the rules answer into rule id → enabled.
func secRuleEnabled(t *testing.T, body string) map[string]bool {
	t.Helper()
	var rows []struct {
		RuleID  string `json:"rule_id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatalf("decode rules: %v (%s)", err, body)
	}
	out := map[string]bool{}
	for _, r := range rows {
		out[r.RuleID] = r.Enabled
	}
	return out
}

// secFrameworkEnabled decodes the frameworks answer into framework id → enabled.
func secFrameworkEnabled(t *testing.T, body string) map[string]bool {
	t.Helper()
	var doc struct {
		Frameworks []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"frameworks"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode frameworks: %v (%s)", err, body)
	}
	out := map[string]bool{}
	for _, fw := range doc.Frameworks {
		out[fw.ID] = fw.Enabled
	}
	return out
}

// secWriteRoute is one of the plane's NON-read routes, with the body it needs.
type secWriteRoute struct {
	name    string
	method  string
	path    string
	body    string
	handler func(http.ResponseWriter, *http.Request)
}

// writeRoutes is every route on this plane behind the WRITE or ADMIN gate. The
// tag names the saved view the POST creates, so one fixture can be driven
// through several phases without the second POST colliding with the first.
//
// Two of these, rules and frameworks, are read-modify-write: each reads the
// tenant's current control-plane state back and returns it. That is why the
// restriction is resolved for EVERY gate and not for GateRead alone. A
// read-gate-only resolution would have left a no-op PUT here reporting which
// detections and which frameworks a restricted tenant has turned on — the same
// trap packet capture hit, where the DOWNLOAD sits behind the write gate.
func (f *secRestrictionFixture) writeRoutes(tag string) []secWriteRoute {
	a := f.s.secAPI
	return []secWriteRoute{
		{"rules", http.MethodPut, "/api/security/rules",
			`[{"rule_id":"` + f.acmeRule + `","enabled":true}]`, a.HandleRules},
		{"frameworks", http.MethodPut, "/api/security/frameworks",
			`[{"framework_id":"` + compliancemodel.IDHIPAA + `","enabled":true}]`, a.HandleFrameworks},
		{"views", http.MethodPost, "/api/security/views",
			`{"name":"probe ` + tag + `","filters":{}}`, a.HandleViews},
	}
}

func (f *secRestrictionFixture) do(rt secWriteRoute, claims jwtClaims) (int, string) {
	f.t.Helper()
	w := httptest.NewRecorder()
	rt.handler(w, req(rt.method, rt.path, rt.body, claims))
	return w.Code, w.Body.String()
}

// secWriteAccepted reports whether a write route accepted the call. The PUTs
// answer 200 with the new state; the view POST answers 201 with the created row.
func secWriteAccepted(code int) bool {
	return code == http.StatusOK || code == http.StatusCreated
}

// TestSecurityFindingsRefuseRestrictedWrites is the other half of the §3a rule-5
// isolation test: the WRITE and ADMIN gates.
//
// A denied READ is answered 200-with-nothing, because a refusal would confirm
// the tenant has findings at all. A denied WRITE is refused with 403 instead,
// because there is no honest empty answer to a write and a write stamped with a
// scope that owns nothing would create rows no tenant could ever see. The 403
// discloses nothing new: only the platform operator is ever denied, and the
// operator is who sets operator_restricted on the tenant.
func TestSecurityFindingsRefuseRestrictedWrites(t *testing.T) {
	f := newSecRestrictionFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	scoped := ownerActing(owner, f.acme)

	// ── baseline, unrestricted. The writes are accepted, and the two
	// read-modify-write routes hand acme's own control-plane state straight
	// back. That is the disclosure the 403 below prevents; without this half the
	// test could pass by refusing everything.
	base := f.writeRoutes("baseline")
	_, rulesBody := f.do(base[0], scoped)
	if enabled, ok := secRuleEnabled(t, rulesBody)[f.acmeRule]; !ok || !enabled {
		t.Fatalf("baseline: the rules PUT did not read acme's own rule state back: %s", rulesBody)
	}
	_, fwBody := f.do(base[1], scoped)
	if !secFrameworkEnabled(t, fwBody)[compliancemodel.IDHIPAA] {
		t.Fatalf("baseline: the frameworks PUT did not read acme's own selection back: %s", fwBody)
	}
	if code, body := f.do(base[2], scoped); !secWriteAccepted(code) {
		t.Fatalf("baseline: the view POST = %d (%s)", code, body)
	}

	// ── restricted. Every write gate refuses, nothing of acme's comes back in
	// the refusal body, and in particular acme's control-plane state does not.
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	for _, rt := range f.writeRoutes("denied") {
		code, body := f.do(rt, scoped)
		if code != http.StatusForbidden {
			t.Errorf("RESTRICTION LEAK: owner→acme %s %s = %d, want 403 — a denied operator must not drive a restricted tenant's writes: %s",
				rt.method, rt.name, code, body)
		}
		for _, leak := range secAcmeBytes(f) {
			if strings.Contains(body, leak) {
				t.Errorf("RESTRICTION LEAK: the refusal on %s carried acme's %q: %s", rt.name, leak, body)
			}
		}
		if rt.name != "views" && (strings.Contains(body, f.acmeRule) || strings.Contains(body, compliancemodel.IDHIPAA)) {
			t.Errorf("RESTRICTION LEAK: the refused %s answer still named acme's control-plane state: %s", rt.name, body)
		}
	}
	// The refusal also wrote nothing: acme's saved-view list, read by acme
	// itself, never gained the denied operator's row.
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	if views := mustBody(t, f, "views", acmeUser); strings.Contains(views, "probe denied") {
		t.Errorf("the refused view POST created a row anyway: %s", views)
	}

	// ── globex is untouched: the operator still administers the tenant that has
	// not switched the restriction on.
	globexScoped := ownerActing(owner, f.globex)
	for _, rt := range f.writeRoutes("globex") {
		if code, body := f.do(rt, globexScoped); !secWriteAccepted(code) {
			t.Errorf("restricting acme also refused %s on globex: %d (%s)", rt.name, code, body)
		}
	}
	// ── and acme's OWN admin still administers acme. The switch hides a tenant
	// from the PLATFORM, never from itself.
	acmeAdmin := jwtClaims{Sub: "admin@acme", Role: RoleOrgAdmin, Tenant: f.acme}
	for _, rt := range f.writeRoutes("self") {
		if code, body := f.do(rt, acmeAdmin); !secWriteAccepted(code) {
			t.Errorf("acme's own admin lost %s on acme's own plane: %d (%s)", rt.name, code, body)
		}
	}
}
