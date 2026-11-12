// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/alerts"
	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/parsercov"
	"netops/backend/secapi"
)

// Tracker 370 — a tenant claimed another owner's UNTAGGED telemetry through a
// colliding device name or address. These are the cross-org tests the row asks
// for: two tenants (and the platform) that share a device name and an address,
// asserted on what each store path actually puts on the wire — the OpenSearch
// filter (logs, export, AI log tool, secapi, parsercov), the ClickHouse clauses
// (flows, findings, tunnels, the AI tools) and the scheduled report.
//
// The fixture, by owner:
//
//	acme    acme-1  "core-rtr-1"  10.0.0.1   ← name AND address shared with globex
//	acme    acme-2  "acme-edge"   10.1.0.2   ← acme's alone
//	acme    acme-3  "pe-1"        10.1.0.3   ← short form of the platform's FQDN
//	globex  glx-1   "core-rtr-1"  10.0.0.1   ← name AND address shared with acme
//	globex  glx-2   "globex-edge" 10.2.0.2   ← globex's alone
//	""      plat-1  "pe-1.lab.local" 192.168.1.1 (platform)
//	""      plat-2  "GLOBEX-EDGE-MGMT" 10.2.0.2 ← platform polls globex's edge address
const (
	sharedName = "core-rtr-1"
	sharedAddr = "10.0.0.1"
)

func claimFixtureDevices() []models.Device {
	return []models.Device{
		{ID: "acme-1", Name: sharedName, Address: sharedAddr, TenantID: "acme"},
		{ID: "acme-2", Name: "acme-edge", Address: "10.1.0.2", TenantID: "acme"},
		{ID: "acme-3", Name: "pe-1", Address: "10.1.0.3", TenantID: "acme"},
		{ID: "glx-1", Name: sharedName, Address: sharedAddr, TenantID: "globex"},
		{ID: "glx-2", Name: "globex-edge", Address: "10.2.0.2", TenantID: "globex"},
		{ID: "plat-1", Name: "pe-1.lab.local", Address: "192.168.1.1"},
		{ID: "plat-2", Name: "GLOBEX-EDGE-MGMT", Address: "10.2.0.2"},
	}
}

func claimFixtureServer(t *testing.T) *server {
	t.Helper()
	s := aiCfgTestServer(t)
	d := discovery.NewDiscoveryAggregator()
	for _, dev := range claimFixtureDevices() {
		d.Upsert(dev)
	}
	// The premise: identity merging is per-tenant, so both core-rtr-1 records
	// survive as two owners' devices. Without that the test would prove nothing.
	n := 0
	for _, dev := range d.Devices() {
		if dev.Name == sharedName {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("fixture premise: want two owners' %q records in the registry, got %d", sharedName, n)
	}
	s.discovery = d
	return s
}

func acmeClaims() jwtClaims   { return jwtClaims{Sub: "a", Role: RoleOperator, Tenant: "acme"} }
func globexClaims() jwtClaims { return jwtClaims{Sub: "g", Role: RoleOperator, Tenant: "globex"} }

func setOf(vals []string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// ---- the rule -----------------------------------------------------------------

func TestUntaggedClaimDropsIdentitiesAnotherOwnerHolds(t *testing.T) {
	s := claimFixtureServer(t)

	a, cross := s.untaggedClaimFor(acmeClaims())
	if cross {
		t.Fatal("acme is scoped")
	}
	keys, addrs := setOf(a.Keys), setOf(a.Addrs)
	for _, leak := range []string{sharedName, "pe-1", "glx-1", "glx-2", "globex-edge", "plat-1", "pe-1.lab.local"} {
		if keys[leak] {
			t.Errorf("acme claims %q — held by another owner (or not acme's at all)", leak)
		}
	}
	for _, want := range []string{"acme-1", "acme-2", "acme-edge", "acme-3"} {
		if !keys[want] {
			t.Errorf("acme lost its unambiguous key %q (keys=%v)", want, a.Keys)
		}
	}
	if addrs[sharedAddr] {
		t.Errorf("acme claims the shared address %s", sharedAddr)
	}
	if !addrs["10.1.0.2"] || !addrs["10.1.0.3"] {
		t.Errorf("acme lost an unambiguous address: %v", a.Addrs)
	}
	if a.Devices != 3 {
		t.Errorf("acme sees %d devices, want 3 (ambiguous devices are still its devices)", a.Devices)
	}

	g, _ := s.untaggedClaimFor(globexClaims())
	gk, ga := setOf(g.Keys), setOf(g.Addrs)
	if gk[sharedName] || ga[sharedAddr] {
		t.Errorf("globex claims the shared identity: keys=%v addrs=%v", g.Keys, g.Addrs)
	}
	// globex-edge's address is also polled by the platform → ambiguous.
	if ga["10.2.0.2"] {
		t.Errorf("globex claims 10.2.0.2, which the platform also holds")
	}
	if !gk["globex-edge"] || !gk["glx-2"] {
		t.Errorf("globex lost its unambiguous keys: %v", g.Keys)
	}
}

func TestUntaggedClaimAsTenantIntoAnotherOrgIgnored(t *testing.T) {
	s := claimFixtureServer(t)
	c := acmeClaims()
	c.ActingTenant = "globex" // a non-owner's acting tenant is never trusted
	got, _ := s.untaggedClaimFor(c)
	if k := setOf(got.Keys); k["glx-2"] || k["globex-edge"] || !k["acme-edge"] {
		t.Fatalf("as_tenant into another org was honoured: %v", got.Keys)
	}
}

func TestUntaggedClaimCrossAndDefaultClosed(t *testing.T) {
	s := claimFixtureServer(t)
	if c, cross := s.untaggedClaimFor(jwtClaims{Sub: "root", Role: RoleSuperAdmin}); !cross || c.Keys != nil || c.Addrs != nil {
		t.Fatalf("platform owner: cross=%v claim=%+v, want cross with no narrowing", cross, c)
	}
	// No registry → no ownership index → nothing claimed.
	if c := (&server{}).untaggedClaimForTenant("acme"); c.Devices != 0 || c.Keys != nil || c.Addrs != nil {
		t.Fatalf("no registry must claim nothing: %+v", c)
	}
	// An unbound scope claims nothing, even though "" is the platform's row owner.
	if c := unambiguousClaim(claimFixtureDevices(), ""); c.Devices != 0 || len(c.Keys)+len(c.Addrs) != 0 {
		t.Fatalf("unbound scope must claim nothing: %+v", c)
	}
}

// The Provider scope owns the untagged rows by the owner rule, so a tenant
// listing the same router does not take the platform's own devices away from it.
func TestUntaggedClaimProviderKeepsItsOwnDevices(t *testing.T) {
	c := unambiguousClaim(claimFixtureDevices(), TenantGlobal)
	if k := setOf(c.Keys); !k["pe-1.lab.local"] || !k["GLOBEX-EDGE-MGMT"] || k["acme-edge"] || k[sharedName] {
		t.Fatalf("provider keys = %v", c.Keys)
	}
	if a := setOf(c.Addrs); !a["10.2.0.2"] || !a["192.168.1.1"] || a[sharedAddr] {
		t.Fatalf("provider addrs = %v", c.Addrs)
	}
}

func TestClaimIdentityFormsErrTowardsAmbiguous(t *testing.T) {
	devs := []models.Device{
		{ID: "a1", Name: "Core-RTR-9", Address: "::ffff:10.9.9.9", TenantID: "acme"},
		{ID: "g1", Name: "core-rtr-9", Address: "10.9.9.9", TenantID: "globex"},
		{ID: "a2", Name: "10.7.7.7", TenantID: "acme"},                   // named by its address
		{ID: "g2", Name: "g-x", Address: "10.7.7.7", TenantID: "globex"}, // that address, another owner
	}
	c := unambiguousClaim(devs, "acme")
	k, a := setOf(c.Keys), setOf(c.Addrs)
	if k["Core-RTR-9"] {
		t.Error("a name differing only in case from another owner's must be ambiguous")
	}
	if a["::ffff:10.9.9.9"] {
		t.Error("an IPv4-mapped spelling of another owner's address must be ambiguous")
	}
	if k["10.7.7.7"] {
		t.Error("a name equal to another owner's ADDRESS must be ambiguous (names and addresses share one namespace)")
	}
	if !k["a1"] || !k["a2"] {
		t.Errorf("unique ids must survive: %v", c.Keys)
	}
}

// ---- OpenSearch paths -----------------------------------------------------------

// filterTerms returns every value of every `terms` clause in an OpenSearch
// filter, by field.
func filterTerms(t *testing.T, f any) map[string][]string {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if terms, ok := x["terms"].(map[string]any); ok {
				for field, vals := range terms {
					if arr, ok := vals.([]any); ok {
						for _, e := range arr {
							if s, ok := e.(string); ok {
								out[field] = append(out[field], s)
							}
						}
					}
				}
			}
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	walk(generic)
	return out
}

func assertNoSharedIdentity(t *testing.T, where string, terms map[string][]string) {
	t.Helper()
	for field, vals := range terms {
		if field == "tenant_id" {
			continue
		}
		for _, v := range vals {
			if strings.EqualFold(v, sharedName) || v == sharedAddr || v == "pe-1" {
				t.Errorf("%s: field %q claims the ambiguous identity %q", where, field, v)
			}
		}
	}
}

func TestLogsScopeSharedIdentityClaimsNeitherTenant(t *testing.T) {
	s := claimFixtureServer(t)
	for _, c := range []jwtClaims{acmeClaims(), globexClaims()} {
		r := req(http.MethodGet, "/api/logs/search", "", c)
		_, filters, _, deny, forbidden := s.logsScope(r, "syslog")
		if deny || forbidden {
			t.Fatalf("%s: unexpected deny/forbidden", c.Tenant)
		}
		terms := filterTerms(t, filters)
		assertNoSharedIdentity(t, "logs/"+c.Tenant, terms)
		if len(terms["host"]) == 0 {
			t.Errorf("%s: its unambiguous keys must still claim its untagged documents: %v", c.Tenant, terms)
		}
	}
}

func TestLogExportSpecSharedIdentityClaimsNothing(t *testing.T) {
	s := claimFixtureServer(t)
	spec := s.exportSpecFor(acmeClaims(), "*", "", "", "syslog", "ndjson")
	for _, v := range append(append([]string{}, spec.DeviceKeys...), spec.DeviceAddrs...) {
		if v == sharedName || v == sharedAddr || v == "pe-1" {
			t.Fatalf("export spec froze the ambiguous identity %q", v)
		}
	}
	if !setOf(spec.DeviceKeys)["acme-edge"] {
		t.Fatalf("export lost acme's own key: %v", spec.DeviceKeys)
	}
}

func TestSecAPIAndParserCovPrincipalsClaimNoSharedIdentity(t *testing.T) {
	s := claimFixtureServer(t)
	check := func(where string, keys, addrs []string) {
		t.Helper()
		for _, v := range append(append([]string{}, keys...), addrs...) {
			if v == sharedName || v == sharedAddr || v == "pe-1" {
				t.Errorf("%s principal carries the ambiguous identity %q", where, v)
			}
		}
		if !setOf(keys)["acme-edge"] {
			t.Errorf("%s principal lost acme's own key: %v", where, keys)
		}
	}
	w := httptest.NewRecorder()
	sp, ok := s.securityAuthz(w, req(http.MethodGet, "/api/security/findings", "", acmeClaims()), secapi.GateRead)
	if !ok {
		t.Fatalf("securityAuthz refused: %d %s", w.Code, w.Body.String())
	}
	check("secapi", sp.DeviceKeys, sp.DeviceAddrs)

	w = httptest.NewRecorder()
	pp, ok := s.parserCovAuthz(w, req(http.MethodGet, "/api/parser-coverage", "", acmeClaims()), parsercov.GateRead)
	if !ok {
		t.Fatalf("parserCovAuthz refused: %d %s", w.Code, w.Body.String())
	}
	check("parsercov", pp.DeviceKeys, pp.DeviceAddrs)
}

// The AI log tool sends its filter to OpenSearch; capture what went on the wire.
func TestAISearchLogsSharedIdentityClaimsNothing(t *testing.T) {
	var body []byte
	osSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer osSrv.Close()
	t.Setenv("OPENSEARCH_URL", osSrv.URL)
	s := claimFixtureServer(t)
	d := aiDataSource{srv: s, ctx: context.Background(), scope: "acme", claims: acmeClaims()}
	if _, err := d.moduleSearchLogs(ai.Principal{Tenant: "acme"}, ai.ToolArgs{"query": "*"}); err != nil {
		t.Fatalf("moduleSearchLogs: %v", err)
	}
	var q any
	if err := json.Unmarshal(body, &q); err != nil {
		t.Fatalf("captured body: %v (%s)", err, body)
	}
	terms := filterTerms(t, q)
	assertNoSharedIdentity(t, "ai/search_logs", terms)
	if !setOf(terms["host"])["acme-edge"] {
		t.Errorf("AI log tool lost acme's own key: %v", terms)
	}
}

// ---- ClickHouse paths -----------------------------------------------------------

func assertCHClauseClaimsNoShared(t *testing.T, where, clause, tenant string) {
	t.Helper()
	for _, leak := range []string{"'" + sharedName + "'", "'" + sharedAddr + "'", "'pe-1'"} {
		if strings.Contains(clause, leak) {
			t.Errorf("%s: clause claims the ambiguous identity %s: %s", where, leak, clause)
		}
	}
	if !strings.Contains(clause, "tenant_id = '"+tenant+"'") {
		t.Errorf("%s: clause must keep the tenant's own stamped rows (tenant_id = '%s'): %s", where, tenant, clause)
	}
}

func TestCHClausesSharedIdentityClaimsNeitherTenant(t *testing.T) {
	s := claimFixtureServer(t)
	for _, c := range []jwtClaims{acmeClaims(), globexClaims()} {
		flow, empty := s.flowTenantClauseFor(c)
		if empty {
			t.Fatalf("%s has devices", c.Tenant)
		}
		assertCHClauseClaimsNoShared(t, "flows/"+c.Tenant, flow, c.Tenant)
		if !strings.HasPrefix(flow, " AND (") || !strings.HasSuffix(flow, ")") {
			t.Errorf("flow clause must be ONE parenthesised group: %q", flow)
		}

		app, _ := s.addrTenantClauseFor(c, "src_ip", "dst_ip")
		assertCHClauseClaimsNoShared(t, "app_identities/"+c.Tenant, app, c.Tenant)

		find, empty := s.deviceTenantCondFor(c, "device")
		if empty {
			t.Fatalf("%s has devices", c.Tenant)
		}
		assertCHClauseClaimsNoShared(t, "findings/"+c.Tenant, find, c.Tenant)

		tun, empty := s.deviceTenantPairCondFor(c, "local_device", "remote_device")
		if empty {
			t.Fatalf("%s has devices", c.Tenant)
		}
		assertCHClauseClaimsNoShared(t, "tunnels/"+c.Tenant, tun, c.Tenant)
	}
	// Each tenant still claims what is ONLY its own.
	if c, _ := s.flowTenantClauseFor(acmeClaims()); !strings.Contains(c, "'10.1.0.2'") || strings.Contains(c, "'10.2.0.2'") {
		t.Errorf("acme flow clause: %s", c)
	}
	if c, _ := s.deviceTenantCondFor(globexClaims(), "device"); !strings.Contains(c, "'globex-edge'") || strings.Contains(c, "'acme-edge'") {
		t.Errorf("globex findings clause: %s", c)
	}
}

// A tenant whose every identity is ambiguous reads ONLY its stamped rows — no
// identity branch at all, never an unscoped read.
func TestCHClauseAllAmbiguousIsOwnStampedRowsOnly(t *testing.T) {
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "r-1", Name: sharedName, Address: sharedAddr, TenantID: "retail"})
	d.Upsert(models.Device{ID: sharedName, Name: sharedName, Address: sharedAddr}) // the platform's SNMP twin
	d.Upsert(models.Device{ID: "o-9", Name: "r-1", TenantID: "other"})             // even the id is another owner's name
	s := &server{discovery: d}
	retail := jwtClaims{Sub: "r", Role: RoleOperator, Tenant: "retail"}
	if c, empty := s.flowTenantClauseFor(retail); empty || c != " AND (tenant_id = 'retail')" {
		t.Fatalf("flows: clause=%q empty=%v", c, empty)
	}
	if c, empty := s.deviceTenantCondFor(retail, "device"); empty || c != "(tenant_id = 'retail')" {
		t.Fatalf("findings: clause=%q empty=%v", c, empty)
	}
	if c, empty := s.deviceTenantPairCondFor(retail, "local_device", "remote_device"); empty || c != "(tenant_id = 'retail')" {
		t.Fatalf("tunnels: clause=%q empty=%v", c, empty)
	}
}

// The findings handler and the AI anomaly tool, on the wire.
func TestFindingsHandlerAndAIToolSendNoSharedIdentity(t *testing.T) {
	var sqls []string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sqls = append(sqls, string(b)+r.URL.Query().Get("query"))
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	s := claimFixtureServer(t)

	w := httptest.NewRecorder()
	s.handleFindings(w, req(http.MethodGet, "/api/findings", "", acmeClaims()))
	d := aiDataSource{srv: s, ctx: context.Background(), scope: "acme", claims: acmeClaims()}
	if _, err := d.moduleMetricAnomalies(); err != nil {
		t.Fatalf("moduleMetricAnomalies: %v", err)
	}
	if _, err := d.moduleAppIdentity(false); err != nil {
		t.Fatalf("moduleAppIdentity: %v", err)
	}
	if len(sqls) < 3 {
		t.Fatalf("want 3 ClickHouse reads, got %d", len(sqls))
	}
	for i, q := range sqls {
		assertCHClauseClaimsNoShared(t, fmt.Sprintf("wire#%d", i), q, "acme")
	}
}

// ---- scheduled report (all-tenants scope: the tenant_id test is load-bearing) --

func TestReportDeviceScopeClaimsNoSharedIdentity(t *testing.T) {
	s := claimFixtureServer(t)
	rs := &reportScheduler{srv: s, discovery: s.discovery}
	sc := rs.reportDeviceKeys("acme")
	if sc.Tenant != "acme" {
		t.Fatalf("report scope tenant = %q", sc.Tenant)
	}
	claim := setOf(sc.Claim)
	if claim[sharedName] || claim["pe-1"] || !claim["acme-edge"] {
		t.Fatalf("report claim = %v", sc.Claim)
	}
	// Keys (VictoriaMetrics device maps) are still the full registry set.
	if !setOf(sc.Keys)[sharedName] {
		t.Fatalf("report Keys must stay the registry set: %v", sc.Keys)
	}
	// No server wired → claims nothing.
	if got := (&reportScheduler{discovery: s.discovery}).reportDeviceKeys("acme").Claim; got != nil {
		t.Fatalf("no server must claim nothing: %v", got)
	}
}

// On the wire: the tunnels and findings reads a tenant-owned report sends.
func TestReportQueriesSharedIdentityClaimNeitherTenant(t *testing.T) {
	s := claimFixtureServer(t)
	rs := &reportScheduler{srv: s, discovery: s.discovery, alerts: alerts.NewEngine("", nil), runs: map[string]reportRun{}}
	rs.ds = rs.dataSource()
	for _, tenant := range []string{"acme", "globex"} {
		rec := &queryRecorder{}
		fakeClickHouse(t, rec)
		rs.ds.DatasetWAN(tenant)
		rs.ds.DatasetSecurity(tenant)
		qs := rec.all()
		if len(qs) < 3 {
			t.Fatalf("%s: expected tunnels + findings reads, got %d", tenant, len(qs))
		}
		for _, q := range qs {
			assertCHClauseClaimsNoShared(t, "report/"+tenant, q, tenant)
		}
	}
}
