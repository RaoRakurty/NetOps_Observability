// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Cross-tenant isolation for flow interface names (tracker 387 PR 13b, §3a.5).
// The names come from netops.iface_names, keyed by the flow ROW's own tenant;
// these tests pin that no caller-supplied tenant ever reaches the lookup, that
// a foreign tenant's name never resolves on your rows, and that ?as_tenant into
// another org is ignored.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/flownames"
	"netops/backend/internal/iana"
	"netops/backend/models"
)

// fakeCHScoped is fakeCH that also records the tenant_scope each query ran at.
type chCall struct{ sql, scope string }

func fakeCHScoped(t *testing.T, reply string) *[]chCall {
	t.Helper()
	var mu sync.Mutex
	var got []chCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, chCall{sql: string(b), scope: r.URL.Query().Get("tenant_scope")})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return &got
}

const ifaceJoinKey = "ON n.tenant_id = a.tid AND n.exporter_addr = a.exporter AND n.ifindex = a.ifx"

func TestFlowsTopNIfaceNameKeyUsesRowTenant(t *testing.T) {
	for _, by := range []string{"in_if", "out_if"} {
		calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
		s := flowsTestServer(t)
		w := httptest.NewRecorder()
		s.handleFlowsTopN(w, req(http.MethodGet, "/api/flows/topn?by="+by, "", acme()))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d (%s)", by, w.Code, w.Body.String())
		}
		if len(*calls) != 1 {
			t.Fatalf("%s: want 1 query, got %d", by, len(*calls))
		}
		c := (*calls)[0]
		for _, want := range []string{
			ifaceJoinKey,
			"SELECT tenant_id AS tid, sampler_address AS exporter, " + by + " AS ifx",
			"FROM netops.iface_names",
			"src_addr IN ('10.1.0.1') OR dst_addr IN ('10.1.0.1') OR sampler_address IN ('10.1.0.1')",
			"AND " + by + " > 0",
			"'sentinel'",
			by + "_name_basis",
		} {
			if !strings.Contains(c.sql, want) {
				t.Errorf("%s: SQL missing %q:\n%s", by, want, c.sql)
			}
		}
		// The principal's tenant reaches the NAME LOOKUP only as the scope
		// setting, never as a literal: the join keys on the row's own tenant.
		// The one literal allowed is the row filter's own-stamped-rows branch
		// (tracker 370), and it must appear exactly once.
		at := strings.Index(c.sql, "LEFT JOIN")
		if at < 0 {
			t.Fatalf("%s: no name lookup join in the SQL:\n%s", by, c.sql)
		}
		join := c.sql[at:]
		if strings.Contains(join, "'acme'") || strings.Contains(c.sql, "globex") || strings.Contains(c.sql, "10.2.0.1") {
			t.Errorf("%s: TENANT LEAK: a tenant literal or foreign address in the SQL:\n%s", by, c.sql)
		}
		if strings.Count(c.sql, "'acme'") != 1 || !strings.Contains(c.sql, "(tenant_id = 'acme' OR src_addr IN") {
			t.Errorf("%s: the row filter must carry the own-tenant branch exactly once:\n%s", by, c.sql)
		}
		if c.scope != "acme" {
			t.Errorf("%s: tenant_scope = %q, want acme", by, c.scope)
		}
	}
}

// A scoped principal with no devices never reaches ClickHouse for names either.
func TestFlowsTopNIfaceNoDeviceTenantNeverQueries(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	w := httptest.NewRecorder()
	nobody := jwtClaims{Sub: "n@nobody", Role: RoleOperator, Tenant: "nobody"}
	s.handleFlowsTopN(w, req(http.MethodGet, "/api/flows/topn?by=in_if", "", nobody))
	if w.Code != http.StatusOK || len(*calls) != 0 {
		t.Fatalf("default-closed: status %d, %d queries, want 200 and 0", w.Code, len(*calls))
	}
}

// ?as_tenant into another org is ignored: user-A's interface top-N stays
// scoped to org A, by address clause and by tenant_scope.
func TestFlowsTopNIfaceAsTenantIgnored(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	ids := map[string]string{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": idOf(t, b)})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		ids[name] = idOf(t, b)
	}
	st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "user-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": ids["A"],
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	s.discovery.Upsert(models.Device{ID: "a-core", Name: "a-core", Address: "10.1.0.1", TenantID: ids["A"]})
	s.discovery.Upsert(models.Device{ID: "b-core", Name: "b-core", Address: "10.2.0.1", TenantID: ids["B"]})
	tok := login(t, srv, "user-a", "Passw0rd!2345").Token

	st, body := do(t, srv, "GET", "/api/flows/topn?by=in_if&as_tenant="+ids["B"], tok, nil)
	if st != 200 {
		t.Fatalf("GET topn: %d %s", st, body)
	}
	if len(*calls) != 1 {
		t.Fatalf("want 1 CH query, got %d", len(*calls))
	}
	c := (*calls)[0]
	if c.scope != ids["A"] {
		t.Errorf("as_tenant widened the scope: tenant_scope = %q, want org A's %q", c.scope, ids["A"])
	}
	if strings.Contains(c.sql, "10.2.0.1") || strings.Contains(c.sql, ids["B"]) {
		t.Errorf("TENANT LEAK: org B reached the SQL:\n%s", c.sql)
	}
	if !strings.Contains(c.sql, "'10.1.0.1'") || !strings.Contains(c.sql, ifaceJoinKey) {
		t.Errorf("org A's scoped interface query is not the one that ran:\n%s", c.sql)
	}
}

// The Logs page's flow documents: a foreign tenant's interface name never
// resolves on your document, the platform's names resolve on platform
// documents, and the sentinels never name.
func TestLogsFlowNamesForeignTenantNeverResolves(t *testing.T) {
	e := flownames.NewExporter()
	e.Install([]flownames.Row{
		{TenantID: "globex", ExporterAddr: "10.1.0.1", IfIndex: 4, IfName: "GLOBEX-SECRET"},
		{TenantID: "acme", ExporterAddr: "10.1.0.1", IfIndex: 2, IfName: "Gi2"},
		{TenantID: "", ExporterAddr: "10.70.245.104", IfIndex: 4, IfName: "ge0/3"},
	})
	resp := map[string]any{}
	raw := `{"hits":{"hits":[
	  {"_index":"netops-flows-acme-x","_source":{"tenant_id":"acme","sampler_address":"10.1.0.1","in_if":4,"out_if":2,"proto":17,"src_port":40000,"dst_port":161}},
	  {"_index":"netops-flows-x","_source":{"tenant_id":"","sampler_address":"10.70.245.104","in_if":4,"out_if":4294967295,"proto":6,"src_port":830,"dst_port":51000}},
	  {"_index":"netops-flows-x","_source":{"sampler_address":"10.70.245.104","in_if":"4","out_if":0}}
	]}}`
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	flownames.AnnotateHits(resp, e, iana.Default(), flownames.PlatformAddrs{})
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	res := func(i int) map[string]any { return hits[i].(map[string]any)["_resolved"].(map[string]any) }

	acme := res(0)
	if acme["in_if_name"] != "" || acme["in_if_name_basis"] != "absent" {
		t.Errorf("TENANT LEAK: globex's name on acme's document: %v", acme)
	}
	if acme["out_if_name"] != "Gi2" || acme["out_if_name_basis"] != "resolved" {
		t.Errorf("acme's own interface not named: %v", acme)
	}
	if acme["proto_name"] != "UDP" || acme["service_name"] != "snmp" {
		t.Errorf("acme protocol/service names = %v", acme)
	}
	platform := res(1)
	if platform["in_if_name"] != "ge0/3" || platform["out_if_name_basis"] != "sentinel" || platform["out_if_name"] != "" {
		t.Errorf("platform document names = %v", platform)
	}
	if platform["service_name"] != "netconf-ssh" {
		t.Errorf("service end is the lower port: got %v", platform["service_name"])
	}
	untagged := res(2)
	if untagged["in_if_name"] != "ge0/3" || untagged["out_if_name_basis"] != "sentinel" {
		t.Errorf("a document without tenant_id reads as platform-owned: %v", untagged)
	}
	if _, stored := hits[0].(map[string]any)["_source"].(map[string]any)["in_if_name"]; stored {
		t.Error("names must ride on _resolved, never inside the stored _source")
	}
}

// flowKeyLabel names from the IANA tables and says when it could not.
func TestFlowKeyLabel(t *testing.T) {
	d := iana.Default()
	for _, c := range []struct {
		kind            flowLabelKind
		k, label, basis string
	}{
		{flowLabelProtocol, "17", "UDP", "iana_protocol"},
		{flowLabelProtocol, "200", "", "absent"},
		{flowLabelProtocol, "x", "", "absent"},
		{flowLabelService, "17/161", "snmp", "iana_service"},
		{flowLabelService, "6/830", "netconf-ssh", "iana_service"},
		{flowLabelService, "17/65000", "", "absent"},
		{flowLabelService, "17-161", "", "absent"},
	} {
		label, basis := flowKeyLabel(d, c.kind, c.k)
		if label != c.label || basis != c.basis {
			t.Errorf("flowKeyLabel(%v, %q) = %q,%q, want %q,%q", c.kind, c.k, label, basis, c.label, c.basis)
		}
	}
}

// by=proto and by=service_port rows carry the IANA label beside the number.
func TestFlowsTopNProtocolAndServiceLabels(t *testing.T) {
	fakeCHScoped(t, `{"meta":[],"data":[{"k":"17/161","bytes_total":"10","packets_total":"1","flows":"1"},{"k":"17/60000","bytes_total":"5","packets_total":"1","flows":"1"}],"rows":2}`)
	s := flowsTestServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsTopN(w, req(http.MethodGet, "/api/flows/topn?by=service_port", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Data) != 2 || out.Data[0]["label"] != "snmp" || out.Data[0]["label_basis"] != "iana_service" ||
		out.Data[1]["label"] != "" || out.Data[1]["label_basis"] != "absent" {
		t.Fatalf("service labels = %v", out.Data)
	}
}
