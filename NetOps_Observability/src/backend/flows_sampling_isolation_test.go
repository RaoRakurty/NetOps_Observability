// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// flows_sampling_isolation_test.go — tracker 401 (c), CLAUDE.md §3a. A declared
// sampling rate belongs to one workspace: the list shows only the caller's own,
// the owner is stamped from the token (never the body), another workspace's
// exporter answers 404, a platform owner must act inside a workspace to write,
// and a declaration multiplies only its owner's records.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/flowquery"
	"netops/backend/internal/flowsampling"
)

func samplingServer(t *testing.T) *server {
	t.Helper()
	s := flowsTestServer(t)
	s.flowSampling = flowsampling.NewFileStore("")
	au, err := newAuditStore(t.TempDir() + "/audit.json")
	if err != nil {
		t.Fatalf("auditStore: %v", err)
	}
	s.audit = au
	ctx := context.Background()
	for _, d := range []struct {
		tenant, exp string
		rate        uint32
	}{{"acme", "10.1.0.1", 100}, {"globex", "10.2.0.1", 7}} {
		if _, err := s.flowSampling.Put(ctx, d.tenant, flowsampling.Declaration{Exporter: d.exp, Rate: d.rate}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func samplingDo(s *server, method, path, body string, c jwtClaims) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handleFlowsSampling(w, req(method, path, body, c))
	return w
}

func TestFlowsSamplingListIsOwnWorkspaceOnly(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[{"tid":"acme","exporter":"10.1.0.1","fl":"10","fl_rr":"0"}],"rows":1}`)
	s := samplingServer(t)
	for _, path := range []string{"/api/flows/sampling", "/api/flows/sampling?as_tenant=globex"} {
		w := samplingDo(s, http.MethodGet, path, "", acme())
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var body flowSamplingBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Declarations) != 1 || body.Declarations[0].Exporter != "10.1.0.1" || strings.Contains(w.Body.String(), "10.2.0.1") {
			t.Fatalf("%s: TENANT LEAK or missing own row: %s", path, w.Body.String())
		}
		if len(body.Exporters) != 1 || !body.Exporters[0].CanDeclare || body.Exporters[0].DeclaredRate != 100 || body.Exporters[0].TenantID != "" {
			t.Fatalf("%s: exporters = %+v", path, body.Exporters)
		}
	}
	for _, c := range *calls {
		if c.scope != "acme" || !strings.Contains(c.sql, acmeLinkClause) || strings.Contains(c.sql, "globex") {
			t.Fatalf("exporter list ran outside acme's scope (%q):\n%s", c.scope, c.sql)
		}
	}
	// The platform owner reads every workspace's declarations.
	w := samplingDo(s, http.MethodGet, "/api/flows/sampling", "", superA())
	var all flowSamplingBody
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil || len(all.Declarations) != 2 {
		t.Fatalf("cross list = %s (%v)", w.Body.String(), err)
	}
}

func TestFlowsSamplingWritesAreStampedAndScoped(t *testing.T) {
	fakeCHScoped(t, `{"meta":[],"data":[{"n":"0"}],"rows":1}`) // acme holds no stamped records from 10.2.0.1
	s := samplingServer(t)

	// Own exporter: saved under acme, whatever tenant the body names.
	w := samplingDo(s, http.MethodPut, "/api/flows/sampling", `{"exporter":"10.1.0.1","rate":1000,"note":"sampler 1:1000","tenant_id":"globex"}`, acme())
	if w.Code != http.StatusOK {
		t.Fatalf("own put: %d %s", w.Code, w.Body.String())
	}
	g, _ := s.flowSampling.List(context.Background(), "globex", false)
	if len(g) != 1 || g[0].Exporter != "10.2.0.1" || g[0].Rate != 7 {
		t.Fatalf("a body tenant reached globex: %+v", g)
	}
	a, _ := s.flowSampling.List(context.Background(), "acme", false)
	if len(a) != 1 || a[0].Rate != 1000 || a[0].UpdatedBy != "a@acme" {
		t.Fatalf("acme's declaration = %+v", a)
	}

	// Another workspace's exporter: 404, nothing stored, nothing revealed.
	w = samplingDo(s, http.MethodPut, "/api/flows/sampling", `{"exporter":"10.2.0.1","rate":5}`, acme())
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("foreign exporter put: %d %s", w.Code, w.Body.String())
	}
	if g, _ := s.flowSampling.List(context.Background(), "globex", false); g[0].Rate != 7 {
		t.Fatalf("acme overwrote globex: %+v", g)
	}

	// Deleting another workspace's declaration: 404, it stays.
	if w = samplingDo(s, http.MethodDelete, "/api/flows/sampling?exporter=10.2.0.1", "", acme()); w.Code != http.StatusNotFound {
		t.Fatalf("foreign delete: %d", w.Code)
	}
	if g, _ := s.flowSampling.List(context.Background(), "globex", false); len(g) != 1 {
		t.Fatal("acme deleted globex's declaration")
	}

	// The platform owner must act inside a workspace.
	if w = samplingDo(s, http.MethodPut, "/api/flows/sampling", `{"exporter":"10.1.0.1","rate":5}`, superA()); w.Code != http.StatusBadRequest {
		t.Fatalf("cross put: %d", w.Code)
	}
	// A viewer cannot write.
	viewer := jwtClaims{Sub: "v@acme", Role: RoleReadOnly, Tenant: "acme"}
	if w = samplingDo(s, http.MethodPut, "/api/flows/sampling", `{"exporter":"10.1.0.1","rate":5}`, viewer); w.Code != http.StatusForbidden {
		t.Fatalf("viewer put: %d", w.Code)
	}
	// Bad input is a 400 with a plain reason.
	for _, b := range []string{`{"exporter":"10.1.0.1","rate":1}`, `{"exporter":"edge-1","rate":10}`, `not json`} {
		if w = samplingDo(s, http.MethodPut, "/api/flows/sampling", b, acme()); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", b, w.Code)
		}
	}
	// Own delete works.
	if w = samplingDo(s, http.MethodDelete, "/api/flows/sampling?exporter=10.1.0.1", "", acme()); w.Code != http.StatusOK {
		t.Fatalf("own delete: %d %s", w.Code, w.Body.String())
	}
}

// A declaration multiplies only its owner's records: acme's link statements
// carry acme's rate (for its stamped and its owned untagged records) and never
// globex's; the All-tenants view applies each to its owner's stamped records.
func TestFlowsDeclaredRateReachesOnlyItsOwner(t *testing.T) {
	s := samplingServer(t)
	got := s.flowDeclared(context.Background(), acme())
	if got[flowquery.DeclKey{Tenant: "acme", Exporter: "10.1.0.1"}] != 100 || got[flowquery.DeclKey{Tenant: "", Exporter: "10.1.0.1"}] != 100 {
		t.Fatalf("acme's view = %v", got)
	}
	for k := range got {
		if k.Tenant == "globex" || k.Exporter == "10.2.0.1" {
			t.Fatalf("TENANT LEAK: globex's declaration in acme's view: %v", got)
		}
	}
	cross := s.flowDeclared(context.Background(), superA())
	if len(cross) != 2 || cross[flowquery.DeclKey{Tenant: "globex", Exporter: "10.2.0.1"}] != 7 {
		t.Fatalf("cross view = %v", cross)
	}
	if _, ok := cross[flowquery.DeclKey{Tenant: "", Exporter: "10.1.0.1"}]; ok {
		t.Fatal("the All-tenants view must not apply a declaration to untagged records")
	}

	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	w := httptest.NewRecorder()
	s.handleFlowsLinks(w, req(http.MethodGet, "/api/flows/links?since=1h", "", acme()))
	if w.Code != http.StatusOK || len(*calls) == 0 {
		t.Fatalf("links: %d", w.Code)
	}
	if sql := (*calls)[0].sql; !strings.Contains(sql, "'acme|10.1.0.1'") || strings.Contains(sql, "globex") {
		t.Fatalf("acme's links statement:\n%s", sql)
	}
}
