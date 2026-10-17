// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// similar_incidents_isolation_test.go — "have we seen this before?" (tracker
// 337 N-F4) under §3a: a tenant's past incidents are the only ones compared,
// an identical twin in another tenant is never recalled, a foreign case is the
// same 404 as a missing one, and every ClickHouse read of a past incident is
// scoped to the subject's own tenant — never "__all__", never another tenant.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/incidentfp"
	"netops/backend/timeintel"
)

const (
	simSubject = "aaaaaaaa-0000-4000-8000-000000000001" // tenant A, open
	simPastA   = "aaaaaaaa-0000-4000-8000-000000000002" // tenant A, closed, same shape
	simOtherA  = "aaaaaaaa-0000-4000-8000-000000000003" // tenant A, closed, different shape
	simTwinB   = "bbbbbbbb-0000-4000-8000-000000000004" // tenant B, closed, IDENTICAL shape
)

type simRow struct{ tenant, state, sig, device string }

// simCH serves corr_objects rows only to a caller whose tenant_scope covers
// the row's tenant, and records every read's scope.
type simCH struct {
	rows   map[string]simRow
	scopes *[]string
}

func (c simCH) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql := readAllLimited(r)
		scope := r.URL.Query().Get("tenant_scope")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(sql, "netops.corr_objects") {
			*c.scopes = append(*c.scopes, scope)
			for id, row := range c.rows {
				if !strings.Contains(sql, id) || (scope != "__all__" && scope != row.tenant) {
					continue
				}
				body := `{"version":1,"tenant_id":"` + row.tenant + `","state":"` + row.state + `",` +
					`"window_start":"2026-09-01 12:00:00.000","window_end":"2026-09-01 12:30:00.000",` +
					`"trigger_signal":"bgp_session_down","verdict_tier":"confirmed","owner":"isp","seam_type":"dia",` +
					`"top_hypothesis":"` + row.sig + `","top_confidence":0.9,"evidence_missing":"","hypotheses":"[]",` +
					`"affected":"{\"devices\":[\"` + row.device + `\"]}","layer_coverage":"{}","app_impact":"{}","attribution":"{}"}`
				_, _ = w.Write([]byte(`{"data":[` + body + `]}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

func simFixture(t *testing.T) (*server, string, string, *[]string) {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var scopes []string
	simCH{scopes: &scopes, rows: map[string]simRow{
		simSubject: {a.ID, "open", "sig.wan.dia-loss", "edge-1"},
		simPastA:   {a.ID, "closed", "sig.wan.dia-loss", "edge-1"},
		simOtherA:  {a.ID, "closed", "sig.dc.fabric-down", "core-9"},
		simTwinB:   {b.ID, "closed", "sig.wan.dia-loss", "edge-1"},
	}}.start(t)
	metrics := timeintel.NewMemMetricsStore()
	when := time.Now().Add(-48 * time.Hour)
	for _, m := range []struct{ tenant, id, sig, device string }{
		{a.ID, simPastA, "sig.wan.dia-loss", "edge-1"},
		{a.ID, simOtherA, "sig.dc.fabric-down", "core-9"},
		{b.ID, simTwinB, "sig.wan.dia-loss", "edge-1"},
	} {
		if err := metrics.Upsert(context.Background(), timeintel.MetricRow{TenantID: m.tenant, CorrelationID: m.id, CalcVersion: timeIntelCalcVersion,
			OccurredAt: when, CalculatedAt: when, State: "closed", Owner: "isp", SeamType: "dia",
			Group: map[string]string{"signature": m.sig, "device": m.device}}); err != nil {
			t.Fatal(err)
		}
	}
	s := &server{roles: roles, tenants: ts, discovery: discovery.NewDiscoveryAggregator(),
		incidentTimeMetrics: metrics, incidentFP: incidentfp.NewMemStore(0)}
	return s, a.ID, b.ID, &scopes
}

func similarAs(s *server, c jwtClaims, id string) (int, string) {
	w := httptest.NewRecorder()
	s.serveCorrelationSimilar(w, req(http.MethodGet, "/api/correlations/"+id+"/similar", "", c), id)
	return w.Code, w.Body.String()
}

func TestSimilarIncidentsStayInTheSubjectsTenant(t *testing.T) {
	s, ta, tb, scopes := simFixture(t)
	alice := jwtClaims{Sub: "alice", Role: "operator", Tenant: ta}
	code, body := similarAs(s, alice, simSubject)
	if code != http.StatusOK || !strings.Contains(body, simPastA) || !strings.Contains(body, `"similar_incidents"`) {
		t.Fatalf("tenant A should recall its own past incident: %d %s", code, body)
	}
	if strings.Contains(body, simTwinB) || strings.Contains(body, simOtherA) {
		t.Fatalf("CROSS-TENANT LEAK or weak match shown: %s", body)
	}
	for i, sc := range *scopes {
		if sc != ta {
			t.Errorf("read %d ran at scope %q — every read of A's incidents must be scoped to A", i, sc)
		}
	}
	// The built fingerprint was written through, in A only.
	if got, _ := s.incidentFP.Get(context.Background(), ta, []string{simPastA}); len(got) != 1 {
		t.Fatal("the past incident's fingerprint should be stored for tenant A")
	}
	if got, _ := s.incidentFP.Get(context.Background(), tb, []string{simPastA}); len(got) != 0 {
		t.Fatal("tenant B must not hold A's fingerprint")
	}

	// Tenant B, and B walking as_tenant into A: the same 404 as a missing case.
	bob := jwtClaims{Sub: "bob", Role: "operator", Tenant: tb}
	walker := bob
	walker.ActingTenant = ta
	for name, c := range map[string]jwtClaims{"other tenant": bob, "as_tenant walk": walker} {
		if code, body := similarAs(s, c, simSubject); code != http.StatusNotFound || strings.Contains(body, simPastA) {
			t.Errorf("%s: %d %s, want 404 with nothing of A's", name, code, body)
		}
	}

	// The platform owner looking at A's case still compares only within A.
	*scopes = nil
	code, body = similarAs(s, platformOwner(), simSubject)
	if code != http.StatusOK || strings.Contains(body, simTwinB) || !strings.Contains(body, simPastA) {
		t.Fatalf("platform owner: %d %s", code, body)
	}
	for i, sc := range (*scopes)[1:] { // [0] is the subject read at the owner's own scope
		if sc != ta {
			t.Errorf("owner: candidate read %d at scope %q, want A's", i, sc)
		}
	}

	// A closed vocabulary window.
	w := httptest.NewRecorder()
	s.serveCorrelationSimilar(w, req(http.MethodGet, "/api/correlations/"+simSubject+"/similar?window=7d", "", alice), simSubject)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("window=7d: %d", w.Code)
	}
}
