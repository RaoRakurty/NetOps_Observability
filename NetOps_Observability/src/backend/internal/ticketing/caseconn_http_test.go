// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_http_test.go — the settings SURFACE, exercised through a real mux so
// the route patterns this file exports are the ones under test.
//
// The cross-org proof lives in the backend package's
// tac_connector_config_isolation_test.go (real router, real auth). What is
// proven HERE is what that test cannot see from outside: that every write and
// every probe writes an AUDIT ROW on both outcomes, that the gate is the right
// one per verb, and that a caller with no tenant is refused rather than served
// a shared bucket.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureAudit records what the surface audited.
type captureAudit struct{ rows []CaseAuditEvent }

func (c *captureAudit) RecordCaseAction(e CaseAuditEvent) { c.rows = append(c.rows, e) }

func (c *captureAudit) find(detail string) (CaseAuditEvent, bool) {
	for _, r := range c.rows {
		if r.Detail == detail {
			return r, true
		}
	}
	return CaseAuditEvent{}, false
}

type connHarness struct {
	srv    *httptest.Server
	store  *TACConnectorStore
	audit  *captureAudit
	gates  []ConnectorGate
	tenant string
	// deny makes the gate refuse, as the platform's own gate would.
	deny bool
}

func newConnHarness(t *testing.T) *connHarness {
	t.Helper()
	h := &connHarness{store: NewTACConnectorStoreForTest(), audit: &captureAudit{}, tenant: "acme"}
	api, err := NewTACConnectorAPI(TACConnectorAPIDeps{
		Authz: func(w http.ResponseWriter, _ *http.Request, gate ConnectorGate) (ConnectorPrincipal, bool) {
			h.gates = append(h.gates, gate)
			if h.deny {
				http.Error(w, "forbidden", http.StatusForbidden)
				return ConnectorPrincipal{}, false
			}
			return ConnectorPrincipal{Tenant: h.tenant, Subject: "user:jane"}, true
		},
		Store:    func() *TACConnectorStore { return h.store },
		Registry: DefaultCaseConnectorRegistry(),
		Resolve: func(_ context.Context, tenant, _ string) (TACConnectorConfig, error) {
			return h.store.Get(tenant, false, tenant)
		},
		Audit: h.audit,
		WriteJSON: func(w http.ResponseWriter, status int, body any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		},
		WriteError: func(w http.ResponseWriter, status int, err error) {
			http.Error(w, err.Error(), status)
		},
		Now:          func() time.Time { return time.Unix(1757000000, 0).UTC() },
		ProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build surface: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(TACConnectorItemPath, api.HandleConnectorItem)
	mux.HandleFunc(TACConnectorTestPath, api.HandleConnectorTest)
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *connHarness) call(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequest(method, h.srv.URL+path, rdr)
	} else {
		req, err = http.NewRequest(method, h.srv.URL+path, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		t.Fatalf("read body: %v", rerr)
	}
	return resp.StatusCode, string(raw)
}

// A credential change is audited whether it landed or was refused: the failed
// attempt is exactly as interesting to a reviewer as the successful one.
func TestEveryCredentialChangeIsAuditedOnBothOutcomes(t *testing.T) {
	h := newConnHarness(t)
	const path = "/api/tac/connectors/email-arista"

	if st, body := h.call(t, "PUT", path,
		`{"enabled":true,"host":"smtp.acme.example:587","from":"noc@acme.example","password":"p"}`); st != 200 {
		t.Fatalf("save: %d %s", st, body)
	}
	ok, found := h.audit.find("save")
	if !found || ok.Result != "ok" || ok.Actor != "user:jane" || ok.TenantID != "acme" || ok.Connector != "email-arista" {
		t.Fatalf("the successful save was not audited properly: %+v", h.audit.rows)
	}
	if strings.Contains(ok.Error, "p") && ok.Error != "" {
		t.Fatalf("the audit row carries request content: %+v", ok)
	}

	h.audit.rows = nil
	if st, _ := h.call(t, "PUT", path, `{"enabled":true,"host":"no-port","from":"noc@acme.example"}`); st != http.StatusBadRequest {
		t.Fatalf("a bad host must be refused, got %d", st)
	}
	bad, found := h.audit.find("save")
	if !found || bad.Result != "error" || !strings.Contains(bad.Error, "host:port") {
		t.Fatalf("the refused save was not audited with its reason: %+v", h.audit.rows)
	}

	h.audit.rows = nil
	if st, _ := h.call(t, "DELETE", path, ""); st != 200 {
		t.Fatal("remove failed")
	}
	if rm, found := h.audit.find("remove"); !found || rm.Result != "ok" {
		t.Fatalf("the removal was not audited: %+v", h.audit.rows)
	}
}

// A probe is audited with its OUTCOME, because "we tested it" is not the fact a
// reviewer needs — "we tested it and the vendor refused" is.
func TestAProbeIsAuditedWithItsOutcome(t *testing.T) {
	h := newConnHarness(t)
	if st, body := h.call(t, "POST", "/api/tac/connectors/juniper/test", ""); st != 200 {
		t.Fatalf("probe: %d %s", st, body)
	}
	row, found := h.audit.find("test:not_configured")
	if !found || row.Result != "error" || row.Connector != "juniper" {
		t.Fatalf("probe audit = %+v", h.audit.rows)
	}
}

// Reads take the read gate; saving, removing and TESTING take the write gate —
// a probe spends the tenant's credential against a vendor.
func TestTheRightGateGuardsEachVerb(t *testing.T) {
	h := newConnHarness(t)
	const path = "/api/tac/connectors/jira"
	h.call(t, "GET", path, "")
	h.call(t, "PUT", path, `{"enabled":true,"deployment":"cloud"}`)
	h.call(t, "DELETE", path, "")
	h.call(t, "POST", path+"/test", "")
	want := []ConnectorGate{ConnectorGateRead, ConnectorGateWrite, ConnectorGateWrite, ConnectorGateWrite}
	if len(h.gates) != len(want) {
		t.Fatalf("gates = %v, want %v", h.gates, want)
	}
	for i := range want {
		if h.gates[i] != want[i] {
			t.Fatalf("gate %d = %v, want %v", i, h.gates[i], want[i])
		}
	}

	// A refused gate writes no audit row and reaches no store.
	h.deny, h.audit.rows = true, nil
	if st, _ := h.call(t, "PUT", path, `{"enabled":true}`); st != http.StatusForbidden {
		t.Fatalf("a denied gate must refuse, got %d", st)
	}
	if len(h.audit.rows) != 0 {
		t.Fatalf("a request that never passed the gate was audited: %+v", h.audit.rows)
	}
}

// A principal with no tenant — the platform owner in the Global view — has no
// connector settings of its own and must scope in before it can touch any.
func TestACallerWithNoTenantIsRefusedRatherThanServedASharedBucket(t *testing.T) {
	h := newConnHarness(t)
	h.tenant = ""
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/tac/connectors/jira", ""},
		{"PUT", "/api/tac/connectors/jira", `{"enabled":true,"deployment":"cloud"}`},
		{"DELETE", "/api/tac/connectors/jira", ""},
		{"POST", "/api/tac/connectors/jira/test", ""},
	} {
		st, body := h.call(t, tc.method, tc.path, tc.body)
		if st != http.StatusConflict || !strings.Contains(body, "choose a tenant") {
			t.Fatalf("%s %s = %d %s, want a conflict asking for a tenant", tc.method, tc.path, st, body)
		}
	}
}

// The surface fails CLOSED: a missing collaborator is a refusal to build, not a
// surface that reads unscoped.
func TestTheSurfaceRefusesToBuildWithoutItsCollaborators(t *testing.T) {
	_, err := NewTACConnectorAPI(TACConnectorAPIDeps{})
	if err == nil {
		t.Fatal("an empty dependency set built a working surface")
	}
	for _, want := range []string{"Authz", "Store", "Registry", "Resolve", "Audit", "WriteJSON", "WriteError", "Now"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
	var nilAPI *TACConnectorAPI
	rec := httptest.NewRecorder()
	nilAPI.HandleConnectorItem(rec, httptest.NewRequest("GET", "/api/tac/connectors/jira", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unbuilt surface must 404, got %d", rec.Code)
	}
}

// A method the surface does not serve is refused rather than silently treated as
// one it does.
func TestAnUnservedMethodIsRefused(t *testing.T) {
	h := newConnHarness(t)
	if st, _ := h.call(t, "PATCH", "/api/tac/connectors/jira", `{}`); st != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH = %d, want 405", st)
	}
	if st, _ := h.call(t, "GET", "/api/tac/connectors/jira/test", ""); st != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the probe = %d, want 405", st)
	}
}
