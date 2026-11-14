// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_view_binding_isolation_test.go — CLAUDE.md §3a rule 5 for N-E4: the
// incident and device the Iris box says are on the screen are bound into the
// ask ONLY after the server re-resolves them in the caller's own scope, over
// the real seams (aiDataSource.GetProblem, aiTroubleshootDeps.ResolveDevice).
// A hostile ClickHouse answers acme's incident to every query, so the app-side
// tenancy check is what holds; another tenant's incident and device never
// bind, never surface in the answer, and an as_tenant parameter does not widen
// a non-cross caller.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/ai"
)

const viewAcmeIncident = "3f2c9a10-7b4e-4c1d-9e2a-1a2b3c4d5e6f"

// hostileIncidentCH returns acme's correlation row for every corr_objects
// query, whatever it is asked, and records each tenant_scope it saw.
func hostileIncidentCH(t *testing.T) func() []string {
	t.Helper()
	var (
		mu     sync.Mutex
		scopes []string
	)
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read query body: %v", err)
		}
		mu.Lock()
		scopes = append(scopes, r.URL.Query().Get("tenant_scope"))
		mu.Unlock()
		if strings.Contains(string(body), "netops.corr_objects") {
			_, _ = w.Write([]byte(`{"data":[{"correlation_id":"` + viewAcmeIncident + `","tenant_id":"acme",` + // a failed write means the client left
				`"top_hypothesis":"acme secret: BGP peer down on acme-e0","top_confidence":0.8,"verdict_tier":"suspected",` +
				`"evidence_missing":"[]","affected":"[]","hypotheses":"[]","signal_count":3,"node_count":1,"created_at":"2026-11-13T10:00:00Z"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`)) // a failed write means the client left
	}))
	t.Cleanup(ch.Close)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), scopes...)
	}
}

// viewOrchestrator is the orchestrator's binding seams exactly as the ask
// handler wires them, for the request r (claims in its context).
func viewOrchestrator(t *testing.T, s *server, r *http.Request, claims jwtClaims) *ai.Orchestrator {
	t.Helper()
	ds := aiDataSource{srv: s, ctx: r.Context(), scope: s.chTenantScope(r), claims: claims}
	return &ai.Orchestrator{DS: ds, Troubleshoot: s.aiTroubleshootDeps(r, claims), Flags: func(string) bool { return true }}
}

func TestIrisViewBindingIsTheCallersOwn(t *testing.T) {
	scopes := hostileIncidentCH(t)
	s := netTopoServer(t)
	ui := map[string]string{"correlation_id": viewAcmeIncident, "device": "acme-e0"}

	// acme's own incident and device bind.
	r := aiTSRequest(acme())
	o := viewOrchestrator(t, s, r, acme())
	if _, err := o.Ask(context.Background(), aiTSPrincipal(), "", ui); err != nil {
		t.Fatalf("acme ask: %v", err)
	}
	if v := o.View(); v.Incident != viewAcmeIncident || v.Device != "acme-e0" {
		t.Fatalf("acme's own subject must bind: %+v", v)
	}

	// globex naming acme's incident and device: neither binds, nothing of
	// acme's reaches the answer, and the decline names nothing.
	r = aiTSRequest(globex())
	o = viewOrchestrator(t, s, r, globex())
	ans, err := o.Ask(context.Background(), aiTSPrincipal(), "explain this", ui)
	if err != nil {
		t.Fatalf("globex ask: %v", err)
	}
	if v := o.View(); v.Incident != "" || v.Device != "" {
		t.Fatalf("CROSS-TENANT BIND: %+v", v)
	}
	blob := ans.Text + " " + strings.Join(ans.Disclaimers, " ")
	for _, leak := range []string{"acme", "BGP peer down", viewAcmeIncident} {
		if strings.Contains(blob, leak) {
			t.Fatalf("LEAK %q in globex's answer: %s", leak, blob)
		}
	}
	if !strings.Contains(blob, ai.ViewIncidentNotUsed) || !strings.Contains(blob, ai.ViewDeviceNotUsed) {
		t.Fatalf("globex must be told the screen's subject was not used: %s", blob)
	}

	// as_tenant=acme on a non-cross globex request is ignored.
	r = req(http.MethodPost, "/api/ai/ask?as_tenant=acme", "", globex())
	o = viewOrchestrator(t, s, r, globex())
	if _, err := o.Ask(context.Background(), aiTSPrincipal(), "explain this", ui); err != nil {
		t.Fatalf("as_tenant ask: %v", err)
	}
	if v := o.View(); v.Incident != "" || v.Device != "" {
		t.Fatalf("as_tenant widened a non-cross caller: %+v", v)
	}
	for _, sc := range scopes() {
		if sc != "acme" && sc != "globex" {
			t.Fatalf("unexpected ClickHouse scope %q", sc)
		}
	}
	if last := scopes(); len(last) == 0 || last[len(last)-1] != "globex" {
		t.Fatalf("globex's lookups must run in globex's scope, saw %v", last)
	}
}
