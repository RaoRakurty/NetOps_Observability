// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ticketing_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for
// the operator-visibility restriction (Tenant.OperatorRestricted) on the manual
// ticketing path: POST /api/correlations/{id}/ticket and .../ticket/sync.
//
// The correlation lane closed both halves. This path reached around the first
// one: it derived its ClickHouse scope by hand (tenant, or "__all__" when
// cross) instead of asking s.chTenantScopeFor, and it passed an EMPTY exclusion
// to loadCorrSliceAtScope where every other correlation read passes
// s.tenantIDExcludeCondFor. So a platform owner could load a restricted
// tenant's correlation object, assemble the ticket payload from it — the case
// id, the top hypothesis, the affected devices — and file it with an external
// system under that tenant's name.
//
// The merged-object refusal is the half that puts it straight in the response
// body: it answers 409 with the SURVIVING case's id, so a restricted tenant's
// other correlation id crosses the wire verbatim.

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/internal/ticketing"
)

const (
	tktAcmeCaseID     = "3a7c1d2e-1111-4444-8888-aaaaaaaaaaaa"
	tktAcmeSurvivorID = "3a7c1d2e-2222-4444-8888-bbbbbbbbbbbb"
	tktAcmeHypothesis = "acme-payments-edge-flap"
	tktAcmeAffected   = "acme-core"
)

// corrObjectCH emulates what ClickHouse actually does with the two rules this
// lane depends on: it returns acme's corr_objects row unless the caller's
// tenant_scope excludes it (the STRICT row policy) or the SQL excludes it (the
// tenant_id predicate). A spy that answers the same rows however it is asked
// cannot tell a fixed lane from a broken one; this one can.
//
// The row is a MERGED object, so the handler's refusal path runs and puts
// acme's surviving case id in the response body — the field the assertions
// below name.
type corrObjectCH struct {
	acme  string
	calls *[]struct{ scope, sql string }
}

func (c corrObjectCH) start(t *testing.T) {
	t.Helper()
	row := `{"version":1,"tenant_id":"` + c.acme + `","state":"merged",` +
		`"merged_into":"` + tktAcmeSurvivorID + `",` +
		`"window_start":"2026-09-01T12:00:00Z","window_end":"2026-09-01T12:30:00Z",` +
		`"trigger_signal":"bgp_session_down","verdict_tier":"confirmed",` +
		`"top_hypothesis":"` + tktAcmeHypothesis + `","top_confidence":0.9,` +
		`"evidence_missing":"","hypotheses":"[]","affected":"` + tktAcmeAffected + `",` +
		`"layer_coverage":"{}","app_impact":"{}","attribution":"{}"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql := readAllLimited(r)
		scope := r.URL.Query().Get("tenant_scope")
		*c.calls = append(*c.calls, struct{ scope, sql string }{scope, sql})
		w.Header().Set("Content-Type", "application/json")
		visible := (scope == "__all__" || scope == c.acme) &&
			!strings.Contains(sql, "tenant_id NOT IN ('"+c.acme+"')")
		if visible && strings.Contains(sql, "netops.corr_objects") {
			_, _ = w.Write([]byte(`{"data":[` + row + `]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

type restrictedTicketFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
	calls  []struct{ scope, sql string }
}

func newRestrictedTicketFixture(t *testing.T) *restrictedTicketFixture {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}
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
	f := &restrictedTicketFixture{t: t, acme: acme.ID, globex: globex.ID}
	f.s = &server{
		roles: roles, tenants: ts,
		discovery: discovery.NewDiscoveryAggregator(),
		ticketing: ticketing.NewMemStore(),
	}
	corrObjectCH{acme: acme.ID, calls: &f.calls}.start(t)
	return f
}

// ticket drives POST /api/correlations/{id}/ticket through the production
// handler and returns the status and the raw body.
func (f *restrictedTicketFixture) ticket(claims jwtClaims) (int, string) {
	f.t.Helper()
	f.calls = nil
	w := httptest.NewRecorder()
	path := "/api/correlations/" + tktAcmeCaseID + "/ticket"
	f.s.handleCorrelationTickets(w, req(http.MethodPost, path, "", claims), tktAcmeCaseID, "ticket")
	return w.Code, w.Body.String()
}

// TestManualTicketingHonoursTheOperatorVisibilityRestriction asserts BOTH
// halves: the platform owner's Global view cannot reach a restricted tenant's
// correlation object through the manual ticket path, and neither can the same
// owner with as_tenant.
func TestManualTicketingHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedTicketFixture(t)
	owner := platformOwner()

	// Baseline: with nothing restricted the owner reaches acme's object and the
	// merged refusal hands back acme's surviving case id. Without this the
	// assertions below could pass on a path that always 404s.
	code, body := f.ticket(owner)
	if code != http.StatusConflict || !strings.Contains(body, tktAcmeSurvivorID) {
		t.Fatalf("baseline: the fixture does not reach acme's object at all: %d %s", code, body)
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// The fields that must not cross.
	hidden := []string{tktAcmeCaseID + `"`, tktAcmeSurvivorID, tktAcmeHypothesis, tktAcmeAffected}

	// ── half 1: the owner's GLOBAL view. The object read must carry the
	//    tenant_id exclusion, and the answer must be the same 404 a foreign or
	//    absent case gets — never a 403, which would confirm the case exists.
	code, body = f.ticket(owner)
	if code != http.StatusNotFound {
		t.Errorf("RESTRICTION LEAK: POST .../ticket in the Global view = %d, want 404: %s", code, body)
	}
	for _, leak := range hidden {
		if strings.Contains(body, leak) {
			t.Errorf("RESTRICTION LEAK: the Global view's ticket response carries acme's %q: %s", leak, body)
		}
	}
	if len(f.calls) == 0 {
		t.Fatal("no ClickHouse read was issued — this fixture proves nothing")
	}
	for i, c := range f.calls {
		if !strings.Contains(c.sql, "tenant_id NOT IN ('"+f.acme+"')") {
			t.Errorf("RESTRICTION LEAK: Global-view read %d does not exclude the restricted tenant.\nscope=%s\nSQL: %s", i, c.scope, c.sql)
		}
		if strings.Contains(c.sql, f.globex) {
			t.Errorf("read %d excluded globex, which is not restricted.\nSQL: %s", i, c.sql)
		}
	}

	// ── half 2: the owner walks in with as_tenant=acme. Every read goes out at
	//    the read-nothing scope, which is what the STRICT row policies enforce.
	code, body = f.ticket(ownerActing(owner, f.acme))
	if code != http.StatusNotFound {
		t.Errorf("RESTRICTION LEAK: POST .../ticket?as_tenant=acme = %d, want 404: %s", code, body)
	}
	for _, leak := range hidden {
		if strings.Contains(body, leak) {
			t.Errorf("RESTRICTION LEAK: the as_tenant ticket response carries acme's %q: %s", leak, body)
		}
	}
	if len(f.calls) == 0 {
		t.Fatal("no ClickHouse read was issued under as_tenant — this fixture proves nothing")
	}
	for i, c := range f.calls {
		if c.scope != chScopeNone {
			t.Errorf("RESTRICTION LEAK: as_tenant read %d went out at scope %q, want %q.\nSQL: %s",
				i, c.scope, chScopeNone, c.sql)
		}
	}

	// ── the owner scoped into the UNRESTRICTED tenant still reads at its scope.
	if _, _ = f.ticket(ownerActing(owner, f.globex)); len(f.calls) > 0 {
		for i, c := range f.calls {
			if c.scope != f.globex {
				t.Errorf("as_tenant=globex read %d went out at scope %q, want %q", i, c.scope, f.globex)
			}
		}
	}

	// ── acme's OWN operator still reaches acme's own object. The switch hides a
	//    tenant from the PLATFORM, never from itself.
	acmeOwn := jwtClaims{Sub: "a@acme", Role: RoleSuperAdmin, Tenant: f.acme}
	code, body = f.ticket(acmeOwn)
	if code != http.StatusConflict || !strings.Contains(body, tktAcmeSurvivorID) {
		t.Fatalf("acme's own operator lost its own case: %d %s", code, body)
	}
	for i, c := range f.calls {
		if strings.Contains(c.sql, "NOT IN ('"+f.acme+"')") {
			t.Fatalf("read %d: acme's own operator was excluded from its own case:\n%s", i, c.sql)
		}
	}
}
