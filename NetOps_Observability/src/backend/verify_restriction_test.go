// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// verify_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// operator-visibility restriction (Tenant.OperatorRestricted) on the Active
// Verification subresource: GET and POST /api/correlations/{id}/verify.
//
// This lane reached around the restriction the same way the manual ticket path
// did (c09aea52): it derived its ClickHouse scope by hand —
//
//	tenant, cross := principalTenant(claims)
//	scope := tenant
//	if cross {
//		scope = "__all__"
//	}
//
// — instead of asking s.chTenantScopeFor, and it passed NO tenant_id exclusion
// to the corr_current read where every other correlation read passes
// s.tenantIDExcludeCondFor. Both halves were therefore open at once:
//
//   - GET leaked the case itself. The row carries the restricted tenant's
//     verdict tier, its winning hypothesis and its AFFECTED DEVICE NAMES, and
//     the handler renders the tenant's verification config alongside it.
//   - POST was worse than a read. A verification run does not just look at a
//     case — it SSHes into the devices the case names, under that tenant's
//     stored credential. A platform operator could start live work inside the
//     estate of a tenant that had asked to be invisible to the platform.
//
// Both are closed here, and the test drives the production handler against a
// ClickHouse that applies the row policy and the predicate the way the deployed
// one does — a spy that answered the same rows however it was asked could not
// tell a fixed lane from a broken one.

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/ratelimit"
	"netops/backend/internal/verify"
	"netops/backend/models"
)

const (
	vrfCaseID     = "5c1f9a10-1111-4444-8888-cccccccccccc"
	vrfHypothesis = "acme-wan-edge-brownout"
	vrfDevice     = "acme-edge-1"
)

// vrfCorrCurrentCH emulates what ClickHouse actually does with the two rules
// this lane depends on: acme's corr_current row comes back unless the caller's
// tenant_scope excludes it (the STRICT row policy) or the SQL excludes it (the
// tenant_id predicate).
type vrfCorrCurrentCH struct {
	acme  string
	calls *[]struct{ scope, sql string }
}

func (c vrfCorrCurrentCH) start(t *testing.T) {
	t.Helper()
	row := `{"tenant_id":"` + c.acme + `","state":"open","verdict":"suspected",` +
		`"affected":"{\"devices\":[\"` + vrfDevice + `\"],\"paths\":[]}",` +
		`"owner":"wan","top_hypothesis":"` + vrfHypothesis + `",` +
		`"window_start":"2026-09-01T12:00:00Z"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql := readAllLimited(r)
		scope := r.URL.Query().Get("tenant_scope")
		*c.calls = append(*c.calls, struct{ scope, sql string }{scope, sql})
		w.Header().Set("Content-Type", "application/json")
		visible := (scope == "__all__" || scope == c.acme) &&
			!strings.Contains(sql, "tenant_id NOT IN ('"+c.acme+"')")
		if visible && strings.Contains(sql, "netops.corr_current") && strings.Contains(sql, vrfCaseID) {
			_, _ = w.Write([]byte(`{"data":[` + row + `]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

type restrictedVerifyFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
	calls  []struct{ scope, sql string }
}

func newRestrictedVerifyFixture(t *testing.T) *restrictedVerifyFixture {
	t.Helper()
	t.Setenv("FEATURE_ACTIVE_VERIFICATION", "true")
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
	f := &restrictedVerifyFixture{t: t, acme: acme.ID, globex: globex.ID}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: vrfDevice, Name: vrfDevice, Address: "10.1.0.1",
		TenantID: acme.ID, Source: "test", LastSeen: time.Now()})
	f.s = &server{
		roles: roles, tenants: ts, discovery: d,
		verifyCfg:     verify.NewConfigStore(filepath.Join(dir, "verify_config.json"), nil),
		verifyRuns:    verify.NewRunStore(filepath.Join(dir, "verify_runs.json")),
		verifyLimiter: ratelimit.New(),
	}
	vrfCorrCurrentCH{acme: acme.ID, calls: &f.calls}.start(t)
	return f
}

// get drives GET /api/correlations/{id}/verify through the production handler.
func (f *restrictedVerifyFixture) get(claims jwtClaims) (int, string) {
	f.t.Helper()
	f.calls = nil
	w := httptest.NewRecorder()
	path := "/api/correlations/" + vrfCaseID + "/verify"
	f.s.handleCorrelationVerify(w, req(http.MethodGet, path, "", claims), vrfCaseID)
	return w.Code, w.Body.String()
}

// post drives POST /api/correlations/{id}/verify — the half that would start
// live SSH work inside the hidden tenant's estate.
func (f *restrictedVerifyFixture) post(claims jwtClaims) (int, string) {
	f.t.Helper()
	f.calls = nil
	w := httptest.NewRecorder()
	path := "/api/correlations/" + vrfCaseID + "/verify"
	f.s.handleCorrelationVerify(w, req(http.MethodPost, path, "", claims), vrfCaseID)
	return w.Code, w.Body.String()
}

// TestActiveVerificationHonoursTheOperatorVisibilityRestriction asserts BOTH
// halves on BOTH methods.
func TestActiveVerificationHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedVerifyFixture(t)
	owner := platformOwner()

	// Baseline. Without this the assertions below could pass on a path that
	// 404s for some unrelated reason and prove nothing at all.
	code, body := f.get(owner)
	if code != http.StatusOK {
		t.Fatalf("baseline: the fixture does not reach acme's case at all: %d %s", code, body)
	}
	if len(f.calls) == 0 {
		t.Fatal("baseline issued no ClickHouse read — this fixture proves nothing")
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the owner's GLOBAL view. '__all__' means all, so the exclusion
	//    has to ride in the SQL. The answer is the same 404 an absent case gets
	//    — never a 403, which would confirm the case exists.
	for _, tc := range []struct {
		name string
		call func(jwtClaims) (int, string)
	}{{"GET", f.get}, {"POST", f.post}} {
		code, body = tc.call(owner)
		if code != http.StatusNotFound {
			t.Errorf("RESTRICTION LEAK: %s .../verify in the Global view = %d, want 404: %s", tc.name, code, body)
		}
		for _, leak := range []string{vrfHypothesis, vrfDevice} {
			if strings.Contains(body, leak) {
				t.Errorf("RESTRICTION LEAK: the Global-view %s response carries acme's %q: %s", tc.name, leak, body)
			}
		}
		if len(f.calls) == 0 {
			t.Fatalf("%s issued no ClickHouse read — this fixture proves nothing", tc.name)
		}
		for i, c := range f.calls {
			if !strings.Contains(c.sql, "tenant_id NOT IN ('"+f.acme+"')") {
				t.Errorf("RESTRICTION LEAK: %s Global-view read %d does not exclude the restricted tenant.\nscope=%s\nSQL: %s",
					tc.name, i, c.scope, c.sql)
			}
			if strings.Contains(c.sql, f.globex) {
				t.Errorf("%s read %d excluded globex, which is not restricted.\nSQL: %s", tc.name, i, c.sql)
			}
		}
	}

	// ── half 2: as_tenant into the restricted tenant. Every read goes out at
	//    the read-nothing scope, which is what the STRICT row policies enforce.
	//    A tenant named in the request is a REQUEST, not an authority: it is
	//    ignored the moment the restriction applies to it.
	for _, tc := range []struct {
		name string
		call func(jwtClaims) (int, string)
	}{{"GET", f.get}, {"POST", f.post}} {
		code, body = tc.call(ownerActing(owner, f.acme))
		if code != http.StatusNotFound {
			t.Errorf("RESTRICTION LEAK: %s .../verify?as_tenant=acme = %d, want 404: %s", tc.name, code, body)
		}
		for _, leak := range []string{vrfHypothesis, vrfDevice} {
			if strings.Contains(body, leak) {
				t.Errorf("RESTRICTION LEAK: the as_tenant %s response carries acme's %q: %s", tc.name, leak, body)
			}
		}
		if len(f.calls) == 0 {
			t.Fatalf("%s as_tenant issued no ClickHouse read — this fixture proves nothing", tc.name)
		}
		for i, c := range f.calls {
			if c.scope != chScopeNone {
				t.Errorf("RESTRICTION LEAK: %s as_tenant read %d went out at scope %q, want %q.\nSQL: %s",
					tc.name, i, c.scope, chScopeNone, c.sql)
			}
		}
	}
	// The run store must be untouched: a denied POST starts nothing.
	if _, ok := f.s.verifyRuns.Latest(f.acme, vrfCaseID); ok {
		t.Error("RESTRICTION LEAK: a denied POST started a verification run against the restricted tenant's devices")
	}

	// ── as_tenant into the UNRESTRICTED tenant is untouched by the restriction.
	if _, _ = f.get(ownerActing(owner, f.globex)); len(f.calls) == 0 {
		t.Fatal("as_tenant=globex issued no read")
	}
	for i, c := range f.calls {
		if c.scope != f.globex {
			t.Errorf("as_tenant=globex read %d went out at scope %q, want %q", i, c.scope, f.globex)
		}
	}

	// ── acme's OWN users still reach their own case. The switch hides a tenant
	//    from the PLATFORM, never from itself.
	acmeOwn := jwtClaims{Sub: "a@acme", Role: RoleSuperAdmin, Tenant: f.acme}
	code, body = f.get(acmeOwn)
	if code != http.StatusOK {
		t.Fatalf("acme's own user lost its own case: %d %s", code, body)
	}
	for i, c := range f.calls {
		if c.scope != f.acme {
			t.Errorf("acme's own read %d went out at scope %q, want %q", i, c.scope, f.acme)
		}
		if strings.Contains(c.sql, "NOT IN ('"+f.acme+"')") {
			t.Fatalf("read %d: acme's own user was excluded from its own case:\n%s", i, c.sql)
		}
	}
}
