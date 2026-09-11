// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// seclane_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// per-tenant OPERATOR-VISIBILITY restriction (Tenant.OperatorRestricted) on the
// security producer lane's two operator surfaces.
//
// A lane status row is not a finding, but it is derived from one tenant's estate
// and it says a lot about it: how many of its devices were assessed, how many
// security findings the pass emitted about them, how many were truncated, and a
// per-lane error string taken from the scan itself. Under the restriction the
// platform owner sees nothing of that tenant, so it must see none of that
// either.
//
// Run through the REAL s.securityAuthz gate mapping and a REAL tenant store, so
// the switch under test is the production one (Tenant.OperatorRestricted →
// effectiveRestrictedIDs → operatorTelemetryRestriction).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/seclane"
	"netops/backend/models"
	"netops/backend/secapi"
)

type restrictedSecLaneFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
}

func newRestrictedSecLaneFixture(t *testing.T) *restrictedSecLaneFixture {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	tenants, err := newTenantStore(dir + "/tenants.json")
	if err != nil {
		t.Fatalf("tenantStore: %v", err)
	}
	acme, err := tenants.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := tenants.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID})
	s := &server{roles: roles, tenants: tenants, discovery: d}
	s.secStore = secapi.NewFileStore("") // in-memory

	deps := s.securityLaneDeps()
	deps.Now = func() time.Time { return time.Date(2026, 9, 2, 4, 0, 0, 0, time.UTC) }
	deps.Tenants = func() []string { return []string{acme.ID, globex.ID} }
	deps.Publish = func(context.Context, string, []seclane.Record) (int, error) { return 0, nil }
	deps.Search = func(string, string, any) (*http.Response, error) { return nil, context.Canceled }
	deps.CHQuery = func(context.Context, string, string) ([]map[string]any, error) { return nil, nil }
	deps.Seams = func(context.Context, string) ([]seclane.SeamRow, error) { return nil, nil }
	deps.Spool = nil

	lane, err := seclane.New(deps)
	if err != nil {
		t.Fatalf("seclane.New: %v", err)
	}
	s.securityLane = lane
	lane.ScanAll(context.Background()) // one completed pass per tenant
	return &restrictedSecLaneFixture{t: t, s: s, acme: acme.ID, globex: globex.ID}
}

func (f *restrictedSecLaneFixture) status(claims jwtClaims) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.s.securityLane.HandleStatus(w, req(http.MethodGet, "/api/security/lane/status", "", claims))
	return w
}

func (f *restrictedSecLaneFixture) rows(w *httptest.ResponseRecorder) []seclane.ScanStatus {
	f.t.Helper()
	var body laneStatusBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		f.t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return body.Tenants
}

// TestSecurityLaneHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test
// for the compliance switch on this lane. It asserts BOTH halves: the restricted
// tenant's status row is absent from the platform owner's Global read, and an
// as_tenant read into that tenant returns nothing. The scan trigger, which is a
// write on that same estate, is refused.
func TestSecurityLaneHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedSecLaneFixture(t)
	owner := platformOwner()

	// Before anything is restricted the platform owner reads both rows, so the
	// test cannot pass by serving nothing.
	if got := f.rows(f.status(owner)); len(got) != 2 {
		t.Fatalf("owner (nothing restricted) saw %d rows, want 2", len(got))
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// Global view: acme's row is gone, globex's is untouched.
	w := f.status(owner)
	if w.Code != http.StatusOK {
		t.Fatalf("owner Global status = %d (%s)", w.Code, w.Body.String())
	}
	got := f.rows(w)
	if len(got) != 1 || got[0].TenantID != f.globex {
		t.Errorf("RESTRICTION LEAK: the owner's Global status = %+v, want globex's row only: %s",
			got, w.Body.String())
	}
	for _, hidden := range []string{f.acme, seclane.TenantSeg(f.acme)} {
		if strings.Contains(w.Body.String(), hidden) {
			t.Errorf("RESTRICTION LEAK: the platform owner saw %q in the lane status: %s",
				hidden, w.Body.String())
		}
	}

	// The as_tenant half: the operator walking into the restricted tenant reads
	// no row at all. A 200 with nothing in it, never a 403, which would confirm
	// the tenant has a lane.
	scoped := ownerActing(owner, f.acme)
	sw := f.status(scoped)
	if sw.Code != http.StatusOK {
		t.Fatalf("owner→acme status = %d, want 200 with no rows (%s)", sw.Code, sw.Body.String())
	}
	if got := f.rows(sw); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→acme saw %+v, want no rows: %s", got, sw.Body.String())
	}

	// The scan trigger is a WRITE on the same estate. An operator that may not
	// read a tenant's lane must not drive its evidence production either.
	scan := httptest.NewRecorder()
	f.s.securityLane.HandleScan(scan, req(http.MethodPost, "/api/security/scan", "", scoped))
	if scan.Code == http.StatusAccepted {
		t.Errorf("RESTRICTION LEAK: owner→acme enqueued a scan of the restricted tenant: %s", scan.Body.String())
	}

	// The operator scoped into the UNRESTRICTED tenant still reads it.
	if got := f.rows(f.status(ownerActing(owner, f.globex))); len(got) != 1 || got[0].TenantID != f.globex {
		t.Errorf("the unrestricted tenant's status broke: %+v", got)
	}

	// And acme's OWN admin is never restricted from acme's own lane.
	acmeAdmin := jwtClaims{Sub: "adm@acme", Role: RoleSuperAdmin, Tenant: f.acme}
	own := f.status(acmeAdmin)
	if got := f.rows(own); len(got) != 1 || got[0].TenantID != f.acme {
		t.Fatalf("acme's own admin lost its own lane row: %+v (%s)", got, own.Body.String())
	}
}
