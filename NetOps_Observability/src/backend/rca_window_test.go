package main

// rca_window_test.go — F-80 and F-81, the last two stored-not-read findings.
//
// F-80: /api/settings/rca-window persisted correctly and was honoured by SEVEN
// cloud endpoints — and by ZERO RCA endpoints, which are what the setting is
// named for. A tenant that set a 7-day RCA window kept receiving 24 hours, with
// the response reporting the window it actually used so the number looked
// authoritative.
//
// F-81: POST /api/tenants and /api/onboard both discarded the error from
// SetOperatorRestricted, so a failed write returned 201 with
// operator_restricted:false — a DATA-PRIVACY control failing open while
// reporting success.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/tenant"
	"testing"
	"time"
)

func requestWithClaims(t *testing.T, target, tenant string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return req.WithContext(context.WithValue(req.Context(), userCtxKey, jwtClaims{Sub: "u", Tenant: tenant, Role: "admin"}))
}

// No tenant override → the surface keeps its own default. A tenant that never
// touched the setting must see exactly the pre-existing behaviour.
func TestRcaSinceFallsBackToTheSurfaceDefault(t *testing.T) {
	_, s := newTestServerState(t)
	got, err := s.tenantRcaSince(requestWithClaims(t, "/api/correlations", "t-a"), 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 24*time.Hour {
		t.Errorf("since = %v, want the 24h surface default", got)
	}
	// A different surface keeps ITS default, not a globally hardcoded one.
	got, err = s.tenantRcaSince(requestWithClaims(t, "/api/correlations/stats", "t-a"), 7*24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 7*24*time.Hour {
		t.Errorf("since = %v, want the 7d surface default", got)
	}
}

// The headline defect: a tenant's configured RCA window must actually reach an
// RCA surface.
func TestRcaSinceHonoursTheTenantSetting(t *testing.T) {
	_, s := newTestServerState(t)
	if s.governance == nil {
		t.Skip("governance store not wired on this test server")
	}
	if err := s.governance.setRcaWindowHours("t-a", 168); err != nil {
		t.Fatalf("set rca window: %v", err)
	}
	got, err := s.tenantRcaSince(requestWithClaims(t, "/api/correlations", "t-a"), 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 168*time.Hour {
		t.Fatalf("since = %v, want 168h — the tenant's rca-window setting was ignored "+
			"(F-80: the setting reached 7 cloud endpoints and 0 RCA endpoints)", got)
	}
	// Another tenant must be unaffected — this is a per-tenant setting.
	other, err := s.tenantRcaSince(requestWithClaims(t, "/api/correlations", "t-b"), 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if other != 24*time.Hour {
		t.Errorf("tenant t-b since = %v, want its own 24h default", other)
	}
}

// An explicit ?since= still wins over the tenant default.
func TestExplicitSinceOverridesTheTenantSetting(t *testing.T) {
	_, s := newTestServerState(t)
	if s.governance != nil {
		if err := s.governance.setRcaWindowHours("t-a", 168); err != nil {
			t.Fatalf("set rca window: %v", err)
		}
	}
	got, err := s.tenantRcaSince(requestWithClaims(t, "/api/correlations?since=2h", "t-a"), 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 2*time.Hour {
		t.Errorf("since = %v, want the explicit 2h", got)
	}
}

// Fails CLOSED on junk — the F-71 rule. durationQuery silently substituted the
// default, so a caller asking for 90 days got 24 hours behind a 200.
func TestRcaSinceFailsClosedOnJunk(t *testing.T) {
	_, s := newTestServerState(t)
	for _, bad := range []string{"abc", "-5h", "0", "99999h", "7"} {
		if _, err := s.tenantRcaSince(requestWithClaims(t, "/api/correlations?since="+bad, "t-a"), 24*time.Hour); err == nil {
			t.Errorf("since=%q must be refused, not silently replaced by the default", bad)
		}
	}
}

// ---- F-81: operator_restricted -------------------------------------------

// The happy path first, so the failure assertion below is about the failure.
func TestTenantCreateAppliesOperatorRestricted(t *testing.T) {
	srv, s := newTestServerState(t)
	tok, _ := loginFor(t, srv.URL)

	code, out := postJSONAuth(t, srv.URL+"/api/tenants", tok,
		`{"name":"Private Co","operator_restricted":true}`)
	if code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %v)", code, out)
	}
	if out["operator_restricted"] != true {
		t.Fatalf("operator_restricted = %v, want true", out["operator_restricted"])
	}
	// And it must be true in the STORE, not merely echoed in the response.
	id, _ := out["id"].(string)
	stored, ok := s.tenants.Get(id)
	if !ok {
		t.Fatalf("tenant %s not found in the store", id)
	}
	if !stored.OperatorRestricted {
		t.Error("the response said restricted but the stored tenant is not")
	}
}

// The error the handler must surface has to EXIST first. This is the store-level
// half of F-81: SetOperatorRestricted returns a real error on a failed persist.
func TestSetOperatorRestrictedReportsAPersistFailure(t *testing.T) {
	_, s := newTestServerState(t)
	tn, err := s.tenants.Create("Private Co", "", "", "", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Break the persist path on the CONCRETE store (the seam is an interface;
	// this store-level test deliberately reaches through it).
	st, ok := s.tenants.(*tenant.Store)
	if !ok {
		t.Fatalf("test server tenants is %T, want *tenant.Store", s.tenants)
	}
	st.SetKVForTest(&faultyKV{failWith: errors.New("kv unavailable: injected")})

	if _, err := s.tenants.SetOperatorRestricted(tn.ID, true); err == nil {
		t.Fatal("SetOperatorRestricted must return a persist failure — the handler " +
			"discarded this error (F-81) and returned 201 with the privacy switch OFF")
	}
}

// failRestrictRepo delegates everything to the real store but fails
// SetOperatorRestricted — the mid-request failure INVARIANTS gap #3 said could
// not be injected while `s.tenants` was a concrete *tenantStore: the CREATE
// succeeds, only the later privacy write fails, so the handler's rollback path
// is what actually runs.
type failRestrictRepo struct {
	tenantRepo
}

func (f *failRestrictRepo) SetOperatorRestricted(ref string, restricted bool) (Tenant, error) {
	return Tenant{}, errors.New("injected: persist failed after the tenant was created")
}

// The handler-level half of F-81, end-to-end: when the privacy control cannot
// be applied, POST /api/tenants must return 500 AND remove the half-created
// tenant — never leave one that is exposed while believed to be restricted.
func TestTenantCreateRollsBackWhenRestrictionFails(t *testing.T) {
	srv, s := newTestServerState(t)
	real := s.tenants
	s.tenants = &failRestrictRepo{tenantRepo: real}
	tok, _ := loginFor(t, srv.URL)

	code, out := postJSONAuth(t, srv.URL+"/api/tenants", tok,
		`{"name":"Private Co","operator_restricted":true}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("create = %d, want 500 — a failed privacy control must not report success (body %v)", code, out)
	}
	if tn, ok := real.Resolve("private-co"); ok {
		t.Fatalf("tenant %s still exists after the rollback — exposed and believed restricted", tn.ID)
	}
}

// Same failure injected into POST /api/onboard: the rollback must remove BOTH
// the tenant and the org, or a failed onboard leaves a tenant-less org shell.
func TestOnboardRollsBackWhenRestrictionFails(t *testing.T) {
	srv, s := newTestServerState(t)
	real := s.tenants
	s.tenants = &failRestrictRepo{tenantRepo: real}
	tok, _ := loginFor(t, srv.URL)

	code, out := postJSONAuth(t, srv.URL+"/api/onboard", tok,
		`{"org_name":"Acme","tenant_name":"Acme Prod","operator_restricted":true}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("onboard = %d, want 500 (body %v)", code, out)
	}
	if tn, ok := real.Resolve("acme-prod"); ok {
		t.Fatalf("tenant %s still exists after the onboard rollback", tn.ID)
	}
	if o, ok := s.orgs.Resolve("acme"); ok {
		t.Fatalf("org %s still exists after the onboard rollback — a tenant-less shell", o.ID)
	}
}

// An unknown tenant must also error rather than silently no-op.
func TestSetOperatorRestrictedRejectsUnknownTenant(t *testing.T) {
	_, s := newTestServerState(t)
	if _, err := s.tenants.SetOperatorRestricted("t-does-not-exist", true); err == nil {
		t.Fatal("SetOperatorRestricted on an unknown tenant must error")
	}
}

// A tenant created WITHOUT the flag is unaffected by all of the above.
func TestTenantCreateWithoutTheFlagIsUnchanged(t *testing.T) {
	srv, _ := newTestServerState(t)
	tok, _ := loginFor(t, srv.URL)
	code, out := postJSONAuth(t, srv.URL+"/api/tenants", tok, `{"name":"Normal Co"}`)
	if code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %v)", code, out)
	}
	if out["operator_restricted"] == true {
		t.Error("operator_restricted must default to false")
	}
}
