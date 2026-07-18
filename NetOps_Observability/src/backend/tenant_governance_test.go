package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// tenant_governance_test.go — per-tenant governance settings (Wave 4 #11).
// Invariants (§3a, tenant_display_test.go template): tenant keying in the
// store itself, default = the pre-editor hard-coded behavior, closed
// validation, writes gated on administration:admin with the tenant stamped
// from the PRINCIPAL (a body tenant is ignored), audited.

func governanceTestServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	rs, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	au, err := newAuditStore(dir + "/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	return &server{roles: rs, audit: au, governance: newTenantGovernanceStore(dir + "/governance.json")}
}

func TestGovernanceStoreRequiredTagsDefaultsAndKeying(t *testing.T) {
	st := newTenantGovernanceStore("")
	tags, custom := st.requiredTags("t-a")
	if custom || !reflect.DeepEqual(tags, []string{"app", "owner", "env"}) {
		t.Fatalf("unconfigured tenant = (%v,%v), want default app/owner/env", tags, custom)
	}
	st.setRequiredTags("t-a", []string{"app", "cost_center"})
	if tags, custom = st.requiredTags("t-a"); !custom || !reflect.DeepEqual(tags, []string{"app", "cost_center"}) {
		t.Fatalf("t-a = (%v,%v)", tags, custom)
	}
	// §3a: another tenant's read is keyed separately — never t-a's list.
	if tags, custom = st.requiredTags("t-b"); custom || len(tags) != 3 {
		t.Fatalf("t-b = (%v,%v) — cross-tenant bleed", tags, custom)
	}
	// Reset returns the tenant to the default.
	st.setRequiredTags("t-a", nil)
	if _, custom = st.requiredTags("t-a"); custom {
		t.Fatal("reset tenant must read as default")
	}
	var nilStore *tenantGovernanceStore
	if tags, _ = nilStore.requiredTags("t-a"); len(tags) != 3 {
		t.Fatalf("nil store must serve the default, got %v", tags)
	}
}

func TestNormalizeRequiredTags(t *testing.T) {
	got, err := normalizeRequiredTags([]string{" App ", "cost_center", "app", "team/unit"})
	if err != nil || !reflect.DeepEqual(got, []string{"app", "cost_center", "team/unit"}) {
		t.Fatalf("normalize = (%v, %v)", got, err)
	}
	bad := [][]string{
		nil,                          // empty
		{""},                         // blank entry
		{"has space"},                // charset
		{"quote'"},                   // charset (SQL-ish)
		{strings.Repeat("a", 65)},    // too long
		make([]string, 33),           // too many
	}
	for i := range bad {
		if bad[i] != nil && len(bad[i]) == 33 {
			for j := range bad[i] {
				bad[i][j] = "t" + strings.Repeat("x", j%3)
			}
		}
		if _, err := normalizeRequiredTags(bad[i]); err == nil {
			t.Errorf("normalizeRequiredTags(%v) must fail", bad[i])
		}
	}
}

func TestRequiredTagsHandlerIsolation(t *testing.T) {
	s := governanceTestServer(t)
	admA := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "adm-a"}
	admB := jwtClaims{Role: "admin", Tenant: "t-b", Sub: "adm-b"}
	viewerA := jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "user-a"}

	put := func(c jwtClaims, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/settings/required-tags", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleRequiredTagsSettings(rec, claimsCtx(r, c))
		return rec
	}
	get := func(c jwtClaims) (tags []string, isDefault bool, tenant string) {
		r := httptest.NewRequest(http.MethodGet, "/api/settings/required-tags", nil)
		rec := httptest.NewRecorder()
		s.handleRequiredTagsSettings(rec, claimsCtx(r, c))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d", rec.Code)
		}
		var out struct {
			TenantID     string   `json:"tenant_id"`
			RequiredTags []string `json:"required_tags"`
			IsDefault    bool     `json:"is_default"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.RequiredTags, out.IsDefault, out.TenantID
	}

	// Tenant admin sets its OWN tenant — a tenant_id in the body is IGNORED.
	if rec := put(admA, `{"required_tags":["app","cost_center"],"tenant_id":"t-b"}`); rec.Code != http.StatusOK {
		t.Fatalf("admin PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if tags, isDef, tenant := get(admA); tenant != "t-a" || isDef || !reflect.DeepEqual(tags, []string{"app", "cost_center"}) {
		t.Fatalf("t-a sees (%v,%v,%q), want its own custom list", tags, isDef, tenant)
	}
	// §3a: tenant B is untouched by A's write (and by A's body claim).
	if tags, isDef, _ := get(admB); !isDef || len(tags) != 3 {
		t.Fatalf("t-b sees (%v,%v) — cross-tenant write leak", tags, isDef)
	}
	// A non-admin of the same tenant READS the tenant's list…
	if tags, _, _ := get(viewerA); !reflect.DeepEqual(tags, []string{"app", "cost_center"}) {
		t.Fatalf("viewer of t-a sees %v", tags)
	}
	// …but cannot write it (governance PUT = administration:admin, never weaker).
	if rec := put(viewerA, `{"required_tags":["app"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT = %d, want 403", rec.Code)
	}
	// Closed validation → 400, never a silent trim.
	if rec := put(admA, `{"required_tags":["bad key!"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad tag PUT = %d, want 400", rec.Code)
	}
	// Reset restores the default.
	if rec := put(admA, `{"reset":true}`); rec.Code != http.StatusOK {
		t.Fatalf("reset PUT = %d", rec.Code)
	}
	if _, isDef, _ := get(admA); !isDef {
		t.Fatal("reset must restore the default list")
	}
	// Unauthenticated GET → 401.
	r := httptest.NewRequest(http.MethodGet, "/api/settings/required-tags", nil)
	rec := httptest.NewRecorder()
	s.handleRequiredTagsSettings(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon GET = %d, want 401", rec.Code)
	}
	// The write is audited with its own action.
	found := false
	for _, e := range s.audit.List("t-a", false, auditQuery{}) {
		if e.Detail["action"] == "set_required_tags" {
			found = true
		}
	}
	if !found {
		t.Fatal("required-tags change must be audited")
	}
}
