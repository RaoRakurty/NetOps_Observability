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
		if len(bad[i]) == 33 {
			for j := range bad[i] {
				bad[i][j] = "t" + strings.Repeat("x", j%3)
			}
		}
		if _, err := normalizeRequiredTags(bad[i]); err == nil {
			t.Errorf("normalizeRequiredTags(%v) must fail", bad[i])
		}
	}
}

func TestGovernanceStoreRcaWindowDefaultsAndKeying(t *testing.T) {
	st := newTenantGovernanceStore("")
	if h, custom := st.rcaWindowHours("t-a"); custom || h != cloudSignalWindowHours {
		t.Fatalf("unconfigured tenant = (%d,%v), want default %d", h, custom, cloudSignalWindowHours)
	}
	st.setRcaWindowHours("t-a", 72)
	if h, custom := st.rcaWindowHours("t-a"); !custom || h != 72 {
		t.Fatalf("t-a = (%d,%v), want 72", h, custom)
	}
	// §3a: keyed per tenant — t-b keeps the default.
	if h, custom := st.rcaWindowHours("t-b"); custom || h != cloudSignalWindowHours {
		t.Fatalf("t-b = (%d,%v) — cross-tenant bleed", h, custom)
	}
	// Reset (0) restores the default; an off-bounds stored value clamps on read.
	st.setRcaWindowHours("t-a", 0)
	if _, custom := st.rcaWindowHours("t-a"); custom {
		t.Fatal("reset tenant must read as default")
	}
	st.setRcaWindowHours("t-a", 10_000)
	if h, _ := st.rcaWindowHours("t-a"); h != cloudSignalWindowMaxHours {
		t.Fatalf("oversize stored window must clamp on read, got %d", h)
	}
	var nilStore *tenantGovernanceStore
	if h, _ := nilStore.rcaWindowHours("t-a"); h != cloudSignalWindowHours {
		t.Fatalf("nil store must serve the default, got %d", h)
	}
}

func TestNormalizeRcaWindowHours(t *testing.T) {
	for _, ok := range []int{1, 24, 168} {
		if got, err := normalizeRcaWindowHours(ok); err != nil || got != ok {
			t.Errorf("normalizeRcaWindowHours(%d) = (%d,%v)", ok, got, err)
		}
	}
	for _, bad := range []int{0, -1, 169, 100000} {
		if _, err := normalizeRcaWindowHours(bad); err == nil {
			t.Errorf("normalizeRcaWindowHours(%d) must fail — clamped bounds", bad)
		}
	}
}

// tenantWindowHours: an explicit ?window_hours= wins (clamped); absent/junk
// falls back to the CALLER's tenant default, never another tenant's.
func TestTenantWindowHours(t *testing.T) {
	s := governanceTestServer(t)
	s.governance.setRcaWindowHours("t-a", 72)
	admA := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "adm-a"}
	admB := jwtClaims{Role: "admin", Tenant: "t-b", Sub: "adm-b"}

	at := func(c jwtClaims, url string) int {
		r := httptest.NewRequest(http.MethodGet, url, nil)
		return s.tenantWindowHours(claimsCtx(r, c))
	}
	if got := at(admA, "/api/cloud/health"); got != 72 {
		t.Fatalf("t-a default window = %d, want its governed 72", got)
	}
	if got := at(admB, "/api/cloud/health"); got != cloudSignalWindowHours {
		t.Fatalf("t-b default window = %d — cross-tenant bleed", got)
	}
	if got := at(admA, "/api/cloud/health?window_hours=6"); got != 6 {
		t.Fatalf("explicit window = %d, want 6 (caller wins)", got)
	}
	if got := at(admA, "/api/cloud/health?window_hours=9999"); got != cloudSignalWindowMaxHours {
		t.Fatalf("oversize explicit window = %d, want clamp %d", got, cloudSignalWindowMaxHours)
	}
	if got := at(admA, "/api/cloud/health?window_hours=junk"); got != 72 {
		t.Fatalf("junk window = %d, want tenant default 72", got)
	}
}

func TestRcaWindowHandlerIsolation(t *testing.T) {
	s := governanceTestServer(t)
	admA := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "adm-a"}
	admB := jwtClaims{Role: "admin", Tenant: "t-b", Sub: "adm-b"}
	viewerA := jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "user-a"}

	put := func(c jwtClaims, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/settings/rca-window", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleRcaWindowSettings(rec, claimsCtx(r, c))
		return rec
	}
	get := func(c jwtClaims) (hours int, isDefault bool, tenant string) {
		r := httptest.NewRequest(http.MethodGet, "/api/settings/rca-window", nil)
		rec := httptest.NewRecorder()
		s.handleRcaWindowSettings(rec, claimsCtx(r, c))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d", rec.Code)
		}
		var out struct {
			TenantID       string `json:"tenant_id"`
			RcaWindowHours int    `json:"rca_window_hours"`
			IsDefault      bool   `json:"is_default"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.RcaWindowHours, out.IsDefault, out.TenantID
	}

	// Tenant admin sets its OWN tenant — a tenant_id in the body is IGNORED.
	if rec := put(admA, `{"rca_window_hours":72,"tenant_id":"t-b"}`); rec.Code != http.StatusOK {
		t.Fatalf("admin PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if h, isDef, tenant := get(admA); tenant != "t-a" || isDef || h != 72 {
		t.Fatalf("t-a sees (%d,%v,%q), want its own 72", h, isDef, tenant)
	}
	// §3a: tenant B is untouched by A's write.
	if h, isDef, _ := get(admB); !isDef || h != cloudSignalWindowHours {
		t.Fatalf("t-b sees (%d,%v) — cross-tenant write leak", h, isDef)
	}
	// Viewer reads, cannot write (governance PUT = administration:admin).
	if h, _, _ := get(viewerA); h != 72 {
		t.Fatalf("viewer of t-a sees %d", h)
	}
	if rec := put(viewerA, `{"rca_window_hours":24}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT = %d, want 403", rec.Code)
	}
	// Off-bounds → 400, never a silent clamp on write.
	if rec := put(admA, `{"rca_window_hours":999}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize PUT = %d, want 400", rec.Code)
	}
	// Reset restores the default; the write is audited.
	if rec := put(admA, `{"reset":true}`); rec.Code != http.StatusOK {
		t.Fatalf("reset PUT = %d", rec.Code)
	}
	if _, isDef, _ := get(admA); !isDef {
		t.Fatal("reset must restore the default window")
	}
	found := false
	for _, e := range s.audit.List("t-a", false, auditQuery{}) {
		if e.Detail["action"] == "set_rca_window" {
			found = true
		}
	}
	if !found {
		t.Fatal("rca-window change must be audited")
	}
}

func TestGovernanceStorePrecedenceDefaultsAndKeying(t *testing.T) {
	st := newTenantGovernanceStore("")
	if order, custom := st.attributionPrecedence("t-a"); custom || order != nil {
		t.Fatalf("unconfigured tenant = (%v,%v), want default", order, custom)
	}
	reordered := []string{"firewall_appid", "operator", "cloud_tag", "cloud_graph", "domain", "ip_catalog"}
	st.setAttributionPrecedence("t-a", reordered)
	if order, custom := st.attributionPrecedence("t-a"); !custom || !reflect.DeepEqual(order, reordered) {
		t.Fatalf("t-a = (%v,%v)", order, custom)
	}
	// §3a: keyed per tenant.
	if _, custom := st.attributionPrecedence("t-b"); custom {
		t.Fatal("t-b must stay default — cross-tenant bleed")
	}
	// A stored order that no longer validates reads as default, never trusted.
	st.setAttributionPrecedence("t-a", []string{"bogus"})
	if _, custom := st.attributionPrecedence("t-a"); custom {
		t.Fatal("invalid stored order must fall back to default")
	}
	var nilStore *tenantGovernanceStore
	if order, custom := nilStore.attributionPrecedence("t-a"); custom || order != nil {
		t.Fatalf("nil store = (%v,%v)", order, custom)
	}
}

func TestAttributionPrecedenceHandlerIsolation(t *testing.T) {
	s := governanceTestServer(t)
	admA := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "adm-a"}
	admB := jwtClaims{Role: "admin", Tenant: "t-b", Sub: "adm-b"}
	viewerA := jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "user-a"}

	put := func(c jwtClaims, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/settings/attribution-precedence", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleAttributionPrecedenceSettings(rec, claimsCtx(r, c))
		return rec
	}
	get := func(c jwtClaims) (order []string, isDefault bool, tenant string) {
		r := httptest.NewRequest(http.MethodGet, "/api/settings/attribution-precedence", nil)
		rec := httptest.NewRecorder()
		s.handleAttributionPrecedenceSettings(rec, claimsCtx(r, c))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d", rec.Code)
		}
		var out struct {
			TenantID              string   `json:"tenant_id"`
			AttributionPrecedence []string `json:"attribution_precedence"`
			IsDefault             bool     `json:"is_default"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.AttributionPrecedence, out.IsDefault, out.TenantID
	}

	reordered := `["firewall_appid","operator","cloud_tag","cloud_graph","domain","ip_catalog"]`
	// Tenant admin sets its OWN tenant — a tenant_id in the body is IGNORED.
	if rec := put(admA, `{"attribution_precedence":`+reordered+`,"tenant_id":"t-b"}`); rec.Code != http.StatusOK {
		t.Fatalf("admin PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if order, isDef, tenant := get(admA); tenant != "t-a" || isDef || order[0] != "firewall_appid" {
		t.Fatalf("t-a sees (%v,%v,%q)", order, isDef, tenant)
	}
	// §3a: tenant B is untouched by A's write.
	if _, isDef, _ := get(admB); !isDef {
		t.Fatal("t-b must stay default — cross-tenant write leak")
	}
	// Viewer reads, cannot write.
	if order, _, _ := get(viewerA); order[0] != "firewall_appid" {
		t.Fatalf("viewer of t-a sees %v", order)
	}
	if rec := put(viewerA, `{"attribution_precedence":`+reordered+`}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT = %d, want 403", rec.Code)
	}
	// NOT a permutation → 400 (missing class / duplicate / unknown class).
	for _, bad := range []string{
		`{"attribution_precedence":["operator"]}`,
		`{"attribution_precedence":["operator","operator","cloud_tag","firewall_appid","cloud_graph","domain"]}`,
		`{"attribution_precedence":["operator","cloud_tag","firewall_appid","cloud_graph","domain","asn"]}`,
	} {
		if rec := put(admA, bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT %s = %d, want 400", bad, rec.Code)
		}
	}
	// Reset restores the default; the write is audited.
	if rec := put(admA, `{"reset":true}`); rec.Code != http.StatusOK {
		t.Fatalf("reset PUT = %d", rec.Code)
	}
	if _, isDef, _ := get(admA); !isDef {
		t.Fatal("reset must restore the default order")
	}
	found := false
	for _, e := range s.audit.List("t-a", false, auditQuery{}) {
		if e.Detail["action"] == "set_attribution_precedence" {
			found = true
		}
	}
	if !found {
		t.Fatal("precedence change must be audited")
	}
}

// The governance audit view: admin-gated, scoped to the caller's audit
// visibility, and filtered to the settings actions only (§3a: a tenant admin
// never sees another tenant's governance changes).
func TestGovernanceAuditViewScopedAndFiltered(t *testing.T) {
	s := governanceTestServer(t)
	admA := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "adm-a"}
	admB := jwtClaims{Role: "admin", Tenant: "t-b", Sub: "adm-b"}
	viewerA := jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "user-a"}

	put := func(c jwtClaims, path, body string, h http.HandlerFunc) {
		r := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h(rec, claimsCtx(r, c))
		if rec.Code != http.StatusOK {
			t.Fatalf("seed PUT %s = %d: %s", path, rec.Code, rec.Body.String())
		}
	}
	// Seed: governance writes in BOTH tenants + a non-governance event in t-a.
	put(admA, "/api/settings/required-tags", `{"required_tags":["app","cost_center"]}`, s.handleRequiredTagsSettings)
	put(admA, "/api/settings/rca-window", `{"rca_window_hours":72}`, s.handleRcaWindowSettings)
	put(admB, "/api/settings/rca-window", `{"rca_window_hours":6}`, s.handleRcaWindowSettings)
	s.audit.Record(AuditEvent{Actor: "adm-a", Tenant: "t-a", Method: "POST", Path: "/api/devices", Status: 200, Decision: "allow"})

	get := func(c jwtClaims) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/settings/governance-audit", nil)
		rec := httptest.NewRecorder()
		s.handleGovernanceAudit(rec, claimsCtx(r, c))
		return rec
	}
	rec := get(admA)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET = %d", rec.Code)
	}
	var out struct {
		Events []AuditEvent `json:"events"`
		Count  int          `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 2 || len(out.Events) != 2 {
		t.Fatalf("t-a admin sees %d events, want exactly its 2 governance writes: %+v", out.Count, out.Events)
	}
	for _, e := range out.Events {
		if e.Tenant != "t-a" {
			t.Fatalf("cross-tenant audit leak: %+v", e)
		}
		if !isGovernanceAuditAction(e.Detail["action"]) {
			t.Fatalf("non-governance event leaked into the view: %+v", e)
		}
	}
	// Non-admin → 403 (audit visibility is admin-gated like /api/audit).
	if rec := get(viewerA); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET = %d, want 403", rec.Code)
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
