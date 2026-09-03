package backend

// security_findings_isolation_test.go — the CLAUDE.md §3a rule 5 cross-org test
// for the Project 3 Security (CTEM) read API. org_isolation_test.go /
// rca_feedback_isolation_test.go are the templates.
//
// The OpenSearch stand-in RECORDS the index pattern and the query body of every
// request, because the two halves of the §3a chokepoint are exactly those two
// things: the pattern is the at-rest boundary (another tenant's indices are
// never NAMED, so its documents are unreachable even if a filter were dropped)
// and the body carries the per-doc tenant clause underneath it. A test that
// only checked the response would pass against an implementation that queried
// every tenant's index and filtered in Go.
//
// Proven here:
//   - own-only list: the pattern is the caller's segment + untagged, never
//     another tenant's, and the body carries the tenant clause;
//   - a platform (cross-tenant) caller gets `netops-secfindings-*` and NO
//     per-doc clause — the deliberate, and only, cross-tenant read;
//   - cross-tenant GET by id → 404, indistinguishable from a missing id;
//   - ?as_tenant= into another org is IGNORED for a non-owner on every route;
//   - the PG/file control-plane state (rules + saved views) is own-only, and a
//     cross-tenant view id → 404;
//   - posture never mixes tenants: both of its queries carry the same pattern
//     and clause, and `scope` counts only the caller's own devices;
//   - filter validation answers 400 (never a silently empty result) and the
//     limit cap is enforced;
//   - every read increments netops_security_findings_queries_total{op}.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/secapi"
)

// secOSCall is one recorded OpenSearch request.
type secOSCall struct {
	Index string // the index pattern the API named (the at-rest boundary)
	Body  string // the raw query DSL (the per-doc tenant clause lives here)
}

// secFakeOS stands in for OpenSearch. `docs` is keyed by the index pattern the
// caller must have used to see them: a request that names a DIFFERENT pattern
// gets zero hits, which is precisely how at-rest separation turns a
// cross-tenant lookup into a 404 upstream.
type secFakeOS struct {
	mu    sync.Mutex
	calls []secOSCall
	docs  map[string]string // index pattern → canned `hits.hits` JSON array body
	aggs  string            // canned `aggregations` object, or ""
}

func (f *secFakeOS) record(c secOSCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func (f *secFakeOS) all() []secOSCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]secOSCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// secStartFakeOS wires the stand-in into the env the real client reads.
func secStartFakeOS(t *testing.T, fake *secFakeOS) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // test double: a short read is a failed assertion below
		index := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/_search")
		fake.record(secOSCall{Index: index, Body: string(body)})
		hits := fake.docs[index]
		if hits == "" {
			hits = "[]"
		}
		n := strings.Count(hits, `"_id"`)
		out := `{"took":1,"timed_out":false,"hits":{"total":{"value":` +
			strconv.Itoa(n) + `,"relation":"eq"},"hits":` + hits + `}`
		if fake.aggs != "" {
			out += `,"aggregations":` + fake.aggs
		}
		out += "}"
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(out))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
}

// secDoc renders one canned findings document for a tenant.
func secDoc(id, tenant, severity, status, seam, device string) string {
	return `{"_index":"netops-secfindings-` + tenant + `-2026.09.01","_id":"` + id + `",` +
		`"_source":{"tenant_id":"` + tenant + `","ts":1756684800000,"severity":"` + severity + `",` +
		`"entity_id":"` + device + `","native_id":"n-` + id + `","seam_type":"` + seam + `",` +
		`"attrs":{"status":"` + status + `","scan_id":"scan-1","evidence_class":"posture",` +
		`"control_id":"AC-17","standards":["CIS:1.2"]}},"sort":[1756684800000,"` + id + `"]}`
}

// secTestServer builds the minimal server the security handlers need, with the
// in-memory control-plane store and a two-tenant device registry.
func secTestServer(t *testing.T) *server {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "acme-edge", Name: "acme-edge", Address: "10.1.0.2", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	s := &server{roles: roles, discovery: d}
	s.secStore = secapi.NewFileStore("") // in-memory
	s.secFindMetrics = secapi.NewMetrics()
	s.secAPI = secapi.New(s.securityAPIDeps())
	return s
}

// secPatternFor is the index pattern a scoped tenant must name — and the ONLY
// one it may name.
func secPatternFor(tenant string) string {
	return "netops-secfindings-" + tenant + "-*,netops-secfindings-untagged-*"
}

// ---- list -------------------------------------------------------------------

func TestSecurityFindingsListIsOwnTenantOnly(t *testing.T) {
	fake := &secFakeOS{docs: map[string]string{
		secPatternFor("acme"):   "[" + secDoc("a1", "acme", "critical", "Fail", "ISP", "acme-core") + "]",
		secPatternFor("globex"): "[" + secDoc("g1", "globex", "high", "Fail", "ISP", "globex-core") + "]",
	}}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d (%s)", w.Code, w.Body.String())
	}
	calls := fake.all()
	if len(calls) != 1 {
		t.Fatalf("want exactly 1 OpenSearch query, got %d", len(calls))
	}
	if calls[0].Index != secPatternFor("acme") {
		t.Fatalf("index pattern = %q, want %q", calls[0].Index, secPatternFor("acme"))
	}
	if strings.Contains(calls[0].Index, "globex") {
		t.Fatal("TENANT LEAK: the query NAMED another tenant's index family")
	}
	if !strings.Contains(calls[0].Body, `{"term":{"tenant_id":"acme"}}`) {
		t.Fatalf("the per-doc tenant clause is missing from the body: %s", calls[0].Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"id":"a1"`) {
		t.Fatalf("acme's own finding missing: %s", body)
	}
	if strings.Contains(body, "g1") || strings.Contains(body, "globex") {
		t.Fatalf("TENANT LEAK: acme's list carried globex data: %s", body)
	}
	var page struct {
		Items      []map[string]any `json:"items"`
		NextCursor *string          `json:"next_cursor"`
		Total      int64            `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page = %+v, want 1 item / total 1", page)
	}
	if page.NextCursor != nil {
		t.Fatalf("a short page must advertise next_cursor null, got %q", *page.NextCursor)
	}
	if n := s.secFindMetrics.Snapshot()["list"]; n != 1 {
		t.Fatalf("netops_security_findings_queries_total{op=\"list\"} = %d, want 1", n)
	}
}

// TestSecurityFindingsPlatformOwnerReadsEveryTenant is the other side of the
// boundary: the cross-tenant platform view gets the wildcard pattern and NO
// per-doc clause. That is the one deliberate cross-tenant read, and it must be
// reachable only this way.
func TestSecurityFindingsPlatformOwnerReadsEveryTenant(t *testing.T) {
	fake := &secFakeOS{docs: map[string]string{
		"netops-secfindings-*": "[" + secDoc("a1", "acme", "critical", "Fail", "ISP", "acme-core") +
			"," + secDoc("g1", "globex", "high", "Fail", "ISP", "globex-core") + "]",
	}}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings", "", platformOwner()))
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d (%s)", w.Code, w.Body.String())
	}
	calls := fake.all()
	if calls[0].Index != "netops-secfindings-*" {
		t.Fatalf("platform pattern = %q, want netops-secfindings-*", calls[0].Index)
	}
	if strings.Contains(calls[0].Body, `"tenant_id"`) {
		t.Fatalf("the platform view must carry no per-doc tenant clause: %s", calls[0].Body)
	}
	if body := w.Body.String(); !strings.Contains(body, "a1") || !strings.Contains(body, "g1") {
		t.Fatalf("platform owner should see every tenant: %s", body)
	}
}

// TestSecurityFindingCrossTenantGetIs404 — §3a rule 1. globex's finding id is
// simply not in acme's index pattern, so the lookup returns nothing and the
// handler answers 404: the same answer a nonexistent id gets, so existence is
// never revealed.
func TestSecurityFindingCrossTenantGetIs404(t *testing.T) {
	fake := &secFakeOS{docs: map[string]string{
		secPatternFor("globex"): "[" + secDoc("g1", "globex", "high", "Fail", "ISP", "globex-core") + "]",
	}}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet, "/api/security/findings/g1", "", acme()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get = %d (%s), want 404", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("the 404 revealed the other tenant: %s", w.Body.String())
	}
	// A genuinely missing id is answered identically.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet, "/api/security/findings/nope", "", acme()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing id = %d, want the same 404", w.Code)
	}
	// Its owner still reads it.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet, "/api/security/findings/g1", "", globex()))
	if w.Code != http.StatusOK {
		t.Fatalf("owner get = %d (%s), want 200", w.Code, w.Body.String())
	}
	for _, c := range fake.all() {
		if strings.Contains(c.Index, "acme") && strings.Contains(c.Index, "globex") {
			t.Fatalf("a single query named two tenants' indices: %q", c.Index)
		}
	}
}

// TestSecurityAsTenantIgnoredForNonOwner — §3a rule 5's third clause, on every
// route. principalTenant NEVER trusts ActingTenant for a non-owner.
func TestSecurityAsTenantIgnoredForNonOwner(t *testing.T) {
	fake := &secFakeOS{docs: map[string]string{}}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	spoofed := acme()
	spoofed.ActingTenant = "globex"

	routes := map[string]func(http.ResponseWriter, *http.Request){
		"/api/security/findings":        s.secAPI.HandleFindings,
		"/api/security/findings/facets": s.secAPI.HandleFacets,
		"/api/security/findings/trend":  s.secAPI.HandleTrend,
		"/api/security/posture":         s.secAPI.HandlePosture,
	}
	for path, h := range routes {
		fake.mu.Lock()
		fake.calls = nil
		fake.mu.Unlock()
		w := httptest.NewRecorder()
		h(w, req(http.MethodGet, path+"?as_tenant=globex", "", spoofed))
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d (%s)", path, w.Code, w.Body.String())
		}
		for _, c := range fake.all() {
			if c.Index != secPatternFor("acme") {
				t.Fatalf("%s: as_tenant WIDENED the scope — pattern %q", path, c.Index)
			}
			if !strings.Contains(c.Body, `{"term":{"tenant_id":"acme"}}`) {
				t.Fatalf("%s: tenant clause lost under as_tenant: %s", path, c.Body)
			}
		}
	}
}

// ---- facets / trend / posture ----------------------------------------------

func TestSecurityFacetsAreTenantScopedAndKeepNonVerdicts(t *testing.T) {
	fake := &secFakeOS{
		docs: map[string]string{},
		aggs: `{"severity":{"buckets":[{"key":"critical","doc_count":2}]},` +
			`"status":{"buckets":[{"key":"Fail","doc_count":2},{"key":"NotApplicable","doc_count":5}]},` +
			`"seam":{"buckets":[{"key":"ISP","doc_count":2}]},` +
			`"framework":{"buckets":[{"key":"CIS:1.2","doc_count":2}]},` +
			`"evidence_class":{"buckets":[{"key":"posture","doc_count":2}]}}`,
	}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleFacets(w, req(http.MethodGet, "/api/security/findings/facets", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("facets = %d (%s)", w.Code, w.Body.String())
	}
	if got := fake.all()[0].Index; got != secPatternFor("acme") {
		t.Fatalf("facets pattern = %q", got)
	}
	var fs struct {
		Severity map[string]int64 `json:"severity"`
		Status   map[string]int64 `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &fs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fs.Status["fail"] != 2 {
		t.Errorf("fail = %d, want 2", fs.Status["fail"])
	}
	if fs.Status["not_applicable"] != 5 {
		t.Errorf("NotApplicable must keep its OWN key (got %v) — folding it away would read as clear", fs.Status)
	}
	if _, present := fs.Status["pass"]; !present {
		t.Error("pass must be present even at zero: an absent key and a zero mean different things")
	}
	if fs.Severity["critical"] != 2 {
		t.Errorf("severity = %v", fs.Severity)
	}
}

func TestSecurityTrendRejectsAnOverWideBucketing(t *testing.T) {
	fake := &secFakeOS{}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleTrend(w, req(http.MethodGet,
		"/api/security/findings/trend?bucket=1h&since=2025-09-02T00:00:00Z&until=2026-09-01T00:00:00Z", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a 365-day 1h trend = %d, want 400 (silently coarsening answers a different question)", w.Code)
	}
	if len(fake.all()) != 0 {
		t.Fatal("the refused query still reached OpenSearch")
	}
	w = httptest.NewRecorder()
	s.secAPI.HandleTrend(w, req(http.MethodGet, "/api/security/findings/trend?bucket=13m", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown bucket = %d, want 400", w.Code)
	}
}

// TestSecurityPostureNeverMixesTenants — both posture queries carry the SAME
// pattern and clause, and `scope` counts the caller's own registry only.
func TestSecurityPostureNeverMixesTenants(t *testing.T) {
	fake := &secFakeOS{
		docs: map[string]string{},
		aggs: `{"native_total":{"value":2},` +
			`"by_native":{"buckets":[` +
			`{"key":"n1","latest":{"hits":{"hits":[{"_source":{"severity":"critical","seam_type":"ISP","attrs":{"status":"Fail","evidence_class":"exposure","scan_id":"scan-1"},"entity_id":"acme-core","ts":1756684800000}}]}}},` +
			`{"key":"n2","latest":{"hits":{"hits":[{"_source":{"severity":"low","attrs":{"status":"Pass","evidence_class":"posture","scan_id":"scan-1"},"entity_id":"acme-core","ts":1756684800000}}]}}}]},` +
			`"assessed_devices":{"value":1},` +
			`"last_scan":{"hits":{"hits":[{"_source":{"ts":1756684800000,"attrs":{"scan_id":"scan-1"}}}]}}}`,
	}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandlePosture(w, req(http.MethodGet, "/api/security/posture", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("posture = %d (%s)", w.Code, w.Body.String())
	}
	calls := fake.all()
	if len(calls) != 2 {
		t.Fatalf("posture should issue exactly 2 bounded queries, got %d", len(calls))
	}
	for _, c := range calls {
		if c.Index != secPatternFor("acme") {
			t.Fatalf("posture query named %q", c.Index)
		}
		if !strings.Contains(c.Body, `{"term":{"tenant_id":"acme"}}`) {
			t.Fatalf("posture query lost the tenant clause: %s", c.Body)
		}
	}
	var out struct {
		Funnel struct {
			Scope      int `json:"scope"`
			Discover   int `json:"discover"`
			Prioritize int `json:"prioritize"`
			Validate   int `json:"validate"`
			Mobilize   int `json:"mobilize"`
		} `json:"funnel"`
		Coverage struct {
			Assessed   int `json:"assessed_assets"`
			Total      int `json:"total_assets"`
			Unassessed int `json:"unassessed"`
		} `json:"coverage"`
		LastScan struct {
			ScanID string `json:"scan_id"`
			Time   string `json:"time"`
		} `json:"last_scan"`
		Notes map[string]string `json:"notes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// acme owns 2 of the 3 registered devices; globex's must not be counted.
	if out.Funnel.Scope != 2 || out.Coverage.Total != 2 {
		t.Fatalf("scope = %d / total = %d, want acme's 2 devices only", out.Funnel.Scope, out.Coverage.Total)
	}
	if out.Funnel.Discover != 2 || out.Funnel.Prioritize != 1 || out.Funnel.Mobilize != 1 {
		t.Fatalf("funnel = %+v, want discover 2 / prioritize 1 / mobilize 1", out.Funnel)
	}
	if out.Funnel.Validate != 0 || out.Notes["validate"] == "" {
		t.Fatal("validate must be 0 AND carry the note saying the model has no validation marker")
	}
	if out.Coverage.Assessed != 1 || out.Coverage.Unassessed != 1 {
		t.Fatalf("coverage = %+v, want 1 assessed / 1 unassessed", out.Coverage)
	}
	if out.Notes["coverage"] == "" {
		t.Fatal("unassessed must never be presented without saying it is NOT a pass")
	}
	if out.LastScan.ScanID != "scan-1" || out.LastScan.Time == "" {
		t.Fatalf("last_scan = %+v", out.LastScan)
	}
}

// ---- control plane ----------------------------------------------------------

func TestSecurityRulesAreOwnOnlyAndOwnerStamped(t *testing.T) {
	fake := &secFakeOS{}
	secStartFakeOS(t, fake)
	s := secTestServer(t)
	ruleID := secapi.Catalog()[0].RuleID

	// globex disables a rule for itself.
	w := httptest.NewRecorder()
	s.secAPI.HandleRules(w, req(http.MethodPut, "/api/security/rules",
		`[{"rule_id":"`+ruleID+`","enabled":false}]`, tAdmin("globex")))
	if w.Code != http.StatusOK {
		t.Fatalf("globex put = %d (%s)", w.Code, w.Body.String())
	}

	// acme must still see it ENABLED — a tenant's ruleset is its own.
	w = httptest.NewRecorder()
	s.secAPI.HandleRules(w, req(http.MethodGet, "/api/security/rules", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("acme get = %d (%s)", w.Code, w.Body.String())
	}
	var rules []secapi.Rule
	if err := json.Unmarshal(w.Body.Bytes(), &rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, r := range rules {
		if r.RuleID == ruleID && !r.Enabled {
			t.Fatal("TENANT LEAK: globex's rule override changed acme's catalog")
		}
	}
	// …and globex sees its own override.
	w = httptest.NewRecorder()
	s.secAPI.HandleRules(w, req(http.MethodGet, "/api/security/rules", "", tAdmin("globex")))
	var theirs []secapi.Rule
	if err := json.Unmarshal(w.Body.Bytes(), &theirs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	off := false
	for _, r := range theirs {
		if r.RuleID == ruleID && !r.Enabled {
			off = true
		}
	}
	if !off {
		t.Fatal("globex's own override was not applied to its own catalog")
	}
}

func TestSecurityRulesWriteRefusesUnknownIDsAndTheGlobalView(t *testing.T) {
	secStartFakeOS(t, &secFakeOS{})
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleRules(w, req(http.MethodPut, "/api/security/rules",
		`[{"rule_id":"not-a-rule","enabled":false}]`, tAdmin("acme")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown rule_id = %d, want 400", w.Code)
	}
	// A tenant in the BODY is refused outright (DisallowUnknownFields), so the
	// owner can only ever come from the token (§3a rule 2).
	w = httptest.NewRecorder()
	s.secAPI.HandleRules(w, req(http.MethodPut, "/api/security/rules",
		`[{"rule_id":"`+secapi.Catalog()[0].RuleID+`","enabled":false,"tenant_id":"globex"}]`, tAdmin("acme")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a tenant in the body = %d, want 400", w.Code)
	}
	// The platform owner's cross-tenant view has no single tenant to stamp.
	w = httptest.NewRecorder()
	s.secAPI.HandleRules(w, req(http.MethodPut, "/api/security/rules",
		`[{"rule_id":"`+secapi.Catalog()[0].RuleID+`","enabled":false}]`, platformOwner()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross-tenant rule write = %d, want 400 (no tenant to own the row)", w.Code)
	}
}

func TestSecurityViewsAreOwnOnlyAndCrossTenantDeleteIs404(t *testing.T) {
	secStartFakeOS(t, &secFakeOS{})
	s := secTestServer(t)

	// globex saves a view.
	w := httptest.NewRecorder()
	s.secAPI.HandleViews(w, req(http.MethodPost, "/api/security/views",
		`{"name":"their view","filters":{"severity":"high"}}`, globex()))
	if w.Code != http.StatusCreated {
		t.Fatalf("globex post = %d (%s)", w.Code, w.Body.String())
	}
	var theirs secapi.SavedView
	if err := json.Unmarshal(w.Body.Bytes(), &theirs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("the owner tenant must never be serialized to a client: %s", w.Body.String())
	}

	// acme's list must be empty.
	w = httptest.NewRecorder()
	s.secAPI.HandleViews(w, req(http.MethodGet, "/api/security/views", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("acme get = %d", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, theirs.ID) || strings.Contains(body, "their view") {
		t.Fatalf("TENANT LEAK: acme's saved views carried globex's row: %s", body)
	}

	// acme cannot delete it, and is told 404 rather than 403 (§3a rule 1).
	w = httptest.NewRecorder()
	s.secAPI.HandleViews(w, req(http.MethodDelete, "/api/security/views/"+theirs.ID, "", acme()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete = %d (%s), want 404", w.Code, w.Body.String())
	}

	// Its owner still can.
	w = httptest.NewRecorder()
	s.secAPI.HandleViews(w, req(http.MethodDelete, "/api/security/views/"+theirs.ID, "", globex()))
	if w.Code != http.StatusOK {
		t.Fatalf("owner delete = %d (%s), want 200", w.Code, w.Body.String())
	}
}

// ---- validation + bounds ----------------------------------------------------

func TestSecurityFindingsRejectsBadInputRatherThanAnsweringEmpty(t *testing.T) {
	fake := &secFakeOS{}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	for _, q := range []string{
		"severity=hgih",
		"status=broken",
		"limit=501",
		"limit=abc",
		"current=maybe",
		"page_size=10", // an unrecognised parameter must be NAMED, not swallowed
		"offset=100",   // this API pages by cursor
	} {
		w := httptest.NewRecorder()
		s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings?"+q, "", acme()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400 — a 200 with no rows reads as 'you have no findings'", q, w.Code)
		}
	}
	if len(fake.all()) != 0 {
		t.Fatalf("%d refused requests still reached OpenSearch", len(fake.all()))
	}
}

func TestSecurityFindingsRequiresPermission(t *testing.T) {
	secStartFakeOS(t, &secFakeOS{})
	s := secTestServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/security/findings", nil) // no claims in context
	s.secAPI.HandleFindings(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", w.Code)
	}
	// A read-only principal may READ but must not change the ruleset.
	w = httptest.NewRecorder()
	s.secAPI.HandleRules(w, req(http.MethodPut, "/api/security/rules",
		`[{"rule_id":"`+secapi.Catalog()[0].RuleID+`","enabled":false}]`, tViewer("acme")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only rule write = %d, want 403", w.Code)
	}
}

// TestSecurityFindingsCursorRoundTripsThroughTheAPI proves the paging contract
// end to end: a FULL page advertises a cursor, and feeding that cursor back
// produces a search_after on the same (ts, doc id) keyset — the caller can
// actually reach page 2, which is the other half of "don't hide".
func TestSecurityFindingsCursorRoundTripsThroughTheAPI(t *testing.T) {
	fake := &secFakeOS{docs: map[string]string{
		secPatternFor("acme"): "[" + secDoc("a1", "acme", "critical", "Fail", "ISP", "acme-core") + "]",
	}}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	// limit=1 with one hit is a FULL page, so a cursor must be offered.
	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings?limit=1", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("page 1 = %d (%s)", w.Code, w.Body.String())
	}
	var page struct {
		NextCursor *string `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.NextCursor == nil || *page.NextCursor == "" {
		t.Fatal("a full page must advertise a cursor — otherwise the rest of the list is unreachable")
	}
	cur, ok := secapi.DecodeCursor(*page.NextCursor)
	if !ok || cur.Collapsed || cur.Millis != 1756684800000 || cur.DocID != "a1" {
		t.Fatalf("cursor decoded to %+v (ok=%v), want the last hit's sort values", cur, ok)
	}

	// Page 2 must carry search_after with exactly those values, still scoped.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet,
		"/api/security/findings?limit=1&cursor="+*page.NextCursor, "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("page 2 = %d (%s)", w.Code, w.Body.String())
	}
	last := fake.all()[len(fake.all())-1]
	if !strings.Contains(last.Body, `"search_after":[1756684800000,"a1"]`) {
		t.Fatalf("page 2 did not carry the keyset: %s", last.Body)
	}
	if last.Index != secPatternFor("acme") {
		t.Fatalf("page 2 left the caller's index pattern: %q", last.Index)
	}

	// A GARBAGE cursor serves page 1 rather than 500 — a stale cursor is a
	// client-side artefact, not an outage.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings?cursor=not-a-cursor", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("garbage cursor = %d, want a 200 serving page 1", w.Code)
	}
	if strings.Contains(fake.all()[len(fake.all())-1].Body, "search_after") {
		t.Fatal("a malformed cursor must not become a search_after")
	}
}

// TestSecurityExposureStoriesEmptyIsNotAnError — a store that matched nothing
// must answer an empty array, not an error: "no exposure stories" and "the
// query failed" must not look the same to the page.
//
// The comment here used to say the list was legitimately empty because the
// engine-side grounding (T2b) had not shipped. It HAD shipped, and the list was
// empty for an entirely different reason — the engine stamped the nil UUID on
// every edge-evidence row, so the signal-id join matched nothing (QA
// 2026-09-03, D-01). Both halves are fixed; the SQL assertions below now cover
// both branches of the predicate.
func TestSecurityExposureStoriesEmptyIsNotAnError(t *testing.T) {
	secStartFakeOS(t, &secFakeOS{})
	sqls, scopes := corrFakeCH(t)
	s := secTestServer(t)
	s.governance = newTenantGovernanceStore(t.TempDir() + "/gov.json")

	w := httptest.NewRecorder()
	s.secAPI.HandleExposureStories(w, req(http.MethodGet, "/api/security/exposure-stories", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("exposure stories = %d (%s)", w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Fatalf("body = %s, want an empty array", got)
	}
	if len(*scopes) != 1 || (*scopes)[0] != "acme" {
		t.Fatalf("tenant_scope = %v, want [acme] — the row policies enforce on it", *scopes)
	}
	sql := (*sqls)[0]
	for _, want := range []string{
		"netops.corr_evidence",
		"netops.corr_signals",
		"'security_posture'",
		"'security_exposure'",
		"'security_signal'",
		// branch 2 (D-01): the exact node-key suffix over subject_id's halves,
		// which is what reads the historical nil-UUID rows.
		"splitByString('->', ev.subject_id)",
		"endsWith(n, ':security_posture')",
		"endsWith(n, ':security_exposure')",
		"endsWith(n, ':security_signal')",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the exposure-story predicate lost %q:\n%s", want, sql)
		}
	}
	if !strings.Contains(sql, "netops.corr_current") {
		t.Error("the list must reuse the correlations list SQL, not a second shape")
	}
}

// TestSecurityFindingsCurrentStatePagesByOffset covers the path the byte-pinned
// unit test cannot: end to end, current=true pages with `from` (OpenSearch 2.16
// REFUSES collapse alongside search_after — verified live against the deployed
// cluster), the cursor carries that offset opaquely, and the group total comes
// from the cardinality aggregation rather than the document count.
func TestSecurityFindingsCurrentStatePagesByOffset(t *testing.T) {
	fake := &secFakeOS{
		docs: map[string]string{
			secPatternFor("acme"): "[" + secDoc("a1", "acme", "critical", "Fail", "ISP", "acme-core") + "]",
		},
		aggs: `{"current_total":{"value":42}}`,
	}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings?current=true&limit=1", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("current list = %d (%s)", w.Code, w.Body.String())
	}
	first := fake.all()[0]
	if !strings.Contains(first.Body, `"collapse":{"field":"native_id"}`) {
		t.Fatalf("current=true did not collapse on the verdict identity: %s", first.Body)
	}
	if strings.Contains(first.Body, "search_after") {
		t.Fatalf("a collapsed body must never carry search_after — OpenSearch rejects the pair: %s", first.Body)
	}
	if first.Index != secPatternFor("acme") {
		t.Fatalf("current list left the caller's pattern: %q", first.Index)
	}

	var page struct {
		NextCursor *string `json:"next_cursor"`
		Total      int64   `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Total != 42 {
		t.Fatalf("total = %d, want the cardinality of native_id (42) — hits.total counts every historical verdict", page.Total)
	}
	if page.NextCursor == nil {
		t.Fatal("a full collapsed page must advertise a cursor")
	}
	cur, ok := secapi.DecodeCursor(*page.NextCursor)
	if !ok || !cur.Collapsed || cur.Offset != 1 {
		t.Fatalf("cursor = %+v (ok=%v), want a collapsed offset of 1", cur, ok)
	}

	// Page 2 must carry `from`, and NOT a keyset.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet,
		"/api/security/findings?current=true&limit=1&cursor="+*page.NextCursor, "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("current page 2 = %d (%s)", w.Code, w.Body.String())
	}
	second := fake.all()[len(fake.all())-1]
	if !strings.Contains(second.Body, `"from":1`) {
		t.Fatalf("collapsed page 2 lost its offset: %s", second.Body)
	}

	// A KEYSET cursor replayed with current=true is the wrong kind: it is
	// ignored (page 1), never turned into a nonsense position.
	keyset := secapi.EncodeKeysetCursor(1756684800000, "a1")
	w = httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet,
		"/api/security/findings?current=true&limit=1&cursor="+keyset, "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("mismatched cursor kind = %d, want a 200 serving page 1", w.Code)
	}
	last := fake.all()[len(fake.all())-1]
	if strings.Contains(last.Body, "search_after") || strings.Contains(last.Body, `"from"`) {
		t.Fatalf("a cursor of the wrong kind must be IGNORED: %s", last.Body)
	}

	// Paging past the result window is REFUSED, not served short: a short page
	// with a null cursor while total says 42 would read as "that is all there is".
	deep := secapi.EncodeOffsetCursor(9999)
	w = httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet,
		"/api/security/findings?current=true&limit=100&cursor="+deep, "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("paging past the result window = %d, want 400", w.Code)
	}
}

// TestSecurityExposureStoryDetailIsTenantScoped covers
// "/api/security/exposure-stories/{id}". The route is a DELEGATE: it rewrites
// the path onto the correlation detail handler so an Exposure Story renders
// identically to the RCA case it is, and — the reason the delegation exists —
// inherits that handler's ownership pre-read verbatim. Re-implementing the
// lookup here is exactly how the 2026-08-04 {id}/replay cross-tenant leak
// happened: a second path to the same object that forgot the check.
//
// Asserted: another tenant's correlation id answers 404 (existence hidden), the
// ClickHouse read carries the CALLER's tenant_scope (never __all__), as_tenant
// into another org is ignored, and a malformed id is a 400 that reaches no store.
func TestSecurityExposureStoryDetailIsTenantScoped(t *testing.T) {
	const storyID = "11111111-2222-4333-8444-555555555555"
	fbFakeCH(t, "acme") // corr_objects rows exist ONLY under the acme scope
	s := secTestServer(t)
	s.governance = newTenantGovernanceStore(t.TempDir() + "/gov.json")

	// globex asking for acme's story: the scoped read returns no rows, so the
	// correlation detail handler answers 404 — the same answer a nonexistent id
	// gets, so acme's id is never confirmed to exist.
	w := httptest.NewRecorder()
	s.handleSecurityExposureStory(w, req(http.MethodGet, "/api/security/exposure-stories/"+storyID, "", globex()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant exposure story = %d (%s), want 404", w.Code, w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "acme") {
		t.Fatalf("the 404 revealed the owning tenant: %s", w.Body.String())
	}

	// ?as_tenant= into another org must not widen a non-owner's scope.
	spoofed := globex()
	spoofed.ActingTenant = "acme"
	w = httptest.NewRecorder()
	s.handleSecurityExposureStory(w, req(http.MethodGet,
		"/api/security/exposure-stories/"+storyID+"?as_tenant=acme", "", spoofed))
	if w.Code != http.StatusNotFound {
		t.Fatalf("as_tenant WIDENED the scope: %d (%s)", w.Code, w.Body.String())
	}

	// A malformed id is refused by the delegate target before any store is read.
	w = httptest.NewRecorder()
	s.handleSecurityExposureStory(w, req(http.MethodGet, "/api/security/exposure-stories/not-a-uuid", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed exposure story id = %d, want 400", w.Code)
	}

	// The delegation really does reach the correlation detail handler: the
	// owner's request is NOT a 404 (the fake serves acme's corr_objects rows).
	w = httptest.NewRecorder()
	s.handleSecurityExposureStory(w, req(http.MethodGet, "/api/security/exposure-stories/"+storyID, "", acme()))
	if w.Code == http.StatusNotFound {
		t.Fatalf("the owner was denied its own exposure story — the delegation is not reaching the correlation detail handler (%s)", w.Body.String())
	}
}

// ---- D-09: by-id resolution ------------------------------------------------

// secIDAwareOS is a stand-in that, unlike secFakeOS, actually HONOURS the query:
// it returns a document only when the request body selects it BY DOCUMENT ID
// and the index pattern is one that may see it. That distinction is the whole
// of D-09 — the previous by-id query filtered `term { cx_finding_id: … }`, a
// field no indexed document carries (the router's `id_key: cx_finding_id` sink
// lifts it into the `_id` and strips it from the body), so every real GET
// answered 404 while a pattern-only test double answered 200.
type secIDAwareOS struct {
	mu   sync.Mutex
	docs map[string]map[string]string // index pattern → doc id → _source JSON
	last string                       // the last query body, for assertions
}

// selects reports whether an OpenSearch query body would match a document whose
// `_id` is id. It walks query.bool.filter and looks for the id resolution
// clause, exactly as the cluster would: an `ids` values entry naming the doc.
func (f *secIDAwareOS) selects(body, id string) bool {
	var q struct {
		Query struct {
			Bool struct {
				Filter []json.RawMessage `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
	}
	if err := json.Unmarshal([]byte(body), &q); err != nil {
		return false
	}
	for _, clause := range q.Query.Bool.Filter {
		var c struct {
			IDs struct {
				Values []string `json:"values"`
			} `json:"ids"`
			Bool struct {
				Should []struct {
					IDs struct {
						Values []string `json:"values"`
					} `json:"ids"`
				} `json:"should"`
			} `json:"bool"`
		}
		if err := json.Unmarshal(clause, &c); err != nil {
			continue
		}
		for _, v := range c.IDs.Values {
			if v == id {
				return true
			}
		}
		for _, s := range c.Bool.Should {
			for _, v := range s.IDs.Values {
				if v == id {
					return true
				}
			}
		}
	}
	return false
}

// lastBody returns the most recent query body under the lock, so a -race build
// sees the same happens-before edge the handler wrote it behind.
func (f *secIDAwareOS) lastBody() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func secStartIDAwareOS(t *testing.T, fake *secIDAwareOS) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // test double: a short read fails the assertions below
		body := string(raw)
		index := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/_search")
		fake.mu.Lock()
		fake.last = body
		hits := ""
		for id, source := range fake.docs[index] {
			if fake.selects(body, id) {
				hits = `{"_index":"` + strings.SplitN(index, "-*", 2)[0] + `-2026.09.01","_id":"` + id +
					`","_source":` + source + `,"sort":[1756684800000,"` + id + `"]}`
				break
			}
		}
		fake.mu.Unlock()
		total := 0
		if hits != "" {
			total = 1
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"took":1,"timed_out":false,"hits":{"total":{"value":` +
			strconv.Itoa(total) + `,"relation":"eq"},"hits":[` + hits + `]}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
}

// secLiveSource is the LIVE indexed shape: no cx_finding_id anywhere in
// _source, because the router's sink consumed it into the `_id`.
func secLiveSource(tenant, device string) string {
	return `{"tenant_id":"` + tenant + `","ts":1756684800000,"severity":"high",` +
		`"entity_id":"` + device + `","native_id":"security|security_posture|posture|AC-17|` + device + `|scan-1|",` +
		`"attrs":{"status":"Fail","scan_id":"scan-1","evidence_class":"posture",` +
		`"status_detail":"OS version not present in sysDescr"}}`
}

// TestSecurityFindingByIDResolvesTheDocumentID is D-09's regression test, at the
// HTTP boundary and against a backend that answers the query rather than the
// index pattern. The owner reads its own finding (200) and the neighbouring
// tenant gets the same 404 a nonexistent id gets — the isolation half of §3a.5.
func TestSecurityFindingByIDResolvesTheDocumentID(t *testing.T) {
	const acmeDoc = "3f2a9c1e5b7d0a4f6e8c2b1d9a7f5e3c1b0d8a6f4e2c0b9d7a5f3e1c9b7d5a30"
	const globexDoc = "9b7d5a301b0d8a6f4e2c0b9d3f2a9c1e5b7d0a4f6e8c2b1d7a5f3e1c9b7d5a31"
	fake := &secIDAwareOS{docs: map[string]map[string]string{
		secPatternFor("acme"):   {acmeDoc: secLiveSource("acme", "acme-core")},
		secPatternFor("globex"): {globexDoc: secLiveSource("globex", "globex-core")},
	}}
	secStartIDAwareOS(t, fake)
	s := secTestServer(t)

	// Own finding, by the id the LIST hands out (the document `_id`) → 200.
	w := httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet, "/api/security/findings/"+acmeDoc, "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("own finding by id = %d (%s), want 200 — D-09 REGRESSION", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"id":"`+acmeDoc+`"`) {
		t.Fatalf("the detail response does not carry the id it was asked for: %s", w.Body.String())
	}
	// The reason survives the bus and the decoder (the D-06 field).
	if !strings.Contains(w.Body.String(), "OS version not present in sysDescr") {
		t.Errorf("attrs.status_detail did not reach the detail response: %s", w.Body.String())
	}
	if body := fake.lastBody(); !strings.Contains(body, `{"term":{"tenant_id":"acme"}}`) {
		t.Fatalf("TENANT LEAK: the by-id query carried no isolation clause: %s", body)
	}

	// Another tenant's finding id → 404, indistinguishable from a missing one.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet, "/api/security/findings/"+globexDoc, "", acme()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get = %d (%s), want 404", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "globex") || strings.Contains(w.Body.String(), globexDoc) {
		t.Fatalf("the 404 revealed the other tenant's finding: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet,
		"/api/security/findings/0000000000000000000000000000000000000000000000000000000000000000", "", acme()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing id = %d, want the same 404 as a cross-tenant id", w.Code)
	}

	// Its owner still reads it — so the 404 above was isolation, not breakage.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet, "/api/security/findings/"+globexDoc, "", globex()))
	if w.Code != http.StatusOK {
		t.Fatalf("owner get = %d (%s), want 200", w.Code, w.Body.String())
	}

	// ?as_tenant= into another org is ignored for a non-owner (§3a.5).
	w = httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet,
		"/api/security/findings/"+globexDoc+"?as_tenant=globex", "", acme()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("as_tenant escape = %d (%s), want 404", w.Code, w.Body.String())
	}

	// A native_id is not a document id: refused at the boundary (§3 zero-trust),
	// never passed into the query.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindingByID(w, req(http.MethodGet,
		"/api/security/findings/security%7Csecurity_posture%7Cposture", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("native_id-shaped id = %d (%s), want 400", w.Code, w.Body.String())
	}
}

// ---- L-01: current=true must actually supersede -----------------------------

// secCollapseOS emulates the one OpenSearch behaviour `current=true` is built
// on: `collapse: {field: native_id}` over a (ts desc) sort returns the NEWEST
// document per group, and `current_total` is the number of GROUPS. Everything
// else about it is a stub — this exists to prove the Go side asks for the
// collapse and reports group counts, which no pattern-only double can show.
type secCollapseOS struct {
	docs []secCollapseDoc
}

type secCollapseDoc struct {
	ID       string
	NativeID string
	TSMillis int64
	Status   string
	Device   string
}

func secStartCollapseOS(t *testing.T, fake *secCollapseOS) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // test double: a short read fails the assertions below
		var q struct {
			Collapse struct {
				Field string `json:"field"`
			} `json:"collapse"`
		}
		_ = json.Unmarshal(raw, &q)
		keep := fake.docs
		if q.Collapse.Field == "native_id" {
			newest := map[string]secCollapseDoc{}
			for _, d := range fake.docs {
				if cur, ok := newest[d.NativeID]; !ok || d.TSMillis > cur.TSMillis {
					newest[d.NativeID] = d
				}
			}
			keep = keep[:0:0]
			for _, d := range newest {
				keep = append(keep, d)
			}
		}
		sort.Slice(keep, func(i, j int) bool { return keep[i].TSMillis > keep[j].TSMillis })
		hits := make([]string, 0, len(keep))
		for _, d := range keep {
			hits = append(hits, `{"_index":"netops-secfindings-acme-2026.09.03","_id":"`+d.ID+`",`+
				`"_source":{"tenant_id":"acme","ts":`+strconv.FormatInt(d.TSMillis, 10)+`,"severity":"high",`+
				`"entity_id":"`+d.Device+`","native_id":"`+d.NativeID+`",`+
				`"attrs":{"status":"`+d.Status+`","scan_id":"scan-`+d.ID+`","evidence_class":"posture",`+
				`"control_id":"AC-17","raw_rule_id":"telnet-vty-enabled"}},`+
				`"sort":[`+strconv.FormatInt(d.TSMillis, 10)+`,"`+d.ID+`"]}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"took":1,"timed_out":false,"hits":{"total":{"value":` +
			strconv.Itoa(len(fake.docs)) + `,"relation":"eq"},"hits":[` + strings.Join(hits, ",") + `]},` +
			`"aggregations":{"current_total":{"value":` + strconv.Itoa(len(keep)) + `}}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
}

// TestSecurityFindingsCurrentSupersedesOlderScans is L-01 at the API boundary.
//
// Live symptom (2026-09-03): `current=true` returned 572 rows spanning nine
// scans, 444 of them stale Unknowns, because native_id folded in the scan id and
// every scan was therefore its own collapse group. secbus.nativeIDOf no longer
// does; the two documents below are two scans of the SAME finding and share one
// native_id (the shape TestNativeIDIsStableAcrossScans pins on the producer
// side). The current view must return ONE row — the newest — and count groups,
// not documents.
func TestSecurityFindingsCurrentSupersedesOlderScans(t *testing.T) {
	// The stable, scan-free identity: tenant, control, device, rule.
	const native = "security|security_posture|posture|acme|AC-17|spine1|telnet-vty-enabled"
	if strings.Contains(native, "scan-") {
		t.Fatal("the fixture identity carries a scan id — that is the bug, not the fixture")
	}
	fake := &secCollapseOS{docs: []secCollapseDoc{
		{ID: "older", NativeID: native, TSMillis: 1756684800000, Status: "Fail", Device: "spine1"},
		{ID: "newest", NativeID: native, TSMillis: 1756873600000, Status: "NotApplicable", Device: "spine1"},
	}}
	secStartCollapseOS(t, fake)
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings?current=true", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("current list = %d (%s)", w.Code, w.Body.String())
	}
	var page struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(page.Items) != 1 {
		t.Fatalf("L-01 REGRESSION: current=true returned %d rows for ONE finding identity — "+
			"the newer verdict never supersedes the older one: %s", len(page.Items), w.Body.String())
	}
	if page.Items[0].ID != "newest" || page.Items[0].Status != "NotApplicable" {
		t.Errorf("the surviving row is %+v, want the NEWEST verdict (NotApplicable)", page.Items[0])
	}
	if page.Total != 1 {
		t.Errorf("total = %d, want 1 — the current view counts finding identities, not documents", page.Total)
	}

	// The history is NOT destroyed: current=false still returns both retained
	// verdicts, which is what the trend/drift views read.
	w = httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("history list = %d (%s)", w.Code, w.Body.String())
	}
	page.Items = nil
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("the retained verdict history was lost: %d rows, want 2 (%s)", len(page.Items), w.Body.String())
	}
}
