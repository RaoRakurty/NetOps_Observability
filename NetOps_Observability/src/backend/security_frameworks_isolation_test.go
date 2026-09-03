package backend

// security_frameworks_isolation_test.go — the CLAUDE.md §3a rule 5 cross-org
// test for the per-tenant compliance FRAMEWORK selection and the scorecards
// computed from it (owner direction 2026-09-03: compliance is analyzed per
// customer requirement, so which frameworks a tenant is assessed against is that
// tenant's own configuration).
//
// security_findings_isolation_test.go is the template and supplies the
// OpenSearch stand-in, the two-tenant server and the claim helpers.
//
// Proven here:
//   - own-only read: one tenant's selection is invisible to another, and a
//     tenant that has not chosen reads the SHIPPED DEFAULT set (not the other
//     tenant's choice, and not "everything");
//   - a write is owner-stamped from the token: a tenant_id in the body is
//     refused outright, and the cross-tenant (platform) view has no tenant to
//     stamp so the write is refused;
//   - ?as_tenant= into another org is IGNORED on both routes;
//   - an id outside the closed framework vocabulary is refused;
//   - the scorecards read only the caller's index pattern and carry the per-doc
//     tenant clause, and score ONLY the frameworks that tenant enabled;
//   - a framework with nothing assessed reports a NULL score and says so — never
//     0 % and never 100 %.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/compliancemodel"
	"netops/backend/secapi"
)

// secFwServer is secTestServer plus the in-memory framework-selection store.
func secFwServer(t *testing.T) *server {
	t.Helper()
	s := secTestServer(t)
	s.secFrameworks = secapi.NewFrameworkFileStore("") // in-memory
	s.secAPI = secapi.New(s.securityAPIDeps())
	return s
}

// fwBody is the shape both framework routes answer with.
type fwBody struct {
	Frameworks []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Source    string `json:"source"`
		DefaultOn bool   `json:"default_on"`
		Enabled   bool   `json:"enabled"`
	} `json:"frameworks"`
	Benchmarks []struct {
		ID               string `json:"id"`
		Version          string `json:"version"`
		SectionsVerified bool   `json:"sections_verified"`
	} `json:"benchmarks"`
	Citations []struct {
		RuleID      string   `json:"rule_id"`
		BenchmarkID string   `json:"benchmark_id"`
		Section     string   `json:"section"`
		Label       string   `json:"label"`
		Controls    []string `json:"controls"`
	} `json:"benchmark_citations"`
	Configured bool `json:"configured"`
}

func decodeFw(t *testing.T, w *httptest.ResponseRecorder) fwBody {
	t.Helper()
	var b fwBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	return b
}

func fwEnabled(b fwBody) map[string]bool {
	out := map[string]bool{}
	for _, f := range b.Frameworks {
		out[f.ID] = f.Enabled
	}
	return out
}

func TestSecurityFrameworkSelectionIsOwnOnlyAndOwnerStamped(t *testing.T) {
	secStartFakeOS(t, &secFakeOS{})
	s := secFwServer(t)

	// globex opts into HIPAA and turns CIS off.
	w := httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodPut, "/api/security/frameworks",
		`[{"framework_id":"`+compliancemodel.IDHIPAA+`","enabled":true},`+
			`{"framework_id":"`+compliancemodel.IDCISv8+`","enabled":false}]`, tAdmin("globex")))
	if w.Code != http.StatusOK {
		t.Fatalf("globex put = %d (%s)", w.Code, w.Body.String())
	}
	theirs := decodeFw(t, w)
	if !theirs.Configured {
		t.Error("a tenant that has just saved a selection must read as configured")
	}
	if on := fwEnabled(theirs); !on[compliancemodel.IDHIPAA] || on[compliancemodel.IDCISv8] {
		t.Fatalf("globex's own selection was not applied: %v", on)
	}

	// acme must still see the SHIPPED DEFAULTS — a tenant's compliance scope is
	// its own, and "has not chosen" must not inherit another tenant's choice.
	w = httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodGet, "/api/security/frameworks", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("acme get = %d (%s)", w.Code, w.Body.String())
	}
	mine := decodeFw(t, w)
	if mine.Configured {
		t.Error("acme has chosen nothing and must not read as configured")
	}
	on := fwEnabled(mine)
	if on[compliancemodel.IDHIPAA] {
		t.Fatal("TENANT LEAK: globex's HIPAA opt-in reached acme")
	}
	if !on[compliancemodel.IDNIST80053] || !on[compliancemodel.IDCISv8] {
		t.Errorf("acme should read the shipped default set, got %v", on)
	}
	// …and not every framework: the whole point of the change.
	for _, id := range []string{compliancemodel.IDNISTCSF, compliancemodel.IDHIPAA, compliancemodel.IDPCIDSS} {
		if on[id] {
			t.Errorf("%q is enabled by default — compliance is analyzed per customer requirement", id)
		}
	}
	// Every listed framework carries its version and its base/projection source.
	for _, f := range mine.Frameworks {
		if f.Version == "" || (f.Source != "base" && f.Source != "projection-of-800-53") {
			t.Errorf("framework %q is not fully identified: %+v", f.ID, f)
		}
		if strings.Contains(strings.ToLower(f.Name), "benchmark") {
			t.Errorf("%q is a device benchmark, not a framework", f.Name)
		}
	}
	// Benchmarks ride in their OWN list, versioned, and a benchmark whose
	// sections were never verified cites nothing.
	verified := map[string]bool{}
	for _, b := range mine.Benchmarks {
		if b.Version == "" {
			t.Errorf("benchmark %q has no version", b.ID)
		}
		verified[b.ID] = b.SectionsVerified
	}
	if len(mine.Citations) == 0 {
		t.Fatal("no benchmark citation was served — the guard would pass vacuously")
	}
	for _, c := range mine.Citations {
		if !verified[c.BenchmarkID] {
			t.Errorf("citation on %q names a benchmark with an unverified section taxonomy", c.RuleID)
		}
		if len(c.Controls) == 0 {
			t.Errorf("citation on %q reaches no control, so it can never be rendered in a control row", c.RuleID)
		}
		if !strings.Contains(c.Label, "§"+c.Section) {
			t.Errorf("citation label %q does not carry its section", c.Label)
		}
	}
	// The producer-derived inputs are the shipped catalogue, adapted in the
	// wiring layer — asserted through the server so this test needs no import of
	// the removable producer.
	in := securityComplianceInputs()
	if len(in.Mappings) == 0 || len(in.Benchmarks) == 0 || len(in.Citations) == 0 {
		t.Fatalf("the wiring layer supplied no compliance inputs: %d mappings, %d benchmarks, %d citations",
			len(in.Mappings), len(in.Benchmarks), len(in.Citations))
	}
	if len(mine.Citations) != len(in.Citations) {
		t.Errorf("the API served %d citations, the wiring built %d", len(mine.Citations), len(in.Citations))
	}
}

func TestSecurityFrameworkWriteRefusesUnknownIDsBodyTenantsAndTheGlobalView(t *testing.T) {
	secStartFakeOS(t, &secFakeOS{})
	s := secFwServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodPut, "/api/security/frameworks",
		`[{"framework_id":"iso-27001","enabled":true}]`, tAdmin("acme")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown framework_id = %d, want 400", w.Code)
	}

	// A tenant in the BODY is refused outright (DisallowUnknownFields), so the
	// owner can only ever come from the token (§3a rule 2).
	w = httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodPut, "/api/security/frameworks",
		`[{"framework_id":"`+compliancemodel.IDHIPAA+`","enabled":true,"tenant_id":"globex"}]`, tAdmin("acme")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a tenant in the body = %d, want 400", w.Code)
	}

	// The platform owner's cross-tenant view has no single tenant to stamp.
	w = httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodPut, "/api/security/frameworks",
		`[{"framework_id":"`+compliancemodel.IDHIPAA+`","enabled":true}]`, platformOwner()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross-tenant framework write = %d, want 400 (no tenant to own the row)", w.Code)
	}

	// An operator without the administration gate cannot change the scope.
	w = httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodPut, "/api/security/frameworks",
		`[{"framework_id":"`+compliancemodel.IDHIPAA+`","enabled":true}]`, acme()))
	if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("an operator write = %d, want 401/403", w.Code)
	}

	// Nothing was stored by any of the refusals.
	w = httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodGet, "/api/security/frameworks", "", acme()))
	if b := decodeFw(t, w); b.Configured {
		t.Fatal("a refused write left state behind")
	}
}

// TestSecurityFrameworkAsTenantIgnoredForNonOwner — §3a rule 5's third clause.
func TestSecurityFrameworkAsTenantIgnoredForNonOwner(t *testing.T) {
	fake := &secFakeOS{}
	secStartFakeOS(t, fake)
	s := secFwServer(t)

	// globex opts into HIPAA…
	w := httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodPut, "/api/security/frameworks",
		`[{"framework_id":"`+compliancemodel.IDHIPAA+`","enabled":true}]`, tAdmin("globex")))
	if w.Code != http.StatusOK {
		t.Fatalf("globex put = %d (%s)", w.Code, w.Body.String())
	}

	// …and an acme admin claiming to act as globex sees nothing of it.
	spoofed := tAdmin("acme")
	spoofed.ActingTenant = "globex"

	w = httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodGet, "/api/security/frameworks?as_tenant=globex", "", spoofed))
	if w.Code != http.StatusOK {
		t.Fatalf("as_tenant get = %d (%s)", w.Code, w.Body.String())
	}
	b := decodeFw(t, w)
	if b.Configured || fwEnabled(b)[compliancemodel.IDHIPAA] {
		t.Fatalf("as_tenant WIDENED the scope: %v", fwEnabled(b))
	}

	// The scorecards route likewise stays on acme's own index pattern.
	fake.mu.Lock()
	fake.calls = nil
	fake.mu.Unlock()
	w = httptest.NewRecorder()
	s.secAPI.HandleCompliance(w, req(http.MethodGet, "/api/security/compliance?as_tenant=globex", "", spoofed))
	if w.Code != http.StatusOK {
		t.Fatalf("as_tenant compliance = %d (%s)", w.Code, w.Body.String())
	}
	calls := fake.all()
	if len(calls) == 0 {
		t.Fatal("the scorecards issued no query")
	}
	for _, c := range calls {
		if c.Index != secPatternFor("acme") {
			t.Fatalf("as_tenant WIDENED the scorecard scope — pattern %q", c.Index)
		}
		if !strings.Contains(c.Body, `{"term":{"tenant_id":"acme"}}`) {
			t.Fatalf("tenant clause lost on the scorecard query: %s", c.Body)
		}
	}
}

// complianceBody is the scorecard response.
type complianceBody struct {
	Frameworks []struct {
		Framework       string   `json:"framework"`
		Version         string   `json:"version"`
		ScorePercent    *float64 `json:"score_percent"`
		CoveragePercent float64  `json:"coverage_percent"`
		Assessed        int      `json:"assessed"`
		Failed          int      `json:"failed"`
		Note            string   `json:"note"`
		Caption         string   `json:"caption"`
	} `json:"frameworks"`
	Enabled    []string          `json:"enabled"`
	Configured bool              `json:"configured"`
	Findings   int               `json:"current_findings"`
	Notes      map[string]string `json:"notes"`
}

// fwFoldAggs is a current-state fold answer: one failing hardening finding on
// AC-17 (remote access), which HIPAA scopes and NIST CSF also scopes.
const fwFoldAggs = `{"native_total":{"value":1},"by_native":{"buckets":[` +
	`{"key":"n-1","doc_count":1,"latest":{"hits":{"hits":[{"_id":"f1","_source":` +
	`{"attrs":{"control_id":"AC-17","raw_rule_id":"telnet-vty-enabled","status":"Fail"}}}]}}}` +
	`]}}`

func TestSecurityComplianceScoresOnlyTheEnabledFrameworks(t *testing.T) {
	secStartFakeOS(t, &secFakeOS{aggs: fwFoldAggs})
	s := secFwServer(t)

	// Default selection: the 800-53 base + CIS Controls, and nothing regulatory.
	w := httptest.NewRecorder()
	s.secAPI.HandleCompliance(w, req(http.MethodGet, "/api/security/compliance", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("compliance = %d (%s)", w.Code, w.Body.String())
	}
	var b complianceBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if b.Configured {
		t.Error("acme has chosen nothing and must not read as configured")
	}
	if len(b.Frameworks) != 2 {
		t.Fatalf("default run scored %d frameworks, want 2 (the base + CIS Controls)", len(b.Frameworks))
	}
	for _, f := range b.Frameworks {
		if strings.Contains(f.Framework, "HIPAA") || strings.Contains(f.Framework, "PCI") {
			t.Errorf("%q was scored without anybody enabling it", f.Framework)
		}
		if f.Caption == "" {
			t.Errorf("%q carries no honesty caption", f.Framework)
		}
		if f.Version == "" {
			t.Errorf("%q carries no version", f.Framework)
		}
	}

	// Opt into HIPAA — the SAME finding now also reports there, through the
	// projection (finding → AC-17 → §164.312(a)(1)). This is the bug the owner
	// reported: HIPAA is never a tag on a finding, so it could never appear.
	w = httptest.NewRecorder()
	s.secAPI.HandleFrameworks(w, req(http.MethodPut, "/api/security/frameworks",
		`[{"framework_id":"`+compliancemodel.IDHIPAA+`","enabled":true}]`, tAdmin("acme")))
	if w.Code != http.StatusOK {
		t.Fatalf("opt-in = %d (%s)", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.secAPI.HandleCompliance(w, req(http.MethodGet, "/api/security/compliance", "", tAdmin("acme")))
	if w.Code != http.StatusOK {
		t.Fatalf("compliance after opt-in = %d (%s)", w.Code, w.Body.String())
	}
	b = complianceBody{}
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !b.Configured {
		t.Error("after a save the tenant must read as configured")
	}
	var hipaa *struct {
		Framework       string   `json:"framework"`
		Version         string   `json:"version"`
		ScorePercent    *float64 `json:"score_percent"`
		CoveragePercent float64  `json:"coverage_percent"`
		Assessed        int      `json:"assessed"`
		Failed          int      `json:"failed"`
		Note            string   `json:"note"`
		Caption         string   `json:"caption"`
	}
	for i := range b.Frameworks {
		if strings.Contains(b.Frameworks[i].Framework, "HIPAA") {
			hipaa = &b.Frameworks[i]
		}
	}
	if hipaa == nil {
		t.Fatalf("HIPAA was enabled but not scored: %+v", b.Frameworks)
	}
	// The rule tags TWO controls (AC-17 remote access, SC-8 transmission
	// protection) and HIPAA scopes both, so one finding fails two controls —
	// the M:N check→control mapping doing its job, not a double count of the
	// finding.
	if hipaa.Failed != 2 || hipaa.Assessed != 2 {
		t.Errorf("HIPAA should carry the AC-17/SC-8 failure through the projection: assessed=%d failed=%d",
			hipaa.Assessed, hipaa.Failed)
	}
	if hipaa.ScorePercent == nil || *hipaa.ScorePercent != 0 {
		t.Errorf("one assessed control, failing, is a 0%% score; got %v", hipaa.ScorePercent)
	}
	if hipaa.CoveragePercent >= 100 {
		t.Errorf("coverage must stay honest below 100%%, got %.1f", hipaa.CoveragePercent)
	}
}

// TestSecurityComplianceUnassessedIsNeverZeroPercent — the §5g honesty rule the
// page depends on. A framework nothing maps to says so in words.
func TestSecurityComplianceUnassessedIsNeverZeroPercent(t *testing.T) {
	// No findings at all: the fold returns nothing.
	secStartFakeOS(t, &secFakeOS{})
	s := secFwServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleCompliance(w, req(http.MethodGet, "/api/security/compliance", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("compliance = %d (%s)", w.Code, w.Body.String())
	}
	var b complianceBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(b.Frameworks) == 0 {
		t.Fatal("the enabled frameworks must still be listed with an honest empty state")
	}
	for _, f := range b.Frameworks {
		if f.ScorePercent != nil {
			t.Errorf("%q reported %.0f%% with nothing assessed — that reads as a verdict", f.Framework, *f.ScorePercent)
		}
		if !strings.Contains(f.Note, "absence of assessment") {
			t.Errorf("%q gives no honest empty-state note: %q", f.Framework, f.Note)
		}
	}
	if b.Findings != 0 {
		t.Errorf("current_findings = %d, want 0", b.Findings)
	}
}
