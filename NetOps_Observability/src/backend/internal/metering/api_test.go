package metering

// api_test.go — the two Usage routes, and the isolation posture they hold
// (CLAUDE.md §3a). The cross-org HTTP proof for the wired routes lives in the
// api's own metering_isolation_test.go; these tests pin the MODULE's behaviour
// so a future wiring change cannot quietly widen it.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordedAudit struct{ evs []AuditRecord }

func (r *recordedAudit) Record(_ *http.Request, ev AuditRecord) { r.evs = append(r.evs, ev) }

func testAPI(t *testing.T, caller Principal) (*API, *recordedAudit) {
	t.Helper()
	store := NewFileStore("")
	fixture(t, store)
	aud := &recordedAudit{}
	return New(Deps{
		Store:    store,
		Key:      NewReportKey(filepath.Join(t.TempDir(), "report-key.json"), nil),
		Recorder: NewRecorder(store, func(context.Context) map[string][]Reading { return nil }, nil),
		ReadGate: func(http.ResponseWriter, *http.Request) (Principal, bool) { return caller, true },
		Audit:    aud,
		Licence: func(_ context.Context, cross bool) ReportLicence {
			l := ReportLicence{Tier: "team", Devices: 250}
			if cross {
				l.Customer, l.LicenceID = "Acme Networks", "lic-1"
			}
			return l
		},
		Now: func() time.Time { return day("2026-09-05T12:00:00Z") },
	}), aud
}

func get(t *testing.T, h http.HandlerFunc, url string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, url, nil))
	return w
}

func decodeView(t *testing.T, w *httptest.ResponseRecorder) UsageView {
	t.Helper()
	var v UsageView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v (body %s)", err, w.Body.String())
	}
	return v
}

func TestUsageTenantSeesOnlyItsOwnRows(t *testing.T) {
	a, _ := testAPI(t, Principal{Subject: "u1", Tenant: "acme"})
	w := get(t, a.HandleUsage, "/api/system/licence/usage?from=2026-09-01&to=2026-09-30")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	v := decodeView(t, w)
	if v.Scope != ReportScopeTenant || v.Tenant != "acme" {
		t.Fatalf("scope = %q/%q, want a tenant projection for acme", v.Scope, v.Tenant)
	}
	for _, d := range v.Days {
		if d.TenantID != "acme" {
			t.Fatalf("acme was shown a %q row", d.TenantID)
		}
	}
	if v.Tenants != nil {
		t.Errorf("the per-tenant breakdown is platform-only and must be ABSENT, not empty")
	}
	if v.Licence.Customer != "" || v.Licence.LicenceID != "" {
		t.Errorf("a tenant's answer carries the provider's commercial identity: %+v", v.Licence)
	}
	if v.ScopeNote == "" {
		t.Errorf("a tenant's numbers must say what they are a slice of")
	}
}

func TestUsageCrossTenantSeesEveryoneAndTheInstallation(t *testing.T) {
	a, _ := testAPI(t, Principal{Subject: "owner", Tenant: "global", CrossTenant: true})
	v := decodeView(t, get(t, a.HandleUsage, "/api/system/licence/usage?from=2026-09-01&to=2026-09-30"))
	if v.Scope != ReportScopePlatform || v.Tenant != "" {
		t.Fatalf("scope = %q/%q, want the platform view", v.Scope, v.Tenant)
	}
	seen := map[string]bool{}
	for _, row := range v.Tenants {
		seen[row.TenantID] = true
	}
	for _, want := range []string{"acme", "globex", ScopeInstallation} {
		if !seen[want] {
			t.Errorf("the platform breakdown is missing %q", want)
		}
	}
	if v.Licence.Customer == "" {
		t.Errorf("the platform view should carry the commercial identity")
	}
}

func TestUsageAsTenantNarrowsForTheOwnerAndIsIgnoredForATenant(t *testing.T) {
	owner, _ := testAPI(t, Principal{Subject: "owner", Tenant: "global", CrossTenant: true})
	v := decodeView(t, get(t, owner.HandleUsage, "/api/system/licence/usage?tenant=globex&from=2026-09-01&to=2026-09-30"))
	if v.Scope != ReportScopeTenant || v.Tenant != "globex" {
		t.Fatalf("the owner's ?tenant= did not narrow: %q/%q", v.Scope, v.Tenant)
	}
	for _, d := range v.Days {
		if d.TenantID != "globex" {
			t.Fatalf("narrowing to globex returned a %q row", d.TenantID)
		}
	}
}

func TestUsageCrossTenantSelectorIs404ForAScopedCaller(t *testing.T) {
	a, _ := testAPI(t, Principal{Subject: "u1", Tenant: "acme"})
	for _, path := range []string{
		"/api/system/licence/usage?tenant=globex",
		"/api/system/licence/usage/report?tenant=globex",
	} {
		h := a.HandleUsage
		if strings.HasSuffix(strings.SplitN(path, "?", 2)[0], "/report") {
			h = a.HandleReport
		}
		w := get(t, h, path)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404 — a cross-tenant selector must not confirm the other tenant exists", path, w.Code)
		}
	}
}

func TestUsageWithNoResolvedTenantReadsNothing(t *testing.T) {
	// An admitted caller whose tenant the gate could not resolve must NOT fall
	// through to the installation row, whose key is also the empty string.
	a, _ := testAPI(t, Principal{Subject: "u1"})
	w := get(t, a.HandleUsage, "/api/system/licence/usage")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for an unresolved scope", w.Code)
	}
}

func TestUsageRefusesAMalformedOrOversizePeriod(t *testing.T) {
	a, _ := testAPI(t, Principal{Subject: "owner", CrossTenant: true})
	for _, q := range []string{
		"?from=2026-09-05&to=2026-09-01",
		"?from=yesterday&to=today",
		"?from=2000-01-01&to=2026-09-05",
	} {
		w := get(t, a.HandleUsage, "/api/system/licence/usage"+q)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, w.Code)
		}
	}
}

func TestUsageDefaultsToTheLastThirtyDays(t *testing.T) {
	a, _ := testAPI(t, Principal{Subject: "owner", CrossTenant: true})
	v := decodeView(t, get(t, a.HandleUsage, "/api/system/licence/usage"))
	if v.To != "2026-09-05" || v.From != "2026-08-07" {
		t.Fatalf("default period = %s..%s, want the 30 days ending today", v.From, v.To)
	}
}

func TestUsageRefusesAnythingButGET(t *testing.T) {
	a, _ := testAPI(t, Principal{Subject: "owner", CrossTenant: true})
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		w := httptest.NewRecorder()
		a.HandleUsage(w, httptest.NewRequest(m, "/api/system/licence/usage", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405 — metering is a read", m, w.Code)
		}
	}
}

func TestReportIsSignedAndVerifiesFromItsOwnBytes(t *testing.T) {
	a, aud := testAPI(t, Principal{Subject: "owner", CrossTenant: true})
	w := get(t, a.HandleReport, "/api/system/licence/usage/report?from=2026-09-01&to=2026-09-30")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "correlix-usage-2026-09-01_2026-09-30.json") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	rep, err := VerifyReport(w.Body.Bytes(), nil)
	if err != nil {
		t.Fatalf("the served report did not verify: %v", err)
	}
	if rep.Scope != ReportScopePlatform || len(rep.Days) != 9 {
		t.Errorf("report scope=%q days=%d", rep.Scope, len(rep.Days))
	}
	if _, disagree := RecomputeTotals(rep); len(disagree) != 0 {
		t.Errorf("the report's totals do not follow from its own rows: %v", disagree)
	}
	if len(aud.evs) != 1 || aud.evs[0].Decision != "allow" {
		t.Fatalf("the download was not audited: %+v", aud.evs)
	}
}

func TestTenantReportCarriesOnlyThatTenant(t *testing.T) {
	a, _ := testAPI(t, Principal{Subject: "u1", Tenant: "acme"})
	w := get(t, a.HandleReport, "/api/system/licence/usage/report?from=2026-09-01&to=2026-09-30")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	rep, err := VerifyReport(w.Body.Bytes(), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Scope != ReportScopeTenant || rep.Tenant != "acme" {
		t.Fatalf("scope=%q tenant=%q", rep.Scope, rep.Tenant)
	}
	for _, d := range rep.Days {
		if d.TenantID != "acme" {
			t.Fatalf("a tenant's report carries a %q row", d.TenantID)
		}
	}
	if rep.Licence.Customer != "" || rep.Licence.LicenceID != "" {
		t.Fatalf("a tenant's report carries the provider's commercial identity: %+v", rep.Licence)
	}
}

func TestUsageServesWithNoGateOrStoreRefused(t *testing.T) {
	a := New(Deps{})
	w := get(t, a.HandleUsage, "/api/system/licence/usage")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a surface that cannot gate served anyway: %d", w.Code)
	}
	w = get(t, a.HandleReport, "/api/system/licence/usage/report")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a surface that cannot gate served a report anyway: %d", w.Code)
	}
}

func TestUsageSaysWhenItCouldNotReadTheHistory(t *testing.T) {
	a := New(Deps{
		Store:    brokenStore{},
		Key:      NewReportKey("", nil),
		ReadGate: func(http.ResponseWriter, *http.Request) (Principal, bool) { return Principal{CrossTenant: true}, true },
		Now:      func() time.Time { return day("2026-09-05T12:00:00Z") },
	})
	v := decodeView(t, get(t, a.HandleUsage, "/api/system/licence/usage"))
	if v.StoreError == "" {
		t.Fatalf("an unreadable history rendered as an empty one — the two are different facts")
	}
}

type brokenStore struct{}

func (brokenStore) Record(context.Context, time.Time, map[string][]Reading) error { return errBroken }
func (brokenStore) List(context.Context, string, bool, string, string) ([]DailyRecord, error) {
	return nil, errBroken
}
func (brokenStore) Rows(context.Context) (int, error)          { return 0, errBroken }
func (brokenStore) Prune(context.Context, string) (int, error) { return 0, errBroken }

var errBroken = errString("the metering store is unavailable")

type errString string

func (e errString) Error() string { return string(e) }
