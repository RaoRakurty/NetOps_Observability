package experience

// http_test.go — the surface's own behaviour, with the platform stubbed out.
// The cross-org half lives in src/backend/dem_experience_isolation_test.go
// (real router, real auth); this file proves the module's contract: honest
// not-measured shapes, refused unknown parameters, refused methods, and the
// round trip of the two writable objects.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem"
)

func newTestAPI(t *testing.T, targets []dem.Target) (*API, *Counters) {
	t.Helper()
	policy, err := EmbeddedScorePolicy()
	if err != nil {
		t.Fatal(err)
	}
	counters := NewCounters()
	api, err := NewAPI(Deps{
		Authz: func(_ http.ResponseWriter, r *http.Request, _ dem.Gate) (dem.Principal, bool) {
			if r.Header.Get("X-Test-Cross") == "1" {
				return dem.Principal{Tenant: "", Cross: true, Subject: "platform"}, true
			}
			return dem.Principal{Tenant: "acme", Subject: "operator"}, true
		},
		Store:   NewFileStore(""),
		Targets: &memCatalogue{rows: targets},
		Policy:  policy,
		Enabled: true,
		Now:     func() time.Time { return testNow },
		WriteJSON: func(w http.ResponseWriter, status int, body any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		},
		WriteError: func(w http.ResponseWriter, status int, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		},
		LogWarn:  func(string, map[string]any) {},
		Counters: counters,
	})
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return api, counters
}

func call(t *testing.T, h http.HandlerFunc, method, target string, body string, headers map[string]string) (int, []byte) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w.Code, w.Body.Bytes()
}

func TestOverviewIsHonestWithNoMetricsBackend(t *testing.T) {
	api, counters := newTestAPI(t, nil)
	code, body := call(t, api.HandleOverview, http.MethodGet, "/api/dem/overview", "", nil)
	if code != http.StatusOK {
		t.Fatalf("overview: %d %s", code, body)
	}
	var resp OverviewResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if resp.Measured || resp.Score.Score != nil {
		t.Fatalf("a window with no measurement published a score: %+v", resp.Score)
	}
	if resp.Reason == "" || resp.Note == "" {
		t.Fatalf("the empty view gave no reason: %+v", resp)
	}
	if resp.PolicyVersion == 0 {
		t.Fatal("the overview did not state which score policy it used")
	}
	if resp.DataHealth.CanConfirm {
		t.Fatal("a deployment with no flowing source claimed it could confirm a cause")
	}
	if resp.AIInvestigator.Available || resp.AIInvestigator.Reason == "" {
		t.Fatalf("the AI panel was not reported as unavailable-with-a-reason: %+v", resp.AIInvestigator)
	}
	if counters.ViewsServed.Load() != 1 {
		t.Fatalf("the view counter did not move: %d", counters.ViewsServed.Load())
	}
	// Every source in the ladder is reported, including the ones with no
	// producer — a source missing from the list is a source nobody notices.
	if len(resp.DataHealth.Sources) != len(SourceLadder) {
		t.Fatalf("the data-health report covered %d of %d sources", len(resp.DataHealth.Sources), len(SourceLadder))
	}
}

func TestUnknownQueryParametersAndMethodsAreRefused(t *testing.T) {
	api, _ := newTestAPI(t, nil)
	handlers := map[string]http.HandlerFunc{
		"/api/dem/overview":            api.HandleOverview,
		"/api/dem/incidents":           api.HandleIncidents,
		"/api/dem/journeys":            api.HandleJourneys,
		"/api/dem/synthetics/coverage": api.HandleCoverage,
		"/api/dem/changes":             api.HandleChanges,
		"/api/dem/data-health":         api.HandleDataHealth,
	}
	for path, h := range handlers {
		if code, body := call(t, h, http.MethodGet, path+"?page_size=1", "", nil); code != http.StatusBadRequest {
			t.Fatalf("%s swallowed an unknown parameter: %d %s", path, code, body)
		}
		if code, _ := call(t, h, http.MethodGet, path+"?window=7d", "", nil); code != http.StatusBadRequest {
			t.Fatalf("%s accepted an unbounded window", path)
		}
	}
	// A read-only route refuses a write method rather than ignoring it.
	if code, _ := call(t, api.HandleOverview, http.MethodPost, "/api/dem/overview", "{}", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("the overview accepted a POST: %d", code)
	}
}

func TestCrossTenantPrincipalIsRefusedOnEverySurface(t *testing.T) {
	api, _ := newTestAPI(t, nil)
	cross := map[string]string{"X-Test-Cross": "1"}
	for path, h := range map[string]http.HandlerFunc{
		"/api/dem/overview":            api.HandleOverview,
		"/api/dem/incidents":           api.HandleIncidents,
		"/api/dem/journeys":            api.HandleJourneys,
		"/api/dem/synthetics/coverage": api.HandleCoverage,
		"/api/dem/changes":             api.HandleChanges,
		"/api/dem/data-health":         api.HandleDataHealth,
	} {
		if code, body := call(t, h, http.MethodGet, path, "", cross); code != http.StatusBadRequest {
			t.Fatalf("%s served a cross-tenant principal: %d %s", path, code, body)
		}
	}
}

func TestJourneyRoundTripAndHonestEmptyList(t *testing.T) {
	api, counters := newTestAPI(t, nil)

	code, body := call(t, api.HandleJourneys, http.MethodGet, "/api/dem/journeys", "", nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	var empty JourneysResponse
	if err := json.Unmarshal(body, &empty); err != nil {
		t.Fatal(err)
	}
	if empty.Reason != ReasonNoJourneys || empty.Note == "" {
		t.Fatalf("an empty journey list was not explained: %+v", empty)
	}

	create := `{"name":"Checkout","app":"checkout","business_importance":"critical",
	  "entry_step_id":"browse","slo":{"success_pct":99},
	  "steps":[{"id":"browse","label":"Browse","next":["pay"]},{"id":"pay","label":"Pay","terminal_success":true}]}`
	code, body = call(t, api.HandleJourneys, http.MethodPost, "/api/dem/journeys", create, nil)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var made JourneyDefinition
	if err := json.Unmarshal(body, &made); err != nil {
		t.Fatal(err)
	}
	if made.TenantID != "acme" {
		t.Fatalf("the owner was not stamped from the token: %q", made.TenantID)
	}
	if counters.JourneysCreated.Load() != 1 {
		t.Fatal("the create counter did not move")
	}

	// An unknown field is REFUSED: a typo'd budget must fail, not vanish.
	if code, _ := call(t, api.HandleJourneys, http.MethodPost, "/api/dem/journeys",
		`{"name":"x","entry_step_id":"s","steps":[{"id":"s","terminal_success":true}],"slo_success":99}`, nil); code != http.StatusBadRequest {
		t.Fatalf("an unknown field was accepted: %d", code)
	}
	// A journey that cannot succeed is refused.
	if code, _ := call(t, api.HandleJourneys, http.MethodPost, "/api/dem/journeys",
		`{"name":"x","entry_step_id":"s","steps":[{"id":"s"}]}`, nil); code != http.StatusBadRequest {
		t.Fatal("a journey with no success terminal was accepted")
	}
}

func TestChangeRoundTripAndHonestEmptyFeed(t *testing.T) {
	api, counters := newTestAPI(t, nil)
	code, body := call(t, api.HandleChanges, http.MethodGet, "/api/dem/changes", "", nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	var feed struct {
		Changes []ChangeEvent `json:"changes"`
		Note    string        `json:"note"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		t.Fatal(err)
	}
	if feed.Note == "" {
		t.Fatal("an empty change feed did not say that silence is not proof nothing changed")
	}

	code, body = call(t, api.HandleChanges, http.MethodPost, "/api/dem/changes",
		`{"type":"APPLICATION_DEPLOY","object":"checkout-api","summary":"v42 deployed","app":"checkout"}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("record: %d %s", code, body)
	}
	var made ChangeEvent
	if err := json.Unmarshal(body, &made); err != nil {
		t.Fatal(err)
	}
	if made.TenantID != "acme" || made.Actor != "operator" {
		t.Fatalf("the owner/actor were not taken from the token: %+v", made)
	}
	if counters.ChangesRecorded.Load() != 1 {
		t.Fatal("the change counter did not move")
	}
	// An unknown change type is refused rather than stored as a mystery.
	if code, _ := call(t, api.HandleChanges, http.MethodPost, "/api/dem/changes",
		`{"type":"SOMETHING_ELSE","object":"x","summary":"y"}`, nil); code != http.StatusBadRequest {
		t.Fatal("an unknown change type was accepted")
	}
	if code, _ := call(t, api.HandleChanges, http.MethodGet, "/api/dem/changes?type=NOPE", "", nil); code != http.StatusBadRequest {
		t.Fatal("an unknown change-type filter was accepted")
	}
}

func TestCoverageReportsUnknownReliabilityRatherThanTrust(t *testing.T) {
	api, _ := newTestAPI(t, nil)
	code, body := call(t, api.HandleCoverage, http.MethodGet, "/api/dem/synthetics/coverage", "", nil)
	if code != http.StatusOK {
		t.Fatalf("coverage: %d %s", code, body)
	}
	var resp struct {
		Coverage        CoverageReport `json:"coverage"`
		ReliabilityNote string         `json:"reliability_note"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ReliabilityNote == "" {
		t.Fatal("the coverage report did not say that no check has been graded")
	}
	if resp.Coverage.CoveragePct != nil {
		t.Fatalf("coverage of nothing was reported as %v", *resp.Coverage.CoveragePct)
	}
}

func TestIncidentSubResourcesAndUnknownIDs(t *testing.T) {
	api, _ := newTestAPI(t, nil)
	for _, path := range []string{
		"/api/dem/incidents/exp-00000000000000000000",
		"/api/dem/incidents/exp-00000000000000000000/evidence",
		"/api/dem/incidents/exp-00000000000000000000/timeline",
		"/api/dem/incidents/exp-00000000000000000000/path",
		"/api/dem/incidents/not-an-id",
		"/api/dem/incidents/exp-00000000000000000000/made-up",
	} {
		if code, body := call(t, api.HandleIncidentItem, http.MethodGet, path, "", nil); code != http.StatusNotFound {
			t.Fatalf("GET %s → %d %s (must be 404)", path, code, body)
		}
	}
}

// memCatalogue is a tenant-agnostic stand-in for internal/dem's catalogue: it
// answers the reads this surface makes and refuses the writes it never makes.
// The isolation it does NOT implement is exactly why the cross-org proof lives
// in the root package against the real store and the real router.
type memCatalogue struct{ rows []dem.Target }

var _ dem.Catalogue = (*memCatalogue)(nil)

func (m *memCatalogue) List(context.Context, string) ([]dem.Target, error) { return m.rows, nil }

func (m *memCatalogue) Get(_ context.Context, _, id string) (dem.Target, error) {
	for _, t := range m.rows {
		if t.ID == id {
			return t, nil
		}
	}
	return dem.Target{}, dem.ErrNotFound
}

func (m *memCatalogue) Create(context.Context, dem.Target) (dem.Target, error) {
	return dem.Target{}, errNotUsedHere
}

func (m *memCatalogue) Update(context.Context, string, string, dem.Patch) (dem.Target, error) {
	return dem.Target{}, errNotUsedHere
}

func (m *memCatalogue) Delete(context.Context, string, string) error { return errNotUsedHere }

func (m *memCatalogue) ListAll(context.Context) ([]dem.Target, error) { return m.rows, nil }

// errNotUsedHere fails LOUDLY rather than silently succeeding: the experience
// surface never writes the catalogue, and a test that started to would be
// telling us something.
var errNotUsedHere = errors.New("experience tests: the experience surface must not write the target catalogue")
