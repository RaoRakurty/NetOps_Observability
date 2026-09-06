package experience

// promote_test.go — tracker 255: promoting a derived experience incident into
// the platform incident record.
//
// The four properties that make promotion trustworthy:
//   1. the platform incident is stamped with the EXPERIENCE evidence class and
//      the derived id, so the incident surfaces can find it and trace it back;
//   2. it is IDEMPOTENT — a second promotion folds into the first incident
//      instead of raising a twin, and does not rewrite the frozen packet;
//   3. the derived view and the stored record cannot silently disagree: where
//      the evidence has moved since promotion, the difference is REPORTED;
//   4. tenant scoping — the owner comes from the token, a foreign id is 404,
//      and one tenant's promotions are invisible to another.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem"
)

// fakePromoter stands in for the platform incident repository, with the same
// dedup contract: the same dedup key folds into one incident.
type fakePromoter struct {
	byKey map[string]string
	calls []PromotionInput
	err   error
	next  int
}

func newFakePromoter() *fakePromoter { return &fakePromoter{byKey: map[string]string{}} }

func (f *fakePromoter) Promote(_ context.Context, in PromotionInput) (string, bool, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return "", false, f.err
	}
	if id, ok := f.byKey[in.TenantID+"|"+in.DedupKey]; ok {
		return id, false, nil
	}
	f.next++
	id := "inc-" + itoaSmall(f.next)
	f.byKey[in.TenantID+"|"+in.DedupKey] = id
	return id, true, nil
}

// failingQuerier answers as a metrics backend would for a target that is
// FAILING: samples were taken and none of them succeeded. That is what makes
// the derived list non-empty, which is what a promotion needs to act on.
type failingQuerier struct{ targetID string }

func (q failingQuerier) Instant(_ context.Context, expr string, _ []string) ([]dem.Sample, error) {
	labels := map[string]string{"target": q.targetID}
	switch {
	case strings.Contains(expr, "count_over_time("+dem.MetricSuccess):
		return []dem.Sample{{Labels: labels, Value: 60}}, nil
	case strings.Contains(expr, "sum_over_time("+dem.MetricSuccess):
		return []dem.Sample{{Labels: labels, Value: 0}}, nil // nothing succeeded
	case strings.Contains(expr, "timestamp("):
		return []dem.Sample{{Labels: labels, Value: float64(testNow.Add(-time.Minute).Unix())}}, nil
	}
	return nil, nil
}

// failingTarget is the catalogue row the failing series belong to.
func failingTarget(tenant string) dem.Target {
	return dem.Target{
		ID: "dem-promote-1", TenantID: tenant, Name: "checkout", Kind: dem.KindHTTP,
		Host: "https://shop.example/health", App: "checkout", Site: "dc1",
		IntervalSec: 60, AvailabilityBudgetPct: 99,
	}
}

// promoteAPI builds a surface whose derived incidents are real: one failing
// target bound to a declared journey step, so Detect() raises an incident the
// promotion path can act on.
func promoteAPI(t *testing.T, promoter IncidentPromoter, store Store, tenant string) (*API, *Counters) {
	t.Helper()
	policy, err := EmbeddedScorePolicy()
	if err != nil {
		t.Fatal(err)
	}
	counters := NewCounters()
	api, err := NewAPI(Deps{
		Authz: func(_ http.ResponseWriter, r *http.Request, _ dem.Gate) (dem.Principal, bool) {
			if v := r.Header.Get("X-Test-Tenant"); v != "" {
				return dem.Principal{Tenant: v, Subject: "operator-" + v}, true
			}
			return dem.Principal{Tenant: tenant, Subject: "operator"}, true
		},
		Store:    store,
		Targets:  &memCatalogue{rows: []dem.Target{failingTarget(tenant)}},
		Metrics:  failingQuerier{targetID: failingTarget(tenant).ID},
		Promoter: promoter,
		Policy:   policy,
		Enabled:  true,
		Now:      func() time.Time { return testNow },
		WriteJSON: func(w http.ResponseWriter, status int, body any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		},
		WriteError: func(w http.ResponseWriter, status int, e error) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
		},
		LogWarn:  func(string, map[string]any) {},
		Counters: counters,
	})
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return api, counters
}

// seedFailingApp declares a journey whose bound target has no measurement, so
// the derived list is deterministic. Returns the derived incident's id.
func derivedIncidentID(t *testing.T, api *API, tenant string) string {
	t.Helper()
	code, body := callTenant(t, api.HandleIncidents, http.MethodGet, IncidentsPath, "", tenant)
	if code != http.StatusOK {
		t.Fatalf("list incidents: %d %s", code, body)
	}
	var resp IncidentsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if len(resp.Incidents) == 0 {
		t.Fatalf("no incident was derived from a target that failed every one of its 60 samples; "+
			"the fixture is not exercising the promotion path at all: %s", body)
	}
	return resp.Incidents[0].ID
}

func callTenant(t *testing.T, h http.HandlerFunc, method, target, body, tenant string) (int, []byte) {
	t.Helper()
	headers := map[string]string{}
	if tenant != "" {
		headers["X-Test-Tenant"] = tenant
	}
	return call(t, h, method, target, body, headers)
}

// ── the promotion contract, without HTTP ────────────────────────────────────

func TestPromotionValidateRefusesWhatItCannotLink(t *testing.T) {
	cases := []struct {
		name string
		p    Promotion
	}{
		{"no tenant", Promotion{ExperienceID: "exp-1", IncidentID: "inc-1", PromotedAt: testNow}},
		{"wildcard tenant", Promotion{TenantID: "*", ExperienceID: "exp-1", IncidentID: "inc-1", PromotedAt: testNow}},
		{"no experience id", Promotion{TenantID: "acme", IncidentID: "inc-1", PromotedAt: testNow}},
		{"no incident id", Promotion{TenantID: "acme", ExperienceID: "exp-1", PromotedAt: testNow}},
		{"no time", Promotion{TenantID: "acme", ExperienceID: "exp-1", IncidentID: "inc-1"}},
		{"packet belongs to another tenant", Promotion{
			TenantID: "acme", ExperienceID: "exp-1", IncidentID: "inc-1", PromotedAt: testNow,
			Packet: ExperienceIncident{TenantID: "globex"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			if err := p.Validate(); err == nil {
				t.Fatalf("accepted: %+v", p)
			}
		})
	}
	ok := Promotion{TenantID: "ACME ", ExperienceID: "exp-1", IncidentID: "inc-1", PromotedAt: testNow}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid promotion was refused: %v", err)
	}
	if ok.TenantID != "acme" {
		t.Fatalf("tenant not normalized: %q", ok.TenantID)
	}
}

func TestPromotionStoreIsTenantKeyedAndIdempotent(t *testing.T) {
	store := NewFileStore("")
	ctx := context.Background()
	a := Promotion{TenantID: "acme", ExperienceID: "exp-1", IncidentID: "inc-a", PromotedAt: testNow, PromotedBy: "alice"}
	b := Promotion{TenantID: "globex", ExperienceID: "exp-1", IncidentID: "inc-b", PromotedAt: testNow, PromotedBy: "bob"}
	if _, err := store.SavePromotion(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SavePromotion(ctx, b); err != nil {
		t.Fatal(err)
	}
	// Same derived id, two tenants, two incidents — and neither can see the
	// other's.
	gotA, err := store.GetPromotion(ctx, "acme", "exp-1")
	if err != nil || gotA.IncidentID != "inc-a" {
		t.Fatalf("acme read %+v (%v)", gotA, err)
	}
	gotB, err := store.GetPromotion(ctx, "globex", "exp-1")
	if err != nil || gotB.IncidentID != "inc-b" {
		t.Fatalf("globex read %+v (%v)", gotB, err)
	}
	for _, scope := range []string{"", "*"} {
		if _, err := store.GetPromotion(ctx, scope, "exp-1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("scope %q resolved a promotion — a scopeless read must return nothing", scope)
		}
		list, _ := store.ListPromotions(ctx, scope)
		if len(list) != 0 {
			t.Fatalf("scope %q listed %d promotions", scope, len(list))
		}
	}
	// Idempotent: re-saving returns the FIRST row and does not rewrite it.
	again, err := store.SavePromotion(ctx, Promotion{
		TenantID: "acme", ExperienceID: "exp-1", IncidentID: "inc-SECOND",
		PromotedAt: testNow.Add(time.Hour), PromotedBy: "carol"})
	if err != nil {
		t.Fatal(err)
	}
	if again.IncidentID != "inc-a" || again.PromotedBy != "alice" {
		t.Fatalf("a re-promotion rewrote the record of what the first operator acted on: %+v", again)
	}
	list, _ := store.ListPromotions(ctx, "acme")
	if len(list) != 1 {
		t.Fatalf("acme holds %d promotions, want 1", len(list))
	}
}

func TestDriftReportsWhatMovedSincePromotion(t *testing.T) {
	promoted := ExperienceIncident{
		Severity: SeverityHigh, VerdictTier: "suspected", Status: "open",
		LeadingHypothesisID: "hyp-1", Confidence: 0.81,
	}
	current := promoted
	if got := DriftSince(promoted, current); len(got) != 0 {
		t.Fatalf("identical packets drifted: %+v", got)
	}
	current.Severity = SeverityMedium
	current.Confidence = 0.42
	current.VerdictTier = "undetermined"
	now := time.Now()
	current.RecoveredAt = &now
	got := DriftSince(promoted, current)
	fields := map[string]PromotionDrift{}
	for _, d := range got {
		fields[d.Field] = d
	}
	for _, want := range []string{"severity", "verdict_tier", "confidence", "recovered"} {
		if _, ok := fields[want]; !ok {
			t.Fatalf("drift did not report %s: %+v", want, got)
		}
	}
	if fields["severity"].AtPromote != SeverityHigh || fields["severity"].Now != SeverityMedium {
		t.Fatalf("severity drift is wrong way round: %+v", fields["severity"])
	}
	// A confidence that barely moved is NOT drift — reporting rounding noise
	// would train an operator to ignore the field.
	small := promoted
	small.Confidence = 0.83
	for _, d := range DriftSince(promoted, small) {
		if d.Field == "confidence" {
			t.Fatalf("a 0.02 confidence move was reported as drift: %+v", d)
		}
	}
}

func TestApplyPromotionsStampsTheLinkage(t *testing.T) {
	incs := []ExperienceIncident{{ID: "exp-1"}, {ID: "exp-2"}}
	out := ApplyPromotions(incs, map[string]Promotion{
		"exp-1": {ExperienceID: "exp-1", IncidentID: "inc-9"},
	})
	if !out[0].Promoted || out[0].IncidentID != "inc-9" {
		t.Fatalf("promoted incident not stamped: %+v", out[0])
	}
	if out[1].Promoted || out[1].IncidentID != "" {
		t.Fatalf("an unpromoted incident claimed a platform record: %+v", out[1])
	}
}

// ── the route ───────────────────────────────────────────────────────────────

func TestPromoteRouteRefusesWhenNoIncidentRecordExists(t *testing.T) {
	api, _ := promoteAPI(t, nil, NewFileStore(""), "acme")
	// A REAL derived id: the 404-for-an-unknown-id check runs first on purpose,
	// so that what a caller learns from probing an id never depends on which
	// storage backend the operator happens to run.
	id := derivedIncidentID(t, api, "acme")
	code, body := call(t, api.HandleIncidentItem, http.MethodPost,
		IncidentItemPath+id+"/promote", "", nil)
	if code != http.StatusConflict {
		t.Fatalf("a deployment with no incident store answered %d %s, want 409", code, body)
	}
	if !strings.Contains(string(body), "no incident system of record") {
		t.Fatalf("the refusal did not name the cause: %s", body)
	}
	// And an id this tenant does not have is 404 on THIS deployment too — the
	// backend must not change what an id probe reveals.
	code, _ = call(t, api.HandleIncidentItem, http.MethodPost,
		IncidentItemPath+"exp-"+strings.Repeat("a", 20)+"/promote", "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("an unknown id answered %d on a backend with no incident store, want 404", code)
	}
}

func TestPromoteRouteRefusesAnUnknownOrForeignID(t *testing.T) {
	api, _ := promoteAPI(t, newFakePromoter(), NewFileStore(""), "acme")
	// Well-formed but not derived in this window: 404, never 403 — a 403 would
	// confirm that the id exists somewhere.
	code, _ := call(t, api.HandleIncidentItem, http.MethodPost,
		IncidentItemPath+"exp-"+strings.Repeat("a", 20)+"/promote", "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("an unknown id answered %d, want 404", code)
	}
	// Malformed: also 404, for the same reason.
	code, _ = call(t, api.HandleIncidentItem, http.MethodPost, IncidentItemPath+"not-an-id/promote", "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("a malformed id answered %d, want 404", code)
	}
	// The wrong METHOD on the promote sub-resource is 405, not a silent read.
	code, _ = call(t, api.HandleIncidentItem, http.MethodGet,
		IncidentItemPath+"exp-"+strings.Repeat("a", 20)+"/promote", "", nil)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the promote route answered %d, want 405", code)
	}
}

func TestPromotedIncidentsAreStampedOnTheListAndTheItem(t *testing.T) {
	store := NewFileStore("")
	api, _ := promoteAPI(t, newFakePromoter(), store, "acme")
	// Seed a promotion directly: the derived list is recomputed on every read,
	// so a stored linkage for an id that IS derived must appear on both
	// surfaces without any further write.
	id := derivedIncidentID(t, api, "acme")
	if _, err := store.SavePromotion(context.Background(), Promotion{
		TenantID: "acme", ExperienceID: id, IncidentID: "inc-7",
		PromotedAt: testNow, PromotedBy: "alice",
		Packet: ExperienceIncident{ID: id, TenantID: "acme", Severity: SeverityCritical},
	}); err != nil {
		t.Fatal(err)
	}
	code, body := call(t, api.HandleIncidents, http.MethodGet, IncidentsPath, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	if !strings.Contains(string(body), "inc-7") {
		t.Fatalf("the list did not carry the platform incident id: %s", body)
	}
	code, body = call(t, api.HandleIncidentItem, http.MethodGet, IncidentItemPath+id, "", nil)
	if code != http.StatusOK {
		t.Fatalf("item: %d %s", code, body)
	}
	var resp IncidentResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Incident.Promoted || resp.Incident.IncidentID != "inc-7" {
		t.Fatalf("the item did not carry the linkage: %+v", resp.Incident)
	}
	if resp.Promotion == nil {
		t.Fatal("the item did not return the stored packet")
	}
	// The seeded packet said CRITICAL; the live derivation says something else,
	// and the difference must be REPORTED rather than silently resolved.
	if len(resp.Drift) == 0 {
		t.Fatal("the stored packet and the live derivation disagree and no drift was reported")
	}
	if !strings.Contains(resp.PromotionNote, "MOVED") {
		t.Fatalf("the note did not say the evidence moved: %q", resp.PromotionNote)
	}
}

func TestOneTenantsPromotionsAreInvisibleToAnother(t *testing.T) {
	store := NewFileStore("")
	api, _ := promoteAPI(t, newFakePromoter(), store, "acme")
	id := derivedIncidentID(t, api, "acme")
	if _, err := store.SavePromotion(context.Background(), Promotion{
		TenantID: "acme", ExperienceID: id, IncidentID: "inc-secret",
		PromotedAt: testNow, PromotedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	// The same derived id under ANOTHER tenant's scope must not resolve the
	// linkage, whether or not that tenant derives an incident of its own.
	code, body := callTenant(t, api.HandleIncidents, http.MethodGet, IncidentsPath, "", "globex")
	if code != http.StatusOK {
		t.Fatalf("list as globex: %d %s", code, body)
	}
	if strings.Contains(string(body), "inc-secret") {
		t.Fatalf("another tenant saw acme's platform incident id: %s", body)
	}
	code, body = callTenant(t, api.HandleIncidentItem, http.MethodGet, IncidentItemPath+id, "", "globex")
	if code == http.StatusOK && strings.Contains(string(body), "inc-secret") {
		t.Fatalf("another tenant read acme's promotion: %s", body)
	}
}

func TestPromoteStampsTheOwnerAndTheEvidenceClass(t *testing.T) {
	store := NewFileStore("")
	promoter := newFakePromoter()
	api, counters := promoteAPI(t, promoter, store, "acme")
	id := derivedIncidentID(t, api, "acme")

	code, body := call(t, api.HandleIncidentItem, http.MethodPost,
		IncidentItemPath+id+"/promote", `{"note":"paging the ISP"}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("promote: %d %s", code, body)
	}
	var resp PromoteResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Created || resp.IncidentID == "" {
		t.Fatalf("promotion did not raise an incident: %+v", resp)
	}
	if resp.SourceType != PromotionSource {
		t.Fatalf("source_type = %q, want %q — the incident surfaces filter on it", resp.SourceType, PromotionSource)
	}
	if len(promoter.calls) != 1 {
		t.Fatalf("promoter calls = %d", len(promoter.calls))
	}
	in := promoter.calls[0]
	if in.TenantID != "acme" {
		t.Fatalf("owner = %q, want the token's tenant", in.TenantID)
	}
	if in.SourceID != id || in.DedupKey != id {
		t.Fatalf("the derived id is not the source/dedup key: %+v", in)
	}
	if in.Actor != "operator" {
		t.Fatalf("actor = %q — a promotion must be audited with who did it", in.Actor)
	}
	if !strings.Contains(in.Description, "paging the ISP") {
		t.Fatalf("the operator's note did not reach the incident: %q", in.Description)
	}
	if counters.IncidentsPromoted.Load() != 1 {
		t.Fatalf("counter = %d", counters.IncidentsPromoted.Load())
	}

	// SECOND promotion of the same window: folds in, does not raise a twin, and
	// does not rewrite the frozen packet.
	code, body = call(t, api.HandleIncidentItem, http.MethodPost, IncidentItemPath+id+"/promote", "", nil)
	if code != http.StatusOK {
		t.Fatalf("re-promote: %d %s", code, body)
	}
	var again PromoteResponse
	if err := json.Unmarshal(body, &again); err != nil {
		t.Fatal(err)
	}
	if again.Created {
		t.Fatal("a second promotion claimed to have raised a new incident")
	}
	if again.IncidentID != resp.IncidentID {
		t.Fatalf("a second promotion pointed at a different incident: %s vs %s", again.IncidentID, resp.IncidentID)
	}
	if again.Promotion.PromotedBy != resp.Promotion.PromotedBy {
		t.Fatal("the second promotion rewrote the record of who acted")
	}
	if len(promoter.calls) != 1 {
		t.Fatalf("the incident repository was called %d times for one window", len(promoter.calls))
	}
}

func TestAFailedPromotionSaysTheIncidentAlreadyExists(t *testing.T) {
	promoter := newFakePromoter()
	promoter.err = errors.New("the database is unavailable")
	api, counters := promoteAPI(t, promoter, NewFileStore(""), "acme")
	id := derivedIncidentID(t, api, "acme")
	code, body := call(t, api.HandleIncidentItem, http.MethodPost, IncidentItemPath+id+"/promote", "", nil)
	if code != http.StatusInternalServerError {
		t.Fatalf("a failed promotion answered %d %s", code, body)
	}
	if counters.PromotionErrors.Load() != 1 {
		t.Fatalf("the failure was not counted: %d", counters.PromotionErrors.Load())
	}
}
