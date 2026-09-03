package backend

// bgp_alerts_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for
// the three BGP alerting/bogon surfaces, exercised through the REAL
// s.bgpWatchAuthz gate mapping (not a fake), because the gate CHOICE is half of
// what §3a rule 3 is about.
//
// Proven here:
//   - own-only reads: acme never sees globex's alerts, incidents, sightings or
//     alert policy, and vice versa;
//   - the alert POLICY is stamped from the token, and an `as_tenant` in the
//     body is impossible (there is no tenant field on the wire) — a cross-org
//     write is refused, not silently re-owned;
//   - a cross-tenant principal (the platform owner in the Global view) is
//     REFUSED on all three rather than being served every tenant's rows;
//   - a read-only principal cannot write the policy;
//   - with the evaluator off the routes are honest (enabled:false + a note),
//     not an empty list that reads as "all clear";
//   - a nil API (construction refused) answers 404, so a broken wiring never
//     degrades into an unscoped read.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/bgpwatch"
)

// bgpWatchTestServer builds the minimal server the handlers need, with an
// evaluator whose upstreams are inert fakes (no network, no bus, no Postgres).
func bgpWatchTestServer(t *testing.T, withEval bool) *server {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	s := &server{roles: roles}
	policies := bgpwatch.NewFileStore("") // in-memory
	s.bgpWatchPolicy = policies
	bogons := bgpwatch.NewBogonSet()

	var eval *bgpwatch.Evaluator
	if withEval {
		now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
		watch := map[string][]string{
			"acme":   {"193.0.0.0/21"},
			"globex": {"10.9.0.0/16"}, // a bogon, so globex gets an incident + a sighting
		}
		eval, err = bgpwatch.New(bgpwatch.Deps{
			Now:       func() time.Time { return now },
			Tenants:   func() []string { return []string{"acme", "globex"} },
			Watchlist: func(_ context.Context, tn string) ([]string, error) { return watch[tn], nil },
			Policies:  policies,
			Observe: func(_ context.Context, p string) (bgpwatch.Observation, error) {
				return bgpwatch.Observation{
					Prefix: p, Measured: true, Announced: true, AnnouncedKnown: true,
					PeersSeeing: 300, PeersTotal: 320, RPKIState: "valid", FetchedAt: now,
				}, nil
			},
			Sightings: func(_ context.Context, tn string) ([]bgpwatch.PrefixSighting, error) {
				if tn == "globex" {
					return []bgpwatch.PrefixSighting{{Prefix: "10.9.0.0/16", Peer: "rrc00", Source: "bmp", At: now}}, nil
				}
				return nil, nil
			},
			Bogons:   bogons,
			LogWarn:  func(string, map[string]any) {},
			LogError: func(string, map[string]any) {},
			Rand:     func() float64 { return 0.5 },
			Sleep:    func(context.Context, time.Duration) error { return nil },
		})
		if err != nil {
			t.Fatalf("bgpwatch.New: %v", err)
		}
		eval.RunOnce(context.Background())
		s.bgpWatchEval = eval
	}
	api, err := s.buildBGPWatchAPI(policies, bogons, eval)
	if err != nil {
		t.Fatalf("buildBGPWatchAPI: %v", err)
	}
	s.bgpWatchAPI = api
	return s
}

type bgpAlertsBody struct {
	Alerts    []bgpwatch.Alert    `json:"alerts"`
	Incidents []bgpwatch.Incident `json:"incidents"`
	Status    bgpwatch.Status     `json:"status"`
}

func bgpAlertsGet(t *testing.T, s *server, claims jwtClaims) (int, bgpAlertsBody) {
	t.Helper()
	w := httptest.NewRecorder()
	s.bgpWatchAPI.HandleAlerts(w, req(http.MethodGet, "/api/bgp/alerts", "", claims))
	var body bgpAlertsBody
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
	}
	return w.Code, body
}

func TestBGPAlertsAreOwnTenantOnly(t *testing.T) {
	s := bgpWatchTestServer(t, true)

	code, acmeBody := bgpAlertsGet(t, s, tAdmin("acme"))
	if code != http.StatusOK {
		t.Fatalf("acme status %d", code)
	}
	for _, inc := range acmeBody.Incidents {
		if inc.Prefix != "193.0.0.0/21" {
			t.Fatalf("acme sees another tenant's prefix %q — cross-tenant leak", inc.Prefix)
		}
	}
	for _, a := range acmeBody.Alerts {
		if strings.Contains(a.Resource, "10.9.0.0") {
			t.Fatalf("acme sees globex's alert %+v", a)
		}
	}

	code, gxBody := bgpAlertsGet(t, s, tAdmin("globex"))
	if code != http.StatusOK {
		t.Fatalf("globex status %d", code)
	}
	if len(gxBody.Incidents) != 1 || gxBody.Incidents[0].Prefix != "10.9.0.0/16" {
		t.Fatalf("globex incidents wrong: %+v", gxBody.Incidents)
	}
	if len(gxBody.Alerts) == 0 {
		t.Fatal("globex's bogon prefix should have raised an alert")
	}
}

// A cross-tenant principal must be REFUSED, never served the fleet's rows.
func TestBGPAlertsRefuseCrossTenantPrincipal(t *testing.T) {
	s := bgpWatchTestServer(t, true)
	for name, h := range map[string]http.HandlerFunc{
		"alerts": s.bgpWatchAPI.HandleAlerts,
		"config": s.bgpWatchAPI.HandleAlertConfig,
		"bogons": s.bgpWatchAPI.HandleBogons,
	} {
		w := httptest.NewRecorder()
		h(w, req(http.MethodGet, "/api/bgp/"+name, "", platformOwner()))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: a cross-tenant read returned %d; it must be refused (400) and told to scope in", name, w.Code)
		}
		if strings.Contains(w.Body.String(), "10.9.0.0") {
			t.Fatalf("%s: the refusal leaked another tenant's data: %s", name, w.Body.String())
		}
	}
}

func TestBGPBogonSightingsAreOwnTenantOnly(t *testing.T) {
	s := bgpWatchTestServer(t, true)
	read := func(claims jwtClaims) []bgpwatch.Sighting {
		w := httptest.NewRecorder()
		s.bgpWatchAPI.HandleBogons(w, req(http.MethodGet, "/api/bgp/bogons", "", claims))
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var body struct {
			Sightings []bgpwatch.Sighting `json:"sightings"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.Sightings
	}
	if got := read(tAdmin("acme")); len(got) != 0 {
		t.Fatalf("acme sees globex's bogon sightings: %+v", got)
	}
	if got := read(tAdmin("globex")); len(got) != 1 || got[0].Prefix != "10.9.0.0/16" {
		t.Fatalf("globex sightings wrong: %+v", got)
	}
}

func TestBGPAlertPolicyIsTenantOwnedAndTokenStamped(t *testing.T) {
	s := bgpWatchTestServer(t, false)
	body := `{"default":{"expected_origins":["AS64496"],"upstreams":["AS64500"]}}`

	w := httptest.NewRecorder()
	s.bgpWatchAPI.HandleAlertConfig(w, req(http.MethodPut, "/api/bgp/alerts/config", body, tAdmin("acme")))
	if w.Code != http.StatusOK {
		t.Fatalf("acme PUT status %d: %s", w.Code, w.Body.String())
	}

	// globex's read must not see it.
	w = httptest.NewRecorder()
	s.bgpWatchAPI.HandleAlertConfig(w, req(http.MethodGet, "/api/bgp/alerts/config", "", tAdmin("globex")))
	if w.Code != http.StatusOK {
		t.Fatalf("globex GET status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "64496") {
		t.Fatalf("globex read acme's alert policy: %s", w.Body.String())
	}

	// The owner is the TOKEN's subject, and the row is the token's tenant.
	pol, err := s.bgpWatchPolicy.Policy(context.Background(), "acme")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if pol.UpdatedBy != "adm@acme" {
		t.Fatalf("updated_by=%q — the owner is stamped from the token (§3a rule 2)", pol.UpdatedBy)
	}
	if other, _ := s.bgpWatchPolicy.Policy(context.Background(), "globex"); len(other.Default.ExpectedOrigins) != 0 {
		t.Fatalf("acme's write landed on globex: %+v", other)
	}

	// A cross-tenant principal cannot write anyone's policy.
	w = httptest.NewRecorder()
	s.bgpWatchAPI.HandleAlertConfig(w, req(http.MethodPut, "/api/bgp/alerts/config", body, platformOwner()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a cross-tenant write returned %d; it must be refused", w.Code)
	}

	// A read-only principal cannot write it either.
	w = httptest.NewRecorder()
	s.bgpWatchAPI.HandleAlertConfig(w, req(http.MethodPut, "/api/bgp/alerts/config", body, tViewer("acme")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a read-only principal wrote the alert policy (status %d)", w.Code)
	}
}

// With FEATURE_BGP_ALERTS off the route is HONEST, not silently empty.
func TestBGPAlertsHonestWhenEvaluatorOff(t *testing.T) {
	s := bgpWatchTestServer(t, false)
	code, body := bgpAlertsGet(t, s, tAdmin("acme"))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if body.Status.Enabled {
		t.Fatal("status.enabled must be false with the evaluator off")
	}
	if !strings.Contains(body.Status.Note, bgpwatch.EnvFeatureFlag) {
		t.Fatalf("the note must name the flag: %q", body.Status.Note)
	}
}

// A nil API (construction refused) answers 404 — a broken wiring must never
// degrade into an unscoped read.
func TestBGPWatchNilAPIIs404(t *testing.T) {
	s := &server{}
	for _, h := range []http.HandlerFunc{
		s.bgpWatchAPI.HandleAlerts, s.bgpWatchAPI.HandleAlertConfig, s.bgpWatchAPI.HandleBogons,
	} {
		w := httptest.NewRecorder()
		h(w, req(http.MethodGet, "/api/bgp/alerts", "", tAdmin("acme")))
		if w.Code != http.StatusNotFound {
			t.Fatalf("a nil bgpWatchAPI returned %d, want 404", w.Code)
		}
	}
}

// The gate mapping itself: the platform/global tenant is treated as scopeless
// so it can never read a shared bucket that no customer owns.
func TestBGPWatchAuthzTreatsGlobalTenantAsScopeless(t *testing.T) {
	s := bgpWatchTestServer(t, true)
	w := httptest.NewRecorder()
	s.bgpWatchAPI.HandleAlerts(w, req(http.MethodGet, "/api/bgp/alerts", "",
		jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("the global tenant returned %d; it must be refused and told to scope in", w.Code)
	}
}

// ── per-tenant counters (no process-wide aggregate in a tenant body) ────────
//
// /api/bgp/alerts used to serve Evaluator.Metrics().Snapshot() — the
// PROCESS-WIDE counter set — inside a per-tenant response. A scoped reader could
// watch runs_total, prefixes_evaluated_total and alerts_notified_total climb
// with every OTHER tenant's evaluation: an aggregate that reveals other
// tenants' activity is other tenants' data (internal/bmp/http.go's handleStats
// states the same rule and is the in-repo precedent).
func TestBGPAlertsMetricsAreTenantScoped(t *testing.T) {
	s := bgpWatchTestServer(t, true) // its harness already ran ONE pass for acme+globex

	body := func(claims jwtClaims) map[string]int64 {
		t.Helper()
		w := httptest.NewRecorder()
		s.bgpWatchAPI.HandleAlerts(w, req(http.MethodGet, "/api/bgp/alerts", "", claims))
		if w.Code != http.StatusOK {
			t.Fatalf("GET alerts as %s: %d %s", claims.Sub, w.Code, w.Body.String())
		}
		var out struct {
			Metrics map[string]int64 `json:"metrics"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		if out.Metrics == nil {
			t.Fatal("no metrics block in the alerts body")
		}
		return out.Metrics
	}

	acmeM := body(tAdmin("acme"))
	globexM := body(tAdmin("globex"))

	// One pass per tenant: each sees its OWN single run, never the sum.
	for name, m := range map[string]map[string]int64{"acme": acmeM, "globex": globexM} {
		if m["runs_total"] != 1 {
			t.Errorf("%s runs_total = %d, want 1 (its OWN pass, not every tenant's)", name, m["runs_total"])
		}
		if m["prefixes_evaluated_total"] != 1 {
			t.Errorf("%s prefixes_evaluated_total = %d, want its own 1 watched prefix", name, m["prefixes_evaluated_total"])
		}
	}
	// globex's watchlist is a bogon (10.9.0.0/16) and acme's is clean, so the
	// alert counter is a per-tenant fact that MUST differ between the two.
	if acmeM["alerts_notified_total"] != 0 {
		t.Errorf("acme sees %d notified alerts; it has none of its own — that is globex's activity",
			acmeM["alerts_notified_total"])
	}
	// Likewise the sighting register: globex has one, acme has none.
	if acmeM["bogon_sightings_total"] != 0 {
		t.Errorf("acme's body carries %d bogon sightings — globex's", acmeM["bogon_sightings_total"])
	}
	if globexM["bogon_sightings_total"] == 0 {
		t.Error("globex's own sighting did not reach its own counter")
	}
	// A counter that only exists process-wide must NOT appear in a tenant body.
	for _, leaked := range []string{"runs_skipped_total", "bogon_feed_errors_total"} {
		if _, ok := acmeM[leaked]; ok {
			t.Errorf("%s is a process-wide counter and must not ride in a tenant body", leaked)
		}
	}
	// A brand-new tenant sees zeros, not the platform's running totals.
	fresh := body(tAdmin("initech"))
	for k, v := range fresh {
		if k == "ring_size" {
			continue
		}
		if v != 0 {
			t.Errorf("a tenant that has never been evaluated sees %s = %d", k, v)
		}
	}
}
