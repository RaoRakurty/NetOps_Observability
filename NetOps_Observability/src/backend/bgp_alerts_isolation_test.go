// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
//     REFUSED on all four rather than being served every tenant's rows;
//   - the ORIGIN BASELINE register (tracker 281) is own-tenant only on every
//     verb: acme never lists, accepts into or deletes globex's baseline, and a
//     cross-tenant delete answers 404 rather than admitting the row exists;
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
	baselines := bgpwatch.NewBaselineFileStore("") // in-memory
	s.bgpWatchBaseline = baselines
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
			Baselines: baselines,
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
	api, err := s.buildBGPWatchAPI(policies, baselines, bogons, eval)
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
		"alerts":    s.bgpWatchAPI.HandleAlerts,
		"config":    s.bgpWatchAPI.HandleAlertConfig,
		"baselines": s.bgpWatchAPI.HandleBaselines,
		"bogons":    s.bgpWatchAPI.HandleBogons,
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
		s.bgpWatchAPI.HandleAlerts, s.bgpWatchAPI.HandleAlertConfig,
		s.bgpWatchAPI.HandleBaselines, s.bgpWatchAPI.HandleBogons,
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

// ── the ORIGIN BASELINE register (tracker 281) ──────────────────────────────
//
// CLAUDE.md §3a rule 5 for /api/bgp/alerts/baselines, through the production
// s.bgpWatchAuthz wiring. This route matters more than a read surface: the
// baseline it holds is what an origin_change is measured against, so reaching
// another tenant's row would not just disclose their address space, it would
// decide whether they get paged for a hijack.
//
// Proven: own-only list; the owner stamped from the token; a cross-tenant
// accept landing in the CALLER'S OWN bucket rather than the victim's; a
// cross-tenant delete answering 404 (absent, never "not yours"); a cross-tenant
// principal refused outright; and a read-only principal unable to write.
func TestBGPOriginBaselinesAreOwnTenantOnly(t *testing.T) {
	ctx := context.Background()
	s := bgpWatchTestServer(t, false)
	store := s.bgpWatchBaseline
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	// globex records a baseline for a prefix in ITS address space.
	if _, _, err := store.Record(ctx, "globex", bgpwatch.OriginBaseline{
		Prefix: "198.51.100.0/24", Origins: []uint32{64510}, Source: bgpwatch.BaselineFirstSeen,
		Vantages: 3, FirstSeen: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed globex: %v", err)
	}
	if _, _, err := store.Record(ctx, "acme", bgpwatch.OriginBaseline{
		Prefix: "193.0.0.0/21", Origins: []uint32{64496}, Source: bgpwatch.BaselineFirstSeen,
		Vantages: 2, FirstSeen: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed acme: %v", err)
	}

	list := func(claims jwtClaims) []bgpwatch.OriginBaseline {
		t.Helper()
		w := httptest.NewRecorder()
		s.bgpWatchAPI.HandleBaselines(w, req(http.MethodGet, "/api/bgp/alerts/baselines", "", claims))
		if w.Code != http.StatusOK {
			t.Fatalf("GET baselines as %s: %d %s", claims.Sub, w.Code, w.Body.String())
		}
		var out struct {
			Baselines []bgpwatch.OriginBaseline `json:"baselines"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		return out.Baselines
	}

	// OWN-ONLY LIST.
	acme := list(tAdmin("acme"))
	if len(acme) != 1 || acme[0].Prefix != "193.0.0.0/21" {
		t.Fatalf("acme's list is wrong (or carries globex's row): %+v", acme)
	}
	gx := list(tAdmin("globex"))
	if len(gx) != 1 || gx[0].Prefix != "198.51.100.0/24" {
		t.Fatalf("globex's list is wrong: %+v", gx)
	}

	// A CROSS-TENANT ACCEPT, naming globex's exact prefix, lands in acme's own
	// bucket. globex's row is untouched and unstamped.
	w := httptest.NewRecorder()
	s.bgpWatchAPI.HandleBaselines(w, req(http.MethodPost, "/api/bgp/alerts/baselines",
		`{"prefix":"198.51.100.0/24","origins":["AS65001"]}`, tAdmin("acme")))
	if w.Code != http.StatusOK {
		t.Fatalf("acme POST status %d: %s", w.Code, w.Body.String())
	}
	rows, err := store.Baselines(ctx, "globex")
	if err != nil {
		t.Fatalf("globex baselines: %v", err)
	}
	row := rows["198.51.100.0/24"]
	if len(row.Origins) != 1 || row.Origins[0] != 64510 {
		t.Fatalf("CROSS-TENANT WRITE: globex's baseline is now %v", row.Origins)
	}
	if row.UpdatedBy != "" || row.Source != bgpwatch.BaselineFirstSeen {
		t.Fatalf("globex's row was rewritten by acme's caller: %+v", row)
	}
	// §3a rule 2: the owner and the tenant both come from the TOKEN.
	own, err := store.Baselines(ctx, "acme")
	if err != nil {
		t.Fatalf("acme baselines: %v", err)
	}
	mine := own["198.51.100.0/24"]
	if mine.UpdatedBy != "adm@acme" {
		t.Fatalf("updated_by=%q — the owner is stamped from the token", mine.UpdatedBy)
	}
	if mine.Source != bgpwatch.BaselineAccepted {
		t.Fatalf("an accepted row must say so: %+v", mine)
	}

	// A CROSS-TENANT DELETE is 404: another tenant's prefix is ABSENT here, and
	// the answer must not distinguish it from one nobody holds.
	before := list(tAdmin("globex"))
	w = httptest.NewRecorder()
	s.bgpWatchAPI.HandleBaselines(w, req(http.MethodDelete,
		"/api/bgp/alerts/baselines?prefix=203.0.113.0/24", "", tAdmin("globex")))
	if w.Code != http.StatusNotFound {
		t.Fatalf("a prefix nobody holds returned %d, want 404", w.Code)
	}
	notMine := w.Body.String()
	// acme holds 193.0.0.0/21; globex asking to delete it must get the SAME
	// answer as for a prefix that does not exist at all.
	w = httptest.NewRecorder()
	s.bgpWatchAPI.HandleBaselines(w, req(http.MethodDelete,
		"/api/bgp/alerts/baselines?prefix=193.0.0.0/21", "", tAdmin("globex")))
	if w.Code != http.StatusNotFound {
		t.Fatalf("a cross-tenant delete returned %d; it must look absent (404)", w.Code)
	}
	if w.Body.String() != notMine {
		t.Fatalf("the cross-tenant 404 differs from the plain 404, which tells globex the row exists:\n plain: %s\n cross: %s", notMine, w.Body.String())
	}
	if after := list(tAdmin("acme")); len(after) != 2 {
		t.Fatalf("globex's delete reached acme's rows: %+v", after)
	}
	if after := list(tAdmin("globex")); len(after) != len(before) {
		t.Fatalf("globex's own rows changed: %+v", after)
	}

	// The URL each verb is actually called with: only DELETE names the prefix
	// in the query, and the POST body carries it instead.
	const baselinesPath = "/api/bgp/alerts/baselines"
	const deletePath = baselinesPath + "?prefix=193.0.0.0/21"
	const acceptBody = `{"prefix":"193.0.0.0/21","origins":["AS1"]}`
	verbs := []struct {
		method, path, body string
	}{
		{http.MethodGet, baselinesPath, ""},
		{http.MethodPost, baselinesPath, acceptBody},
		{http.MethodDelete, deletePath, ""},
	}

	// A CROSS-TENANT PRINCIPAL is refused outright on every verb.
	for _, v := range verbs {
		w = httptest.NewRecorder()
		s.bgpWatchAPI.HandleBaselines(w, req(v.method, v.path, v.body, platformOwner()))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s as a cross-tenant principal returned %d; it must be refused", v.method, w.Code)
		}
		if strings.Contains(w.Body.String(), "64510") || strings.Contains(w.Body.String(), "198.51.100") {
			t.Fatalf("%s: the refusal leaked another tenant's data: %s", v.method, w.Body.String())
		}
	}

	// A READ-ONLY principal can list but cannot move a baseline. Moving one
	// changes what the tenant is paged for.
	if got := list(tViewer("acme")); len(got) != 2 {
		t.Fatalf("a read-only principal must still see its own rows: %+v", got)
	}
	for _, v := range verbs[1:] {
		w = httptest.NewRecorder()
		s.bgpWatchAPI.HandleBaselines(w, req(v.method, v.path, v.body, tViewer("acme")))
		if w.Code != http.StatusForbidden {
			t.Fatalf("a read-only principal %s'd a baseline (status %d: %s)", v.method, w.Code, w.Body.String())
		}
	}
}
