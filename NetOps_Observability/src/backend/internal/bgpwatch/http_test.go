package bgpwatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testAPI(t *testing.T, eval *Evaluator, principals map[string]Principal) (*API, PolicyStore) {
	t.Helper()
	store := NewFileStore("")
	a, err := NewAPI(APIDeps{
		Authz: func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool) {
			p, ok := principals[r.Header.Get("X-Test-Principal")]
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Principal{}, false
			}
			if gate == GateWrite && p.Subject == "reader" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Principal{}, false
			}
			return p, true
		},
		Policies: store, Bogons: NewBogonSet(), Eval: eval,
		Now: func() time.Time { return clsNow },
		WriteJSON: func(w http.ResponseWriter, s int, b any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s)
			_ = json.NewEncoder(w).Encode(b)
		},
		WriteError: func(w http.ResponseWriter, s int, err error) { http.Error(w, err.Error(), s) },
		LogWarn:    func(string, map[string]any) {},
	})
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return a, store
}

var testPrincipals = map[string]Principal{
	"acme":   {Tenant: "acme", Subject: "u-acme"},
	"globex": {Tenant: "globex", Subject: "u-globex"},
	"owner":  {Tenant: "", Cross: true, Subject: "platform-owner"},
	"reader": {Tenant: "acme", Subject: "reader"},
}

func do(a http.HandlerFunc, method, url, principal, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, url, nil)
	} else {
		r = httptest.NewRequest(method, url, strings.NewReader(body))
	}
	r.Header.Set("X-Test-Principal", principal)
	w := httptest.NewRecorder()
	a(w, r)
	return w
}

func TestNewAPIFailsClosedOnIncompleteDeps(t *testing.T) {
	if _, err := NewAPI(APIDeps{}); err == nil {
		t.Fatal("an incomplete APIDeps must fail construction")
	}
}

func TestAlertsRouteRefusesCrossTenantAndUnknownParams(t *testing.T) {
	a, _ := testAPI(t, nil, testPrincipals)
	if w := do(a.HandleAlerts, http.MethodGet, "/api/bgp/alerts", "owner", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("a cross-tenant read must be refused, got %d", w.Code)
	}
	if w := do(a.HandleAlerts, http.MethodGet, "/api/bgp/alerts?tenant=globex", "acme", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown query parameter must be refused, got %d", w.Code)
	}
	if w := do(a.HandleAlerts, http.MethodGet, "/api/bgp/alerts?limit=9999", "acme", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("an out-of-range limit must be refused, got %d", w.Code)
	}
	if w := do(a.HandleAlerts, http.MethodPost, "/api/bgp/alerts", "acme", ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST must be refused, got %d", w.Code)
	}
}

// With the flag off the route is HONEST: enabled:false plus an explanation,
// never an empty list that reads as "all clear".
func TestAlertsRouteIsHonestWhenDisabled(t *testing.T) {
	a, _ := testAPI(t, nil, testPrincipals)
	w := do(a.HandleAlerts, http.MethodGet, "/api/bgp/alerts", "acme", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Alerts []Alert `json:"alerts"`
		Status Status  `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status.Enabled {
		t.Fatal("status.enabled must be false with the evaluator off")
	}
	if !strings.Contains(body.Status.Note, EnvFeatureFlag) {
		t.Fatalf("the note must name the flag: %q", body.Status.Note)
	}
	if body.Alerts == nil {
		t.Fatal("alerts must be an empty array, never null")
	}
}

func TestAlertsRouteIsTenantIsolated(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.tenants = []string{"acme", "globex"}
	h.watch["globex"] = []string{"193.0.16.0/21"}
	bad := healthy()
	bad.Prefix = "193.0.16.0/21"
	bad.RPKIState = "invalid"
	h.obs["193.0.16.0/21"] = bad
	h.mu.Unlock()
	h.eval.RunOnce(context.Background())

	a, _ := testAPI(t, h.eval, testPrincipals)
	read := func(principal string) []Alert {
		w := do(a.HandleAlerts, http.MethodGet, "/api/bgp/alerts", principal, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", principal, w.Code)
		}
		var body struct {
			Alerts []Alert `json:"alerts"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.Alerts
	}
	if got := read("acme"); len(got) != 0 {
		t.Fatalf("acme received globex's alerts: %+v", got)
	}
	if got := read("globex"); len(got) != 1 || got[0].Resource != "193.0.16.0/21" {
		t.Fatalf("globex alerts wrong: %+v", got)
	}
}

func TestAlertConfigRoundTripsAndStampsTheOwnerFromTheToken(t *testing.T) {
	a, store := testAPI(t, nil, testPrincipals)
	body := `{"default":{"expected_origins":["AS64496","64497"],"upstreams":["AS64500"],"min_visibility":0.7,"min_vantages":3},
	          "prefixes":{"193.0.0.0/21":{"expected_origins":["AS64496"]}}}`
	w := do(a.HandleAlertConfig, http.MethodPut, "/api/bgp/alerts/config", "acme", body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT status %d: %s", w.Code, w.Body.String())
	}
	pol, err := store.Policy(context.Background(), "acme")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if len(pol.Default.ExpectedOrigins) != 2 || pol.Default.ExpectedOrigins[0] != 64496 {
		t.Fatalf("origins not stored: %+v", pol.Default)
	}
	if pol.UpdatedBy != "u-acme" {
		t.Fatalf("updated_by=%q — the owner comes from the TOKEN, never the body", pol.UpdatedBy)
	}
	// Another tenant's read must not see it.
	if other, _ := store.Policy(context.Background(), "globex"); len(other.Default.ExpectedOrigins) != 0 {
		t.Fatalf("globex sees acme's policy: %+v", other)
	}
	w = do(a.HandleAlertConfig, http.MethodGet, "/api/bgp/alerts/config", "globex", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "64496") {
		t.Fatalf("globex read acme's policy: %s", w.Body.String())
	}
}

func TestAlertConfigRejectsBadInput(t *testing.T) {
	a, _ := testAPI(t, nil, testPrincipals)
	for _, c := range []struct{ name, body string }{
		{"bad asn", `{"default":{"expected_origins":["not-an-asn"]}}`},
		{"AS0", `{"default":{"expected_origins":["AS0"]}}`},
		{"bad prefix key", `{"prefixes":{"not-a-prefix":{}}}`},
		{"visibility out of range", `{"default":{"min_visibility":9}}`},
		{"malformed json", `{`},
	} {
		if w := do(a.HandleAlertConfig, http.MethodPut, "/api/bgp/alerts/config", "acme", c.body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d (want 400) — %s", c.name, w.Code, w.Body.String())
		}
	}
	if w := do(a.HandleAlertConfig, http.MethodPut, "/api/bgp/alerts/config", "reader", `{}`); w.Code != http.StatusForbidden {
		t.Fatalf("a read-only principal must not write the policy, got %d", w.Code)
	}
	if w := do(a.HandleAlertConfig, http.MethodDelete, "/api/bgp/alerts/config", "acme", ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE must be refused, got %d", w.Code)
	}
}

func TestBogonsRouteServesTheSetAndIsScoped(t *testing.T) {
	a, _ := testAPI(t, nil, testPrincipals)
	if w := do(a.HandleBogons, http.MethodGet, "/api/bgp/bogons", "owner", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("a cross-tenant read must be refused, got %d", w.Code)
	}
	w := do(a.HandleBogons, http.MethodGet, "/api/bgp/bogons", "acme", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Sightings []Sighting `json:"sightings"`
		Set       struct {
			Source string `json:"source"`
			Date   string `json:"date"`
			Blocks int    `json:"blocks"`
		} `json:"set"`
		Feed FeedStatus `json:"feed"`
		Note string     `json:"note"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Set.Blocks == 0 || body.Set.Date != StaticSetDate || body.Set.Source == "" {
		t.Fatalf("the served set must name its source and date: %+v", body.Set)
	}
	if body.Feed.Enabled {
		t.Fatal("the optional feed must be off by default")
	}
	if body.Feed.Note == "" {
		t.Fatal("a disabled feed must say so, so an empty full-bogon half is not read as 'nothing is bogus'")
	}
	if body.Sightings == nil {
		t.Fatal("sightings must be an empty array, never null")
	}
	if body.Note == "" {
		t.Fatal("with the evaluator off the sighting register's emptiness must be explained")
	}
}

func TestNilAPIAnswers404(t *testing.T) {
	var a *API
	for _, h := range []http.HandlerFunc{a.HandleAlerts, a.HandleAlertConfig, a.HandleBogons} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, "/api/bgp/alerts", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("a nil API must 404, got %d", w.Code)
		}
	}
}

func TestLookupPrefixHelper(t *testing.T) {
	a, _ := testAPI(t, nil, testPrincipals)
	if _, ok := a.LookupPrefix("10.1.0.0/16"); !ok {
		t.Fatal("10.1.0.0/16 is a bogon")
	}
	if _, ok := a.LookupPrefix("193.0.0.0/21"); ok {
		t.Fatal("193.0.0.0/21 is not a bogon")
	}
	if _, ok := a.LookupPrefix("not a prefix"); ok {
		t.Fatal("garbage input must not match")
	}
}
