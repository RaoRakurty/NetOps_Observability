// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// http_test.go — the read surface.
//
// The fixture wires the REAL handlers over the REAL store; only Authz is a
// test double, because mapping a request onto a Principal is the integrator's
// job (bmp_deps.go) and is tested there against the production RBAC.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testAuthz maps two headers onto a Principal. An absent tenant header with no
// cross grant is an UNAUTHENTICATED caller and is refused before any read.
func testAuthz(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool) {
	if gate != GateRead {
		http.Error(w, "unsupported gate", http.StatusForbidden)
		return Principal{}, false
	}
	tenant := r.Header.Get("X-Test-Tenant")
	cross := r.Header.Get("X-Test-Cross") == "1"
	if tenant == "" && !cross {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return Principal{}, false
	}
	return Principal{Tenant: tenant, Cross: cross, Subject: "tester"}, true
}

func testWriteJSON(w http.ResponseWriter, status int, body any) {
	buf, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

func testWriteError(w http.ResponseWriter, status int, err error) {
	testWriteJSON(w, status, map[string]string{"error": err.Error()})
}

type httpFixture struct {
	api *API
	t   *testing.T
}

func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	api, err := New(Deps{
		Now:                  fixedClock(),
		ResolveDevice:        func(_ netipAddr) (string, string, bool) { return "", "", false },
		Authz:                testAuthz,
		Metrics:              NewMetrics(),
		WriteJSON:            testWriteJSON,
		WriteError:           testWriteError,
		LogInfo:              func(string, map[string]any) {},
		LogWarn:              func(string, map[string]any) {},
		LogError:             func(string, map[string]any) {},
		MaxSessionRecords:    16,
		MaxUpdatesPerSession: 32,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &httpFixture{api: api, t: t}
}

// get runs one request through the module's real dispatcher.
func (f *httpFixture) get(path, tenant string, cross bool) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if tenant != "" {
		r.Header.Set("X-Test-Tenant", tenant)
	}
	if cross {
		r.Header.Set("X-Test-Cross", "1")
	}
	w := httptest.NewRecorder()
	f.api.Handler()(w, r)
	return w
}

func (f *httpFixture) decode(w *httptest.ResponseRecorder) map[string]any {
	f.t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return out
}

// seed loads two tenants' feeds into the store.
func (f *httpFixture) seed() {
	f.t.Helper()
	s := f.api.Store()
	feed(f.t, s, "bmp-1", "acme", "acme-core",
		initiation("acme-rtr", "IOS-XR"),
		peerUp(0, "192.0.2.10", 64512),
		announce("192.0.2.10", 64512, "10.1.0.0/24"),
		announce("192.0.2.10", 64512, "10.2.0.0/24"))
	feed(f.t, s, "bmp-2", "globex", "gx-edge",
		initiation("gx-rtr", "Junos"),
		peerUp(0, "198.51.100.7", 65001),
		announce("198.51.100.7", 65001, "203.0.113.0/24"))
}

// ── routing + method ────────────────────────────────────────────────────────

func TestHandlerRejectsNonGET(t *testing.T) {
	f := newHTTPFixture(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := httptest.NewRequest(m, "/api/bgp/bmp/sessions", strings.NewReader("{}"))
		r.Header.Set("X-Test-Tenant", "acme")
		w := httptest.NewRecorder()
		f.api.Handler()(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d, want 405", m, w.Code)
		}
		if w.Header().Get("Allow") != "GET" {
			t.Fatalf("%s Allow header = %q", m, w.Header().Get("Allow"))
		}
	}
}

func TestHandlerRoutesOnlyItsThreeOperations(t *testing.T) {
	f := newHTTPFixture(t)
	for _, p := range []string{
		"/api/bgp/bmp/",
		"/api/bgp/bmp/nope",
		"/api/bgp/bmp/sessions/extra",
		"/api/bgp/watchlist",
	} {
		if w := f.get(p, "acme", false); w.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", p, w.Code)
		}
	}
	for _, p := range []string{"sessions", "updates", "stats"} {
		if w := f.get("/api/bgp/bmp/"+p, "acme", false); w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", p, w.Code, w.Body.String())
		}
	}
}

func TestNilAPIIs404NotAPanic(t *testing.T) {
	var a *API
	w := httptest.NewRecorder()
	a.Handler()(w, httptest.NewRequest(http.MethodGet, "/api/bgp/bmp/sessions", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("nil API = %d, want 404", w.Code)
	}
	if a.Metrics() != nil || a.Store() != nil || a.Listener() != nil {
		t.Fatal("a nil API must expose nothing")
	}
}

// ── the gate ────────────────────────────────────────────────────────────────

func TestEveryRouteIsGatedBeforeAnyRead(t *testing.T) {
	f := newHTTPFixture(t)
	f.seed()
	for _, p := range []string{
		"/api/bgp/bmp/sessions",
		"/api/bgp/bmp/updates",
		"/api/bgp/bmp/stats",
	} {
		w := f.get(p, "", false)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s unauthenticated = %d, want 401", p, w.Code)
		}
		if strings.Contains(w.Body.String(), "acme") || strings.Contains(w.Body.String(), "10.1.0.0") {
			t.Fatalf("GET %s leaked data to an unauthenticated caller: %s", p, w.Body.String())
		}
	}
}

// ── tenant isolation ────────────────────────────────────────────────────────

func TestSessionsAreOwnTenantOnlyOverHTTP(t *testing.T) {
	f := newHTTPFixture(t)
	f.seed()

	w := f.get("/api/bgp/bmp/sessions", "acme", false)
	if w.Code != http.StatusOK {
		t.Fatalf("acme sessions = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "acme-core") {
		t.Fatalf("acme cannot see its own session: %s", body)
	}
	for _, foreign := range []string{"gx-edge", "gx-rtr", "bmp-2", "198.51.100.7", "203.0.113.0"} {
		if strings.Contains(body, foreign) {
			t.Fatalf("CROSS-TENANT LEAK — acme saw %q: %s", foreign, body)
		}
	}
	if got := f.decode(w)["count"]; got != float64(1) {
		t.Fatalf("acme count = %v, want 1", got)
	}
	// The platform owner (cross) is the ONLY principal that sees both.
	all := f.decode(f.get("/api/bgp/bmp/sessions", "", true))
	if all["count"] != float64(2) {
		t.Fatalf("cross-tenant count = %v, want 2", all["count"])
	}
}

func TestUpdatesAreOwnTenantOnlyOverHTTP(t *testing.T) {
	f := newHTTPFixture(t)
	f.seed()
	body := f.get("/api/bgp/bmp/updates", "acme", false).Body.String()
	if !strings.Contains(body, "10.1.0.0/24") {
		t.Fatalf("acme cannot see its own updates: %s", body)
	}
	if strings.Contains(body, "203.0.113.0/24") || strings.Contains(body, "gx-edge") {
		t.Fatalf("CROSS-TENANT LEAK: %s", body)
	}
	// A filter cannot be used to reach another tenant's rows.
	leak := f.get("/api/bgp/bmp/updates?prefix=203.0.113.0/24", "acme", false)
	if got := f.decode(leak)["count"]; got != float64(0) {
		t.Fatalf("a filter reached another tenant's prefix: %s", leak.Body.String())
	}
	leakPeer := f.get("/api/bgp/bmp/updates?peer=198.51.100.7", "acme", false)
	if got := f.decode(leakPeer)["count"]; got != float64(0) {
		t.Fatalf("a peer filter reached another tenant: %s", leakPeer.Body.String())
	}
	leakSession := f.get("/api/bgp/bmp/updates?session=bmp-2", "acme", false)
	if got := f.decode(leakSession)["count"]; got != float64(0) {
		t.Fatalf("a session filter reached another tenant: %s", leakSession.Body.String())
	}
}

func TestStatsAreOwnTenantOnlyOverHTTP(t *testing.T) {
	f := newHTTPFixture(t)
	f.seed()
	acme := f.decode(f.get("/api/bgp/bmp/stats", "acme", false))["stats"].(map[string]any)
	if acme["sessions"] != float64(1) || acme["updates_held"] != float64(2) {
		t.Fatalf("acme stats = %+v", acme)
	}
	globex := f.decode(f.get("/api/bgp/bmp/stats", "globex", false))["stats"].(map[string]any)
	if globex["updates_held"] != float64(1) {
		t.Fatalf("globex stats = %+v", globex)
	}
	all := f.decode(f.get("/api/bgp/bmp/stats", "", true))["stats"].(map[string]any)
	if all["sessions"] != float64(2) || all["updates_held"] != float64(3) {
		t.Fatalf("cross-tenant stats = %+v", all)
	}
}

func TestATenantWithNoSessionSeesAnEmptyFeedNotAnotherTenants(t *testing.T) {
	f := newHTTPFixture(t)
	f.seed()
	for _, p := range []string{"/api/bgp/bmp/sessions", "/api/bgp/bmp/updates"} {
		w := f.get(p, "initech", false)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", p, w.Code)
		}
		if got := f.decode(w)["count"]; got != float64(0) {
			t.Fatalf("GET %s for a third tenant = %v rows, want 0: %s", p, got, w.Body.String())
		}
	}
}

// ── bounds are refused, not clamped ─────────────────────────────────────────

func TestUnknownQueryParametersAreRefused(t *testing.T) {
	f := newHTTPFixture(t)
	cases := []string{
		"/api/bgp/bmp/sessions?limit=10",
		"/api/bgp/bmp/stats?prefix=10.0.0.0/8",
		"/api/bgp/bmp/updates?page_size=1",
		"/api/bgp/bmp/updates?offset=5",
		"/api/bgp/bmp/updates?tenant=globex",
		"/api/bgp/bmp/updates?envelope=true",
	}
	for _, p := range cases {
		w := f.get(p, "acme", false)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("GET %s = %d, want 400 (an ignored parameter is the F-61 defect)", p, w.Code)
		}
		if !strings.Contains(w.Body.String(), "unknown query parameter") {
			t.Fatalf("GET %s error does not name the parameter: %s", p, w.Body.String())
		}
	}
	// as_tenant is always allowed — the tenancy middleware consumes it.
	if w := f.get("/api/bgp/bmp/updates?as_tenant=acme", "acme", false); w.Code != http.StatusOK {
		t.Fatalf("as_tenant = %d (%s)", w.Code, w.Body.String())
	}
}

func TestLimitIsRefusedNotClamped(t *testing.T) {
	f := newHTTPFixture(t)
	f.seed()
	for _, q := range []string{"limit=0", "limit=-1", "limit=abc", "limit=1001", "limit=999999999999999999999"} {
		w := f.get("/api/bgp/bmp/updates?"+q, "acme", false)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("GET ?%s = %d, want 400 — a clamped bound reads as \"that is all the data\"", q, w.Code)
		}
		if !strings.Contains(w.Body.String(), "limit") {
			t.Fatalf("?%s error does not name the bound: %s", q, w.Body.String())
		}
	}
	if w := f.get("/api/bgp/bmp/updates?limit=1000", "acme", false); w.Code != http.StatusOK {
		t.Fatalf("the maximum limit must be accepted: %d", w.Code)
	}
}

func TestFilterValuesAreRefusedWhenUnparseable(t *testing.T) {
	f := newHTTPFixture(t)
	f.seed()
	bad := []string{
		"prefix=not-a-prefix",
		"prefix=10.0.0.0/99",
		"prefix=" + strings.Repeat("a", maxFilterLen+1),
		"peer=not-an-ip",
		"peer=192.0.2.10/24",
		"session=../../etc/passwd",
		"session=bmp-",
		"session=bmp-x",
		"cursor=not!base64",
		"cursor=Zm9v",                     // valid base64, wrong contents
		"cursor=" + encodeCursor(1) + "A", // a mutated cursor of ours
	}
	for _, q := range bad {
		if w := f.get("/api/bgp/bmp/updates?"+q, "acme", false); w.Code != http.StatusBadRequest {
			t.Fatalf("GET ?%s = %d, want 400", q, w.Code)
		}
	}
	// A bare address is accepted as a host prefix.
	if w := f.get("/api/bgp/bmp/updates?prefix=10.1.0.0", "acme", false); w.Code != http.StatusOK {
		t.Fatalf("a bare address filter = %d (%s)", w.Code, w.Body.String())
	}
}

// ── paging ──────────────────────────────────────────────────────────────────

func TestCursorPagingWalksTheFeedExactlyOnce(t *testing.T) {
	f := newHTTPFixture(t)
	s := f.api.Store()
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		s.Apply("bmp-1", mustParse(t, announce("192.0.2.10", 64512, cidrN(i))))
	}
	seen := map[string]bool{}
	path := "/api/bgp/bmp/updates?limit=3"
	for page := 0; page < 10; page++ {
		w := f.get(path, "acme", false)
		if w.Code != http.StatusOK {
			t.Fatalf("page %d = %d (%s)", page, w.Code, w.Body.String())
		}
		body := f.decode(w)
		rows, _ := body["updates"].([]any)
		for _, row := range rows {
			pfx := row.(map[string]any)["prefix"].(string)
			if seen[pfx] {
				t.Fatalf("prefix %s appeared on two pages", pfx)
			}
			seen[pfx] = true
		}
		next, ok := body["next_cursor"].(string)
		if !ok {
			// A short page carries NO cursor — otherwise a walker loops forever.
			if len(rows) == 3 {
				t.Fatalf("a full page carried no cursor: %s", w.Body.String())
			}
			break
		}
		path = "/api/bgp/bmp/updates?limit=3&cursor=" + next
	}
	if len(seen) != 7 {
		t.Fatalf("walked %d of 7 records: %v", len(seen), seen)
	}
}

func TestCursorRoundTripsAndRefusesForeignFormats(t *testing.T) {
	enc := encodeCursor(42)
	got, err := decodeCursor(enc)
	if err != nil || got != 42 {
		t.Fatalf("round trip = %d, %v", got, err)
	}
	for _, bad := range []string{"", "!!!", "Zm9v", strings.Repeat("A", 200)} {
		if _, err := decodeCursor(bad); err == nil {
			t.Fatalf("decodeCursor(%q) accepted a cursor that is not ours", bad)
		}
	}
}

// ── the honesty contract ────────────────────────────────────────────────────

func TestAnEmptyFeedSaysNothingIsExportingRatherThanLookingHealthy(t *testing.T) {
	f := newHTTPFixture(t)
	body := f.decode(f.get("/api/bgp/bmp/sessions", "acme", false))
	cov, ok := body["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("no coverage block: %s", f.get("/api/bgp/bmp/sessions", "acme", false).Body.String())
	}
	if cov["complete"] != false {
		t.Fatal("an empty feed reported complete=true — that is the comfortable lie")
	}
	notes, _ := cov["notes"].([]any)
	joined := ""
	for _, n := range notes {
		joined += n.(string)
	}
	if !strings.Contains(joined, "No router is exporting BMP") {
		t.Fatalf("coverage notes do not explain the emptiness: %v", notes)
	}
}

func TestDroppedUpdatesMakeTheAnswerIncomplete(t *testing.T) {
	api, err := New(Deps{
		Now:                  fixedClock(),
		ResolveDevice:        func(_ netipAddr) (string, string, bool) { return "", "", false },
		Authz:                testAuthz,
		WriteJSON:            testWriteJSON,
		WriteError:           testWriteError,
		LogInfo:              func(string, map[string]any) {},
		LogWarn:              func(string, map[string]any) {},
		LogError:             func(string, map[string]any) {},
		MaxUpdatesPerSession: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &httpFixture{api: api, t: t}
	s := api.Store()
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		s.Apply("bmp-1", mustParse(t, announce("192.0.2.10", 64512, cidrN(i))))
	}
	cov := f.decode(f.get("/api/bgp/bmp/updates", "acme", false))["coverage"].(map[string]any)
	if cov["complete"] != false {
		t.Fatal("a feed with dropped records reported complete=true")
	}
	joined := ""
	for _, n := range cov["notes"].([]any) {
		joined += n.(string)
	}
	if !strings.Contains(joined, "dropped by the bounded ring") {
		t.Fatalf("the drop is not surfaced: %v", cov["notes"])
	}
}

func TestStatsPublishesTheReceiverBounds(t *testing.T) {
	f := newHTTPFixture(t)
	limits := f.decode(f.get("/api/bgp/bmp/stats", "acme", false))["limits"].(map[string]any)
	if limits["max_updates_per_session"] != float64(32) {
		t.Fatalf("limits = %+v — an operator reading a dropped count must see what it was measured against", limits)
	}
	if limits["max_message_bytes"] != float64(MaxMessageSize) {
		t.Fatalf("limits = %+v", limits)
	}
}

func TestClosedSessionsAreNotReportedAsUp(t *testing.T) {
	f := newHTTPFixture(t)
	f.seed()
	f.api.Store().Close("bmp-1", "peer closed")
	body := f.decode(f.get("/api/bgp/bmp/sessions", "acme", false))
	cov := body["coverage"].(map[string]any)
	if cov["sessions_up"] != float64(0) || cov["complete"] != false {
		t.Fatalf("coverage after the only session closed = %+v", cov)
	}
	sessions := body["sessions"].([]any)
	st := sessions[0].(map[string]any)
	if st["state"] != "closed" {
		t.Fatalf("session state = %v", st["state"])
	}
	peers := st["peers"].([]any)
	if peers[0].(map[string]any)["state"] != "unknown" {
		t.Fatalf("peer state after the feed died = %v", peers[0])
	}
}

// ── construction ────────────────────────────────────────────────────────────

func TestNewRefusesAnIncompleteDeps(t *testing.T) {
	full := func() Deps {
		return Deps{
			Now:           fixedClock(),
			ResolveDevice: func(_ netipAddr) (string, string, bool) { return "", "", false },
			Authz:         testAuthz,
			WriteJSON:     testWriteJSON,
			WriteError:    testWriteError,
			LogInfo:       func(string, map[string]any) {},
			LogWarn:       func(string, map[string]any) {},
			LogError:      func(string, map[string]any) {},
		}
	}
	if _, err := New(full()); err != nil {
		t.Fatalf("a complete Deps must build: %v", err)
	}
	strip := map[string]func(*Deps){
		"Now":           func(d *Deps) { d.Now = nil },
		"ResolveDevice": func(d *Deps) { d.ResolveDevice = nil },
		"Authz":         func(d *Deps) { d.Authz = nil },
		"WriteJSON":     func(d *Deps) { d.WriteJSON = nil },
		"WriteError":    func(d *Deps) { d.WriteError = nil },
		"LogInfo":       func(d *Deps) { d.LogInfo = nil },
		"LogWarn":       func(d *Deps) { d.LogWarn = nil },
		"LogError":      func(d *Deps) { d.LogError = nil },
	}
	for name, drop := range strip {
		d := full()
		drop(&d)
		api, err := New(d)
		if err == nil {
			t.Fatalf("New succeeded without %s — an incomplete Deps must fail CLOSED", name)
		}
		if api != nil {
			t.Fatalf("New returned an API alongside an error for %s", name)
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("the error for a missing %s does not name it: %v", name, err)
		}
	}
}

func TestUnsupportedGateIsRefused(t *testing.T) {
	f := newHTTPFixture(t)
	w := httptest.NewRecorder()
	if _, ok := f.api.deps.Authz(w, httptest.NewRequest(http.MethodGet, "/x", nil), Gate(99)); ok {
		t.Fatal("an unknown gate must never authorize")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("unknown gate = %d, want 403", w.Code)
	}
}
