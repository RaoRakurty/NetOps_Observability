package igpmon

// http_test.go — the read surface. Each handler is asserted on the five things
// the package doc promises, in order: the gate, the refusal of unknown/out-of-
// range parameters, the identical 404 for a foreign and an absent device, the
// tenant scope actually carried into ClickHouse and the device boundary
// actually carried into VictoriaMetrics, and the honest coverage block.
//
// The harness records what was SENT, so the isolation assertions are made on
// the outgoing scope/filters, not merely on the response body: an isolation
// property that is only observable through the response is one that can rot.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// allRoutes is every (proto, op) pair the module serves.
var allRoutes = []struct{ proto, op string }{
	{"ospf", "adjacencies"}, {"ospf", "summary"}, {"ospf", "health"},
	{"isis", "adjacencies"}, {"isis", "summary"}, {"isis", "health"},
}

// pathFor builds a route path, adding the ?device= that health always requires.
func pathFor(proto, op string) string {
	p := "/api/protocols/" + proto + "/" + op
	if op == "health" {
		p += "?device=leaf1"
	}
	return p
}

// seedDevice registers a visible device on the harness.
func (h *harness) seedDevice(id, name, tenant string) {
	h.devices[id] = Device{ID: id, Name: name, TenantID: tenant}
}

// ── dispatch ────────────────────────────────────────────────────────────────

func TestDispatchRejectsNonGET(t *testing.T) {
	h := newHarness(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := httptest.NewRecorder()
		h.api.Handler()(w, httptest.NewRequest(m, "/api/protocols/ospf/summary", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", m, w.Code)
		}
		if got := w.Header().Get("Allow"); got != "GET" {
			t.Errorf("%s Allow header = %q, want GET", m, got)
		}
	}
}

func TestDispatchUnknownProtocolOrOperationIs404(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{
		"/api/protocols/bgp/summary",       // a protocol this module does not serve
		"/api/protocols/ospfv3/summary",    // near-miss spelling
		"/api/protocols/ospf/lsdb",         // unknown operation
		"/api/protocols/ospf",              // no operation
		"/api/protocols/",                  // nothing at all
		"/api/protocols/ospf/a/b",          // nested path
		"/api/protocols/ospf/adjacencies/", // trailing slash makes it a nested path
	} {
		w, _ := h.get(p)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, w.Code)
		}
	}
	// A path outside the prefix reaches the dispatcher only by misregistration;
	// it must still 404 rather than serve.
	w := httptest.NewRecorder()
	h.api.Handler()(w, httptest.NewRequest(http.MethodGet, "/api/other/ospf/summary", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("out-of-prefix path = %d, want 404", w.Code)
	}
	// A nil API serves nothing.
	var nilAPI *API
	w = httptest.NewRecorder()
	nilAPI.Handler()(w, httptest.NewRequest(http.MethodGet, "/api/protocols/ospf/summary", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("nil API = %d, want 404", w.Code)
	}
}

// ── the gate ────────────────────────────────────────────────────────────────

// TestGateRefusalIsFirstOnEveryRoute — nothing is read before the caller is
// authorized, on any route. A 401/403 that still issued the ClickHouse read
// would be a leak the status code hides.
func TestGateRefusalIsFirstOnEveryRoute(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for _, rt := range allRoutes {
			h := newHarness(t)
			h.seedDevice("leaf1", "leaf1", "acme")
			h.authzOK = false
			h.authzStatus = status
			w, _ := h.get(pathFor(rt.proto, rt.op))
			if w.Code != status {
				t.Errorf("%s/%s unauthorized = %d, want %d", rt.proto, rt.op, w.Code, status)
			}
			if len(h.ch) != 0 || len(h.vm) != 0 {
				t.Errorf("%s/%s read a store BEFORE the gate: ch=%d vm=%d", rt.proto, rt.op, len(h.ch), len(h.vm))
			}
		}
	}
}

// ── parameter refusal (fail closed) ─────────────────────────────────────────

func TestUnknownQueryParameterIsRefused(t *testing.T) {
	for _, rt := range allRoutes {
		h := newHarness(t)
		h.seedDevice("leaf1", "leaf1", "acme")
		q := "?page_size=1"
		if rt.op == "health" {
			q = "?device=leaf1&page_size=1"
		}
		w, body := h.get("/api/protocols/" + rt.proto + "/" + rt.op + q)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s/%s ?page_size= = %d, want 400", rt.proto, rt.op, w.Code)
		}
		if msg, _ := body["error"].(string); !strings.Contains(msg, "page_size") {
			t.Errorf("%s/%s error must name the parameter: %v", rt.proto, rt.op, body)
		}
	}
	// summary accepts no ?device= at all — it is a fleet roll-up.
	h := newHarness(t)
	if w, _ := h.get("/api/protocols/ospf/summary?device=leaf1"); w.Code != http.StatusBadRequest {
		t.Errorf("summary ?device= = %d, want 400", w.Code)
	}
	// adjacencies/health take no ?cursor= on health.
	if w, _ := h.get("/api/protocols/ospf/health?device=leaf1&cursor=x"); w.Code != http.StatusBadRequest {
		t.Errorf("health ?cursor= = %d, want 400", w.Code)
	}
}

func TestWindowBoundsAreRefusedNotClamped(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	ok := []struct {
		in   string
		secs float64
	}{
		{"", 86400},       // default
		{"90m", 5400},     // duration
		{"24h", 86400},    //
		{"7d", 604800},    // the ceiling, accepted
		{"3600", 3600},    // bare seconds
		{"1m", 60},        // the floor, accepted
		{"%20%20", 86400}, // whitespace-only reads as "unset", i.e. the default
	}
	for _, c := range ok {
		w, body := h.get("/api/protocols/ospf/adjacencies?since=" + c.in)
		if w.Code != http.StatusOK {
			t.Fatalf("since=%q = %d (%v)", c.in, w.Code, body)
		}
		if got, _ := body["window_seconds"].(float64); got != c.secs {
			t.Errorf("since=%q → window_seconds %v, want %v", c.in, got, c.secs)
		}
	}
	bad := []string{"8d", "30d", "abc", "30", "0", "-5", "59s", "1y"}
	for _, c := range bad {
		w, body := h.get("/api/protocols/ospf/adjacencies?since=" + c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("since=%q = %d, want 400 (a caller who asked for 30 days must LEARN they cannot have it)", c, w.Code)
		}
		if msg, _ := body["error"].(string); !strings.HasPrefix(msg, "since:") {
			t.Errorf("since=%q error = %v", c, body)
		}
	}
	// Every route bounds the window the same way.
	for _, rt := range allRoutes {
		q := "?since=90d"
		if rt.op == "health" {
			q = "?device=leaf1&since=90d"
		}
		if w, _ := h.get("/api/protocols/" + rt.proto + "/" + rt.op + q); w.Code != http.StatusBadRequest {
			t.Errorf("%s/%s since=90d = %d, want 400", rt.proto, rt.op, w.Code)
		}
	}
}

func TestLimitBoundsAreRefusedNotClamped(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		path      string
		def       float64
		max, over int
	}{
		{"/api/protocols/ospf/adjacencies", 200, maxLimit, maxLimit + 1},
		{"/api/protocols/isis/summary", 100, maxSummaryLimit, maxSummaryLimit + 1},
	}
	for _, c := range cases {
		w, body := h.get(c.path)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d", c.path, w.Code)
		}
		if got, _ := body["limit"].(float64); got != c.def {
			t.Errorf("%s default limit = %v, want %v", c.path, got, c.def)
		}
		if w, _ := h.get(c.path + "?limit=" + itoa(c.max)); w.Code != http.StatusOK {
			t.Errorf("%s limit=%d = %d, want 200 (the ceiling is accepted)", c.path, c.max, w.Code)
		}
		for _, bad := range []string{itoa(c.over), "0", "-1", "abc", "1e3", "999999"} {
			w, body := h.get(c.path + "?limit=" + bad)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s limit=%s = %d, want 400", c.path, bad, w.Code)
			}
			if msg, _ := body["error"].(string); !strings.HasPrefix(msg, "limit:") {
				t.Errorf("%s limit=%s error = %v", c.path, bad, body)
			}
		}
	}
	// health takes no ?limit= — its scan bound is fixed.
	if w, _ := h.get("/api/protocols/ospf/health?device=leaf1&limit=5"); w.Code == http.StatusOK {
		t.Error("health silently accepted ?limit=")
	}
}

func TestMalformedCursorIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, c := range []string{"x", "!!!", b64("1|nope")} {
		w, body := h.get("/api/protocols/isis/adjacencies?cursor=" + c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("cursor=%q = %d, want 400", c, w.Code)
		}
		if msg, _ := body["error"].(string); msg != "cursor: malformed" {
			t.Errorf("cursor=%q error = %v", c, body)
		}
	}
	// A well-formed cursor reaches the SQL as a keyset predicate.
	good := encodeCursor(1756900000000, "0f8fad5b-d9cb-469f-a165-70867728950e")
	if w, _ := h.get("/api/protocols/isis/adjacencies?cursor=" + good); w.Code != http.StatusOK {
		t.Fatalf("valid cursor = %d", w.Code)
	}
	if len(h.ch) == 0 || !strings.Contains(h.ch[len(h.ch)-1].sql, "toInt64(1756900000000)") {
		t.Error("the cursor did not reach the keyset predicate")
	}
}

// ── §3a rule 1: foreign and absent are indistinguishable ────────────────────

// TestForeignAndAbsentDeviceAnswerIdentically is the existence-oracle guard:
// the two answers must be byte-identical, on every route that takes ?device=.
func TestForeignAndAbsentDeviceAnswerIdentically(t *testing.T) {
	for _, op := range []string{"adjacencies", "health"} {
		for _, proto := range []string{"ospf", "isis"} {
			h := newHarness(t)
			h.seedDevice("leaf1", "leaf1", "acme")      // the caller's own
			h.seedDevice("globex-core", "gx", "globex") // another tenant's

			base := "/api/protocols/" + proto + "/" + op + "?device="
			foreign, fBody := h.get(base + "globex-core")
			absent, aBody := h.get(base + "does-not-exist")

			if foreign.Code != http.StatusNotFound {
				t.Errorf("%s/%s foreign device = %d, want 404", proto, op, foreign.Code)
			}
			if absent.Code != http.StatusNotFound {
				t.Errorf("%s/%s absent device = %d, want 404", proto, op, absent.Code)
			}
			if foreign.Body.String() != absent.Body.String() {
				t.Errorf("%s/%s EXISTENCE ORACLE: foreign %q != absent %q",
					proto, op, foreign.Body.String(), absent.Body.String())
			}
			if fBody != nil && strings.Contains(foreign.Body.String(), "globex") {
				t.Errorf("%s/%s leaked the foreign id: %v", proto, op, fBody)
			}
			_ = aBody
			if len(h.ch) != 0 || len(h.vm) != 0 {
				t.Errorf("%s/%s read a store for an unauthorized device: ch=%d vm=%d", proto, op, len(h.ch), len(h.vm))
			}
		}
	}
}

func TestDeviceParamRequiredAndShapeValidated(t *testing.T) {
	h := newHarness(t)
	// health requires ?device=.
	w, body := h.get("/api/protocols/ospf/health")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("health without device = %d, want 400", w.Code)
	}
	if msg, _ := body["error"].(string); msg != "device: required" {
		t.Errorf("health error = %v", body)
	}
	// A device value that shape-validation empties is refused rather than
	// silently dropped into a fleet-wide read.
	w, body = h.get("/api/protocols/ospf/adjacencies?device=" + "%27%27")
	if w.Code != http.StatusBadRequest {
		t.Errorf("adjacencies ?device='' = %d, want 400 (%v)", w.Code, body)
	}
	// An empty ?device= on adjacencies means "no narrowing", not "device ''".
	if w, _ := h.get("/api/protocols/ospf/adjacencies?device="); w.Code != http.StatusOK {
		t.Errorf("adjacencies with an empty device = %d, want 200 (fleet read)", w.Code)
	}
	if len(h.ch) == 0 || strings.Contains(h.ch[len(h.ch)-1].sql, "entity_id IN") {
		t.Error("an empty ?device= must not narrow the read to a device")
	}
	// A cross-tenant principal reaches another tenant's device.
	h2 := newHarness(t)
	h2.seedDevice("globex-core", "gx", "globex")
	h2.principal = Principal{Tenant: "global", Cross: true, Subject: "root"}
	h2.scope = "__all__"
	h2.scopeFilters = nil
	if w, _ := h2.get("/api/protocols/ospf/health?device=globex-core"); w.Code != http.StatusOK {
		t.Errorf("cross-tenant principal = %d, want 200", w.Code)
	}
}

// ── §3a rule 4: the scope and the filters actually leave the process ────────

func TestClickHouseReadCarriesTheCallersScope(t *testing.T) {
	for _, scope := range []string{"acme", "globex", "__all__"} {
		for _, rt := range allRoutes {
			h := newHarness(t)
			h.seedDevice("leaf1", "leaf1", "acme")
			h.scope = scope
			if w, _ := h.get(pathFor(rt.proto, rt.op)); w.Code != http.StatusOK {
				t.Fatalf("%s/%s = %d", rt.proto, rt.op, w.Code)
			}
			if len(h.ch) != 1 {
				t.Fatalf("%s/%s issued %d ClickHouse reads, want 1", rt.proto, rt.op, len(h.ch))
			}
			if h.ch[0].scope != scope {
				t.Errorf("%s/%s ClickHouse scope = %q, want %q", rt.proto, rt.op, h.ch[0].scope, scope)
			}
			if !strings.Contains(h.ch[0].sql, "kind = '"+Proto(rt.proto).Kind()+"'") {
				t.Errorf("%s/%s read the wrong protocol's signals: %s", rt.proto, rt.op, h.ch[0].sql)
			}
		}
	}
}

// TestScopelessPrincipalReadsNothing — "" and "__none__" short-circuit BEFORE
// the database is touched, on every route.
func TestScopelessPrincipalReadsNothing(t *testing.T) {
	for _, scope := range []string{"", "__none__"} {
		for _, rt := range allRoutes {
			h := newHarness(t)
			h.seedDevice("leaf1", "leaf1", "acme")
			h.scope = scope
			h.rows = []map[string]any{chRow(1756814400000, "0f8fad5b-d9cb-469f-a165-70867728950e", "leaf1", "p", "down", "warn", "syslog", "")}
			w, body := h.get(pathFor(rt.proto, rt.op))
			if w.Code != http.StatusOK {
				t.Fatalf("%s/%s scope=%q = %d", rt.proto, rt.op, scope, w.Code)
			}
			if len(h.ch) != 0 {
				t.Errorf("%s/%s scope=%q reached ClickHouse: %+v", rt.proto, rt.op, scope, h.ch)
			}
			if n, _ := body["event_count"].(float64); n != 0 {
				t.Errorf("%s/%s scope=%q returned %v events", rt.proto, rt.op, scope, n)
			}
		}
	}
}

// TestEveryMetricsReadCarriesTheDeviceBoundary — an unfiltered VictoriaMetrics
// read for a scoped principal is a fleet-wide read; there must be none.
func TestEveryMetricsReadCarriesTheDeviceBoundary(t *testing.T) {
	for _, rt := range allRoutes {
		h := newHarness(t)
		h.seedDevice("leaf1", "leaf1", "acme")
		h.scopeFilters = []string{`{device=~"leaf1"}`, `{hostname=~"leaf1"}`}
		if w, _ := h.get(pathFor(rt.proto, rt.op)); w.Code != http.StatusOK {
			t.Fatalf("%s/%s = %d", rt.proto, rt.op, w.Code)
		}
		if len(h.vm) == 0 {
			t.Fatalf("%s/%s issued no metrics read", rt.proto, rt.op)
		}
		for i, c := range h.vm {
			if len(c.filters) != 2 || c.filters[0] != `{device=~"leaf1"}` {
				t.Errorf("%s/%s vm[%d] query %q carried filters %v — the device boundary is missing",
					rt.proto, rt.op, i, c.query, c.filters)
			}
		}
	}
}

// TestScopedPrincipalWithNoFiltersIsRefusedNotServedTheFleet — the fail-closed
// wiring bug: no device boundary means NO live series, never the fleet.
func TestScopedPrincipalWithNoFiltersIsRefusedNotServedTheFleet(t *testing.T) {
	for _, rt := range allRoutes {
		h := newHarness(t)
		h.seedDevice("leaf1", "leaf1", "acme")
		h.scopeFilters = nil // a scoped principal with no boundary
		var warned int
		h.onWarn = func(string, map[string]any) { warned++ }
		w, body := h.get(pathFor(rt.proto, rt.op))
		if w.Code != http.StatusOK {
			t.Fatalf("%s/%s = %d", rt.proto, rt.op, w.Code)
		}
		if len(h.vm) != 0 {
			t.Errorf("%s/%s issued an UNSCOPED metrics read: %+v", rt.proto, rt.op, h.vm)
		}
		cov := coverageOf(t, body)
		if cov.LiveSeries || cov.LSDB {
			t.Errorf("%s/%s claimed live coverage with no device boundary: %+v", rt.proto, rt.op, cov)
		}
		if warned == 0 {
			t.Errorf("%s/%s refused the read silently — §10 forbids a silent failure", rt.proto, rt.op)
		}
		if !hasNote(body, "no device scope could be derived") {
			t.Errorf("%s/%s notes do not explain the refusal: %v", rt.proto, rt.op, notesOf(body))
		}
	}
}

// A cross-tenant principal legitimately carries no filter — nothing to restrict.
func TestCrossTenantPrincipalMayReadWithoutFilters(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	h.principal = Principal{Tenant: "global", Cross: true, Subject: "root"}
	h.scope = "__all__"
	h.scopeFilters = nil
	h.samples[seriesQuery(ProtoISIS.AdjMetric(), nil)] = []Sample{
		{Labels: map[string]string{"device": "leaf1", "isis_neighbor": "0000.0000.0002"}, Value: 3},
	}
	w, body := h.get("/api/protocols/isis/summary")
	if w.Code != http.StatusOK {
		t.Fatalf("cross summary = %d", w.Code)
	}
	if len(h.vm) == 0 {
		t.Fatal("the cross-tenant principal was refused the metrics read")
	}
	if !coverageOf(t, body).LiveSeries {
		t.Errorf("cross-tenant live series not reported: %v", body)
	}
}

// ── the honesty contract ────────────────────────────────────────────────────

// TestAbsentSourcesAreNullWithANoteNeverZero is the module's reason to exist.
func TestAbsentSourcesAreNullWithANoteNeverZero(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	// No CH rows, no VM series at all: nothing is collected for this protocol.
	w, body := h.get("/api/protocols/ospf/health?device=leaf1")
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d", w.Code)
	}
	cov := coverageOf(t, body)
	if cov.LiveSeries || cov.LSDB {
		t.Errorf("coverage claimed absent sources: %+v", cov)
	}
	for _, k := range []string{"neighbor_count", "adjacencies_up", "adjacencies_down"} {
		v, present := body[k]
		if !present {
			t.Errorf("%s missing from the response", k)
		}
		if v != nil {
			t.Errorf("%s = %v, want null — a fabricated 0 from a protocol nobody is watching is the lie", k, v)
		}
	}
	lsdb, _ := body["lsdb"].(map[string]any)
	if lsdb == nil || lsdb["lsp_count"] != nil {
		t.Errorf("lsdb = %v, want {lsp_count: null, note}", body["lsdb"])
	}
	if note, _ := lsdb["note"].(string); !strings.Contains(note, "device_ospf_lsdb_count") {
		t.Errorf("the lsdb note must name the absent series: %q", note)
	}
	if src, _ := body["source"].(string); src != "events" {
		t.Errorf("source = %q, want events (the only class that answered)", src)
	}
	if !hasNote(body, "no live series collected for this device") {
		t.Errorf("no honest live-series note: %v", notesOf(body))
	}
	if !hasNote(body, "OSPF area membership is not collected") {
		t.Errorf("OSPF area absence is not declared: %v", notesOf(body))
	}
	if body["areas"] != nil {
		t.Errorf("areas = %v, want null (collected by nothing)", body["areas"])
	}
}

func TestHealthReportsLiveCountsWhenASeriesExists(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	q := seriesQuery(ProtoISIS.AdjMetric(), []string{"leaf1"})
	h.samples[q] = []Sample{
		{Labels: map[string]string{"device": "leaf1", "isis_neighbor": "0000.0000.0002", "isis_level": "L2", "ifName": "ethernet-1/1"}, Value: 3},
		{Labels: map[string]string{"device": "leaf1", "isis_neighbor": "0000.0000.0003", "isis_level": "L1"}, Value: 1},
		{Labels: map[string]string{"isis_neighbor": "orphan"}, Value: 3}, // no device label → not evidence
	}
	w, body := h.get("/api/protocols/isis/health?device=leaf1")
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d (%v)", w.Code, body)
	}
	if n, _ := body["neighbor_count"].(float64); n != 2 {
		t.Errorf("neighbor_count = %v, want 2 (the label-less series is not attributable)", body["neighbor_count"])
	}
	if n, _ := body["adjacencies_up"].(float64); n != 1 {
		t.Errorf("adjacencies_up = %v, want 1", body["adjacencies_up"])
	}
	if n, _ := body["adjacencies_down"].(float64); n != 1 {
		t.Errorf("adjacencies_down = %v, want 1", body["adjacencies_down"])
	}
	levels, _ := body["levels"].([]any)
	if len(levels) != 2 || levels[0] != "L1" || levels[1] != "L2" {
		t.Errorf("levels = %v, want [L1 L2] sorted", body["levels"])
	}
	if !coverageOf(t, body).LiveSeries {
		t.Error("coverage.live_series is false with a series present")
	}
	if !hasNote(body, "IS-IS area addresses are not collected") {
		t.Errorf("IS-IS area absence is not declared: %v", notesOf(body))
	}
}

func TestLSDBLightsUpByItselfWhenASeriesAppears(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	h.samples[seriesQuery(ProtoISIS.LSDBMetric(), []string{"leaf1"})] = []Sample{
		{Labels: map[string]string{"device": "leaf1"}, Value: 41},
		{Labels: map[string]string{"device": "leaf1"}, Value: 1},
		{Labels: map[string]string{}, Value: 9}, // unattributable
	}
	w, body := h.get("/api/protocols/isis/health?device=leaf1")
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d", w.Code)
	}
	if !coverageOf(t, body).LSDB {
		t.Fatalf("coverage.lsdb = false with an LSDB series present: %v", body)
	}
	lsdb, _ := body["lsdb"].(map[string]any)
	if n, _ := lsdb["lsp_count"].(float64); n != 42 {
		t.Errorf("lsp_count = %v, want 42", lsdb["lsp_count"])
	}
	if note, _ := lsdb["note"].(string); note != "" {
		t.Errorf("a present source must carry no absence note: %q", note)
	}
}

// TestStoreFailureIsReportedNotSwallowed — a failed read is coverage:false with
// a note, never an empty-but-healthy answer.
func TestStoreFailureIsReportedNotSwallowed(t *testing.T) {
	for _, rt := range allRoutes {
		h := newHarness(t)
		h.seedDevice("leaf1", "leaf1", "acme")
		h.chErr = errors.New("clickhouse unreachable")
		h.vmErr = errors.New("victoria unreachable")
		w, body := h.get(pathFor(rt.proto, rt.op))
		if w.Code != http.StatusOK {
			t.Fatalf("%s/%s = %d", rt.proto, rt.op, w.Code)
		}
		cov := coverageOf(t, body)
		if cov.Events || cov.LiveSeries || cov.LSDB {
			t.Errorf("%s/%s claimed coverage after both stores failed: %+v", rt.proto, rt.op, cov)
		}
		if src, _ := body["source"].(string); src != "none" {
			t.Errorf("%s/%s source = %q, want none", rt.proto, rt.op, src)
		}
		if !hasNote(body, "the correlation store could not be queried") {
			t.Errorf("%s/%s hid the events failure: %v", rt.proto, rt.op, notesOf(body))
		}
		if !hasNote(body, "the metric store could not be queried") {
			t.Errorf("%s/%s hid the metrics failure: %v", rt.proto, rt.op, notesOf(body))
		}
	}
}

// ── adjacencies: paging + merge through the handler ─────────────────────────

func TestAdjacenciesPagesAndMergesBothSources(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	h.rows = []map[string]any{
		chRow(1756814402000, "0f8fad5b-d9cb-469f-a165-70867728950e", "leaf1", "0000.0000.0002", "up", "info", "syslog", "ethernet-1/1"),
		chRow(1756814401000, "1f8fad5b-d9cb-469f-a165-70867728950e", "leaf1", "0000.0000.0002", "down", "warn", "trap", ""),
		// the SAME signal from the archive arm: deduplicated on signal_id
		chRow(1756814401000, "1f8fad5b-d9cb-469f-a165-70867728950e", "leaf1", "0000.0000.0002", "down", "warn", "trap", ""),
	}
	h.samples[seriesQuery(ProtoISIS.AdjMetric(), []string{"leaf1"})] = []Sample{
		{Labels: map[string]string{"device": "leaf1", "isis_neighbor": "0000.0000.0002", "vrf": "default"}, Value: 3},
	}
	w, body := h.get("/api/protocols/isis/adjacencies?device=leaf1")
	if w.Code != http.StatusOK {
		t.Fatalf("adjacencies = %d (%v)", w.Code, body)
	}
	if n, _ := body["event_count"].(float64); n != 2 {
		t.Errorf("event_count = %v, want 2 after cross-table dedup", body["event_count"])
	}
	adjs, _ := body["adjacencies"].([]any)
	if len(adjs) != 1 {
		t.Fatalf("adjacencies = %v, want one merged row", body["adjacencies"])
	}
	a, _ := adjs[0].(map[string]any)
	if a["state_source"] != "live_series" || a["current_state"] != "up" || a["up"] != true {
		t.Errorf("merged row = %v", a)
	}
	if n, _ := a["flaps"].(float64); n != 1 {
		t.Errorf("flaps = %v, want 1", a["flaps"])
	}
	tl, _ := a["timeline"].([]any)
	if len(tl) != 2 {
		t.Errorf("timeline = %v, want 2 entries newest-first", a["timeline"])
	}
	if cov := coverageOf(t, body); !cov.Events || !cov.LiveSeries {
		t.Errorf("coverage = %+v, want both classes", cov)
	}
	if src, _ := body["source"].(string); src != "events+live_series" {
		t.Errorf("source = %q", src)
	}
	if body["truncated"] != false || body["next_cursor"] != "" {
		t.Errorf("a short page must not advertise a cursor: %v / %v", body["truncated"], body["next_cursor"])
	}
	// The device narrowed BOTH reads by id and by name.
	if !strings.Contains(h.ch[0].sql, "entity_id IN ('leaf1')") {
		t.Errorf("the ClickHouse read was not narrowed to the device: %s", h.ch[0].sql)
	}
	if !strings.Contains(h.vm[0].query, `{device=~"leaf1"}`) {
		t.Errorf("the metrics read was not narrowed to the device: %s", h.vm[0].query)
	}
}

func TestAdjacenciesTruncatesAndEmitsACursor(t *testing.T) {
	h := newHarness(t)
	ids := []string{
		"0f8fad5b-d9cb-469f-a165-70867728950e",
		"1f8fad5b-d9cb-469f-a165-70867728950e",
		"2f8fad5b-d9cb-469f-a165-70867728950e",
	}
	for i, id := range ids {
		h.rows = append(h.rows, chRow(1756814400000-int64(i)*1000, id, "leaf1", "p", "down", "warn", "syslog", ""))
	}
	w, body := h.get("/api/protocols/ospf/adjacencies?limit=2")
	if w.Code != http.StatusOK {
		t.Fatalf("adjacencies = %d", w.Code)
	}
	if n, _ := body["event_count"].(float64); n != 2 {
		t.Errorf("event_count = %v, want the limit (2)", body["event_count"])
	}
	if body["truncated"] != true {
		t.Errorf("truncated = %v, want true", body["truncated"])
	}
	cur, _ := body["next_cursor"].(string)
	ms, sid, ok := decodeCursor(cur)
	if !ok || ms != 1756814399000 || sid != ids[1] {
		t.Errorf("next_cursor decodes to (%d,%q,%v), want the LAST returned row", ms, sid, ok)
	}
}

// ── summary ─────────────────────────────────────────────────────────────────

func TestSummaryRollsUpAndBoundsItsScan(t *testing.T) {
	h := newHarness(t)
	h.samples[seriesQuery(ProtoISIS.AdjMetric(), nil)] = []Sample{
		{Labels: map[string]string{"device": "leaf1", "isis_neighbor": "a"}, Value: 3},
		{Labels: map[string]string{"device": "leaf2", "isis_neighbor": "b"}, Value: 1},
	}
	h.rows = []map[string]any{
		chRow(1756814402000, "0f8fad5b-d9cb-469f-a165-70867728950e", "leaf2", "b", "down", "warn", "syslog", ""),
	}
	w, body := h.get("/api/protocols/isis/summary")
	if w.Code != http.StatusOK {
		t.Fatalf("summary = %d (%v)", w.Code, body)
	}
	devs, _ := body["devices"].([]any)
	if len(devs) != 2 {
		t.Fatalf("devices = %v, want 2", body["devices"])
	}
	first, _ := devs[0].(map[string]any)
	if first["device"] != "leaf2" {
		t.Errorf("roll-up is not worst-first: %v", devs)
	}
	if n, _ := first["down_adjacencies"].(float64); n != 1 {
		t.Errorf("leaf2 down_adjacencies = %v, want 1", first["down_adjacencies"])
	}
	// The summary is a FLEET read: no device narrowing in either store.
	if strings.Contains(h.ch[0].sql, "entity_id IN") {
		t.Errorf("the summary narrowed to a device: %s", h.ch[0].sql)
	}
	if strings.Contains(h.vm[0].query, "device=~") {
		t.Errorf("the summary narrowed the metrics read: %s", h.vm[0].query)
	}
	// It still asks the store for a bounded number of rows.
	if !strings.Contains(h.ch[0].sql, "LIMIT 4000 ") {
		t.Errorf("the summary scan is not bounded: %s", h.ch[0].sql)
	}
}

func TestSummaryDeclaresATruncatedRollUp(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < maxSummaryEvents; i++ {
		h.rows = append(h.rows, chRow(int64(1756814400000-i), uuidN(i), "leaf1", "p", "down", "warn", "syslog", ""))
	}
	w, body := h.get("/api/protocols/ospf/summary")
	if w.Code != http.StatusOK {
		t.Fatalf("summary = %d", w.Code)
	}
	if body["truncated"] != true {
		t.Errorf("truncated = %v, want true", body["truncated"])
	}
	if !hasNote(body, "roll-up covers only the 2000 most recent") {
		t.Errorf("a partial roll-up was presented as a complete one: %v", notesOf(body))
	}
}

func TestSummaryTruncatesTheDeviceList(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 5; i++ {
		h.rows = append(h.rows, chRow(int64(1756814400000-i), uuidN(i), "dev"+itoa(i), "p", "down", "warn", "syslog", ""))
	}
	w, body := h.get("/api/protocols/ospf/summary?limit=2")
	if w.Code != http.StatusOK {
		t.Fatalf("summary = %d", w.Code)
	}
	devs, _ := body["devices"].([]any)
	if len(devs) != 2 {
		t.Errorf("devices = %d rows, want the limit (2)", len(devs))
	}
	if body["truncated"] != true {
		t.Errorf("truncated = %v, want true", body["truncated"])
	}
}

// ── health: the flap/stability verdict ──────────────────────────────────────

func TestHealthCountsFlapsAndExplainsTheScore(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	h.rows = []map[string]any{
		chRow(1756814403000, uuidN(1), "leaf1", "p", "down", "warn", "syslog", ""),
		chRow(1756814402000, uuidN(2), "leaf1", "p", "up", "info", "syslog", ""),
		chRow(1756814401000, uuidN(3), "leaf1", "p", "down", "warn", "trap", ""),
	}
	w, body := h.get("/api/protocols/ospf/health?device=leaf1&since=1h")
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d (%v)", w.Code, body)
	}
	if n, _ := body["flaps"].(float64); n != 2 {
		t.Errorf("flaps = %v, want 2 (down transitions only)", body["flaps"])
	}
	if n, _ := body["adjacency_changes"].(float64); n != 3 {
		t.Errorf("adjacency_changes = %v, want 3", body["adjacency_changes"])
	}
	if body["last_change"] == "" || body["last_change"] == nil {
		t.Errorf("last_change is empty with events present")
	}
	st, _ := body["stability"].(map[string]any)
	if st == nil {
		t.Fatalf("no stability block: %v", body)
	}
	if r, _ := st["flaps_per_hour"].(float64); r != 2 {
		t.Errorf("flaps_per_hour = %v, want 2", st["flaps_per_hour"])
	}
	if basis, _ := st["basis"].(string); !strings.Contains(basis, "2 adjacency down-transitions over 1h") {
		t.Errorf("basis = %q — a bare score is not an explanation", basis)
	}
	if body["device"] != "leaf1" || body["device_name"] != "leaf1" {
		t.Errorf("health did not echo the RESOLVED device: %v / %v", body["device"], body["device_name"])
	}
}

// TestDeviceNameIsAlsoAnIdentity — the two collector lanes label series with the
// id and with the name; a device whose name differs must be matched on both.
func TestDeviceNameIsAlsoAnIdentity(t *testing.T) {
	h := newHarness(t)
	h.devices["dev-7"] = Device{ID: "dev-7", Name: "leaf1", TenantID: "acme"}
	if w, _ := h.get("/api/protocols/isis/adjacencies?device=dev-7"); w.Code != http.StatusOK {
		t.Fatalf("adjacencies = %d", w.Code)
	}
	if !strings.Contains(h.ch[0].sql, "entity_id IN ('dev-7','leaf1')") {
		t.Errorf("the events read did not carry both identities: %s", h.ch[0].sql)
	}
	if !strings.Contains(h.vm[0].query, `{device=~"dev-7|leaf1"}`) {
		t.Errorf("the metrics read did not carry both identities: %s", h.vm[0].query)
	}
}

// ── response envelope ───────────────────────────────────────────────────────

func TestEveryResponseCarriesItsWindowAndCoverage(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	for _, rt := range allRoutes {
		w, body := h.get(pathFor(rt.proto, rt.op))
		if w.Code != http.StatusOK {
			t.Fatalf("%s/%s = %d", rt.proto, rt.op, w.Code)
		}
		for _, k := range []string{"protocol", "window_seconds", "since", "now", "coverage", "source", "notes"} {
			if _, ok := body[k]; !ok {
				t.Errorf("%s/%s response has no %q", rt.proto, rt.op, k)
			}
		}
		if body["protocol"] != rt.proto {
			t.Errorf("%s/%s protocol = %v", rt.proto, rt.op, body["protocol"])
		}
		if body["since"] == body["now"] {
			t.Errorf("%s/%s since == now", rt.proto, rt.op)
		}
	}
}

// hasNote reports whether any note contains the substring.
func hasNote(body map[string]any, want string) bool {
	for _, n := range notesOf(body) {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

// uuidN builds a distinct, well-formed signal id for row n.
func uuidN(n int) string {
	hex := "0123456789abcdef"
	b := []byte("00000000-0000-4000-8000-000000000000")
	for i, pos := range []int{7, 6, 5, 4, 2, 1} {
		b[pos] = hex[(n>>(4*i))&0xf]
	}
	return string(b)
}

// TestRowsWithoutASignalIDAreDropped — a row the dedup key cannot identify is
// not evidence about an adjacency; it must be skipped, not counted.
func TestRowsWithoutASignalIDAreDropped(t *testing.T) {
	h := newHarness(t)
	h.rows = []map[string]any{
		chRow(1756814402000, "", "leaf1", "p", "down", "warn", "syslog", ""),
		chRow(1756814401000, uuidN(1), "leaf1", "p", "down", "warn", "syslog", ""),
	}
	w, body := h.get("/api/protocols/ospf/adjacencies")
	if w.Code != http.StatusOK {
		t.Fatalf("adjacencies = %d", w.Code)
	}
	if n, _ := body["event_count"].(float64); n != 1 {
		t.Errorf("event_count = %v, want 1 (the id-less row is not an event)", body["event_count"])
	}
}

// TestMalformedTimestampsDoNotBecomeSilentZeroes — a ts the parser cannot read
// still yields a well-formed (epoch) event rather than corrupting the page, and
// the ordering stays deterministic.
func TestMalformedTimestampsSortLast(t *testing.T) {
	h := newHarness(t)
	bad := chRow(0, uuidN(2), "leaf1", "p", "up", "info", "syslog", "")
	bad["ts_ms"] = "not-a-number"
	h.rows = []map[string]any{bad, chRow(1756814401000, uuidN(1), "leaf1", "p", "down", "warn", "syslog", "")}
	w, body := h.get("/api/protocols/ospf/adjacencies")
	if w.Code != http.StatusOK {
		t.Fatalf("adjacencies = %d", w.Code)
	}
	adjs, _ := body["adjacencies"].([]any)
	if len(adjs) != 1 {
		t.Fatalf("adjacencies = %v", body["adjacencies"])
	}
	a, _ := adjs[0].(map[string]any)
	tl, _ := a["timeline"].([]any)
	if len(tl) != 2 {
		t.Fatalf("timeline = %v, want both events", a["timeline"])
	}
	first, _ := tl[0].(map[string]any)
	if first["signal_id"] != uuidN(1) {
		t.Errorf("the readable timestamp must sort first: %v", tl)
	}
}

// TestLSDBFailureIsNotReportedAsAbsence — the §10 split. Both a failed metric
// read and a genuinely absent series end in lsdb:false, but they are DIFFERENT
// facts: claiming "no LSDB series is collected on this deployment" when the
// store merely errored is a claim the module has not earned.
func TestLSDBFailureIsNotReportedAsAbsence(t *testing.T) {
	for _, rt := range allRoutes {
		// (a) the store answered, and there is genuinely no such series.
		absent := newHarness(t)
		absent.seedDevice("leaf1", "leaf1", "acme")
		wA, bodyA := absent.get(pathFor(rt.proto, rt.op))
		if wA.Code != http.StatusOK {
			t.Fatalf("%s/%s absent = %d", rt.proto, rt.op, wA.Code)
		}
		if !hasNote(bodyA, "is emitted by no collector today") {
			t.Errorf("%s/%s absence is not stated as absence: %v", rt.proto, rt.op, notesOf(bodyA))
		}

		// (b) the store FAILED. Coverage is still false, but the note must not
		// claim anything about what this deployment collects.
		broken := newHarness(t)
		broken.seedDevice("leaf1", "leaf1", "acme")
		broken.vmErr = errors.New("victoria unreachable")
		wB, bodyB := broken.get(pathFor(rt.proto, rt.op))
		if wB.Code != http.StatusOK {
			t.Fatalf("%s/%s broken = %d", rt.proto, rt.op, wB.Code)
		}
		if coverageOf(t, bodyB).LSDB {
			t.Errorf("%s/%s claimed LSDB coverage after the store failed", rt.proto, rt.op)
		}
		if hasNote(bodyB, "is emitted by no collector today") {
			t.Errorf("%s/%s reported a STORE FAILURE as 'no collector emits it': %v",
				rt.proto, rt.op, notesOf(bodyB))
		}
		if !hasNote(bodyB, "NOT evidence that no LSDB series exists") {
			t.Errorf("%s/%s did not distinguish the failure from absence: %v", rt.proto, rt.op, notesOf(bodyB))
		}
	}
}

// TestLSDBRefusalIsLoggedAndDistinct — a scoped principal with no device
// boundary is a WIRING fault, and must not be reported as "nothing collects it"
// either.
func TestLSDBRefusalIsLoggedAndDistinct(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	h.scopeFilters = nil
	var warnings []string
	h.onWarn = func(msg string, _ map[string]any) { warnings = append(warnings, msg) }
	w, body := h.get("/api/protocols/isis/health?device=leaf1")
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d", w.Code)
	}
	if hasNote(body, "is emitted by no collector today") {
		t.Errorf("a scope wiring fault was reported as an absent collector: %v", notesOf(body))
	}
	if !hasNote(body, "this is a wiring fault") {
		t.Errorf("the wiring fault is not named: %v", notesOf(body))
	}
	found := false
	for _, m := range warnings {
		if strings.Contains(m, "LSDB") {
			found = true
		}
	}
	if !found {
		t.Errorf("the refused LSDB read was not logged (§10 forbids a silent failure): %v", warnings)
	}
	lsdb, _ := body["lsdb"].(map[string]any)
	if lsdb == nil || lsdb["lsp_count"] != nil {
		t.Errorf("lsp_count = %v, want null", body["lsdb"])
	}
}
