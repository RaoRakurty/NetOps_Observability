package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/ticketing"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/metricval"
	"netops/backend/models"
)

// resource_bounds_test.go — FAILURE-PATH tests for F-21 (writeJSON discarded the
// encode error), F-27 (unbounded ClickHouse reads) and F-33 (unbounded maps).
//
// Every one of these defects sat behind a green happy-path test. The cases here
// are only faults: a NaN in a response, a ClickHouse that is down / slow /
// enormous, an alert set that churns forever.

// ── F-21 ─────────────────────────────────────────────────────────────────────

// TestWriteJSONNaNIsNotAnEmpty200 is the finding proper. json.Encoder marshals
// to an internal buffer BEFORE writing, so the old
// `WriteHeader(200); _ = Encode(body)` emitted 200 + Content-Type + zero bytes
// for a body containing NaN — and the alert built on that endpoint went quiet.
func TestWriteJSONNaNIsNotAnEmpty200(t *testing.T) {
	before := jsonEncodeFailures.Load()
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]any{"utilization": math.NaN()})

	if w.Code == http.StatusOK {
		t.Fatalf("status = 200 for an unencodable body — this is the F-21 silent empty-200")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Fatal("500 with an EMPTY body — the client still cannot tell anything went wrong")
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("error body is not valid JSON: %q", w.Body.String())
	}
	if out["code"] != "RESPONSE_ENCODE_FAILED" {
		t.Errorf("error code = %q, want RESPONSE_ENCODE_FAILED (the SPA branches on it)", out["code"])
	}
	if jsonEncodeFailures.Load() != before+1 {
		t.Error("the encode failure was not counted — it stays invisible on /metrics")
	}
}

// TestWriteJSONInfIsAlsoRejected: ±Inf hits the same encoder path and arrives
// from the same sources (a rate over a zero interval).
func TestWriteJSONInfIsAlsoRejected(t *testing.T) {
	for _, v := range []float64{math.Inf(1), math.Inf(-1)} {
		w := httptest.NewRecorder()
		writeJSON(w, http.StatusOK, map[string]any{"rate": v})
		if w.Code != http.StatusInternalServerError {
			t.Errorf("value %v: status = %d, want 500", v, w.Code)
		}
	}
}

// TestWriteJSONHappyPathBytesUnchanged: the fix must not alter the wire format
// (the SPA and every API test depend on it) — same JSON, same trailing newline
// the Encoder produced.
func TestWriteJSONHappyPathBytesUnchanged(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, map[string]string{"a": "b<c"})
	if got, want := w.Body.String(), "{\"a\":\"b\\u003cc\"}\n"; got != want {
		t.Errorf("body = %q, want %q (HTML escaping + trailing newline must match encoding/json's Encoder)", got, want)
	}
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
}

// The F-21 parse-boundary unit tests moved into internal/metricval with the
// code; the end-to-end shape below stays because it asserts the RELATIONSHIP
// with this package's writeJSON.

// TestNaNSampleDoesNotEmptyAResponse is the end-to-end shape: a metric store
// returning NaN must degrade one FIELD, never the whole response.
func TestNaNSampleDoesNotEmptyAResponse(t *testing.T) {
	body := map[string]any{"device": "leaf1", "utilization": metricval.FiniteOrZero("NaN")}
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d — a NaN sample must not fail the response once sanitised at the parse boundary", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"device":"leaf1"`) {
		t.Errorf("the rest of the payload was lost: %s", w.Body.String())
	}
}

// ── F-27 ─────────────────────────────────────────────────────────────────────

// TestCHQuerySendsExecutionGuards: a Go client timeout does not stop a
// ClickHouse query. Without these parameters the server keeps executing work
// nobody is waiting for — the client-side shape of the #100 incident.
func TestCHQuerySendsExecutionGuards(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		fmt.Fprintln(w, "1")
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	if got := chQuery("SELECT 1"); len(got) != 1 {
		t.Fatalf("chQuery returned %v", got)
	}
	for _, want := range []string{"max_execution_time", "cancel_http_readonly_queries_on_client_close"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query string %q is missing %s — the query outlives the caller without it", gotQuery, want)
		}
	}
}

// TestCHQueryIsCancelledWhenTheCallerGivesUp: the request must carry the
// context, so closing the connection actually cancels the server-side query.
// The old code used http.NewRequest (no context) — cancellation was impossible.
func TestCHQueryIsCancelledWhenTheCallerGivesUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second): // a slow query
		}
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := chQueryCtx(ctx, "SELECT sleep(3)")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a query abandoned by its caller returned success")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded — the request must carry the CALLER's context, "+
			"not just the client's own timeout (the old code used http.NewRequest, which cannot be cancelled at all)", err)
	}
	if elapsed > time.Second {
		t.Errorf("returned after %v — the caller's 150ms deadline did not bound the call", elapsed)
	}
}

// TestCHQueryRefusesAnOversizedResponse: an unbounded io.ReadAll on a response
// whose size scales with table size is the exact incident shape. Truncation
// must be an ERROR, never a short answer that looks complete.
func TestCHQueryRefusesAnOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		line := strings.Repeat("x", 1024) + "\n"
		for written := 0; written < int(chMaxResponseBytes)+1<<20; written += len(line) {
			if _, err := io.WriteString(w, line); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	_, err := chQueryCtx(context.Background(), "SELECT * FROM huge")
	if err == nil {
		t.Fatal("an over-cap response was accepted — a truncated result set would be served as if it were complete")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %v, want an explicit size-cap error", err)
	}
}

// TestCHQueryCountsFailures: "ClickHouse is down" and "there is no data"
// produced an identical empty report before. The counter is the difference.
func TestCHQueryCountsFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "DB::Exception: memory limit exceeded", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	before := chReadFailures.Load()
	if got := chQuery("SELECT 1"); got != nil {
		t.Errorf("chQuery returned %v on a 500, want nil", got)
	}
	if chReadFailures.Load() != before+1 {
		t.Error("a failed ClickHouse read was not counted — the report renders 'no data' with no way to tell it apart from an outage")
	}
}

// ── F-33 ─────────────────────────────────────────────────────────────────────
// The rate-limiter leak tests moved into internal/ratelimit with the limiter
// (they are white-box: they reach into the windows map).

// TestMemTicketingAuditIsRingBuffered: the in-memory ticketing audit slice was
// append-only forever, while its sibling audit store ring-buffers at 5000.
func TestMemTicketingAuditIsRingBuffered(t *testing.T) {
	m := newMemTicketingStore()
	total := memTicketAuditMax + 500
	for i := 0; i < total; i++ {
		if err := m.AppendAudit(context.Background(), ticketing.AuditEntry{
			TenantID: "t1", ID: fmt.Sprintf("c%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.RLock()
	n := len(m.audit)
	oldest := m.audit[0].ID
	m.mu.RUnlock()
	if n > memTicketAuditMax {
		t.Fatalf("audit trail holds %d entries, cap is %d — append-only growth in the API heap", n, memTicketAuditMax)
	}
	if oldest == "c0" {
		t.Error("the oldest entry survived — nothing was evicted")
	}
}

// TestSeenAlertsDoNotAccumulateForever: the WebSocket alert watcher's dedup map
// was keyed by alert fingerprint (rule|device|ifName|…) and nothing ever deleted
// from it, so on a fleet with churning labels it grew for the life of the
// process — inside the API, with the growth alarm F-35 had disabled.
func TestSeenAlertsDoNotAccumulateForever(t *testing.T) {
	seen := map[string]bool{}
	// 10,000 distinct series fire once each and resolve (label churn).
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("HighCPU|device=leaf%d,ifName=Et%d", i, i)
		pruneSeenAlerts(seen, []models.Alert{{ID: id}})
		seen[id] = true
	}
	pruneSeenAlerts(seen, nil) // everything has resolved
	if len(seen) != 0 {
		t.Fatalf("dedup map still holds %d entries after every alert resolved — unbounded growth (F-33)", len(seen))
	}
}

// TestResolvedAndRefiredAlertIsBroadcastAgain: pruning also fixes the behaviour
// the watcher's own comment promised ("exactly once per FIRING"). Before the
// fix a re-fire after a resolve was silently never broadcast, because its
// `seen` entry was immortal.
func TestResolvedAndRefiredAlertIsBroadcastAgain(t *testing.T) {
	seen := map[string]bool{}
	a := models.Alert{ID: "LinkDown|device=core1"}

	pruneSeenAlerts(seen, []models.Alert{a})
	seen[a.ID] = true

	pruneSeenAlerts(seen, nil) // resolved
	pruneSeenAlerts(seen, []models.Alert{a})
	if seen[a.ID] {
		t.Fatal("a re-fired alert is still marked as already broadcast — the dashboard never shows the second outage")
	}
}

// TestPruneKeepsStillActiveAlerts: pruning must not cause a duplicate broadcast
// of an alert that is still firing.
func TestPruneKeepsStillActiveAlerts(t *testing.T) {
	seen := map[string]bool{"a": true, "b": true}
	pruneSeenAlerts(seen, []models.Alert{{ID: "a"}})
	if !seen["a"] {
		t.Error("an alert that is still active lost its dedup entry — it would be re-broadcast every 2s")
	}
	if seen["b"] {
		t.Error("a resolved alert kept its dedup entry")
	}
}

// TestBodyLimitIsTighterForPreAuthRoutes (F-32): the route-class cap is what
// makes the NEXT public route safe without its author remembering.
func TestBodyLimitIsTighterForPreAuthRoutes(t *testing.T) {
	const global = 50 << 20
	for _, p := range publicPaths {
		if got := requestBodyLimit(p, global); got != preAuthMaxBodyBytes {
			t.Errorf("public path %s: body limit = %d, want the pre-auth cap %d", p, got, preAuthMaxBodyBytes)
		}
	}
	if got := requestBodyLimit("/api/devices", global); got != global {
		t.Errorf("authenticated path got the pre-auth cap (%d) — that would break large SOT imports", got)
	}
}

// TestPreAuthHandlersRejectOversizedBodies exercises the real handlers with a
// body far past their per-handler cap. These five routes are reachable with NO
// credentials at all.
func TestPreAuthHandlersRejectOversizedBodies(t *testing.T) {
	_, srv := newTestServerState(t)
	huge := `{"refresh_token":"` + strings.Repeat("A", int(authCredentialBodyBytes)*4) + `"}`

	cases := []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{"refresh", srv.handleRefresh, "/api/auth/refresh"},
		{"change-password", srv.handleChangePassword, "/api/auth/change-password"},
		{"ldap-login", srv.handleLDAPLogin, "/api/auth/ldap/login"},
		{"tacacs-login", srv.handleTACACSLogin, "/api/auth/tacacs/login"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(huge))
			w := httptest.NewRecorder()
			tc.handler(w, r)
			if w.Code == http.StatusOK {
				t.Fatalf("%s accepted a %d-byte pre-auth body", tc.name, len(huge))
			}
		})
	}
}

// TestLogoutBoundsItsBodyButStillSucceeds: logout must tolerate a missing body
// (it always has to work) while still bounding what it reads.
func TestLogoutBoundsItsBodyButStillSucceeds(t *testing.T) {
	_, srv := newTestServerState(t)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/logout", strings.NewReader(""))
	w := httptest.NewRecorder()
	srv.handleLogout(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("logout with an empty body = %d, want 200", w.Code)
	}
}

// TestDecodeJSONBodyReportsTheCap: a caller must be able to distinguish "too
// big" from "malformed".
func TestDecodeJSONBodyReportsTheCap(t *testing.T) {
	var dst map[string]string
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"a":"`+strings.Repeat("b", 4096)+`"}`))
	w := httptest.NewRecorder()
	err := decodeJSONBody(w, r, 128, &dst)
	if err == nil {
		t.Fatal("an over-cap body decoded successfully")
	}
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) && !strings.Contains(err.Error(), "too large") {
		t.Errorf("error %v does not identify the size cap", err)
	}
}
