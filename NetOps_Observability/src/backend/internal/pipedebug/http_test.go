// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── a fake backend ──────────────────────────────────────────────────────────

// fakeBackend is the injected seam set every test runs the debug API over.
//
// IT IS SHARED WITH GOROUTINES, and that is why every field below is behind a
// mutex. A trace does not finish inside the request that starts it: POST
// /api/debug/trace returns a receipt and leaves a FOLLOW goroutine polling the
// stores for up to the TTL, so the Search / CHSelect / inject / audit closures
// keep running while the test body reads what they recorded. The fixture used
// to let both sides touch the same map, slice and string unsynchronised, which
// the race detector reported (and which could also make an assertion read a
// half-appended slice).
//
// The rule the fixture now enforces:
//   - the closures take f.mu for every read AND write;
//   - a test READS recorded state through f.snap(), which copies under the lock;
//   - a test that has to change the fake AFTER a follow may be running does it
//     through f.set(...). Seeding before the request stays the normal case.
type fakeBackend struct {
	// mu guards every field below. See the type comment.
	mu        sync.Mutex
	principal Principal
	authOK    bool

	injectedSyslog []string
	injectedTrap   [][]byte
	injectErr      error

	osStatus int
	osBody   string
	osIndex  string

	peek    PeekResult
	peekErr error

	chRows []map[string]any
	chErr  error
	chSeen []string

	corrLevel LevelChange
	audits    []map[string]any
	ring      *Ring

	injectedFlow [][]byte
	vmBody       []byte
	vmErr        error
	vmMatch      string
	uiProbe      UIProbe
	uiErr        error
	uiCalls      []Kind
	parseFilter  ParseSwitch
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		principal: Principal{Subject: "owner", Cross: true},
		authOK:    true,
		osStatus:  200,
		osBody:    `{"hits":{"total":{"value":0},"hits":[]}}`,
		ring:      NewRing(),
	}
}

// fakeSnapshot is a value copy of everything the fake RECORDS. Slices are
// copied, not aliased: an assertion must never observe a slice the follow
// goroutine is still appending to.
type fakeSnapshot struct {
	injectedSyslog []string
	injectedTrap   [][]byte
	injectedFlow   [][]byte
	osIndex        string
	chSeen         []string
	vmMatch        string
	uiCalls        []Kind
	audits         []map[string]any
}

// snap copies the recorded calls under the lock.
func (f *fakeBackend) snap() fakeSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeSnapshot{
		injectedSyslog: append([]string(nil), f.injectedSyslog...),
		injectedTrap:   append([][]byte(nil), f.injectedTrap...),
		injectedFlow:   append([][]byte(nil), f.injectedFlow...),
		osIndex:        f.osIndex,
		chSeen:         append([]string(nil), f.chSeen...),
		vmMatch:        f.vmMatch,
		uiCalls:        append([]Kind(nil), f.uiCalls...),
		audits:         append([]map[string]any(nil), f.audits...),
	}
}

// set changes the fake under the lock. Use it when a test must change the fake
// after a request that may have left a follow goroutine running; plain field
// assignment before the first request is still fine.
func (f *fakeBackend) set(fn func(*fakeBackend)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeBackend) deps() Deps {
	return Deps{
		Authz: func(w http.ResponseWriter, _ *http.Request) (Principal, bool) {
			f.mu.Lock()
			ok, p := f.authOK, f.principal
			f.mu.Unlock()
			if !ok {
				http.Error(w, "platform administrator required", http.StatusForbidden)
				return Principal{}, false
			}
			return p, true
		},
		Search: func(_, path string, _ any) (*http.Response, error) {
			f.mu.Lock()
			f.osIndex = path
			status, body := f.osStatus, f.osBody
			f.mu.Unlock()
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
		OSIndexPattern: func(signal, tenant string, cross bool) string {
			if cross {
				return "netops-" + signal + "-*"
			}
			return "netops-" + signal + "-" + tenant + "-*"
		},
		CHSelect: func(_ context.Context, scope, sql string, _ ...string) ([]map[string]any, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.chSeen = append(f.chSeen, scope+"|"+sql)
			return f.chRows, f.chErr
		},
		CHScopeFor: func(p Principal) string {
			if p.Cross {
				return "__all__"
			}
			return p.Tenant
		},
		KafkaPeek: func(context.Context, PeekRequest) (PeekResult, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.peek, f.peekErr
		},
		CorrHealth: func(context.Context) (map[string]any, error) {
			return map[string]any{"durability": map[string]any{"quarantined_events": 7}}, nil
		},
		SetAPILevel: func(l Level, w time.Duration) LevelChange {
			return LevelChange{Module: ModuleAPI, Applied: true, Level: l, RevertAt: time.Now().Add(w)}
		},
		CorrLogLevel: func(context.Context, Level, time.Duration) (LevelChange, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.corrLevel, nil
		},
		InjectSyslog: func(_ context.Context, frame string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.injectErr != nil {
				return f.injectErr
			}
			f.injectedSyslog = append(f.injectedSyslog, frame)
			return nil
		},
		InjectTrap: func(_ context.Context, pdu []byte) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.injectErr != nil {
				return f.injectErr
			}
			f.injectedTrap = append(f.injectedTrap, pdu)
			return nil
		},
		InjectFlow: func(_ context.Context, pkt []byte) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.injectErr != nil {
				return f.injectErr
			}
			f.injectedFlow = append(f.injectedFlow, pkt)
			return nil
		},
		VictoriaExport: func(_ context.Context, match string, _, _ time.Time) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.vmMatch = match
			return f.vmBody, f.vmErr
		},
		UIQueryRun: func(_ *http.Request, kind Kind, _ string, _ PassiveSpec, _ string) (UIProbe, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.uiCalls = append(f.uiCalls, kind)
			return f.uiProbe, f.uiErr
		},
		ParseFilter: f.parseFilter,
		Ring:        f.ring,
		Audit: func(_ *http.Request, tenant, action string, detail map[string]any) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.audits = append(f.audits, map[string]any{"tenant": tenant, "action": action, "detail": detail})
		},
		WriteJSON: func(w http.ResponseWriter, status int, body any) {
			buf, err := json.Marshal(body)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(buf)
		},
		WriteError: func(w http.ResponseWriter, status int, err error) {
			http.Error(w, err.Error(), status)
		},
		Now: func() time.Time { return time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC) },
	}
}

func post(t *testing.T, h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return call(t, h, http.MethodPost, path, body)
}

func call(t *testing.T, h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// ── authorization ───────────────────────────────────────────────────────────

// §3a rule 3: these are platform-GLOBAL surfaces. The gate is injected, and a
// denial must stop every route before anything is injected or queried.
func TestEveryDebugRouteRefusesAnUnauthorizedCaller(t *testing.T) {
	f := newFakeBackend()
	f.authOK = false
	api := New(f.deps())

	routes := []struct {
		name   string
		h      http.HandlerFunc
		method string
		path   string
		body   string
	}{
		{"trace", api.HandleTrace, http.MethodPost, "/api/debug/trace", `{"kind":"syslog","device":"spine1"}`},
		{"status", api.HandleTraceStatus, http.MethodGet, "/api/debug/trace/01j9abcdefghjkmnpqrstvwxyz", ""},
		{"loglevel", api.HandleLogLevel, http.MethodPut, "/api/debug/loglevel", `{"module":"api","level":"debug"}`},
		{"stage", api.HandleStage, http.MethodGet, "/api/debug/stage/opensearch?marker=01j9abcdefghjkmnpqrstvwxyz", ""},
	}
	for _, rt := range routes {
		w := call(t, rt.h, rt.method, rt.path, rt.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: unauthorized caller got %d, want 403", rt.name, w.Code)
		}
	}
	if len(f.snap().injectedSyslog) != 0 || len(f.snap().chSeen) != 0 {
		t.Error("a denied request still injected or queried — the gate must run first")
	}
}

func TestWrongMethodsAreRefused(t *testing.T) {
	api := New(newFakeBackend().deps())
	if w := call(t, api.HandleTrace, http.MethodGet, "/api/debug/trace", ""); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /trace = %d", w.Code)
	}
	if w := call(t, api.HandleLogLevel, http.MethodPost, "/api/debug/loglevel", "{}"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /loglevel = %d", w.Code)
	}
}

// ── POST /api/debug/trace ───────────────────────────────────────────────────

func TestTraceInjectsATaggedSyntheticRecordAndReturnsAMarker(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"spine1","tenant":"t1","ttl_seconds":5}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !ValidMarker(got.Marker) || !got.Injected || !got.Synthetic {
		t.Fatalf("bad receipt: %+v", got)
	}
	if len(f.snap().injectedSyslog) != 1 {
		t.Fatalf("want 1 injected frame, got %d", len(f.snap().injectedSyslog))
	}
	frame := f.snap().injectedSyslog[0]
	if !strings.Contains(frame, MarkerTag(got.Marker)) {
		t.Error("the injected frame does not carry the returned marker")
	}
	if !strings.Contains(frame, SyntheticTag) {
		t.Error("the injected frame is not tagged synthetic")
	}
	if !strings.Contains(frame, "spine1") {
		t.Error("the injected frame does not claim the requested device")
	}
}

func TestTrapKindInjectsABinaryPDUNotASyslogFrame(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"trap","device":"spine1","ttl_seconds":5}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(f.snap().injectedTrap) != 1 || len(f.snap().injectedSyslog) != 0 {
		t.Fatalf("trap kind used the wrong injector: %d traps, %d frames", len(f.snap().injectedTrap), len(f.snap().injectedSyslog))
	}
}

// A failed injection must be REPORTED on the receipt, not swallowed into a
// trace that then reports "not seen" everywhere and blames the pipeline.
func TestAFailedInjectionIsReportedAndNoFollowIsStarted(t *testing.T) {
	f := newFakeBackend()
	f.injectErr = errors.New("syslog-ng unreachable")
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"spine1"}`)
	var got traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Injected {
		t.Error("a failed injection was reported as injected")
	}
	if !strings.Contains(got.InjectErr, "syslog-ng unreachable") {
		t.Errorf("the injection failure is not named: %q", got.InjectErr)
	}
	if _, ok := api.traces.get(got.Marker); ok {
		t.Error("a follow was started for a record that was never injected")
	}
}

func TestTraceRejectsMalformedInput(t *testing.T) {
	api := New(newFakeBackend().deps())
	for _, body := range []string{
		`{"kind":"netconf","device":"spine1"}`,
		// gNMI is passive-only: an injectable-shaped request for it must be
		// refused, never quietly turned into a write toward a device.
		`{"kind":"gnmi","device":"spine1"}`,
		// …and the mirror image: --passive on a kind that carries a real marker.
		`{"kind":"syslog","device":"spine1","passive":true}`,
		`{"kind":"syslog","device":""}`,
		`{"kind":"syslog","device":"spine 1; rm -rf /"}`,
		`not json`,
	} {
		w := post(t, api.HandleTrace, "/api/debug/trace", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q got %d, want 400", body, w.Code)
		}
	}
}

// §3/§15: the body is MaxBytesReader-capped, so an oversized payload is refused
// rather than decoded.
func TestTraceBodyIsBounded(t *testing.T) {
	api := New(newFakeBackend().deps())
	huge := `{"kind":"syslog","device":"spine1","tenant":"` + strings.Repeat("x", maxDebugBody*2) + `"}`
	if w := post(t, api.HandleTrace, "/api/debug/trace", huge); w.Code != http.StatusBadRequest {
		t.Errorf("an oversized body got %d, want 400", w.Code)
	}
}

func TestTTLIsClampedNotTrusted(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"spine1","ttl_seconds":999999}`)
	var got traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.TTLSec != int(MaxTraceTTL.Seconds()) {
		t.Errorf("ttl %d was not clamped to %v", got.TTLSec, MaxTraceTTL)
	}
}

func TestTraceIsAudited(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"spine1","tenant":"t1"}`)
	if len(f.snap().audits) != 1 || f.snap().audits[0]["action"] != "debug.trace" {
		t.Fatalf("the trace was not audited: %+v", f.snap().audits)
	}
	detail, _ := f.snap().audits[0]["detail"].(map[string]any)
	if detail["synthetic"] != true || detail["device"] != "spine1" {
		t.Errorf("the audit record does not say what was injected: %+v", detail)
	}
}

// ── tenant scoping (§3a rules 1 and 2) ──────────────────────────────────────

func TestAScopedPrincipalCannotNameAnotherTenant(t *testing.T) {
	f := newFakeBackend()
	f.principal = Principal{Subject: "owner", Tenant: "t_own", Cross: false}
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"spine1","tenant":"t_other"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a scoped principal widened its scope: %d %s", w.Code, w.Body.String())
	}
	if len(f.snap().injectedSyslog) != 0 {
		t.Error("a refused request still injected a record")
	}
}

func TestAScopedPrincipalsTenantComesFromTheTokenNotTheBody(t *testing.T) {
	f := newFakeBackend()
	f.principal = Principal{Subject: "owner", Tenant: "t_own", Cross: false}
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"spine1"}`)
	var got traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tenant != "t_own" {
		t.Errorf("tenant = %q, want the principal's own t_own", got.Tenant)
	}
}

// Cross-tenant status reads 404 — never a 403 that would confirm the id exists.
func TestTraceStatusIs404ForAnotherTenantsMarkerAndForAnUnknownOne(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"spine1","tenant":"t_a"}`)
	var got traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// The trace POST above left a follow goroutine running, so the switch of
	// identity goes through the lock — this is the one test that has to change
	// the fake AFTER a run has started.
	f.set(func(s *fakeBackend) { s.principal = Principal{Subject: "other", Tenant: "t_b", Cross: false} })
	if w := call(t, api.HandleTraceStatus, http.MethodGet, "/api/debug/trace/"+got.Marker, ""); w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant status read got %d, want 404", w.Code)
	}
	f.set(func(s *fakeBackend) { s.principal = Principal{Subject: "owner", Cross: true} })
	unknown := NewMarker(time.Now())
	if w := call(t, api.HandleTraceStatus, http.MethodGet, "/api/debug/trace/"+unknown, ""); w.Code != http.StatusNotFound {
		t.Errorf("unknown marker got %d, want 404", w.Code)
	}
	if w := call(t, api.HandleTraceStatus, http.MethodGet, "/api/debug/trace/not-a-marker", ""); w.Code != http.StatusBadRequest {
		t.Errorf("malformed marker got %d, want 400", w.Code)
	}
}

// ── PUT /api/debug/loglevel ─────────────────────────────────────────────────

func TestLogLevelRaisesTheAPIAndReportsTheRevertTime(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	w := call(t, api.HandleLogLevel, http.MethodPut, "/api/debug/loglevel", `{"module":"api","level":"debug","for_seconds":120}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got LevelChange
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Applied || got.RevertAt.IsZero() {
		t.Errorf("no bounded raise happened: %+v", got)
	}
}

// A module with no runtime switch answers 200 + applied:false + the reason. A
// 5xx would make an honest refusal indistinguishable from a broken endpoint,
// and a faked success is the thing the design forbids outright.
func TestAModuleWithNoRuntimeSwitchSaysSoAndIsNotAnError(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	for _, module := range []string{"vector", "router", "ingress"} {
		w := call(t, api.HandleLogLevel, http.MethodPut, "/api/debug/loglevel",
			fmt.Sprintf(`{"module":%q,"level":"debug","for_seconds":60}`, module))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", module, w.Code)
			continue
		}
		var got LevelChange
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Applied {
			t.Errorf("%s: reported a level change it cannot make", module)
		}
		if got.Reason == "" {
			t.Errorf("%s: refused without saying why", module)
		}
	}
}

func TestLogLevelGrammarsAreClosed(t *testing.T) {
	api := New(newFakeBackend().deps())
	for _, body := range []string{
		`{"module":"postgres","level":"debug"}`,
		`{"module":"api","level":"trace"}`,
		`{"module":"api","level":"warn"}`,
		`nope`,
	} {
		if w := call(t, api.HandleLogLevel, http.MethodPut, "/api/debug/loglevel", body); w.Code != http.StatusBadRequest {
			t.Errorf("body %q got %d, want 400", body, w.Code)
		}
	}
}

func TestLogLevelIsAudited(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	call(t, api.HandleLogLevel, http.MethodPut, "/api/debug/loglevel", `{"module":"api","level":"debug"}`)
	if len(f.snap().audits) != 1 || f.snap().audits[0]["action"] != "debug.loglevel" {
		t.Fatalf("the level change was not audited: %+v", f.snap().audits)
	}
}

// ── GET /api/debug/stage/{stage} ────────────────────────────────────────────

func TestStageRouteRefusesHostCollectedStages(t *testing.T) {
	api := New(newFakeBackend().deps())
	// ingress and router are collected by `vector tap` on the HOST. The API has
	// no docker socket, so claiming them would be a fabricated answer.
	for _, stage := range []Stage{StageIngress, StageRouter} {
		path := "/api/debug/stage/" + string(stage) + "?marker=01j9abcdefghjkmnpqrstvwxyz"
		if w := call(t, api.HandleStage, http.MethodGet, path, ""); w.Code != http.StatusBadRequest {
			t.Errorf("stage %s got %d, want 400 (the API has no docker socket — claiming it would be fabricated)", stage, w.Code)
		}
	}
	// parser and ui ARE answerable: the API holds the Go collectors' decision
	// lines and can run the SPA's own query. They are answered on demand and
	// never polled by the follow.
	for _, stage := range []Stage{StageParser, StageUI} {
		path := "/api/debug/stage/" + string(stage) + "?marker=01j9abcdefghjkmnpqrstvwxyz"
		if w := call(t, api.HandleStage, http.MethodGet, path, ""); w.Code != http.StatusOK {
			t.Errorf("stage %s got %d, want 200", stage, w.Code)
		}
	}
}

func TestStageRouteValidatesStageAndMarker(t *testing.T) {
	api := New(newFakeBackend().deps())
	bad := []string{
		"/api/debug/stage/../../etc?marker=01j9abcdefghjkmnpqrstvwxyz",
		"/api/debug/stage/opensearch?marker=short",
		"/api/debug/stage/opensearch",
		"/api/debug/stage/opensearch?marker=01j9abcdefghjkmnpqrstvwxyz&kind=netconf",
		"/api/debug/stage/ingress?marker=01j9abcdefghjkmnpqrstvwxyz",
	}
	for _, path := range bad {
		if w := call(t, api.HandleStage, http.MethodGet, path, ""); w.Code != http.StatusBadRequest {
			t.Errorf("%s got %d, want 400", path, w.Code)
		}
	}
}
