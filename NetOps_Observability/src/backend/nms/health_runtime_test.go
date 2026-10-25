// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

// fakeAuth logs in with a GET to base+"/login": a non-200 answer is an
// HTTPStatusError, exactly like the real providers.
type fakeAuth struct{}

func (fakeAuth) Authenticate(ctx context.Context, base string, _ Credentials, do Doer) (Session, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/login", nil)
	if err != nil {
		return Session{}, err
	}
	resp, err := do.Do(req)
	if err != nil {
		return Session{}, err
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		return Session{}, &HTTPStatusError{Op: "fake auth", Code: resp.StatusCode}
	}
	return Session{Header: http.Header{"X-Fake": {"1"}}}, nil
}

// registerFake installs a test connector whose streams GET /<stream>.
func registerFake(rt *Runtime, vendor string, rate float64, streams ...string) {
	paths := map[string]string{}
	for _, s := range streams {
		paths[s] = "/" + s
	}
	rt.reg.connectors[vendor] = connector{
		spec:   ConnectorSpec{Vendor: vendor, Product: vendor, SourceSystem: vendor, Poll: true, Streams: streams, RatePerSec: rate},
		auth:   fakeAuth{}, poller: restPoller{paths: paths}, transformer: GenericTransformer{},
	}
}

// ctrl is a scripted controller: per-path status, a login status, a
// blackhole switch, and a hit counter.
type ctrl struct {
	mu        sync.Mutex
	status    map[string]int // path → status (default 200 "[]")
	login     int            // login status (default 200)
	blackhole map[string]bool
	hits      atomic.Int64
	logins    atomic.Int64
}

func newCtrl() *ctrl { return &ctrl{status: map[string]int{}, blackhole: map[string]bool{}} }

func (c *ctrl) set(path string, code int) { c.mu.Lock(); c.status[path] = code; c.mu.Unlock() }
func (c *ctrl) setLogin(code int)         { c.mu.Lock(); c.login = code; c.mu.Unlock() }

func (c *ctrl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.hits.Add(1)
	c.mu.Lock()
	code, hole, login := c.status[r.URL.Path], c.blackhole[r.URL.Path], c.login
	c.mu.Unlock()
	if r.URL.Path == "/login" {
		c.logins.Add(1)
		if login != 0 && login != http.StatusOK {
			w.WriteHeader(login)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if hole {
		<-r.Context().Done() // accept, never answer
		return
	}
	if code != 0 && code != http.StatusOK {
		w.WriteHeader(code)
		return
	}
	_, _ = w.Write([]byte("[]")) // test server: a write failure fails the poll, which the test would see
}

func okSinks() Sinks {
	return Sinks{
		EmitMetrics:   func(context.Context, []string) error { return nil },
		ProduceEvents: func(_ context.Context, _ string, evs []ControllerEvent) (int64, error) { return int64(len(evs)), nil },
	}
}

func addIntegration(t *testing.T, m *memStore, tenant, id, vendor, base string, intervalS int) Integration {
	t.Helper()
	ic := Integration{Tenant: tenant, ID: id, Vendor: vendor, Product: vendor, DisplayName: id, BaseURL: base, Enabled: true, PollIntervalS: intervalS}
	if err := m.Upsert(context.Background(), ic); err != nil {
		t.Fatal(err)
	}
	return ic
}

func metricsText(rt *Runtime) string {
	var b bytes.Buffer
	rt.WriteMetrics(&b)
	return b.String()
}

// sample returns the value of the one series whose name and labels contain
// every needle, or "" if there is none.
func sample(t *testing.T, text, name string, needles ...string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, name+"{") {
			continue
		}
		hit := true
		for _, n := range needles {
			if !strings.Contains(line, n) {
				hit = false
			}
		}
		if hit {
			return line[strings.LastIndexByte(line, ' ')+1:]
		}
	}
	return ""
}

// ── per-stream status (F10) ──────────────────────────────────────────────────

func TestPollRecordsPerStreamStatusAndPartial(t *testing.T) {
	c := newCtrl()
	srv := httptest.NewServer(c)
	defer srv.Close()
	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	registerFake(rt, "fake", 0, "a", "b", "c")
	ic := addIntegration(t, m, "t-a", "i-1", "fake", srv.URL, 60)
	ctx := context.Background()

	c.set("/b", http.StatusNotFound)
	rec := rt.PollIntegration(ctx, ic)
	if rec.Status != RunStatusPartial {
		t.Fatalf("one stream of three failing: status %q, want partial (%s)", rec.Status, rec.Error)
	}
	if len(rec.Streams) != 3 || rec.Streams[0].Stream != "a" || rec.Streams[1].Stream != "b" || rec.Streams[2].Stream != "c" {
		t.Fatalf("streams not reported in configured order: %+v", rec.Streams)
	}
	if rec.Streams[0].Status != ResultOK || rec.Streams[0].Payloads != 1 || rec.Streams[2].Status != ResultOK {
		t.Fatalf("healthy streams misreported: %+v", rec.Streams)
	}
	if b := rec.Streams[1]; b.Status != ResultError || !strings.Contains(b.Error, "status 404") {
		t.Fatalf("failed stream misreported: %+v", b)
	}
	if !strings.Contains(rec.Error, "b: poll b: status 404") {
		t.Fatalf("run error does not name the failing stream: %q", rec.Error)
	}
	h, _, _ := m.Health(ctx, "t-a", false, "i-1")
	if h.Healthy || h.ErrorRate != 1 {
		t.Fatalf("partial must mark unhealthy and count as an error: healthy=%v rate=%v", h.Healthy, h.ErrorRate)
	}
	if len(h.Runs) != 1 || len(h.Runs[0].Streams) != 3 {
		t.Fatalf("run history lost the per-stream detail: %+v", h.Runs)
	}
	text := metricsText(rt)
	if v := sample(t, text, "netops_nms_last_success_timestamp_seconds", `integration_id="i-1"`); v == "0" || v == "" {
		t.Fatalf("a partial run that delivered must advance last_success; got %q", v)
	}
	if v := sample(t, text, "netops_nms_poll_runs_total", `stream="b"`, `result="error"`); v != "1" {
		t.Fatalf("stream b error count = %q, want 1", v)
	}

	c.set("/b", http.StatusOK)
	if rec = rt.PollIntegration(ctx, ic); rec.Status != RunStatusOK || rec.Error != "" {
		t.Fatalf("all streams healthy: %q %q", rec.Status, rec.Error)
	}
	h, _, _ = m.Health(ctx, "t-a", false, "i-1")
	if !h.Healthy || h.ErrorRate != 0.5 {
		t.Fatalf("after one ok run: healthy=%v rate=%v (want true, 0.5)", h.Healthy, h.ErrorRate)
	}

	for _, p := range []string{"/a", "/b", "/c"} {
		c.set(p, http.StatusNotFound)
	}
	if rec = rt.PollIntegration(ctx, ic); rec.Status != RunStatusError {
		t.Fatalf("no stream delivering: status %q, want error", rec.Status)
	}
	if v := sample(t, metricsText(rt), "netops_nms_consecutive_failures", `integration_id="i-1"`); v != "1" {
		t.Fatalf("consecutive_failures = %q, want 1", v)
	}
}

// A sink that refuses a run's output marks the run (never "ok") and counts
// the lane; a refused event lane is not a delivery.
func TestSinkFailureMarksRunAndCountsLane(t *testing.T) {
	// The generic connector's events stream answers one event, so the event
	// lane is exercised.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"event_id":"e1","severity":"major","event_type":"x","message":"x","device_id":"d1","event_time":"2026-10-25T12:00:00Z"}]`)) // test server
	}))
	defer srv.Close()
	m := NewMemStore()
	sinks := okSinks()
	sinks.ProduceEvents = func(context.Context, string, []ControllerEvent) (int64, error) {
		return 0, errors.New("bus down")
	}
	rt := NewRuntime(m, sinks, 0)
	ic := addIntegration(t, m, "t-a", "g-1", "generic", srv.URL, 60)
	rec := rt.PollIntegration(context.Background(), ic)
	if rec.Status != RunStatusPartial || !strings.Contains(rec.Error, "sink events: bus down") {
		t.Fatalf("refused event lane: status %q error %q; want partial naming the lane", rec.Status, rec.Error)
	}
	text := metricsText(rt)
	if v := sample(t, text, "netops_nms_sink_failures_total", `integration_id="g-1"`, `lane="events"`); v != "1" {
		t.Fatalf("events sink failure count = %q, want 1", v)
	}
	if v := sample(t, text, "netops_nms_ever_succeeded", `integration_id="g-1"`); v != "0" {
		t.Fatalf("a run whose events were refused is not a delivery: ever_succeeded=%q", v)
	}
}

// ── breaker in the runtime ───────────────────────────────────────────────────

func TestBreakerOpensOnAuthFailureAndStopsCalls(t *testing.T) {
	c := newCtrl()
	srv := httptest.NewServer(c)
	defer srv.Close()
	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	clk := newFakeClock()
	rt.now, rt.jitter = clk.Now, func() float64 { return 0.5 }
	registerFake(rt, "fake", 0, "a")
	ic := addIntegration(t, m, "t-a", "i-1", "fake", srv.URL, 60)
	ctx := context.Background()

	c.setLogin(http.StatusUnauthorized)
	for i := 0; i < breakerTripAfter; i++ {
		rec := rt.pollClaimed(ctx, ic, false)
		if rec.Status != RunStatusError || rec.Streams[0].Status != ResultAuthFailed {
			t.Fatalf("cycle %d: %+v", i, rec)
		}
		if i < breakerTripAfter-1 {
			clk.Advance(time.Minute)
		}
	}
	if got := c.logins.Load(); got != breakerTripAfter {
		t.Fatalf("logins before open = %d, want %d (401 is never retried)", got, breakerTripAfter)
	}
	text := metricsText(rt)
	if v := sample(t, text, "netops_nms_circuit_open", `integration_id="i-1"`); v != "1" {
		t.Fatalf("circuit_open = %q after %d auth failures", v, breakerTripAfter)
	}
	if v := sample(t, text, "netops_nms_auth_failures_total", `integration_id="i-1"`); v != "3" {
		t.Fatalf("auth_failures_total = %q, want 3", v)
	}

	// Open: the cycle makes NO network call and is recorded circuit_open.
	hits := c.hits.Load()
	clk.Advance(10 * time.Second) // inside the 0.5 × 60s cooldown
	rec := rt.pollClaimed(ctx, ic, false)
	if c.hits.Load() != hits {
		t.Fatal("an open breaker called the controller")
	}
	if rec.Status != RunStatusError || rec.Streams[0].Status != ResultCircuitOpen {
		t.Fatalf("open cycle: %+v", rec)
	}

	// Past the cooldown: ONE login probe, which fails again → re-open.
	clk.Advance(time.Minute)
	rt.pollClaimed(ctx, ic, false)
	if got := c.hits.Load() - hits; got != 1 {
		t.Fatalf("half-open probe made %d calls, want exactly one login", got)
	}

	// The operator fixes the password and presses "Poll now": the manual
	// poll is the probe (no cooldown wait), and the cycle then polls.
	c.setLogin(http.StatusOK)
	rec = rt.PollIntegration(ctx, ic)
	if rec.Status != RunStatusOK {
		t.Fatalf("manual poll after the fix: %+v", rec)
	}
	if v := sample(t, metricsText(rt), "netops_nms_circuit_open", `integration_id="i-1"`); v != "0" {
		t.Fatalf("circuit_open = %q after a good probe", v)
	}
}

// Unreachable / timeout / 5xx trip the breaker; a 404 does not.
func TestBreakerTripClassesFromStreams(t *testing.T) {
	c := newCtrl()
	srv := httptest.NewServer(c)
	defer srv.Close()
	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	registerFake(rt, "fake", 0, "a")
	ic := addIntegration(t, m, "t-a", "i-1", "fake", srv.URL, 60)
	key := Key("t-a", "i-1")

	c.set("/a", http.StatusNotFound)
	for i := 0; i < 4; i++ {
		rt.pollClaimed(context.Background(), ic, false)
	}
	if st := rt.breaker(key, time.Minute).State(); st != BreakerClosed {
		t.Fatalf("404s opened the breaker (%v): a config error is not a dead controller", st)
	}

	// 5xx: the retry policy would back off for seconds; use a no-retry
	// classification check instead of waiting it out.
	if r, trip := classifyPollError(&HTTPStatusError{Op: "poll a", Code: 503}); r != ResultError || !trip {
		t.Fatalf("503: %q trip=%v", r, trip)
	}
	// Unreachable: a closed port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + ln.Addr().String()
	_ = ln.Close() // the port is now closed: connections are refused
	ic.BaseURL = dead
	for i := 0; i < breakerTripAfter; i++ {
		rec := rt.pollClaimed(context.Background(), ic, false)
		if rec.Streams[0].Status != ResultUnreachable {
			t.Fatalf("refused connection classified %q (%s)", rec.Streams[0].Status, rec.Streams[0].Error)
		}
	}
	if st := rt.breaker(key, time.Minute).State(); st != BreakerOpen {
		t.Fatalf("3 unreachable cycles left the breaker %v", st)
	}
}

func TestClassifyPollError(t *testing.T) {
	urlErr := &url.Error{Op: "Get", URL: "https://x", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}
	cases := []struct {
		err   error
		want  string
		tripe bool
	}{
		{nil, ResultOK, false},
		{context.DeadlineExceeded, ResultTimeout, true},
		{fmt.Errorf("%w: %w", ErrAuthFailed, context.DeadlineExceeded), ResultTimeout, true},
		{urlErr, ResultUnreachable, true},
		{fmt.Errorf("%w: %w", ErrAuthFailed, urlErr), ResultUnreachable, true},
		{&net.DNSError{Err: "no such host", Name: "ctl"}, ResultUnreachable, true},
		{&HTTPStatusError{Op: "poll x", Code: 500}, ResultError, true},
		{fmt.Errorf("%w: %w", ErrAuthFailed, &HTTPStatusError{Op: "vmanage auth", Code: 502}), ResultError, true},
		{fmt.Errorf("%w: %w", ErrAuthFailed, &HTTPStatusError{Op: "vmanage auth", Code: 401}), ResultAuthFailed, true},
		{ErrUnauthorized, ResultAuthFailed, true},
		{&HTTPStatusError{Op: "poll x", Code: 404}, ResultError, false},
		{context.Canceled, ResultError, false},
		{errors.New("transform: bad json"), ResultError, false},
	}
	for _, tc := range cases {
		got, trip := classifyPollError(tc.err)
		if got != tc.want || trip != tc.tripe {
			t.Errorf("classify(%v) = %q,%v; want %q,%v", tc.err, got, trip, tc.want, tc.tripe)
		}
	}
	for _, r := range []string{ResultOK, ResultError, ResultAuthFailed, ResultUnreachable, ResultTimeout, ResultCircuitOpen, ResultSkippedDeadline} {
		found := false
		for _, x := range PollResults() {
			found = found || x == r
		}
		if !found {
			t.Errorf("result %q missing from the closed set", r)
		}
	}
}

// ── persistent rate buckets ──────────────────────────────────────────────────

func TestRateBucketPersistsAcrossCycles(t *testing.T) {
	c := newCtrl()
	srv := httptest.NewServer(c)
	defer srv.Close()
	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	registerFake(rt, "fake", 1000, "a")
	ic := addIntegration(t, m, "t-a", "i-1", "fake", srv.URL, 60)
	key := Key("t-a", "i-1")

	rt.PollIntegration(context.Background(), ic)
	first := rt.buckets[key]
	if first == nil || first.rate != 1000 {
		t.Fatalf("no persistent bucket after a cycle: %+v", first)
	}
	rt.PollIntegration(context.Background(), ic)
	if rt.buckets[key] != first {
		t.Fatal("the bucket was rebuilt on the next cycle — the limit never carries over")
	}
	// The bucket is the one the cycle used: its tokens were spent.
	first.b.mu.Lock()
	spent := first.b.tokens < first.b.capacity
	first.b.mu.Unlock()
	if !spent {
		t.Fatal("the persistent bucket was not the one the cycle drew from")
	}
	// A rate change rebuilds it.
	registerFake(rt, "fake", 5, "a")
	rt.PollIntegration(context.Background(), ic)
	if rt.buckets[key] == first || rt.buckets[key].rate != 5 {
		t.Fatal("a changed rate did not rebuild the bucket")
	}
	// Two integrations never share one.
	if rt.bucket(Key("t-b", "i-1"), 5) == rt.buckets[key].b {
		t.Fatal("two tenants' integrations share one rate bucket")
	}
}

func TestVendorRateDefaultsAreSet(t *testing.T) {
	for _, v := range []string{"vmanage", "catalyst_center", "ndfc", "versa_director", "versa_concerto"} {
		if r := Specs()[v].RatePerSec; r <= 0 {
			t.Errorf("%s has no rate limit (RatePerSec=%v) — an unbounded poller against a controller", v, r)
		}
	}
}

// ── worker pool, deadline, inFlight ──────────────────────────────────────────

// A hung controller is cut off by its deadline and does not delay another
// tenant's poll: both run in parallel; the healthy one finishes promptly.
func TestPoolHungControllerDoesNotDelayOtherTenant(t *testing.T) {
	hung := newCtrl()
	hung.blackhole["/a"] = true
	hsrv := httptest.NewServer(hung)
	defer hsrv.Close()
	good := newCtrl()
	gsrv := httptest.NewServer(good)
	defer gsrv.Close()

	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	rt.SetPoolOptions(2, time.Second)
	registerFake(rt, "fake", 0, "a", "b")
	addIntegration(t, m, "t-a", "hung", "fake", hsrv.URL, 60)
	addIntegration(t, m, "t-b", "good", "fake", gsrv.URL, 60)

	start := time.Now()
	rt.tickOnce(context.Background())
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("one tick took %v — the hung controller was not cut off by its deadline", elapsed)
	}
	hh, _, _ := m.Health(context.Background(), "t-a", false, "hung")
	gh, _, _ := m.Health(context.Background(), "t-b", false, "good")
	if len(hh.Runs) != 1 || len(gh.Runs) != 1 {
		t.Fatalf("both integrations must have run once: hung=%d good=%d", len(hh.Runs), len(gh.Runs))
	}
	hr, gr := hh.Runs[0], gh.Runs[0]
	if gr.Status != RunStatusOK {
		t.Fatalf("healthy tenant: %+v", gr)
	}
	if d := gr.Finished.Sub(gr.Started); d > 800*time.Millisecond { // below the hung cycle's 1 s deadline
		t.Fatalf("the healthy tenant's cycle took %v — it waited behind the hung one", d)
	}
	if !gr.Finished.Before(hr.Finished) {
		t.Fatal("the healthy tenant finished after the hung one: the pool did not run them in parallel")
	}
	if hr.Status != RunStatusError || hr.Streams[0].Status != ResultTimeout || hr.Streams[1].Status != ResultSkippedDeadline {
		t.Fatalf("hung controller: want a=timeout b=skipped_deadline, got %+v", hr.Streams)
	}
	if hung.hits.Load() != 2 { // login + /a; /b never called
		t.Fatalf("hung controller saw %d calls; the deadline must stop the cycle before stream b", hung.hits.Load())
	}
	text := metricsText(rt)
	if v := sample(t, text, "netops_nms_poll_runs_total", `integration_id="hung"`, `stream="b"`, `result="skipped_deadline"`); v != "1" {
		t.Fatalf("skipped_deadline not counted: %q", v)
	}
}

// The pool runs NMS_POLL_WORKERS cycles at once — measured, not assumed.
func TestPoolRunsWorkersInParallel(t *testing.T) {
	var cur, peak atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			return
		}
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		cur.Add(-1)
		_, _ = w.Write([]byte("[]")) // test server
	}))
	defer srv.Close()
	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	rt.SetPoolOptions(3, 5*time.Second)
	registerFake(rt, "fake", 0, "a")
	for i := 0; i < 5; i++ {
		addIntegration(t, m, fmt.Sprintf("t-%d", i), "i", "fake", srv.URL, 60)
	}
	done := make(chan struct{})
	go func() { rt.tickOnce(context.Background()); close(done) }()
	deadline := time.After(5 * time.Second)
	for peak.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("peak concurrency %d, want 3", peak.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(release)
	<-done
	if p := peak.Load(); p != 3 {
		t.Fatalf("peak concurrency %d exceeded the pool size 3", p)
	}
}

func TestClampPollWorkers(t *testing.T) {
	for in, want := range map[int]int{-1: 4, 0: 4, 1: 1, 4: 4, 16: 16, 17: 16, 1000: 16} {
		if got := ClampPollWorkers(in); got != want {
			t.Errorf("ClampPollWorkers(%d) = %d, want %d", in, got, want)
		}
	}
	rt := NewRuntime(NewMemStore(), Sinks{}, 0)
	rt.SetPoolOptions(0, 0)
	if rt.workers != DefaultPollWorkers || rt.deadline != DefaultPollDeadline {
		t.Fatalf("defaults: workers=%d deadline=%v", rt.workers, rt.deadline)
	}
	if d := rt.deadlineFor(30 * time.Second); d != 30*time.Second {
		t.Fatalf("deadline must be min(interval, cap): %v", d)
	}
	if d := rt.deadlineFor(10 * time.Minute); d != DefaultPollDeadline {
		t.Fatalf("deadline must be min(interval, cap): %v", d)
	}
}

func TestInFlightGuard(t *testing.T) {
	c := newCtrl()
	srv := httptest.NewServer(c)
	defer srv.Close()
	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	registerFake(rt, "fake", 0, "a")
	ic := addIntegration(t, m, "t-a", "i-1", "fake", srv.URL, 60)
	key := Key("t-a", "i-1")

	if !rt.claim(key) {
		t.Fatal("first claim refused")
	}
	rec := rt.PollIntegration(context.Background(), ic)
	if rec.Status != RunStatusBusy {
		t.Fatalf("Poll now during a running cycle: %q, want busy", rec.Status)
	}
	rt.tickOnce(context.Background())
	if c.hits.Load() != 0 {
		t.Fatal("the scheduler started a second cycle of an integration already running")
	}
	if h, _, _ := m.Health(context.Background(), "t-a", false, "i-1"); len(h.Runs) != 0 {
		t.Fatal("a busy answer was recorded as a run")
	}
	rt.release(key)
	rt.tickOnce(context.Background())
	if c.hits.Load() == 0 {
		t.Fatal("released integration never polled")
	}
	if rt.isInFlight(key) {
		t.Fatal("the worker did not release its claim")
	}
}

func TestDispatchOrderInterleavesTenants(t *testing.T) {
	rt := NewRuntime(NewMemStore(), Sinks{}, 0)
	ints := []Integration{
		{Tenant: "a", ID: "1"}, {Tenant: "a", ID: "2"}, {Tenant: "a", ID: "3"},
		{Tenant: "b", ID: "1"}, {Tenant: "c", ID: "1"},
	}
	got := rt.dispatchOrder(ints)
	var seq []string
	for _, ic := range got {
		seq = append(seq, ic.Tenant+ic.ID)
	}
	if strings.Join(seq, ",") != "a1,b1,c1,a2,a3" {
		t.Fatalf("order %v: tenants must interleave", seq)
	}
	got = rt.dispatchOrder(ints) // next tick: rotation starts at b
	if got[0].Tenant != "b" {
		t.Fatalf("tenant order did not rotate: first %q", got[0].Tenant)
	}
}

// ── exposition ───────────────────────────────────────────────────────────────

const healthGolden = `# HELP netops_nms_poll_runs_total NMS poll stream outcomes per cycle, by stream and result.
# TYPE netops_nms_poll_runs_total counter
netops_nms_poll_runs_total{tenant_id="t1",integration_id="i1",vendor="vmanage",stream="alarms",result="ok"} 0
netops_nms_poll_runs_total{tenant_id="t1",integration_id="i1",vendor="vmanage",stream="alarms",result="error"} 0
netops_nms_poll_runs_total{tenant_id="t1",integration_id="i1",vendor="vmanage",stream="alarms",result="auth_failed"} 0
netops_nms_poll_runs_total{tenant_id="t1",integration_id="i1",vendor="vmanage",stream="alarms",result="unreachable"} 0
netops_nms_poll_runs_total{tenant_id="t1",integration_id="i1",vendor="vmanage",stream="alarms",result="timeout"} 0
netops_nms_poll_runs_total{tenant_id="t1",integration_id="i1",vendor="vmanage",stream="alarms",result="circuit_open"} 0
netops_nms_poll_runs_total{tenant_id="t1",integration_id="i1",vendor="vmanage",stream="alarms",result="skipped_deadline"} 0
# HELP netops_nms_last_success_timestamp_seconds Unix time of the integration's last cycle that delivered data (0 = never).
# TYPE netops_nms_last_success_timestamp_seconds gauge
netops_nms_last_success_timestamp_seconds{tenant_id="t1",integration_id="i1",vendor="vmanage"} 0
# HELP netops_nms_poll_duration_seconds Wall time of the integration's last poll cycle.
# TYPE netops_nms_poll_duration_seconds gauge
netops_nms_poll_duration_seconds{tenant_id="t1",integration_id="i1",vendor="vmanage"} 0
# HELP netops_nms_poll_interval_seconds The integration's configured poll interval (after the floor).
# TYPE netops_nms_poll_interval_seconds gauge
netops_nms_poll_interval_seconds{tenant_id="t1",integration_id="i1",vendor="vmanage"} 120
# HELP netops_nms_ever_succeeded 1 once the integration has delivered data at least once (seeded from connector_health across api restarts).
# TYPE netops_nms_ever_succeeded gauge
netops_nms_ever_succeeded{tenant_id="t1",integration_id="i1",vendor="vmanage"} 0
# HELP netops_nms_consecutive_failures Poll cycles in a row that delivered nothing.
# TYPE netops_nms_consecutive_failures gauge
netops_nms_consecutive_failures{tenant_id="t1",integration_id="i1",vendor="vmanage"} 0
# HELP netops_nms_circuit_open 1 while the integration's circuit breaker is open or half-open (polling suspended).
# TYPE netops_nms_circuit_open gauge
netops_nms_circuit_open{tenant_id="t1",integration_id="i1",vendor="vmanage"} 0
# HELP netops_nms_devices_reported Devices in the integration's last complete inventory snapshot.
# TYPE netops_nms_devices_reported gauge
netops_nms_devices_reported{tenant_id="t1",integration_id="i1",vendor="vmanage"} 0
# HELP netops_nms_devices_unreachable Devices the controller reported unreachable in its last complete inventory snapshot.
# TYPE netops_nms_devices_unreachable gauge
netops_nms_devices_unreachable{tenant_id="t1",integration_id="i1",vendor="vmanage"} 0
# HELP netops_nms_auth_failures_total Poll cycles whose controller login failed.
# TYPE netops_nms_auth_failures_total counter
netops_nms_auth_failures_total{tenant_id="t1",integration_id="i1",vendor="vmanage"} 0
# HELP netops_nms_sink_failures_total NMS output a sink refused, by lane.
# TYPE netops_nms_sink_failures_total counter
netops_nms_sink_failures_total{tenant_id="t1",integration_id="i1",vendor="vmanage",lane="metrics"} 0
netops_nms_sink_failures_total{tenant_id="t1",integration_id="i1",vendor="vmanage",lane="events"} 0
netops_nms_sink_failures_total{tenant_id="t1",integration_id="i1",vendor="vmanage",lane="states"} 0
netops_nms_sink_failures_total{tenant_id="t1",integration_id="i1",vendor="vmanage",lane="devices"} 0
netops_nms_sink_failures_total{tenant_id="t1",integration_id="i1",vendor="vmanage",lane="wireless"} 0
# HELP netops_nms_integrations_enabled Enabled NMS integrations, by vendor.
# TYPE netops_nms_integrations_enabled gauge
netops_nms_integrations_enabled{vendor="generic"} 0
netops_nms_integrations_enabled{vendor="vmanage"} 1
`

func TestHealthExpositionGolden(t *testing.T) {
	h := NewHealthMetrics([]string{"vmanage", "generic"})
	h.Sync([]enabledIntegration{{Tenant: "t1", ID: "i1", Vendor: "vmanage", Interval: 2 * time.Minute, Streams: []string{"alarms"}}})
	var b bytes.Buffer
	h.WriteMetrics(&b)
	if b.String() != healthGolden {
		t.Fatalf("exposition drifted from the golden:\n--- got ---\n%s--- want ---\n%s", b.String(), healthGolden)
	}
}

// Every NMS health series carries ONLY the allowed label keys. In particular
// never device/hostname/source (the tenant metrics scope matches on those) and
// never anything operator-typed.
func TestHealthExpositionLabelKeysAreClosed(t *testing.T) {
	c := newCtrl()
	srv := httptest.NewServer(c)
	defer srv.Close()
	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	registerFake(rt, "fake", 0, "a")
	ic := addIntegration(t, m, `t"evil`, "i\n1", "fake", srv.URL, 60)
	ic.DisplayName, ic.BaseURL = "Secret Name", srv.URL
	rt.PollIntegration(context.Background(), ic)
	rt.tickOnce(context.Background())
	text := metricsText(rt)

	allowed := map[string]bool{"tenant_id": true, "integration_id": true, "vendor": true, "stream": true, "result": true, "lane": true}
	labelKey := regexp.MustCompile(`([a-z_]+)="(?:[^"\\]|\\.)*"`)
	types := 0
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if strings.HasPrefix(line, "# TYPE ") {
			types++
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		open, closeIdx := strings.IndexByte(line, '{'), strings.LastIndexByte(line, '}')
		if open < 0 || closeIdx < open {
			t.Fatalf("series without labels: %q", line)
		}
		for _, mm := range labelKey.FindAllStringSubmatch(line[open+1:closeIdx], -1) {
			if !allowed[mm[1]] {
				t.Errorf("forbidden label key %q in %q", mm[1], line)
			}
		}
		if strings.Contains(line, "Secret Name") || strings.Contains(line, srv.URL) {
			t.Errorf("operator-typed text leaked into a label: %q", line)
		}
	}
	if types != 12 {
		t.Fatalf("%d TYPE lines, want 12 (one per series family)", types)
	}
	if strings.Contains(text, "i\n1") || !strings.Contains(text, `tenant_id="t\"evil"`) {
		t.Fatalf("label values not escaped:\n%s", text)
	}
}

// ── pruning + restart seed ───────────────────────────────────────────────────

func TestDisabledIntegrationIsPrunedEverywhere(t *testing.T) {
	c := newCtrl()
	srv := httptest.NewServer(c)
	defer srv.Close()
	m := NewMemStore()
	rt := NewRuntime(m, okSinks(), 0)
	registerFake(rt, "fake", 10, "a")
	keep := addIntegration(t, m, "t-a", "keep", "fake", srv.URL, 60)
	gone := addIntegration(t, m, "t-b", "gone", "fake", srv.URL, 60)
	_ = keep
	rt.tickOnce(context.Background())
	gk := Key("t-b", "gone")
	rt.mu.Lock()
	present := rt.pipes[gk] != nil && rt.buckets[gk] != nil && rt.breakers[gk] != nil && !rt.lastRun[gk].IsZero()
	rt.mu.Unlock()
	if !present || !strings.Contains(metricsText(rt), `integration_id="gone"`) {
		t.Fatal("precondition: the integration's state was never built")
	}

	gone.Enabled = false
	if err := m.Upsert(context.Background(), gone); err != nil {
		t.Fatal(err)
	}
	rt.tickOnce(context.Background())
	rt.mu.Lock()
	_, p := rt.pipes[gk]
	_, l := rt.lastRun[gk]
	_, s := rt.sessions[gk]
	_, b := rt.buckets[gk]
	_, br := rt.breakers[gk]
	rt.mu.Unlock()
	if p || l || s || b || br {
		t.Fatalf("disabled integration left scheduler state: pipes=%v lastRun=%v sessions=%v buckets=%v breakers=%v", p, l, s, b, br)
	}
	text := metricsText(rt)
	if strings.Contains(text, `integration_id="gone"`) {
		t.Fatal("a disabled integration's series are still exported (they must go absent, not freeze)")
	}
	if !strings.Contains(text, `integration_id="keep"`) {
		t.Fatal("pruning removed an enabled integration")
	}
}

// An api restart must not reset ever_succeeded: it is seeded from the store.
func TestHealthSeededFromStoreAfterRestart(t *testing.T) {
	m := NewMemStore()
	ic := addIntegration(t, m, "t-a", "i-1", "fake", "http://unused", 60)
	fin := time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)
	if err := m.RecordRun(context.Background(), RunRecord{Tenant: ic.Tenant, IntegrationID: ic.ID, RunID: "r1", Started: fin, Finished: fin, Status: RunStatusOK}); err != nil {
		t.Fatal(err)
	}
	rt := NewRuntime(m, okSinks(), 0) // the "restarted" api
	rt.syncEnabled(context.Background(), []Integration{ic})
	text := metricsText(rt)
	if v := sample(t, text, "netops_nms_ever_succeeded", `integration_id="i-1"`); v != "1" {
		t.Fatalf("ever_succeeded after restart = %q, want 1", v)
	}
	if v := sample(t, text, "netops_nms_last_success_timestamp_seconds", `integration_id="i-1"`); v != fmt.Sprint(fin.Unix()) {
		t.Fatalf("last_success after restart = %q, want %d", v, fin.Unix())
	}
}

// ── store round-trip ─────────────────────────────────────────────────────────

func TestMemStoreRunStreamsRoundTrip(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	addIntegration(t, m, "t-a", "i-1", "vmanage", "https://x", 60)
	addIntegration(t, m, "t-b", "i-1", "vmanage", "https://y", 60) // same id, other tenant
	streams := []StreamResult{
		{Stream: "alarms", Status: ResultOK, Payloads: 2, DurationMS: 12},
		{Stream: "bfd", Status: ResultTimeout, Error: "context deadline exceeded", DurationMS: 120000},
	}
	now := time.Now().UTC()
	if err := m.RecordRun(ctx, RunRecord{Tenant: "t-a", IntegrationID: "i-1", RunID: "r1", Started: now, Finished: now, Status: RunStatusPartial, Streams: streams}); err != nil {
		t.Fatal(err)
	}
	h, ok, err := m.Health(ctx, "t-a", false, "i-1")
	if err != nil || !ok || len(h.Runs) != 1 {
		t.Fatalf("health: %v %v %+v", ok, err, h)
	}
	if fmt.Sprint(h.Runs[0].Streams) != fmt.Sprint(streams) {
		t.Fatalf("streams round-trip: %+v", h.Runs[0].Streams)
	}
	if h.Healthy || h.ErrorRate != 1 {
		t.Fatalf("partial run: healthy=%v rate=%v", h.Healthy, h.ErrorRate)
	}
	if hb, _, _ := m.Health(ctx, "t-b", false, "i-1"); len(hb.Runs) != 0 {
		t.Fatal("CROSS-TENANT LEAK: tenant b read tenant a's run under the same integration id")
	}
	// JSON codec used by the Postgres store.
	enc, err := encodeRunStreams(streams)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decodeRunStreams([]byte(enc))
	if err != nil || fmt.Sprint(dec) != fmt.Sprint(streams) {
		t.Fatalf("codec round-trip: %v %+v", err, dec)
	}
	if e, _ := encodeRunStreams(nil); e != "[]" {
		t.Fatalf("empty streams encode to %q, want []", e)
	}
	if d, err := decodeRunStreams([]byte("[]")); err != nil || d != nil {
		t.Fatalf("pre-0064 default decodes to %v %v", d, err)
	}
}

func TestTransportRetryBound(t *testing.T) {
	r := DefaultRetry()
	if _, ok := r.Next(2, 0, 0); !ok {
		t.Fatal("second transport attempt must still retry")
	}
	if _, ok := r.Next(3, 0, 0); ok {
		t.Fatal("transport failures must stop after 3 attempts")
	}
	if _, ok := r.Next(3, 503, 0); !ok {
		t.Fatal("a 503 keeps the full 5-attempt budget")
	}
}
