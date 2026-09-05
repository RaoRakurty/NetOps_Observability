package collectors

// dem_test.go — the Digital Experience runner, per kind, with fakes. No real
// network, no real resolver, no key-value store.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/dem"
)

// demHarness captures what the runner would have pushed instead of pushing it.
type demHarness struct {
	runner  *demRunner
	metrics *httptest.Server
	events  *httptest.Server

	mu     sync.Mutex
	lines  []string
	pushed []ProbeEvent
}

func newDEMHarness(t *testing.T, work []dem.WireTarget) *demHarness {
	t.Helper()
	h := &demHarness{}
	h.metrics = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<16)
		n, _ := r.Body.Read(b)
		h.mu.Lock()
		h.lines = append(h.lines, strings.Split(strings.TrimSpace(string(b[:n])), "\n")...)
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(h.metrics.Close)
	h.events = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev ProbeEvent
		_ = json.NewDecoder(r.Body).Decode(&ev)
		h.mu.Lock()
		h.pushed = append(h.pushed, ev)
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(h.events.Close)
	t.Setenv("VICTORIA_URL", h.metrics.URL)
	t.Setenv("PROBE_EVENT_SINK_URL", h.events.URL)
	t.Setenv("PROBER_ID", "test-prober")

	r := NewDEM().(*demRunner)
	r.fetch = func(context.Context) ([]dem.WireTarget, error) { return work, nil }
	h.runner = r
	return h
}

func (h *demHarness) tick(t *testing.T) {
	t.Helper()
	h.runner.tick(context.Background())
}

func (h *demHarness) lineFor(metric, targetID string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, l := range h.lines {
		if strings.HasPrefix(l, metric+"{") && strings.Contains(l, `target="`+targetID+`"`) {
			return l, true
		}
	}
	return "", false
}

func (h *demHarness) event(targetID string) (ProbeEvent, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.pushed {
		if e.TargetID == targetID {
			return e, true
		}
	}
	return ProbeEvent{}, false
}

// ── the work queue is untrusted input ────────────────────────────────────────

func TestSanitizeWorkDropsUnusableEntries(t *testing.T) {
	in := []dem.WireTarget{
		{ID: "dem-1", Tenant: "acme", Kind: "icmp", Host: "10.0.0.1", IntervalSec: 60},
		{ID: "", Tenant: "acme", Kind: "icmp", Host: "10.0.0.2"},        // no id
		{ID: "dem-3", Tenant: "", Kind: "icmp", Host: "10.0.0.3"},       // no owner
		{ID: "dem-4", Tenant: "acme", Kind: "smtp", Host: "10.0.0.4"},   // unknown kind
		{ID: "dem-5", Tenant: "acme", Kind: "tunnel", Host: "10.0.0.5"}, // reserved kind
		{ID: "dem-6", Tenant: "acme", Kind: "icmp", Host: ""},           // no destination
		{ID: "dem-7", Tenant: "acme", Kind: "http", Host: "https://x/"}, // interval defaulted
	}
	out := sanitizeWork(in)
	if len(out) != 2 {
		t.Fatalf("sanitize kept %d entries: %+v", len(out), out)
	}
	if out[1].IntervalSec != dem.DefaultIntervalSec {
		t.Fatalf("interval not defaulted: %+v", out[1])
	}
}

// A queue we cannot READ is not an empty queue. Reporting zero healthy targets
// for an unreadable queue is the accept-and-ignore defect §10 exists to kill.
func TestUnreadableWorkQueueIsLoud(t *testing.T) {
	h := newDEMHarness(t, nil)
	h.runner.fetch = func(context.Context) ([]dem.WireTarget, error) { return nil, errors.New("kv down") }
	h.tick(t)
	st := h.runner.Status()
	if st.Healthy || !strings.Contains(st.LastError, "kv down") {
		t.Fatalf("status after an unreadable queue: %+v", st)
	}
}

// ── per-kind checks ──────────────────────────────────────────────────────────

func TestHTTPCheckMeasuresAndLabels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tgt := dem.WireTarget{ID: "dem-http", Tenant: "acme", Kind: dem.KindHTTP,
		Host: srv.URL + "/health", Site: "dc1", App: "portal", IntervalSec: 15}
	h := newDEMHarness(t, []dem.WireTarget{tgt})
	h.tick(t)

	line, ok := h.lineFor(dem.MetricSuccess, "dem-http")
	if !ok {
		t.Fatalf("no success sample; lines=%v", h.lines)
	}
	for _, want := range []string{`tenant="acme"`, `kind="http"`, `site="dc1"`, `app="portal"`, `source="synthetic"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("sample %q is missing %s", line, want)
		}
	}
	if !strings.HasSuffix(strings.Fields(line)[len(strings.Fields(line))-2], "1") {
		t.Fatalf("a 200 response did not record success: %q", line)
	}
	if _, ok := h.lineFor(dem.MetricLatencyMs, "dem-http"); !ok {
		t.Fatal("a successful check recorded no latency")
	}
	ev, ok := h.event("dem-http")
	if !ok {
		t.Fatal("no bus event")
	}
	if ev.Tenant != "acme" || ev.AppID != "portal" || ev.SiteID != "dc1" || ev.Source != dem.SourceSynthetic {
		t.Fatalf("event grounding: %+v", ev)
	}
	if ev.ScheduleID != "dem-http" {
		t.Fatalf("schedule id should be the catalogue id, got %q", ev.ScheduleID)
	}
}

// A DECLARED expected status overrides the default 2xx/3xx verdict: an endpoint
// that legitimately answers 503 is not "down" if the operator said so.
func TestHTTPExpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	for _, tc := range []struct {
		name   string
		expect int
		wantUp bool
	}{
		{"default verdict", 0, false},
		{"declared 503", 503, true},
		{"declared 200", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tgt := dem.WireTarget{ID: "dem-x", Tenant: "acme", Kind: dem.KindHTTP,
				Host: srv.URL, IntervalSec: 15, ExpectStatus: tc.expect}
			h := newDEMHarness(t, []dem.WireTarget{tgt})
			h.tick(t)
			line, ok := h.lineFor(dem.MetricSuccess, "dem-x")
			if !ok {
				t.Fatal("no success sample")
			}
			gotUp := strings.Fields(line)[1] == "1"
			if gotUp != tc.wantUp {
				t.Fatalf("up=%v want %v (%q)", gotUp, tc.wantUp, line)
			}
		})
	}
}

func TestTCPCheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p := 0
	_, _ = fmtSscan(port, &p)

	open := dem.WireTarget{ID: "dem-tcp", Tenant: "acme", Kind: dem.KindTCP, Host: host, Port: p, IntervalSec: 15}
	h := newDEMHarness(t, []dem.WireTarget{open})
	h.tick(t)
	line, ok := h.lineFor(dem.MetricSuccess, "dem-tcp")
	if !ok || strings.Fields(line)[1] != "1" {
		t.Fatalf("open port did not report success: %q %v", line, ok)
	}

	// A closed port is a FAILED check with full loss, not a missing sample.
	closed := dem.WireTarget{ID: "dem-tcp-closed", Tenant: "acme", Kind: dem.KindTCP,
		Host: "127.0.0.1", Port: 1, IntervalSec: 15}
	h2 := newDEMHarness(t, []dem.WireTarget{closed})
	h2.tick(t)
	line, ok = h2.lineFor(dem.MetricSuccess, "dem-tcp-closed")
	if !ok || strings.Fields(line)[1] != "0" {
		t.Fatalf("closed port: %q %v", line, ok)
	}
	loss, ok := h2.lineFor(dem.MetricLossPct, "dem-tcp-closed")
	if !ok || !strings.Contains(loss, "100.00") {
		t.Fatalf("a failed check must record full loss: %q", loss)
	}
	// …and NO latency: a failed check has no timing, and emitting a 0 would drag
	// every percentile down with a number nothing measured.
	if l, found := h2.lineFor(dem.MetricLatencyMs, "dem-tcp-closed"); found {
		t.Fatalf("a failed check emitted a latency sample: %q", l)
	}
}

// ── DNS ──────────────────────────────────────────────────────────────────────

type fakeResolver struct {
	addrs []string
	err   error
}

func (f fakeResolver) LookupHost(context.Context, string) ([]string, error) { return f.addrs, f.err }

func TestDNSCheck(t *testing.T) {
	cases := []struct {
		name      string
		res       fakeResolver
		wantUp    bool
		wantClass string
	}{
		{"resolves", fakeResolver{addrs: []string{"192.0.2.1"}}, true, ""},
		{"nxdomain", fakeResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}}, false, "nxdomain"},
		{"timeout", fakeResolver{err: &net.DNSError{Err: "timeout", IsTimeout: true}}, false, "timeout"},
		{"servfail", fakeResolver{err: &net.DNSError{Err: "server misbehaving"}}, false, "dns"},
		// A resolver that answers with NO addresses has not resolved the name.
		{"empty answer", fakeResolver{addrs: nil}, false, "no_answer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt := dem.WireTarget{ID: "dem-dns", Tenant: "acme", Kind: dem.KindDNS,
				Host: "www.example.com.", IntervalSec: 15}
			h := newDEMHarness(t, []dem.WireTarget{tgt})
			h.runner.resolver = c.res
			h.tick(t)
			line, ok := h.lineFor(dem.MetricSuccess, "dem-dns")
			if !ok {
				t.Fatal("no success sample")
			}
			gotUp := strings.Fields(line)[1] == "1"
			if gotUp != c.wantUp {
				t.Fatalf("up=%v want %v", gotUp, c.wantUp)
			}
			ev, _ := h.event("dem-dns")
			if ev.FailClass != c.wantClass {
				t.Fatalf("fail_class %q want %q", ev.FailClass, c.wantClass)
			}
			if c.wantUp && ev.DNSMs <= 0 {
				t.Fatal("a successful resolution recorded no timing")
			}
		})
	}
}

func TestDNSResolverPinning(t *testing.T) {
	if r := demSystemResolver("", time.Second); r != net.DefaultResolver {
		t.Fatal("an unpinned dns target should use the system resolver")
	}
	if r := demSystemResolver("10.0.0.53", time.Second); r == net.DefaultResolver {
		t.Fatal("a pinned resolver was ignored — 'our resolver is slow' would be unseparable from 'the internet is slow'")
	}
}

// ── scheduling, census, liveness ─────────────────────────────────────────────

func TestPerTargetIntervalIsHonoured(t *testing.T) {
	tgt := dem.WireTarget{ID: "dem-slow", Tenant: "acme", Kind: dem.KindTCP,
		Host: "127.0.0.1", Port: 1, IntervalSec: 3600}
	h := newDEMHarness(t, []dem.WireTarget{tgt})
	h.tick(t)
	first := len(h.pushed)
	if first != 1 {
		t.Fatalf("first tick produced %d events", first)
	}
	h.tick(t) // immediately again: nothing is due
	if len(h.pushed) != first {
		t.Fatalf("an hourly target ran twice in one scheduler resolution")
	}
}

// The census is what lets the page tell "this tenant declared nothing" apart
// from "the prober is not reporting" — two very different answers that both
// render as an empty table.
func TestCensusAndLivenessAreEmitted(t *testing.T) {
	work := []dem.WireTarget{
		{ID: "dem-a", Tenant: "acme", Kind: dem.KindTCP, Host: "127.0.0.1", Port: 1, IntervalSec: 15},
		{ID: "dem-b", Tenant: "globex", Kind: dem.KindTCP, Host: "127.0.0.1", Port: 1, IntervalSec: 15},
	}
	h := newDEMHarness(t, work)
	h.tick(t)
	h.mu.Lock()
	joined := strings.Join(h.lines, "\n")
	h.mu.Unlock()
	for _, want := range []string{
		dem.MetricTargets + `{tenant="acme",source="synthetic"} 1`,
		dem.MetricTargets + `{tenant="globex",source="synthetic"} 1`,
		`collector_up{collector="dem"} 1`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
}

// Path stability must be NOT MEASURED when no fresh traceroute exists. Rendering
// "stable" for a path we never looked at is a claim we did not earn.
// A latency budget nobody declared must publish NO gauge: a rule that fired
// against an invented threshold would be an alert about a number the operator
// never set.
func TestBudgetGaugesFollowWhatWasDeclared(t *testing.T) {
	declared := dem.WireTarget{ID: "dem-bud", Tenant: "acme", Kind: dem.KindTCP, Host: "127.0.0.1",
		Port: 1, IntervalSec: 15, AvailBudgetPct: 99.9, LatencyBudgetMs: 250}
	h := newDEMHarness(t, []dem.WireTarget{declared})
	h.tick(t)
	if _, ok := h.lineFor(dem.MetricAvailBudgetPct, "dem-bud"); !ok {
		t.Fatal("no availability-budget gauge")
	}
	if _, ok := h.lineFor(dem.MetricLatencyBudgetMs, "dem-bud"); !ok {
		t.Fatal("no latency-budget gauge")
	}

	none := dem.WireTarget{ID: "dem-nobud", Tenant: "acme", Kind: dem.KindTCP, Host: "127.0.0.1",
		Port: 1, IntervalSec: 15, AvailBudgetPct: 99}
	h2 := newDEMHarness(t, []dem.WireTarget{none})
	h2.tick(t)
	if l, ok := h2.lineFor(dem.MetricLatencyBudgetMs, "dem-nobud"); ok {
		t.Fatalf("a latency budget nobody declared was published: %q", l)
	}
}

func TestPathFingerprintOnlyWhenAPathWasMeasured(t *testing.T) {
	tgt := dem.WireTarget{ID: "dem-p", Tenant: "acme", Kind: dem.KindICMP, Host: "198.51.100.7", IntervalSec: 15}
	h := newDEMHarness(t, []dem.WireTarget{tgt})
	h.tick(t)
	if l, ok := h.lineFor(dem.MetricPathFingerprint, "dem-p"); ok {
		t.Fatalf("a path fingerprint appeared with no traceroute behind it: %q", l)
	}

	Paths.set(PathResult{Dst: "198.51.100.7", Method: "icmp", TS: time.Now().UTC(),
		Hops: []Hop{{TTL: 1, IP: "10.0.0.1"}, {TTL: 2, IP: "198.51.100.7"}}})
	fp, hops, ok := observedPath("198.51.100.7", time.Now().UTC())
	if !ok || hops != 2 || fp == 0 {
		t.Fatalf("fresh path not observed: %v %d %v", ok, hops, fp)
	}
	// A stale trace is NOT this window's observation.
	if _, _, stale := observedPath("198.51.100.7", time.Now().UTC().Add(2*demPathMaxAge)); stale {
		t.Fatal("a stale traceroute counted as a current path observation")
	}
	// A different path yields a different fingerprint, which is what `changes()`
	// counts.
	Paths.set(PathResult{Dst: "198.51.100.7", Method: "icmp", TS: time.Now().UTC(),
		Hops: []Hop{{TTL: 1, IP: "10.9.9.9"}, {TTL: 2, IP: "198.51.100.7"}}})
	fp2, _, _ := observedPath("198.51.100.7", time.Now().UTC())
	if fp2 == fp {
		t.Fatal("a re-routed path produced the same fingerprint")
	}
}

func TestDemPathHostStripsSchemeAndPort(t *testing.T) {
	cases := map[dem.WireTarget]string{
		{Kind: dem.KindHTTP, Host: "https://portal.example:8443/health?x=1"}: "portal.example",
		{Kind: dem.KindTCP, Host: "db.example", Port: 5432}:                  "db.example",
		{Kind: dem.KindICMP, Host: "10.0.0.1"}:                               "10.0.0.1",
	}
	for in, want := range cases {
		if got := demPathHost(in); got != want {
			t.Fatalf("demPathHost(%+v) = %q want %q", in, got, want)
		}
	}
}

// The DEM additions to the probe event are ADDITIVE: a producer that does not
// set them emits exactly what it emitted before.
func TestProbeEventDEMFieldsAreOmittedWhenUnset(t *testing.T) {
	b, err := json.Marshal(ProbeEvent{Kind: "stamp", Prober: "p", Target: "t", TS: "now"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"tenant", "target_id", "app_id", "source"} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Fatalf("a bare probe event carries %q: %s", key, b)
		}
	}
}

func TestDemTransportSeam(t *testing.T) {
	r := NewDEM().(*demRunner)
	rt := http.DefaultTransport
	r.setTransport(rt)
	if r.checks.transport == nil {
		t.Fatal("transport seam not wired")
	}
	_ = os.Getenv("HOME")
}

// fmtSscan keeps the tcp test free of a fmt import in the harness.
func fmtSscan(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}
