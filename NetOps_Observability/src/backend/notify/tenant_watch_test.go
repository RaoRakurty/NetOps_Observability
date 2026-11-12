// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

// tenant_watch_test.go — tracker 359: a tenant's own watch alerts reach that
// tenant's own lanes, once per episode, through the dispatcher's delivery pool,
// and a lane secret never reaches a log line. Fakes only: no real webhook or
// PagerDuty key is ever called.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

// laneRecorder is the fake sender every lane is built as. It records which
// lane (system + secret) received which alert and whether it was a resolve.
type laneRecorder struct {
	mu    sync.Mutex
	got   []laneHit
	fail  map[string]error // secret → error to return
	calls int
}

type laneHit struct {
	system, secret, alertID, summary string
	resolve                          bool
}

func (r *laneRecorder) build(l TenantLane) Channel { return &fakeLane{r: r, l: l} }

func (r *laneRecorder) hits() []laneHit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]laneHit(nil), r.got...)
}

func (r *laneRecorder) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type fakeLane struct {
	r *laneRecorder
	l TenantLane
}

func (f *fakeLane) Name() string { return "fake-" + f.l.System }

func (f *fakeLane) record(a models.Alert, resolve bool) error {
	f.r.mu.Lock()
	defer f.r.mu.Unlock()
	f.r.calls++
	if err := f.r.fail[f.l.Secret]; err != nil {
		return err
	}
	f.r.got = append(f.r.got, laneHit{system: f.l.System, secret: f.l.Secret, alertID: a.ID, summary: a.Summary, resolve: resolve})
	return nil
}

func (f *fakeLane) Send(a models.Alert) error { return f.record(a, false) }

// Only the PagerDuty fake has resolve semantics, like the real senders.
type fakePDLane struct{ fakeLane }

func (f *fakePDLane) SendResolve(a models.Alert) error { return f.record(a, true) }

func (r *laneRecorder) buildWithPD(l TenantLane) Channel {
	if l.System == TenantLanePagerDuty {
		return &fakePDLane{fakeLane{r: r, l: l}}
	}
	return &fakeLane{r: r, l: l}
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *logSink) log(level, msg string, fields map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf("%s %s %v", level, msg, fields))
}

func (s *logSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

func newRouterUnderTest(t *testing.T, lanes map[string][]TenantLane) (*TenantWatchRouter, *Dispatcher, *laneRecorder, *logSink) {
	t.Helper()
	d := NewDispatcher()
	fastRetries(d)
	t.Cleanup(d.Close)
	rec := &laneRecorder{fail: map[string]error{}}
	logs := &logSink{}
	d.SetLogger(logs.log)
	r := NewTenantWatchRouter(d, TenantWatchDeps{
		Lanes: func(tenant string) []TenantLane { return lanes[tenant] },
		Build: rec.buildWithPD,
		Log:   logs.log,
	})
	return r, d, rec, logs
}

func watchAlert(id string) models.Alert {
	return models.Alert{ID: id, Rule: "bgp_origin_change", Severity: "critical", Summary: "origin changed"}
}

func TestTenantWatchOneMessagePerEpisode(t *testing.T) {
	r, _, rec, _ := newRouterUnderTest(t, map[string][]TenantLane{
		"acme": {{System: TenantLaneSlack, Secret: "https://hooks.example/A"}, {System: TenantLanePagerDuty, Secret: "rk-acme"}},
	})
	a := watchAlert("bgp:acme:203.0.113.0/24:origin_change")
	// The evaluator re-notifies after its cool-down while the incident is open,
	// and a monitor whose state failed to persist re-fires every tick.
	for i := 0; i < 5; i++ {
		r.Fire("acme", a)
	}
	waitUntil(t, "fire delivered to both lanes", func() bool { return len(rec.hits()) == 2 })
	cleared := a
	cleared.Summary = "Cleared: 203.0.113.0/24 is no longer classified origin_change."
	r.Resolve("acme", cleared)
	r.Resolve("acme", cleared) // a second clear of the same episode is not re-sent
	waitUntil(t, "resolve delivered to both lanes", func() bool { return len(rec.hits()) == 4 })
	waitUntil(t, "queue drained", func() bool { return r.d.QueueDepth() == 0 })
	if n := len(rec.hits()); n != 4 {
		t.Fatalf("a re-clear of the same episode was re-sent: %d hits", n)
	}

	var fires, resolves, slackClear int
	for _, h := range rec.hits() {
		switch {
		case h.system == TenantLanePagerDuty && h.resolve:
			resolves++
		case h.system == TenantLaneSlack && strings.HasPrefix(h.summary, "Cleared"):
			slackClear++
		default:
			fires++
		}
	}
	if fires != 2 || resolves != 1 || slackClear != 1 {
		t.Fatalf("want 2 fires + PD resolve + one Slack clear message; got fires=%d pdResolve=%d slackClear=%d (%+v)", fires, resolves, slackClear, rec.hits())
	}
	var buf bytes.Buffer
	r.WriteMetrics(&buf)
	for _, want := range []string{
		`netops_notify_tenant_watch_total{outcome="queued"} 1`,
		`netops_notify_tenant_watch_total{outcome="duplicate"} 5`, // 4 re-fires + 1 re-clear
		`netops_notify_tenant_watch_total{outcome="resolve_queued"} 1`,
		`netops_notify_tenant_watch_total{outcome="resolve_unmatched"} 0`,
		`netops_notify_tenant_watch_open_episodes 0`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, buf.String())
		}
	}

	// A NEW episode of the same alert after the clear is delivered again.
	r.Fire("acme", a)
	waitUntil(t, "second episode delivered", func() bool { return len(rec.hits()) == 6 })
}

func TestTenantWatchSlackClearReadsAsResolved(t *testing.T) {
	r, _, rec, _ := newRouterUnderTest(t, map[string][]TenantLane{
		"acme": {{System: TenantLaneSlack, Secret: "https://hooks.example/A"}},
	})
	a := models.Alert{ID: "cloud-monitor-m1", Rule: "High CPU", Severity: "warning", Summary: `Cloud monitor "High CPU": cpu 95`}
	r.Fire("acme", a)
	ok := a
	ok.Summary = `Cloud monitor "High CPU": cpu worst reading 10`
	r.Resolve("acme", ok)
	waitUntil(t, "fire + clear", func() bool { return len(rec.hits()) == 2 })
	if got := rec.hits()[1].summary; !strings.HasPrefix(got, "Resolved: ") {
		t.Fatalf("Slack clear must say it resolved, got %q", got)
	}
}

func TestTenantWatchRefusesPlatformAndEmptyTenants(t *testing.T) {
	lanes := []TenantLane{{System: TenantLaneSlack, Secret: "https://hooks.example/P"}, {System: TenantLanePagerDuty, Secret: "rk-platform"}}
	r, d, rec, _ := newRouterUnderTest(t, map[string][]TenantLane{
		"": lanes, "global": lanes, "GLOBAL": lanes, "__all__": lanes, "*": lanes,
	})
	for _, tenant := range []string{"", "  ", "global", "GLOBAL", " Global ", "__all__", "*"} {
		r.Fire(tenant, watchAlert("x-"+tenant))
		r.Resolve(tenant, watchAlert("x-"+tenant))
	}
	if d.QueueDepth() != 0 || len(rec.hits()) != 0 || rec.callCount() != 0 {
		t.Fatalf("a platform/empty/wildcard tenant reached a lane: hits=%v", rec.hits())
	}
	var buf bytes.Buffer
	r.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `netops_notify_tenant_watch_total{outcome="refused_tenant"} 14`) {
		t.Fatalf("refusals must be counted:\n%s", buf.String())
	}
}

func TestTenantWatchNoLaneIsCountedNotDelivered(t *testing.T) {
	r, _, rec, _ := newRouterUnderTest(t, map[string][]TenantLane{})
	r.Fire("acme", watchAlert("a1"))
	var buf bytes.Buffer
	r.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `netops_notify_tenant_watch_total{outcome="no_lane"} 1`) || len(rec.hits()) != 0 {
		t.Fatalf("no-lane must be counted and deliver nothing:\n%s", buf.String())
	}
	// No episode was recorded, so a lane configured later receives the next
	// fire (the evaluator's re-notify) rather than it being deduped forever.
	r.deps.Lanes = func(string) []TenantLane {
		return []TenantLane{{System: TenantLaneSlack, Secret: "https://hooks.example/A"}}
	}
	r.Fire("acme", watchAlert("a1"))
	waitUntil(t, "delivered once a lane exists", func() bool { return len(rec.hits()) == 1 })
}

func TestTenantWatchAlertWithoutIDIsRefused(t *testing.T) {
	r, _, rec, logs := newRouterUnderTest(t, map[string][]TenantLane{
		"acme": {{System: TenantLaneSlack, Secret: "https://hooks.example/A"}},
	})
	r.Fire("acme", models.Alert{Rule: "x"})
	if len(rec.hits()) != 0 || !strings.Contains(logs.text(), "has no id") {
		t.Fatalf("an id-less alert must be refused and said")
	}
}

// TestTenantWatchUnmatchedResolveClosesPagerDutyOnly: after a restart the
// router holds no episode. PagerDuty still gets the close (a no-op if nothing
// is open — suppressing a close is never safe); Slack gets no "cleared"
// message for an alert it was never told about.
func TestTenantWatchUnmatchedResolveClosesPagerDutyOnly(t *testing.T) {
	r, _, rec, _ := newRouterUnderTest(t, map[string][]TenantLane{
		"acme": {{System: TenantLaneSlack, Secret: "https://hooks.example/A"}, {System: TenantLanePagerDuty, Secret: "rk-acme"}},
	})
	r.Resolve("acme", watchAlert("never-fired"))
	waitUntil(t, "PD close", func() bool { return len(rec.hits()) == 1 })
	if h := rec.hits()[0]; h.system != TenantLanePagerDuty || !h.resolve {
		t.Fatalf("unmatched resolve must reach PagerDuty as a resolve only, got %+v", h)
	}
}

// TestTenantWatchResolveUsesTheKeyThatOpened: PagerDuty closes by the routing
// key that opened the incident. A key rotated mid-episode must not strand the
// open incident.
func TestTenantWatchResolveUsesTheKeyThatOpened(t *testing.T) {
	cur := []TenantLane{{System: TenantLanePagerDuty, Secret: "rk-old"}}
	r, _, rec, _ := newRouterUnderTest(t, nil)
	r.deps.Lanes = func(string) []TenantLane { return cur }
	r.Fire("acme", watchAlert("a1"))
	cur = []TenantLane{{System: TenantLanePagerDuty, Secret: "rk-new"}}
	r.Resolve("acme", watchAlert("a1"))
	waitUntil(t, "fire + resolve", func() bool { return len(rec.hits()) == 2 })
	for _, h := range rec.hits() {
		if h.secret != "rk-old" {
			t.Fatalf("episode must close on the key that opened it, got %+v", h)
		}
	}
}

// TestTenantWatchDeliveryFailureIsCountedAndLoggedWithoutTheSecret: a lane
// that keeps failing is retried by the pool, then counted on the dispatcher's
// failure counter for the FIXED channel name and logged — and neither the log
// nor the metric carries the lane secret, even when the sender's own error
// text does.
func TestTenantWatchDeliveryFailureIsCountedAndLoggedWithoutTheSecret(t *testing.T) {
	const hook = "https://hooks.example/services/T000/B000/SEKRETtoken123"
	const key = "rk-SEKRET-routing-key"
	r, d, rec, logs := newRouterUnderTest(t, map[string][]TenantLane{
		"acme": {{System: TenantLaneSlack, Secret: hook}, {System: TenantLanePagerDuty, Secret: key}},
	})
	rec.fail[hook] = fmt.Errorf("Post %q: dial tcp: connection refused", hook)
	rec.fail[key] = errors.New("pagerduty rejected routing key " + key)

	r.Fire("acme", watchAlert("a1"))
	waitUntil(t, "both lanes exhausted their retries", func() bool {
		return d.statsSnapshot("tenant-slack").failed == 1 && d.statsSnapshot("tenant-pagerduty").failed == 1
	})
	if got := rec.callCount(); got != 2*deliveryAttempts {
		t.Fatalf("want %d attempts (retry with backoff), got %d", 2*deliveryAttempts, got)
	}
	txt := logs.text()
	if !strings.Contains(txt, "did not go out") || !strings.Contains(txt, `"acme"`) {
		t.Fatalf("failure must be logged with the tenant:\n%s", txt)
	}
	var buf bytes.Buffer
	d.WriteMetrics(&buf)
	r.WriteMetrics(&buf)
	all := txt + buf.String()
	for _, secret := range []string{hook, key, "SEKRETtoken123", "/services/T000/B000/SEKRETtoken123"} {
		if strings.Contains(all, secret) {
			t.Fatalf("lane secret %q leaked into logs/metrics:\n%s", secret, all)
		}
	}
	if !strings.Contains(buf.String(), `netops_notify_failures_total{channel="tenant-slack"} 1`) {
		t.Fatalf("failure must be on the fixed tenant-slack counter:\n%s", buf.String())
	}
}

// TestTenantWatchRealSlackTransportErrorIsScrubbed drives the REAL Slack
// sender at a closed local port: net/http's error names the full webhook URL,
// which is the credential. Nothing reaches the network.
func TestTenantWatchRealSlackTransportErrorIsScrubbed(t *testing.T) {
	const hook = "http://127.0.0.1:1/services/T999/B999/realSEKRET"
	d := NewDispatcher()
	fastRetries(d)
	t.Cleanup(d.Close)
	logs := &logSink{}
	d.SetLogger(logs.log)
	r := NewTenantWatchRouter(d, TenantWatchDeps{
		Lanes: func(string) []TenantLane { return []TenantLane{{System: TenantLaneSlack, Secret: hook}} },
	})
	r.Fire("acme", watchAlert("a1"))
	waitUntil(t, "real sender failed", func() bool { return d.statsSnapshot("tenant-slack").failed == 1 })
	if txt := logs.text(); strings.Contains(txt, "realSEKRET") || strings.Contains(txt, "/services/") {
		t.Fatalf("webhook URL leaked into the delivery log:\n%s", txt)
	}
	// The sender scrubs at the source too, so the platform-global Slack
	// channel's failures stop carrying its webhook as well.
	err := NewSlack(hook).Send(watchAlert("a2"))
	if err == nil || strings.Contains(err.Error(), "realSEKRET") {
		t.Fatalf("Slack.Send error must not carry the webhook URL: %v", err)
	}
}

func TestTenantWatchEpisodeRegisterIsBounded(t *testing.T) {
	r, _, _, logs := newRouterUnderTest(t, map[string][]TenantLane{
		"acme": {{System: TenantLaneSlack, Secret: "https://hooks.example/A"}},
	})
	r.mu.Lock()
	for i := 0; i < tenantWatchMaxEpisodes; i++ {
		r.recordLocked(fmt.Sprintf("k%d", i), nil)
	}
	r.mu.Unlock()
	r.Fire("acme", watchAlert("overflow"))
	r.mu.Lock()
	n, orderLen := len(r.open), len(r.order)
	_, oldest := r.open["k0"]
	r.mu.Unlock()
	if n != tenantWatchMaxEpisodes || oldest {
		t.Fatalf("register must stay at its bound by forgetting the oldest; size=%d k0 present=%v", n, oldest)
	}
	if orderLen > 2*n+64 {
		t.Fatalf("order slice unbounded: %d", orderLen)
	}
	var buf bytes.Buffer
	r.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `netops_notify_tenant_watch_total{outcome="evicted"} 1`) || !strings.Contains(logs.text(), "register full") {
		t.Fatalf("eviction must be counted and logged:\n%s", buf.String())
	}
}

func TestTenantWatchNilRouterIsSafe(t *testing.T) {
	var r *TenantWatchRouter
	r.Fire("acme", watchAlert("a"))
	r.Resolve("acme", watchAlert("a"))
	r.WriteMetrics(&bytes.Buffer{})
}
