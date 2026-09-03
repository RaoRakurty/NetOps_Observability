package alertwebhook

// hostroute_test.go — the HOST-MONITORING route (owner decision, 2026-09-03).
//
// Every test here drives the real HTTP surface and asserts on what would reach
// the operator's phone: how many pushes, at what priority, with what in the
// title. Delivery is async, so the fake pusher is the synchronization point —
// tests wait on a push, never on a duration.

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

// fakePusher is the injected host-route seam (§5). Push both RECORDS and
// SIGNALS, so a test waits on a delivery instead of sleeping for one.
type fakePusher struct {
	mu     sync.Mutex
	got    []notify.NtfyPush
	err    error
	gate   chan struct{} // non-nil: Push blocks until it is closed
	signal chan notify.NtfyPush
}

func newFakePusher() *fakePusher {
	return &fakePusher{signal: make(chan notify.NtfyPush, 1024)}
}

func (f *fakePusher) Push(p notify.NtfyPush) error {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	f.got = append(f.got, p)
	err := f.err
	f.mu.Unlock()
	f.signal <- p
	return err
}

func (f *fakePusher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

// await returns the next n pushes, failing the test if they do not arrive.
func (f *fakePusher) await(t *testing.T, n int) []notify.NtfyPush {
	t.Helper()
	out := make([]notify.NtfyPush, 0, n)
	for i := 0; i < n; i++ {
		select {
		case p := <-f.signal:
			out = append(out, p)
		case <-time.After(5 * time.Second):
			t.Fatalf("push %d/%d never arrived on the host route", i+1, n)
		}
	}
	return out
}

// quiet asserts no further push arrives. Bounded wait: the enqueue is
// synchronous with the request, so anything that was going to be delivered has
// already been queued by the time the response is written.
func (f *fakePusher) quiet(t *testing.T) {
	t.Helper()
	select {
	case p := <-f.signal:
		t.Fatalf("an unexpected push reached the host route: %+v", p)
	case <-time.After(150 * time.Millisecond):
	}
}

type hostRig struct {
	*rig
	push *fakePusher
	logs *logSpy
}

// logSpy captures the injected structured logs so "logged ONCE" is assertable.
type logSpy struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logSpy) log(level, msg string, _ map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, level+": "+msg)
}

func (l *logSpy) countContaining(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, m := range l.msgs {
		if strings.Contains(m, sub) {
			n++
		}
	}
	return n
}

// newHostRig builds the receiver with the host route wired. push==nil wires NO
// route, which is the "no topic configured" case.
func newHostRig(t *testing.T, cooldown time.Duration, push *fakePusher) *hostRig {
	t.Helper()
	d := &fakeDispatcher{}
	c := &testClock{t: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)}
	m := NewMetrics()
	spy := &logSpy{}
	deps := Deps{
		Dispatcher: d,
		Token:      testToken,
		Cooldown:   cooldown,
		Now:        c.now,
		Metrics:    m,
		Log:        spy.log,
	}
	if push != nil {
		deps.HostRoute = push
	}
	h, err := Handler(deps)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return &hostRig{rig: &rig{h: h, disp: d, clock: c, mx: m}, push: push, logs: spy}
}

func alertJSON(name, severity, layer, tier, status, summary string) string {
	return fmt.Sprintf(`[{"status":%q,"labels":{"alertname":%q,"severity":%q,"layer":%q,"tier":%q},`+
		`"annotations":{"summary":%q,"description":"detail line"},`+
		`"startsAt":"2026-09-03T11:45:00Z","endsAt":"2026-09-03T11:59:00Z"}]`,
		status, name, severity, layer, tier, summary)
}

// ── the tier ladder ─────────────────────────────────────────────────────────

func TestPageTierPushesOneHighPriorityPushToTheHostRoute(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	body := alertJSON("CorrelationConsumerDead", "critical", "correlation", "page", "firing",
		"correlation consumer group has zero members")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	got := r.push.await(t, 1)
	if len(got) != 1 {
		t.Fatalf("pushes = %d, want exactly 1", len(got))
	}
	p := got[0]
	if p.Priority != notify.NtfyPriorityHigh {
		t.Errorf("Priority = %q, want %q (page must wake someone)", p.Priority, notify.NtfyPriorityHigh)
	}
	// The tier, the alertname and the summary must all be in the TITLE — that
	// is the whole of what a lock screen shows.
	for _, want := range []string{"PAGE", "CorrelationConsumerDead", "correlation consumer group has zero members"} {
		if !strings.Contains(p.Title, want) {
			t.Errorf("title %q is missing %q", p.Title, want)
		}
	}
	if !strings.Contains(p.Body, "severity=critical") || !strings.Contains(p.Body, "detail line") {
		t.Errorf("body must carry the label context and the description, got %q", p.Body)
	}
	r.push.quiet(t)
	txt := metricsText(r.mx)
	if !strings.Contains(txt, `netops_alert_webhook_pushed_total{route="host_monitoring",tier="page"} 1`) {
		t.Errorf("the page push was not counted:\n%s", txt)
	}
	if !strings.Contains(txt, "netops_alert_webhook_host_route_enabled 1") {
		t.Error("the host route gauge must read 1 when the route is wired")
	}
}

func TestWarningTierPushesAtDefaultPriority(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	// No tier label at all — the matrix's "watch" default. It must still reach
	// the phone, just without waking anyone.
	body := alertJSON("VectorEventsDiscarded", "warning", "ingest", "", "firing", "events discarded")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	p := r.push.await(t, 1)[0]
	if p.Priority != notify.NtfyPriorityDefault {
		t.Errorf("Priority = %q, want %q", p.Priority, notify.NtfyPriorityDefault)
	}
	if !strings.Contains(p.Title, "WARNING") {
		t.Errorf("title %q must name the tier", p.Title)
	}
	if !strings.Contains(metricsText(r.mx), `netops_alert_webhook_pushed_total{route="host_monitoring",tier="warning"} 1`) {
		t.Error("the warning push was not counted under its tier")
	}
}

// A CRITICAL severity without tier=page must NOT be promoted: the rule files
// carry ~140 critical/warning rules and only four conditions are page-worthy.
func TestCriticalSeverityAloneDoesNotPage(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	body := alertJSON("OpenSearchDocumentsRejected", "critical", "storage", "", "firing", "docs rejected")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if p := r.push.await(t, 1)[0]; p.Priority != notify.NtfyPriorityDefault {
		t.Errorf("Priority = %q, want %q — only the tier label pages", p.Priority, notify.NtfyPriorityDefault)
	}
}

func TestResolvedPushesAtLowPriority(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	body := alertJSON("CorrelationConsumerDead", "critical", "correlation", "page", "resolved", "consumer rejoined")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	p := r.push.await(t, 1)[0]
	if p.Priority != notify.NtfyPriorityLow {
		t.Errorf("Priority = %q, want %q (a resolution must not buzz like a page)", p.Priority, notify.NtfyPriorityLow)
	}
	if !strings.Contains(p.Title, "RESOLVED") || !strings.Contains(p.Body, "RESOLVED") {
		t.Errorf("a resolution must say so in the title AND the body: %q / %q", p.Title, p.Body)
	}
	if _, resolved := r.disp.counts(); resolved != 1 {
		t.Error("the product dispatcher must still receive the resolution")
	}
	if !strings.Contains(metricsText(r.mx), `netops_alert_webhook_pushed_total{route="host_monitoring",tier="resolved"} 1`) {
		t.Error("the resolved push was not counted under its tier")
	}
}

// ── the heartbeat ───────────────────────────────────────────────────────────

func TestHeartbeatIsNeverPushedToThePhone(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	hb := fmt.Sprintf(`[{"status":"firing","labels":{"alertname":%q,"severity":"info","tier":"heartbeat"}}]`,
		HeartbeatAlertName)
	if w := r.post(t, hb, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.quiet(t)
	if n := r.push.count(); n != 0 {
		t.Fatalf("the heartbeat was pushed to the phone %d time(s) — it exists for the watchdog's freshness probe", n)
	}
	// Counted, though: it is the only proof the delivery chain is alive.
	if got, want := r.mx.HeartbeatAt(), r.clock.now().Unix(); got != want {
		t.Fatalf("heartbeat gauge = %d, want %d", got, want)
	}
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_heartbeat_total 1") {
		t.Error("the heartbeat was not counted")
	}
	if page, warn, res := r.mx.HostPushed(); page+warn+res != 0 {
		t.Errorf("the heartbeat moved a push counter: %d/%d/%d", page, warn, res)
	}
}

// ── dedup / cool-down ───────────────────────────────────────────────────────

func TestCooldownSuppressesTheRepeatPush(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	body := alertJSON("RouterConsumerDead", "critical", "bus", "page", "firing", "router group empty")
	for i := 0; i < 3; i++ {
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("post %d: status %d", i, w.Code)
		}
		r.clock.advance(time.Minute) // still inside the 30m window
	}
	r.push.await(t, 1)
	r.push.quiet(t)
	if n := r.push.count(); n != 1 {
		t.Fatalf("pushes = %d, want 1 — vmalert re-posts every active alert and the phone must not repeat it", n)
	}
	// Past the window the same alert may buzz again.
	r.clock.advance(30 * time.Minute)
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.await(t, 1)
	if n := r.push.count(); n != 2 {
		t.Fatalf("pushes = %d, want 2 after the cool-down elapsed", n)
	}
}

// ── not configured ──────────────────────────────────────────────────────────

func TestNoTopicConfiguredIsCountedAndLoggedOnce(t *testing.T) {
	r := newHostRig(t, time.Nanosecond, nil) // no host route
	for i := 0; i < 5; i++ {
		body := alertJSON(fmt.Sprintf("Alert%d", i), "critical", "stack", "page", "firing", "x")
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
	}
	txt := metricsText(r.mx)
	if !strings.Contains(txt, `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="not_configured"} 5`) {
		t.Errorf("an unconfigured route must be COUNTED per alert:\n%s", txt)
	}
	if !strings.Contains(txt, "netops_alert_webhook_host_route_enabled 0") {
		t.Error("the host route gauge must read 0 when no topic is configured")
	}
	if n := r.logs.countContaining("NOT pushed to host monitoring"); n != 1 {
		t.Fatalf("logged %d times, want exactly 1 — a per-alert warning is its own outage", n)
	}
	// The product path is untouched by the missing host route.
	if fired, _ := r.disp.counts(); fired != 5 {
		t.Fatalf("product dispatches = %d, want 5", fired)
	}
}

// ── isolation ───────────────────────────────────────────────────────────────

// §3a: an alert carrying a tenant identity is refused BEFORE either route, so
// it can no more reach the operator's phone than the product channels.
func TestTenantLabelledAlertIsNeverPushed(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	body := `[{"status":"firing","labels":{"alertname":"DeviceDown","severity":"critical","tier":"page","tenant":"acme"}}]`
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.quiet(t)
	if n := r.push.count(); n != 0 {
		t.Fatalf("a tenant-scoped alert was pushed to the platform phone channel %d time(s)", n)
	}
	if fired, _ := r.disp.counts(); fired != 0 {
		t.Fatal("a tenant-scoped alert reached the product dispatcher")
	}
}

// The two routes are INDEPENDENT: the product dispatcher keeps receiving
// exactly what it received before this change, and the host push happens
// alongside it rather than instead of it.
func TestProductDispatcherBehaviourIsUnchangedByTheHostRoute(t *testing.T) {
	withRoute := newHostRig(t, 30*time.Minute, newFakePusher())
	withoutRoute := newHostRig(t, 30*time.Minute, nil)
	body := alertJSON("ContainerDown", "critical", "stack", "page", "firing", "api is down")
	for _, r := range []*hostRig{withRoute, withoutRoute} {
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
	}
	withRoute.push.await(t, 1)
	a, b := withRoute.disp.fired, withoutRoute.disp.fired
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("product dispatches = %d / %d, want 1 each", len(a), len(b))
	}
	if !sameAlert(a[0], b[0]) {
		t.Fatalf("the host route changed what the product dispatcher receives:\n%+v\n%+v", a[0], b[0])
	}
}

func sameAlert(x, y models.Alert) bool {
	if x.ID != y.ID || x.Rule != y.Rule || x.Severity != y.Severity ||
		x.Summary != y.Summary || x.Description != y.Description || len(x.Labels) != len(y.Labels) {
		return false
	}
	for k, v := range x.Labels {
		if y.Labels[k] != v {
			return false
		}
	}
	return true
}

// ── failure handling ────────────────────────────────────────────────────────

func TestPushFailureIsCountedAndNeverFailsTheRequest(t *testing.T) {
	p := newFakePusher()
	p.err = fmt.Errorf("ntfy: status 502")
	r := newHostRig(t, 30*time.Minute, p)
	body := alertJSON("ClickHouseWritesRejected", "critical", "clickhouse", "page", "firing", "writes rejected")
	w := r.post(t, body, bearer)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d — a push failure must never 5xx vmalert into a retry storm", w.Code)
	}
	r.push.await(t, 1)
	// The counter moves just AFTER Push returns, which is just after the signal
	// this test woke on — so settle on the metric rather than on a duration.
	waitForMetric(t, r.mx, `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="send_error"} 1`)
	if page, warn, res := r.mx.HostPushed(); page+warn+res != 0 {
		t.Errorf("a failed push was counted as delivered: %d/%d/%d", page, warn, res)
	}
}

// The queue is BOUNDED (§9): a wedged ntfy must cost dropped pushes, not a
// growing backlog and not a blocked vmalert request.
func TestQueueFullDropsAreCountedNotBlocking(t *testing.T) {
	p := newFakePusher()
	p.gate = make(chan struct{})
	r := newHostRig(t, time.Nanosecond, p) // every alert distinct: no suppression
	var sb strings.Builder
	sb.WriteString("[")
	total := hostQueueSize + 120
	for i := 0; i < total; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"status":"firing","labels":{"alertname":"A%d","severity":"warning","layer":"stack"}}`, i)
	}
	sb.WriteString("]")

	done := make(chan int, 1)
	go func() { done <- r.post(t, sb.String(), bearer).Code }()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request blocked on a wedged push — vmalert would retry into a storm")
	}
	txt := metricsText(r.mx)
	if !strings.Contains(txt, `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="queue_full"}`) {
		t.Fatalf("the queue_full series is missing:\n%s", txt)
	}
	if strings.Contains(txt, `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="queue_full"} 0`) {
		t.Errorf("%d alerts against a %d-deep queue dropped nothing:\n%s", total, hostQueueSize, txt)
	}
	close(p.gate) // let the drain finish so the goroutine does not outlive the test
	r.push.await(t, 1)
}

// ── composition units ───────────────────────────────────────────────────────

// waitForMetric settles on a counter that is written immediately after the
// event the caller already synchronized on. Bounded, and it fails with the
// whole metrics text so a mismatch names itself.
func waitForMetric(t *testing.T, m *Metrics, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		txt := metricsText(m)
		if strings.Contains(txt, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("metric %q never appeared:\n%s", want, txt)
		}
		runtime.Gosched()
	}
}

func TestHostTierClassification(t *testing.T) {
	for _, tc := range []struct{ status, label, want string }{
		{"firing", "page", tierPage},
		{"firing", "PAGE", tierPage},
		{"firing", "watch", tierWarning},
		{"firing", "", tierWarning},
		{"resolved", "page", tierResolved},
		{"resolved", "", tierResolved},
	} {
		if got := hostTier(tc.status, tc.label); got != tc.want {
			t.Errorf("hostTier(%q,%q) = %q, want %q", tc.status, tc.label, got, tc.want)
		}
	}
}

func TestHostTitleIsBounded(t *testing.T) {
	title := hostTitle(tierPage, "Rule", strings.Repeat("x", 4000))
	if len(title) > maxHostTitle {
		t.Fatalf("title length = %d, want <= %d", len(title), maxHostTitle)
	}
}
