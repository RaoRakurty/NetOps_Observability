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
	mu  sync.Mutex
	got []notify.NtfyPush
	err error
	// script, when non-empty, is consumed one entry per call BEFORE err takes
	// over: "429, 429, then success" is a sequence, and a retry ladder can only
	// be asserted against a sequence.
	script []error
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
	if len(f.script) > 0 {
		err = f.script[0]
		f.script = f.script[1:]
	}
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
	naps *sleepSpy
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

// sleepSpy is the injected backoff wait (Deps.Sleep). Recording it instead of
// serving it is what lets a five-attempt, minutes-long retry ladder be asserted
// in microseconds — and asserted EXACTLY, which a real sleep never can.
type sleepSpy struct {
	mu   sync.Mutex
	took []time.Duration
}

func (s *sleepSpy) sleep(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.took = append(s.took, d)
}

func (s *sleepSpy) waits() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]time.Duration, len(s.took))
	copy(out, s.took)
	return out
}

// newHostRig builds the receiver with the host route wired. push==nil wires NO
// route, which is the "no topic configured" case.
func newHostRig(t *testing.T, cooldown time.Duration, push *fakePusher) *hostRig {
	return newHostRigWith(t, cooldown, push, nil)
}

// newHostRigWith is newHostRig plus a hook that adjusts the injected Deps —
// the digest window, the push budget, the reserve. Kept separate so the plain
// three-argument constructor the isolation suite uses stays exactly as it is.
func newHostRigWith(t *testing.T, cooldown time.Duration, push *fakePusher, tune func(*Deps)) *hostRig {
	t.Helper()
	d := &fakeDispatcher{}
	c := &testClock{t: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)}
	m := NewMetrics()
	spy := &logSpy{}
	naps := &sleepSpy{}
	deps := Deps{
		Dispatcher: d,
		Token:      testToken,
		Cooldown:   cooldown,
		Now:        c.now,
		Sleep:      naps.sleep,
		Metrics:    m,
		Log:        spy.log,
	}
	if push != nil {
		deps.HostRoute = push
	}
	if tune != nil {
		tune(&deps)
	}
	h, err := Handler(deps)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return &hostRig{rig: &rig{h: h, disp: d, clock: c, mx: m}, push: push, logs: spy, naps: naps}
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

// The warning tier is NEVER pushed on its own any more (2026-09-03): it is
// folded into the periodic digest. This is the behaviour change that ends the
// live 429 storm, so it is asserted first — one warning in, zero pushes out,
// one fold counted.
func TestWarningTierIsFoldedIntoTheDigestNotPushed(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	// No tier label at all — the matrix's "watch" default.
	body := alertJSON("VectorEventsDiscarded", "warning", "ingest", "", "firing", "events discarded")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.quiet(t)
	if n := r.push.count(); n != 0 {
		t.Fatalf("pushes = %d, want 0 — a chronic warning must not spend a push of its own", n)
	}
	txt := metricsText(r.mx)
	if !strings.Contains(txt, "netops_alert_webhook_digest_alerts_total 1") {
		t.Errorf("the warning was not counted as folded:\n%s", txt)
	}
	if !strings.Contains(txt, `netops_alert_webhook_pushed_total{route="host_monitoring",tier="warning"} 0`) {
		t.Errorf("the warning tier must show ZERO individual pushes:\n%s", txt)
	}
	// The product dispatcher is untouched: the digest is a HOST-ROUTE policy,
	// not a change to what the configured channels receive.
	if fired, _ := r.disp.counts(); fired != 1 {
		t.Fatalf("product dispatches = %d, want 1 — digesting must not swallow the product leg", fired)
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
	r.push.quiet(t)
	if n := r.push.count(); n != 0 {
		t.Fatalf("pushes = %d, want 0 — only the server-stamped tier label pages, "+
			"and everything else is digested", n)
	}
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_digest_alerts_total 1") {
		t.Error("a critical-without-tier alert must be folded into the digest, not lost")
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
	// ONE failure is counted for the whole delivery, not one per attempt: the
	// counter measures pages that never landed, and a retried-then-failed page
	// is one such page.
	if n := r.push.count(); n != hostMaxAttempts {
		t.Errorf("attempts = %d, want %d — a page must be retried before it is given up on", n, hostMaxAttempts)
	}
	if n := r.logs.countContaining("error: platform alert push to host monitoring FAILED"); n != 1 {
		t.Errorf("a page that never landed must be logged ERROR exactly once, got %d", n)
	}
}

// The queue is BOUNDED (§9): a wedged ntfy must cost dropped pushes, not a
// growing backlog and not a blocked vmalert request.
func TestQueueFullDropsAreCountedNotBlocking(t *testing.T) {
	p := newFakePusher()
	p.gate = make(chan struct{})
	// PAGE tier: the warning tier is digested now and never touches the queue.
	// The budget guard is disabled (negative) so this test measures the QUEUE
	// bound and nothing else — the budget has its own tests.
	r := newHostRigWith(t, time.Nanosecond, p, func(d *Deps) { d.PushBudget = -1 })
	var sb strings.Builder
	sb.WriteString("[")
	total := hostQueueSize + 120
	for i := 0; i < total; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"status":"firing","labels":{"alertname":"A%d","severity":"critical","layer":"stack","tier":"page"}}`, i)
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

// ── D-12 on the phone route (QA run 2026-09-03) ─────────────────────────────
//
// The measured symptom was operational, not theoretical: one page-tier alert
// was delivered during the engine-down drill and the operator never got an
// all-clear, because vmalert's Alertmanager-v2 body carries no `status` field
// and the resolve was classified as a repeat firing (then swallowed by the
// trigger's own cool-down). This drives the real HTTP surface with the wire
// shape vmalert actually sends.

// vmalertV2 renders the captured vmalert body: no `status` key, resolution
// signalled purely by endsAt. The host rig's clock is 2026-09-03T12:00:00Z.
func vmalertV2(name, tier, endsAt, summary string) string {
	return fmt.Sprintf(`[{"startsAt":"2026-09-03T11:45:00Z",`+
		`"generatorURL":"http://vmalert:8880/vmalert/alert?group_id=42&alert_id=99",`+
		`"endsAt":%q,"labels":{"alertname":%q,"severity":"critical","layer":"correlation","tier":%q},`+
		`"annotations":{"summary":%q,"description":"detail line"}}]`,
		endsAt, name, tier, summary)
}

func TestVmalertResolveReachesThePhoneAsAnAllClear(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())

	firing := vmalertV2("CorrelationConsumerDead", "page", "2026-09-03T12:04:00Z",
		"correlation consumer group has zero members")
	if w := r.post(t, firing, bearer); w.Code != http.StatusOK {
		t.Fatalf("firing post: %d (%s)", w.Code, w.Body.String())
	}
	page := r.push.await(t, 1)[0]
	if page.Priority != notify.NtfyPriorityHigh {
		t.Fatalf("the firing leg must page: priority = %q", page.Priority)
	}

	resolve := vmalertV2("CorrelationConsumerDead", "page", "2026-09-03T11:58:00Z",
		"correlation consumer group has zero members")
	if w := r.post(t, resolve, bearer); w.Code != http.StatusOK {
		t.Fatalf("resolve post: %d (%s)", w.Code, w.Body.String())
	}
	clear := r.push.await(t, 1)[0]
	if clear.Priority != notify.NtfyPriorityLow {
		t.Errorf("Priority = %q, want %q (an all-clear must not buzz like a page)",
			clear.Priority, notify.NtfyPriorityLow)
	}
	if !strings.Contains(clear.Title, "RESOLVED") {
		t.Errorf("the all-clear must say so on the lock screen: %q", clear.Title)
	}
	r.push.quiet(t)
	txt := metricsText(r.mx)
	for _, want := range []string{
		`netops_alert_webhook_pushed_total{route="host_monitoring",tier="page"} 1`,
		`netops_alert_webhook_pushed_total{route="host_monitoring",tier="resolved"} 1`,
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %s in:\n%s", want, txt)
		}
	}
}

// A warning-tier resolution is still folded, not pushed — the tier ladder is
// unchanged by the status derivation.
func TestVmalertWarningResolveIsStillDigested(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, newFakePusher())
	body := vmalertV2("VectorComponentErrors", "watch", "2026-09-03T11:58:00Z", "component errors cleared")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.quiet(t)
	if n := r.push.count(); n != 0 {
		t.Fatalf("pushes = %d, want 0 — a warning resolution belongs in the digest", n)
	}
	if _, resolved := r.disp.counts(); resolved != 1 {
		t.Error("the product dispatcher must still receive the resolution")
	}
}

func TestStatusOfDerivation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	r := &receiver{now: func() time.Time { return now }}
	for _, tc := range []struct {
		name, status, endsAt, want string
	}{
		{"explicit firing wins", "firing", "2026-09-03T11:00:00Z", statusFiring},
		{"explicit resolved wins", "RESOLVED", "2026-09-03T23:00:00Z", statusResolved},
		{"v2 future endsAt is firing", "", "2026-09-03T12:04:00Z", statusFiring},
		{"v2 past endsAt is resolved", "", "2026-09-03T11:58:00Z", statusResolved},
		{"v2 endsAt == now is resolved", "", "2026-09-03T12:00:00Z", statusResolved},
		{"absent endsAt is firing", "", "", statusFiring},
		{"unparseable endsAt is firing", "", "whenever", statusFiring},
	} {
		if got := r.statusOf(wireAlert{Status: tc.status, EndsAt: tc.endsAt}); got != tc.want {
			t.Errorf("%s: statusOf(status=%q, endsAt=%q) = %q, want %q",
				tc.name, tc.status, tc.endsAt, got, tc.want)
		}
	}
}
