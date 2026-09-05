package notify

// pushbudget_test.go — the SHARED, per-push-server outbound budget.
//
// The defect under test was observed live on 2026-09-03: fourteen product ntfy
// pushes in one hour, each answered `429` and each retried four times, while
// the platform host route's own per-topic bucket still read "full". ntfy.sh
// rate-limits per SOURCE IP, so the two senders were spending one allowance
// through two counters, and the page reserve protected nothing.
//
// Every test here is written against that failure: one bucket per SERVER, both
// senders drawing from it, the reserve honoured across them, and a 429 answered
// by sending LESS rather than four times as much.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/models"
)

type budgetClock struct{ t time.Time }

func (c *budgetClock) now() time.Time          { return c.t }
func (c *budgetClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// The bucket arithmetic is the contract, so it is asserted directly: the
// reserve floor, the page override, continuous refill, the capacity ceiling,
// the clamp on a nonsense reserve, and the -1 "not enforced" reading (which
// must stay distinguishable from an empty bucket).
func TestPushBudgetArithmetic(t *testing.T) {
	c := &budgetClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	b := NewPushBudget("ntfy.sh", 10, 4, c.now)

	for i := 0; i < 6; i++ {
		if !b.Take(false) {
			t.Fatalf("non-privileged take %d refused with %d left", i, b.Remaining())
		}
	}
	if b.Take(false) {
		t.Fatal("a warning spent into the page reserve")
	}
	if got := b.Refused(); got != 1 {
		t.Fatalf("refusals = %d, want 1 — a local refusal must be countable", got)
	}
	for i := 0; i < 4; i++ {
		if !b.Take(true) {
			t.Fatalf("page take %d refused with %d left", i, b.Remaining())
		}
	}
	if b.Take(true) {
		t.Fatal("an empty bucket handed out a token")
	}
	// Continuous refill: half an hour at 10/h is 5 tokens.
	c.advance(30 * time.Minute)
	if got := b.Remaining(); got != 5 {
		t.Fatalf("remaining after 30m at 10/h = %d, want 5", got)
	}
	c.advance(10 * time.Hour)
	if got := b.Remaining(); got != 10 {
		t.Fatalf("remaining = %d, want the capacity 10", got)
	}
	if nb := NewPushBudget("x", 5, 99, c.now); !nb.Take(false) {
		t.Fatal("an over-large reserve starved the non-privileged lane entirely")
	}
	// Disabled: nil bucket, always allows, gauge reads -1 (not 0).
	if nb := NewPushBudget("x", 0, 0, c.now); nb != nil || !nb.Take(false) || nb.Remaining() != -1 {
		t.Fatal("a disabled budget must allow every push and read -1")
	}
}

// The KEY is the fix. Two senders that name the same host in different
// spellings must land in one bucket — the remote rate limiter cannot tell them
// apart either — while a genuinely different host keeps its own.
func TestPushBudgetsAreKeyedByServerHostNotTopic(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "ntfy.sh"},
		{"ntfy.sh", "ntfy.sh"},
		{"https://ntfy.sh", "ntfy.sh"},
		{"HTTPS://NTFY.SH/", "ntfy.sh"},
		{"http://ntfy.internal:8080/push", "ntfy.internal:8080"},
	} {
		if got := PushServerKey(tc.in); got != tc.want {
			t.Errorf("PushServerKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	c := &budgetClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	reg := NewPushBudgets(4, 1, c.now)
	if reg.For("https://ntfy.sh/") != reg.For("NTFY.SH") {
		t.Fatal("the same host in two spellings got two buckets — the whole defect")
	}
	if reg.For("ntfy.sh") == reg.For("ntfy.internal") {
		t.Fatal("two different servers share one rate limiter, which they do not")
	}
	// A disabled registry hands out nil buckets that always allow.
	if b := NewPushBudgets(0, 0, c.now).For("ntfy.sh"); b != nil || !b.Take(false) {
		t.Fatal("capacity <= 0 must disable the guard entirely")
	}
	// Snapshot is the metrics surface: sorted, one row per known server.
	reg.For("ntfy.internal").Take(false)
	got := reg.Snapshot()
	if len(got) != 2 || got[0].Server != "ntfy.internal" || got[1].Server != "ntfy.sh" {
		t.Fatalf("snapshot = %+v, want one sorted row per server", got)
	}
}

// ── the product channel's draw ──────────────────────────────────────────────

// ntfyServer is a stub push server that records requests and answers with a
// scripted status, so the retry ladder is asserted without touching ntfy.sh.
type ntfyServer struct {
	calls  atomic.Int64
	status atomic.Int64
	retry  string
}

func newNtfyServer(t *testing.T, status int, retryAfter string) (*ntfyServer, string) {
	t.Helper()
	s := &ntfyServer{retry: retryAfter}
	s.status.Store(int64(status))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		code := int(s.status.Load())
		if code >= 300 && s.retry != "" {
			w.Header().Set("Retry-After", s.retry)
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return s, srv.URL
}

// The product channel must draw from the SAME bucket the platform route uses,
// and it must never spend the page reserve for anything but a critical alert on
// a channel the operator configured as a pager.
func TestProductNtfyChannelDrawsTheSharedBudgetAndRespectsTheReserve(t *testing.T) {
	c := &budgetClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	_, url := newNtfyServer(t, http.StatusOK, "")
	reg := NewPushBudgets(3, 2, c.now)

	pager := NewNtfy(url, "topic", "").WithBudget(reg.For(url)).WithPagePolicy("critical")
	feed := NewNtfy(url, "topic", "").WithBudget(reg.For(url)).WithPagePolicy("warning")

	// One non-reserved token: the first warning gets it.
	if err := pager.Send(models.Alert{Rule: "CollectorDown", Severity: "warning"}); err != nil {
		t.Fatalf("first warning: %v", err)
	}
	// The second stops at the reserve — this is the push that used to be a 429.
	if err := pager.Send(models.Alert{Rule: "CollectorDown", Severity: "warning"}); !errors.Is(err, ErrPushBudgetExhausted) {
		t.Fatalf("a second warning must be refused locally, got %v", err)
	}
	// A critical on a FEED channel is still not a page: min_severity=warning
	// means the operator wired a feed, and a feed may not spend the reserve.
	if err := feed.Send(models.Alert{Rule: "DeviceUnreachable", Severity: "critical"}); !errors.Is(err, ErrPushBudgetExhausted) {
		t.Fatalf("a critical on a non-pager channel must not reach the reserve, got %v", err)
	}
	// A critical on a PAGER channel may.
	if err := pager.Send(models.Alert{Rule: "DeviceUnreachable", Severity: "critical"}); err != nil {
		t.Fatalf("a critical on a pager channel must spend the reserve: %v", err)
	}
	if got := reg.For(url).Remaining(); got != 1 {
		t.Fatalf("remaining = %d, want 1 (3 - warning - page)", got)
	}
}

// ── the 429 retry policy ────────────────────────────────────────────────────

// budgetLogSpy captures the delivery layer's structured events so the failure
// REASON can be asserted, not just the fact of a failure.
type budgetLogSpy struct {
	mu   sync.Mutex
	msgs []string
}

func (l *budgetLogSpy) log(level, msg string, fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, level+": "+msg+" reason="+text(fields["reason"])+" attempts="+text(fields["attempts"]))
}

func (l *budgetLogSpy) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.msgs, "\n")
}

func (l *budgetLogSpy) contains(sub string) bool { return strings.Contains(l.text(), sub) }

func text(v any) string { return fmt.Sprintf("%v", v) }

// recordWaits swaps the backoff for a recorder, so a retry LADDER is asserted
// exactly instead of being waited out.
func recordWaits(d *Dispatcher, mu *sync.Mutex, waits *[]time.Duration) {
	d.delivery.sleep = func(ctx context.Context, dur time.Duration) bool {
		mu.Lock()
		*waits = append(*waits, dur)
		mu.Unlock()
		return ctx.Err() == nil
	}
}

// A rate-limited WARNING must not retry at all: the server has just said "you
// are sending too much", and four more requests is the wrong answer. Live, this
// was 14 pushes x 4 attempts = 56 requests into a server already refusing us,
// spending the allowance the platform PAGE route needed.
func TestRateLimitedWarningNeverRetries(t *testing.T) {
	s, url := newNtfyServer(t, http.StatusTooManyRequests, "")
	d := NewDispatcher()
	defer d.Close()
	logs := &budgetLogSpy{}
	d.SetLogger(logs.log)
	d.Register(NewSeverityGate(NewNtfy(url, "topic", "").WithPagePolicy("critical"), "info"))

	d.Dispatch(models.Alert{ID: "a1", Rule: "CollectorDown", Severity: "warning"})
	waitUntil(t, "the failure to be reported", func() bool { return logs.contains("FAILED") })

	if got := s.calls.Load(); got != 1 {
		t.Fatalf("requests = %d, want exactly 1 — a warning must never retry a 429", got)
	}
	if !logs.contains("reason=rate_limited") {
		t.Fatalf("the failure was not classified as rate_limited:\n%s", logs.text())
	}
	// The log must report the ATTEMPTS THAT HAPPENED. It used to print the
	// constant 4 regardless, which is how the live log said "attempts: 4" for
	// sends that had a different policy.
	if !logs.contains("attempts=1") {
		t.Fatalf("the log must report the real attempt count:\n%s", logs.text())
	}
}

// A rate-limited PAGE gets exactly ONE retry (not three), and it waits the
// server's own Retry-After when it sent one — the only party that knows when
// its budget refills.
func TestRateLimitedPageRetriesOnceAndHonoursRetryAfter(t *testing.T) {
	s, url := newNtfyServer(t, http.StatusTooManyRequests, "1")
	d := NewDispatcher()
	defer d.Close()
	logs := &budgetLogSpy{}
	d.SetLogger(logs.log)
	var mu sync.Mutex
	var waits []time.Duration
	recordWaits(d, &mu, &waits)
	d.Register(NewSeverityGate(NewNtfy(url, "topic", "").WithPagePolicy("critical"), "critical"))

	d.Dispatch(models.Alert{ID: "a2", Rule: "CorrelationConsumerDead", Severity: "critical"})
	waitUntil(t, "the failure to be reported", func() bool { return logs.contains("FAILED") })

	if got := s.calls.Load(); got != 2 {
		t.Fatalf("requests = %d, want exactly 2 (1 send + 1 bounded retry)", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(waits) != 1 || waits[0] != time.Second {
		t.Fatalf("waits = %v, want a single 1s wait taken from the server's Retry-After", waits)
	}
}

// A 4xx that is NOT 429 is the server saying "you are wrong": a bad token will
// not fix itself, and each retry spends allowance something else needs.
func TestNonRetryableStatusStopsImmediately(t *testing.T) {
	s, url := newNtfyServer(t, http.StatusForbidden, "")
	d := NewDispatcher()
	defer d.Close()
	logs := &budgetLogSpy{}
	d.SetLogger(logs.log)
	d.Register(NewNtfy(url, "topic", ""))

	d.Dispatch(models.Alert{ID: "a3", Rule: "CollectorDown", Severity: "critical"})
	waitUntil(t, "the failure to be reported", func() bool { return logs.contains("FAILED") })

	if got := s.calls.Load(); got != 1 {
		t.Fatalf("requests = %d, want exactly 1 for a 403", got)
	}
	if !logs.contains("reason=rejected") {
		t.Fatalf("a 403 must be classified as rejected:\n%s", logs.text())
	}
}

// A 5xx keeps the ORIGINAL budget — the no-regression guard: this change
// narrows the rate-limit lane only, it does not make the platform give up on a
// transient server fault.
func TestServerErrorKeepsTheFullRetryBudget(t *testing.T) {
	s, url := newNtfyServer(t, http.StatusBadGateway, "")
	d := NewDispatcher()
	defer d.Close()
	fastRetries(d)
	logs := &budgetLogSpy{}
	d.SetLogger(logs.log)
	d.Register(NewNtfy(url, "topic", ""))

	d.Dispatch(models.Alert{ID: "a4", Rule: "CollectorDown", Severity: "critical"})
	waitUntil(t, "the failure to be reported", func() bool { return logs.contains("FAILED") })

	if got := s.calls.Load(); got != deliveryAttempts {
		t.Fatalf("requests = %d, want the full %d attempts for a 502", got, deliveryAttempts)
	}
}

// A LOCAL budget refusal is never retried — the request was not made and the
// token has not refilled — and it is reported as such, not as a send error.
func TestBudgetRefusalIsNotRetried(t *testing.T) {
	c := &budgetClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	s, url := newNtfyServer(t, http.StatusOK, "")
	reg := NewPushBudgets(1, 0, c.now)
	d := NewDispatcher()
	defer d.Close()
	logs := &budgetLogSpy{}
	d.SetLogger(logs.log)
	d.Register(NewNtfy(url, "topic", "").WithBudget(reg.For(url)))

	// The two sends are ORDERED deliberately. The dispatcher runs eight delivery
	// workers, so dispatching both at once lets the refusal be logged before the
	// accepted push has reached the server — the assertion below then reads
	// `requests = 0` and the test fails for a reason that has nothing to do with
	// the budget (observed on CI under -race, which widens that window).
	//
	// So: dispatch the first, and wait for the server to have SEEN it. The token
	// is taken before the request is built (Ntfy.Push takes it first), so once
	// the request has arrived the bucket is provably empty — and the clock is a
	// frozen budgetClock, so nothing refills it.
	d.Dispatch(models.Alert{ID: "b1", Rule: "CollectorDown", Severity: "warning"})
	waitUntil(t, "the first push to reach the server", func() bool { return s.calls.Load() == 1 })

	// Only now is the second attempted, and it must be refused LOCALLY: no
	// request, no retry ladder.
	d.Dispatch(models.Alert{ID: "b2", Rule: "CollectorDown", Severity: "warning"})
	waitUntil(t, "the local refusal to be reported", func() bool {
		return logs.contains("reason=budget_exhausted")
	})

	if got := s.calls.Load(); got != 1 {
		t.Fatalf("requests = %d, want exactly 1 — the second was refused locally", got)
	}
	if !logs.contains("FAILED") {
		t.Fatalf("a local refusal must be reported as a delivery failure:\n%s", logs.text())
	}
}

// The gauge and the refusal counter are per SERVER, which is the granularity
// the remote limiter enforces at (§10).
func TestPushBudgetMetricsAreLabelledByServer(t *testing.T) {
	c := &budgetClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	reg := NewPushBudgets(2, 0, c.now)
	reg.For("https://ntfy.sh").Take(false)
	reg.For("ntfy.sh").Take(false)
	reg.For("ntfy.sh").Take(false) // refused: the bucket is shared

	d := NewDispatcher()
	defer d.Close()
	d.SetPushBudgets(reg)
	var b strings.Builder
	d.WriteMetrics(&b)
	out := b.String()
	if !strings.Contains(out, `netops_notify_push_budget_remaining{server="ntfy.sh"} 0`) {
		t.Errorf("the per-server gauge is missing:\n%s", out)
	}
	if !strings.Contains(out, `netops_notify_push_budget_refused_total{server="ntfy.sh"} 1`) {
		t.Errorf("the per-server refusal counter is missing:\n%s", out)
	}
}

// A configured push server that yields no host has THREE distinguishable
// outcomes, not two. Collapsing "that is not a URL" into "it named no host"
// (the `if err != nil || u.Host == ""` this replaced) reports a broken setting
// as an ordinary bucket key — the caller cannot tell a typo from a well-formed
// value that happens to carry no authority (§10).
func TestPushServerParseKeepsTheThreeStatesApart(t *testing.T) {
	for _, tc := range []struct {
		in     string
		key    string
		parse  pushServerParse
		reason string
	}{
		{"https://ntfy.sh", "ntfy.sh", pushServerOK, ""},
		{"", "ntfy.sh", pushServerOK, ""}, // unset is the default, NOT a fault
		{"ntfy.internal:8080", "ntfy.internal:8080", pushServerOK, ""},
		// Not a URL at all: a FAULT the HTTP client will refuse too.
		{"ht tp://ntfy.sh", "ht tp://ntfy.sh", pushServerUnreadable, "unreadable"},
		// Well-formed, but names no server.
		{"file:///var/run/ntfy", "file:///var/run/ntfy", pushServerNoHost, "no_host"},
	} {
		key, parse := parsePushServerKey(tc.in)
		if key != tc.key || parse != tc.parse || parse.reason() != tc.reason {
			t.Errorf("parsePushServerKey(%q) = (%q, %v/%q), want (%q, %v/%q)",
				tc.in, key, parse, parse.reason(), tc.key, tc.parse, tc.reason)
		}
		if got := PushServerKey(tc.in); got != tc.key {
			t.Errorf("PushServerKey(%q) = %q, want %q — the shim must agree with the core", tc.in, got, tc.key)
		}
	}

	// A degraded server must NOT be collapsed into the default bucket: that
	// would spend a real server's allowance under a misconfigured name.
	c := &budgetClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	reg := NewPushBudgets(4, 1, c.now)
	if reg.For("ht tp://ntfy.sh") == reg.For("https://ntfy.sh") {
		t.Fatal("a misconfigured server shares the real server's budget")
	}
	// The fault is REPORTED, with its reason, and lands on the metrics surface.
	bad, why := reg.For("ht tp://ntfy.sh").Misconfigured()
	if !bad || why != "unreadable" {
		t.Fatalf("Misconfigured() = (%v, %q), want (true, \"unreadable\")", bad, why)
	}
	if ok, why := reg.For("https://ntfy.sh").Misconfigured(); ok || why != "" {
		t.Fatalf("a healthy server reported misconfigured: (%v, %q)", ok, why)
	}
	d := NewDispatcher()
	defer d.Close()
	d.SetPushBudgets(reg)
	var b strings.Builder
	d.WriteMetrics(&b)
	out := b.String()
	if !strings.Contains(out, `netops_notify_push_server_misconfigured{server="ht tp://ntfy.sh"} 1`) {
		t.Errorf("the configuration fault is not surfaced:\n%s", out)
	}
	// Present as a 0 for a healthy server — "correct" is a value, not a gap.
	if !strings.Contains(out, `netops_notify_push_server_misconfigured{server="ntfy.sh"} 0`) {
		t.Errorf("the healthy server has no series at all:\n%s", out)
	}
}
