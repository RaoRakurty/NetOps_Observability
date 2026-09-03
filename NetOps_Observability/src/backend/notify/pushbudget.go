package notify

// pushbudget.go — the OUTBOUND PUSH BUDGET, keyed by PUSH SERVER HOST.
//
// WHY THIS MOVED HERE (2026-09-03, second live incident). The first version of
// this bucket lived in internal/alertwebhook and was keyed PER TOPIC, one
// bucket per receiver. That is the wrong key: **ntfy.sh rate-limits per source
// IP**, not per topic. Both of this process's ntfy senders — the platform
// self-health HOST route (internal/alertwebhook/hostroute.go) and the PRODUCT
// notification channel (ntfy.go) — leave the box on the same address, so they
// spend ONE server-side allowance while each believed it owned a private one.
//
// The live evidence: 14 pushes on the PRODUCT channel in an hour
// (CollectorDown ×6, CollectorAllTargetsUnreachable ×6, DeviceUnreachable ×2),
// each retried four times against `ntfy: status 429` — 56 requests — while the
// host route's own bucket still read "full" and would have let a PAGE through
// to a server that was already refusing everything. The page reserve protected
// nothing, because the traffic it had to be protected FROM was not counted in
// the same bucket.
//
// So the bucket is now keyed by the server HOST and shared: every sender aimed
// at `ntfy.sh` draws from the same tokens, and the page reserve is honoured
// ACROSS both routes. A self-hosted ntfy on another host keeps its own bucket,
// which is the correct behaviour — it is a different rate limiter.
//
// WHAT COUNTS AS A PAGE (the reserve is deliberately narrow):
//
//   - HOST route: `tier: page` — the four page conditions from
//     rules-scale-slo.yaml — and the RESOLUTION of one. Unchanged.
//   - PRODUCT side: an alert of severity `critical` on an ntfy channel the
//     operator configured AS A PAGER, i.e. whose min_severity is `critical`
//     (Ntfy.WithPagePolicy → Ntfy.Pages). A critical on a channel gated at
//     `warning`/`info` is a FEED, not a pager, and does not qualify.
//
// That is the whole definition and it is not widened anywhere: everything else
// — every warning, every info, every non-pager channel — stops at the reserve.
//
// Refill is continuous (capacity per hour, prorated per nanosecond) rather than
// per-window, so a burst does not have to wait for a window edge and the gauge
// moves smoothly instead of sawtoothing.

import (
	"errors"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Budget defaults. Deliberately conservative against ntfy.sh's free tier: the
// public server's documented allowance is a small per-visitor burst refilled
// slowly, and the whole point of this file is to stay under it rather than to
// discover the limit by being refused.
//
// The operator knobs are still spelled PLATFORM_ALERTS_PUSH_BUDGET and
// PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE (internal/alertwebhook/hostroute.go
// owns those names). They now govern the SERVER-wide budget shared by the
// platform and product routes, not one route's topic.
const (
	// DefaultPushBudget is the sustained outbound push allowance per hour for
	// one push server host, across every sender in this process.
	DefaultPushBudget = 30
	// DefaultPageReserve is how many of those tokens ONLY a page (or the
	// resolution of one) may spend.
	DefaultPageReserve = 10
)

// DefaultNtfyServer is the public ntfy server assumed when none is configured.
// Declared here rather than inline in NewNtfy so the budget key and the request
// URL can never disagree about which host is being talked to.
const DefaultNtfyServer = "https://ntfy.sh"

// ErrPushBudgetExhausted is a LOCAL refusal: the shared allowance for this push
// server is spent, so the request was never made. It is deliberately distinct
// from an *NtfyStatusError 429 (the server refused) — one is our own guard
// working, the other is the guard having failed — and it is NOT retryable:
// re-sending inside the delivery budget only burns a worker on a token that has
// not refilled yet.
var ErrPushBudgetExhausted = errors.New("push budget exhausted for this push server — the request was not sent")

// PushBudget is the token bucket for ONE push server host, shared by every
// sender aimed at that host.
type PushBudget struct {
	server string
	// parse records whether `server` is a real host or a degraded fallback, so
	// a misconfigured push server is REPORTED rather than silently becoming an
	// odd-looking metric label (§10).
	parse pushServerParse

	mu       sync.Mutex
	capacity float64
	reserve  float64
	perNano  float64
	tokens   float64
	last     time.Time
	now      func() time.Time

	refused atomic.Uint64
}

// NewPushBudget builds a bucket FULL: a freshly started api may legitimately
// need to page immediately, and starting empty would mean the first alert of
// the process's life is the one that gets refused.
//
// capacity <= 0 disables the guard entirely (documented as the escape hatch for
// a self-hosted ntfy with no limits) by returning nil — every method is
// nil-safe, so callers need no branch. reserve is clamped into [0, capacity-1]
// so a misconfiguration can never reserve the whole bucket and starve the
// warning digest completely — nor leave a page unprotected.
func NewPushBudget(server string, capacity, reserve int, now func() time.Time) *PushBudget {
	if now == nil {
		now = time.Now
	}
	if capacity <= 0 {
		return nil
	}
	if reserve < 0 {
		reserve = 0
	}
	if reserve > capacity-1 {
		reserve = capacity - 1
	}
	key, parse := parsePushServerKey(server)
	return &PushBudget{
		server:   key,
		parse:    parse,
		capacity: float64(capacity),
		reserve:  float64(reserve),
		perNano:  float64(capacity) / float64(time.Hour),
		tokens:   float64(capacity),
		last:     now(),
		now:      now,
	}
}

// refill must be called with the lock held.
func (b *PushBudget) refill(now time.Time) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += float64(elapsed) * b.perNano
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
}

// Take spends one token, or reports that there is none to spend. privileged
// callers (see "WHAT COUNTS AS A PAGE" above) may spend down to zero;
// everything else stops at the reserve. A nil bucket always allows — "no budget
// configured" is not "no pushes".
func (b *PushBudget) Take(privileged bool) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(b.now())
	floor := b.reserve
	if privileged {
		floor = 0
	}
	if b.tokens < floor+1 {
		b.refused.Add(1) // atomic: safe to touch under the bucket lock
		return false
	}
	b.tokens--
	return true
}

// Remaining is the gauge value: whole tokens available right now. Nil-safe and
// side-effect-free apart from the refill, which is what makes the gauge honest
// between pushes instead of frozen at the last take.
func (b *PushBudget) Remaining() int {
	if b == nil {
		return -1 // "no budget configured" — distinguishable from an empty one
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(b.now())
	return int(b.tokens)
}

// Server is the normalized host this bucket governs (the metric label value).
func (b *PushBudget) Server() string {
	if b == nil {
		return ""
	}
	return b.server
}

// Misconfigured reports whether the configured push server could not be
// resolved to a host, and why ("unreadable" / "no_host"). A nil bucket is not
// misconfigured — it is a disabled guard, which is a different fact.
func (b *PushBudget) Misconfigured() (bool, string) {
	if b == nil {
		return false, ""
	}
	return b.parse != pushServerOK, b.parse.reason()
}

// Refused counts local refusals — pushes this guard stopped before the request.
func (b *PushBudget) Refused() uint64 {
	if b == nil {
		return 0
	}
	return b.refused.Load()
}

// PushBudgets is the process's registry of per-server buckets. It is
// CONSTRUCTED ONCE at wiring and INJECTED (no package global, no hidden
// singleton — CLAUDE.md §2/§5); every sender that talks to a push server asks
// it for the bucket of the host it is about to call.
type PushBudgets struct {
	capacity int
	reserve  int
	now      func() time.Time

	mu       sync.Mutex
	byServer map[string]*PushBudget
}

// NewPushBudgets builds the registry. capacity <= 0 means "no budget guard"
// and every For() then yields a nil (always-allow) bucket.
func NewPushBudgets(capacity, reserve int, now func() time.Time) *PushBudgets {
	if now == nil {
		now = time.Now
	}
	return &PushBudgets{
		capacity: capacity,
		reserve:  reserve,
		now:      now,
		byServer: map[string]*PushBudget{},
	}
}

// For returns the bucket for a push server, creating it on first use. Two
// senders naming the same host in different spellings ("ntfy.sh",
// "https://ntfy.sh/", "HTTPS://NTFY.SH") get the SAME bucket — that is the
// whole point, since the server's own rate limiter cannot tell them apart
// either. A nil registry yields a nil bucket (always allow).
func (r *PushBudgets) For(server string) *PushBudget {
	if r == nil || r.capacity <= 0 {
		return nil
	}
	key := PushServerKey(server)
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok := r.byServer[key]; ok {
		return b
	}
	// The ORIGINAL string, not the derived key: the bucket must reach the same
	// verdict the map key was derived from, and re-parsing an already-degraded
	// key could turn "unreadable" into "no_host".
	b := NewPushBudget(server, r.capacity, r.reserve, r.now)
	r.byServer[key] = b
	return b
}

// PushBudgetState is one server's live budget, for the metrics surface.
type PushBudgetState struct {
	Server    string
	Remaining int
	Refused   uint64
	// Misconfigured is true when Server is a degraded fallback rather than a
	// host parsed out of the configured URL, and Reason says which of the two
	// degraded states it is.
	Misconfigured bool
	Reason        string
}

// Snapshot reports every known server's budget, sorted by host so the metric
// output is stable between scrapes. The label set is bounded by the number of
// CONFIGURED push servers (one or two in practice) — nothing an alert payload
// carries can mint a series here (§10 cardinality).
func (r *PushBudgets) Snapshot() []PushBudgetState {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	out := make([]PushBudgetState, 0, len(r.byServer))
	for _, b := range r.byServer {
		bad, why := b.Misconfigured()
		out = append(out, PushBudgetState{
			Server: b.Server(), Remaining: b.Remaining(), Refused: b.Refused(),
			Misconfigured: bad, Reason: why,
		})
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Server < out[j].Server })
	return out
}

// pushServerParse says WHY a configured push server did not yield a host.
//
// "The operator typed something that is not a URL" and "it parsed, but names no
// server" are DIFFERENT facts, and a function that collapses them reports a
// broken configuration as an ordinary bucket key (CLAUDE.md §10). Same
// three-state shape as internal/bgpdepth's parseASNValue.
type pushServerParse int

const (
	// pushServerOK: the value named a host, and that host is the bucket key.
	pushServerOK pushServerParse = iota
	// pushServerUnreadable: the value is not a URL at all. A FAULT — the HTTP
	// client will refuse it too, so every push to this "server" is already
	// failing and the operator needs to see the cause here.
	pushServerUnreadable
	// pushServerNoHost: well-formed, but carries no authority (a bare path, a
	// scheme with nothing after it). Not a parse fault, still unusable as a
	// rate-limit key.
	pushServerNoHost
)

func (p pushServerParse) reason() string {
	switch p {
	case pushServerUnreadable:
		return "unreadable"
	case pushServerNoHost:
		return "no_host"
	default:
		return ""
	}
}

// PushServerKey normalizes a configured push-server URL to the HOST that a rate
// limiter actually sees. Scheme, path, credentials and trailing slashes are
// irrelevant to "which server's allowance am I spending", so they are dropped.
//
// It is the string-only shim over parsePushServerKey, for callers that just
// need a map key. A caller that must REPORT a broken server setting uses the
// three states directly — NewPushBudget does, and carries the verdict into
// PushBudget.Misconfigured and the metrics surface.
func PushServerKey(server string) string {
	key, _ := parsePushServerKey(server)
	return key
}

// parsePushServerKey is the three-state core.
//
// Both degraded states fall back to the value's own literal text rather than to
// the default server: collapsing a misconfigured entry into the `ntfy.sh`
// bucket would make it spend a REAL server's allowance, which is precisely the
// cross-sender conflation this file exists to prevent. The fallback is
// deterministic, so two senders configured identically-wrongly still share one
// bucket.
func parsePushServerKey(server string) (string, pushServerParse) {
	raw := strings.TrimSpace(server)
	s := raw
	if s == "" {
		s = DefaultNtfyServer // unset is not misconfigured — it is the default
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return literalPushServerKey(raw), pushServerUnreadable
	}
	if u.Host == "" {
		return literalPushServerKey(raw), pushServerNoHost
	}
	return strings.ToLower(u.Host), pushServerOK
}

// literalPushServerKey is the degraded key: the configured text itself, folded
// so that spelling variants of the same broken value still collide.
func literalPushServerKey(raw string) string {
	return strings.ToLower(strings.Trim(raw, "/"))
}
