package alertwebhook

// pushbudget.go — the OUTBOUND PUSH BUDGET for the host-monitoring route.
//
// WHY THIS EXISTS. Observed live 2026-09-03 ~04:00 UTC: ntfy.sh's free public
// server rate-limits per topic/IP, and the route was spending that budget on
// chronic warnings (VectorComponentErrors, CorrDeadLettersRising,
// DiskHeadroomLow, …) which repeat every cool-down forever. Every one of those
// pushes is budget a real PAGE might need in the next minute, and the api log
// showed exactly that: repeated `ntfy: status 429`.
//
// The digest (digest.go) removes most of that traffic. This bucket is the
// BACKSTOP for what the digest cannot predict — a genuinely novel warning
// storm, a second stack sharing the topic, someone else's client on the same
// public IP. It is a classic token bucket with ONE addition: the last
// `reserve` tokens are spendable by PAGE-tier traffic only. A warning can
// therefore never be the reason a page is refused.
//
// Refill is continuous (capacity per hour, prorated per nanosecond) rather than
// per-window, so a burst does not have to wait for a window edge and the gauge
// moves smoothly instead of sawtoothing.

import (
	"sync"
	"time"
)

// Budget defaults. Deliberately conservative against ntfy.sh's free tier: the
// public server's documented allowance is a small per-visitor burst refilled
// slowly, and the whole point of this file is to stay under it rather than to
// discover the limit by being refused.
const (
	// DefaultPushBudget is the sustained outbound push allowance per hour for
	// the route's topic.
	DefaultPushBudget = 30
	// DefaultPageReserve is how many of those tokens ONLY a page (or the
	// resolution of one) may spend.
	DefaultPageReserve = 10
)

// pushBudget is the per-topic token bucket. One receiver drives one topic, so
// one bucket per receiver is one bucket per topic.
type pushBudget struct {
	mu       sync.Mutex
	capacity float64
	reserve  float64
	perNano  float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

// newPushBudget builds the bucket FULL: a freshly started api may legitimately
// need to page immediately, and starting empty would mean the first alert of
// the process's life is the one that gets refused.
//
// capacity <= 0 disables the guard entirely (documented as the escape hatch for
// a self-hosted ntfy with no limits); reserve is clamped into [0, capacity-1]
// so a misconfiguration can never reserve the whole bucket and starve the
// warning digest completely — nor leave a page unprotected.
func newPushBudget(capacity, reserve int, now func() time.Time) *pushBudget {
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
	return &pushBudget{
		capacity: float64(capacity),
		reserve:  float64(reserve),
		perNano:  float64(capacity) / float64(time.Hour),
		tokens:   float64(capacity),
		last:     now(),
		now:      now,
	}
}

// refill must be called with the lock held.
func (b *pushBudget) refill(now time.Time) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += float64(elapsed) * b.perNano
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
}

// take spends one token, or reports that there is none to spend. privileged
// callers (page tier, and the resolution of a page) may spend down to zero;
// everything else stops at the reserve. A nil bucket always allows — "no
// budget configured" is not "no pushes".
func (b *pushBudget) take(privileged bool) bool {
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
		return false
	}
	b.tokens--
	return true
}

// remaining is the gauge value: whole tokens available right now. Nil-safe and
// side-effect-free apart from the refill, which is what makes the gauge honest
// between pushes instead of frozen at the last take.
func (b *pushBudget) remaining() int {
	if b == nil {
		return -1 // "no budget configured" — distinguishable from an empty one
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(b.now())
	return int(b.tokens)
}
