// Package ratelimit is the per-key fixed-window request limiter guarding the
// export, verify and copilot endpoints against flooding and enumeration.
// Keys are AUTHENTICATED identities (tenant, or tenant|user) — never a
// spoofable client IP — so one abusive principal can't starve others
// (noisy-neighbor). The per-minute budget is the caller's to supply on every
// call (read live from its own config/env), so runtime policy changes take
// effect without a restart and this package stays free of config knowledge.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a per-key fixed-window counter. The zero value is not usable;
// construct with New.
type Limiter struct {
	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	start time.Time
	count int
}

func New() *Limiter {
	return &Limiter{windows: make(map[string]*window)}
}

// sweepThreshold is the map size above which AllowN reclaims expired windows.
// Sweeping is O(n), so it runs only when the map is big enough for the scan to
// pay for itself.
const sweepThreshold = 1024

// AllowN is the generic per-key fixed-window check: at most perMin requests per
// key per minute (≤0 disables).
//
// F-33: this map had no deletion path. A window whose minute had elapsed was
// OVERWRITTEN when the same key came back, but a key that never returned stayed
// forever. The copilot limiter keys on tenant|user, so the map grew with every
// principal that ever made one request and never shrank for the life of the
// process.
func (l *Limiter) AllowN(key string, perMin int) bool {
	if l == nil || perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.windows) >= sweepThreshold {
		l.sweepLocked(now)
	}
	w := l.windows[key]
	if w == nil || now.Sub(w.start) >= time.Minute {
		l.windows[key] = &window{start: now, count: 1}
		return true
	}
	if w.count >= perMin {
		return false
	}
	w.count++
	return true
}

// sweepLocked drops windows whose minute has elapsed. Removing an expired
// window can never weaken the limit: a fresh window is created on the next
// request with count=1, which is exactly what the expired one would have been
// reset to.
func (l *Limiter) sweepLocked(now time.Time) {
	for k, w := range l.windows {
		if now.Sub(w.start) >= time.Minute {
			delete(l.windows, k)
		}
	}
}

// Size reports the number of tracked windows (tests + leak assertions).
func (l *Limiter) Size() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.windows)
}
