package main

import (
	"sync"
	"time"
)

// export_ratelimit.go — a per-tenant fixed-window limiter guarding the export
// endpoints against flooding and enumeration. Per-TENANT (not global) so one
// abusive tenant can't starve others (noisy-neighbor), and keyed off the
// authenticated tenant rather than a (spoofable) client IP.

type tenantRateLimiter struct {
	mu      sync.Mutex
	windows map[string]*rlWindow
}

type rlWindow struct {
	start time.Time
	count int
}

func newTenantRateLimiter() *tenantRateLimiter {
	return &tenantRateLimiter{windows: make(map[string]*rlWindow)}
}

// allow reports whether a request for tenant may proceed in the current minute.
// The per-minute budget is read live (EXPORT_RATE_PER_MIN) so the runtime export
// policy takes effect without a restart; ≤0 disables the limit.
func (l *tenantRateLimiter) allow(tenant string) bool {
	return l.allowN(tenant, envInt("EXPORT_RATE_PER_MIN", 10))
}

// rlSweepThreshold is the map size above which allowN reclaims expired windows.
// Sweeping is O(n), so it runs only when the map is big enough for the scan to
// pay for itself.
const rlSweepThreshold = 1024

// allowN is the generic per-key fixed-window check: at most perMin requests per
// key per minute (≤0 disables). Keyed off an authenticated identity (tenant, or
// tenant|user) — never a spoofable client IP.
//
// F-33: this map had no deletion path. A window whose minute had elapsed was
// OVERWRITTEN when the same key came back, but a key that never returned stayed
// forever. The copilot limiter keys on tenant|user, so the map grew with every
// principal that ever made one request and never shrank for the life of the
// process.
func (l *tenantRateLimiter) allowN(key string, perMin int) bool {
	if l == nil || perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.windows) >= rlSweepThreshold {
		l.sweepLocked(now)
	}
	w := l.windows[key]
	if w == nil || now.Sub(w.start) >= time.Minute {
		l.windows[key] = &rlWindow{start: now, count: 1}
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
func (l *tenantRateLimiter) sweepLocked(now time.Time) {
	for k, w := range l.windows {
		if now.Sub(w.start) >= time.Minute {
			delete(l.windows, k)
		}
	}
}

// size reports the number of tracked windows (tests + leak assertions).
func (l *tenantRateLimiter) size() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.windows)
}
