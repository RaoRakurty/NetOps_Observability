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
	perMin := envInt("EXPORT_RATE_PER_MIN", 10)
	if l == nil || perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w := l.windows[tenant]
	if w == nil || now.Sub(w.start) >= time.Minute {
		l.windows[tenant] = &rlWindow{start: now, count: 1}
		return true
	}
	if w.count >= perMin {
		return false
	}
	w.count++
	return true
}
