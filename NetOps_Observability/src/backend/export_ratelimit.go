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

// allowN is the generic per-key fixed-window check: at most perMin requests per
// key per minute (≤0 disables). Keyed off an authenticated identity (tenant, or
// tenant|user) — never a spoofable client IP.
func (l *tenantRateLimiter) allowN(key string, perMin int) bool {
	if l == nil || perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
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
