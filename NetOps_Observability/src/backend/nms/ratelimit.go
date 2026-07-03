package nms

import (
	"context"
	"sync"
	"time"
)

// ratelimit.go — a token-bucket RateLimiter (per integration). Meraki caps at
// 10 req/s per org; Prime wants conservative limits. stdlib-only (no
// golang.org/x/time/rate — keeps the dependency graph minimal).

// TokenBucket is a simple refilling token bucket. Safe for concurrent use.
type TokenBucket struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	ratePerSec float64
	last     time.Time
	now      func() time.Time // injectable clock for tests
	sleep    func(context.Context, time.Duration) error
}

// NewTokenBucket builds a bucket of ratePerSec sustained rate and burst = ceil
// (at least 1). ratePerSec <= 0 → unlimited (Wait never blocks).
func NewTokenBucket(ratePerSec float64) *TokenBucket {
	burst := ratePerSec
	if burst < 1 {
		burst = 1
	}
	return &TokenBucket{
		capacity:   burst,
		tokens:     burst,
		ratePerSec: ratePerSec,
		now:        time.Now,
		sleep:      sleepCtx,
	}
}

// Wait blocks until a token is available or ctx is done. Unlimited if rate<=0.
func (b *TokenBucket) Wait(ctx context.Context) error {
	if b.ratePerSec <= 0 {
		return ctx.Err()
	}
	for {
		b.mu.Lock()
		now := b.now()
		if b.last.IsZero() {
			b.last = now
		}
		// Refill.
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.ratePerSec
			if b.tokens > b.capacity {
				b.tokens = b.capacity
			}
			b.last = now
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		// Time until the next token.
		need := (1 - b.tokens) / b.ratePerSec
		b.mu.Unlock()
		if err := b.sleep(ctx, time.Duration(need*float64(time.Second))); err != nil {
			return err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
