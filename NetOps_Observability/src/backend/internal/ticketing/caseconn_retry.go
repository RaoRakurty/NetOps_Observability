package ticketing

// caseconn_retry.go — the bounded retry every TAC connector call runs through
// (CLAUDE.md §9: all network calls retry with backoff + jitter; all queues and
// loops are bounded).
//
// It differs from the outbox worker's backoffDelay in scale, not in principle:
// the worker schedules minutes-to-hours across a persisted queue, this one
// bounds a single interactive call an operator is waiting on. Jitter is
// DETERMINISTIC (hash of the idempotency key + attempt), not math/rand — the
// same reason the worker does it: two tenants retrying the same failing vendor
// must not march in lockstep, and a test must be able to assert an exact delay.

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"time"
)

// RetryPolicy bounds one connector call.
type RetryPolicy struct {
	MaxAttempts int           // total attempts, including the first
	Base        time.Duration // first backoff
	Cap         time.Duration // ceiling before jitter
}

// DefaultCaseRetry is the interactive-call policy: three attempts over ~4.5 s
// worst case. An operator is watching; a longer curve belongs in the outbox.
func DefaultCaseRetry() RetryPolicy {
	return RetryPolicy{MaxAttempts: 3, Base: 1 * time.Second, Cap: 8 * time.Second}
}

// caseBackoff is capped exponential backoff with 0-50% deterministic jitter.
func caseBackoff(p RetryPolicy, attempt int, key string) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 16 { // guard the Pow: 2^16 is already far past any cap
		attempt = 16
	}
	base := time.Duration(float64(p.Base) * math.Pow(2, float64(attempt-1)))
	if p.Cap > 0 && base > p.Cap {
		base = p.Cap
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))           // hash.Write never returns an error
	_, _ = h.Write([]byte{byte(attempt)}) // hash.Write never returns an error
	frac := float64(h.Sum32()) / float64(math.MaxUint32)
	return base + time.Duration(frac*0.5*float64(base))
}

// retryable reports whether one more attempt could plausibly succeed. Permanent
// rejections (bad payload, revoked credential), entitlement refusals, oversize
// bundles and unsupported capabilities are terminal — retrying burns the
// operator's time and, for a create, risks a duplicate case.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	var perm PermanentDeliveryError
	if errors.As(err, &perm) {
		return false
	}
	var ent EntitlementError
	if errors.As(err, &ent) {
		return false
	}
	var big AttachTooLargeError
	if errors.As(err, &big) {
		return false
	}
	if errors.Is(err, ErrUnsupported) || errors.Is(err, ErrNotConfigured) ||
		errors.Is(err, ErrNotOnboarded) || errors.Is(err, ErrNotApproved) ||
		errors.Is(err, context.Canceled) {
		return false
	}
	return true
}

// retryDelay picks the wait before the next attempt, honouring a provider's
// Retry-After over our own curve (research §8.5).
func retryDelay(p RetryPolicy, err error, attempt int, key string) time.Duration {
	var rl RateLimitedError
	if errors.As(err, &rl) && rl.After > 0 {
		if p.Cap > 0 && rl.After > p.Cap {
			return p.Cap
		}
		return rl.After
	}
	return caseBackoff(p, attempt, key)
}

// withRetry runs fn under the policy. key seeds the jitter and MUST be the
// call's idempotency key so a retried create is deduplicated by the vendor.
func withRetry[T any](ctx context.Context, p RetryPolicy, key string, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T
	if p.MaxAttempts < 1 {
		p.MaxAttempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= p.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return zero, fmt.Errorf("%w (last error: %w)", err, lastErr)
			}
			return zero, err
		}
		out, err := fn(ctx)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !retryable(err) || attempt == p.MaxAttempts {
			return zero, err
		}
		select {
		case <-ctx.Done():
			return zero, fmt.Errorf("%w (last error: %w)", ctx.Err(), lastErr)
		case <-time.After(retryDelay(p, err, attempt, key)):
		}
	}
	return zero, lastErr
}
