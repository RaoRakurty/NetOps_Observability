package nms

import (
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// retry.go — the retry policy: exponential backoff with jitter, honoring HTTP
// 429 Retry-After. Pure + deterministic given a jitter source (so it's testable
// without sleeping).

// ExpoRetry is the default RetryPolicy.
type ExpoRetry struct {
	Base     time.Duration // first backoff (e.g. 500ms)
	Max      time.Duration // cap per delay (e.g. 30s)
	MaxTries int           // total attempts before giving up (e.g. 5)
	// Jitter returns a fraction in [0,1) added to the backoff; injected for
	// determinism in tests. Nil → no jitter.
	Jitter func() float64
}

// DefaultRetry returns a sane policy: 500ms base, 30s cap, 5 tries, and REAL
// jitter — every production caller gets it.
//
// The hook existed and was unit-tested but was never wired, so every connector
// that failed during one upstream outage retried on an identical schedule and
// hit the recovering controller as a synchronized herd (§9). Tests that need a
// deterministic delay override Jitter (or build ExpoRetry directly).
func DefaultRetry() ExpoRetry {
	return ExpoRetry{Base: 500 * time.Millisecond, Max: 30 * time.Second, MaxTries: 5, Jitter: randJitter}
}

// randJitter spreads a delay uniformly over [delay, 2*delay). Not
// cryptographic and doesn't need to be: it exists to decorrelate clients, not
// to be unguessable.
func randJitter() float64 { return rand.Float64() }

// Next implements RetryPolicy. 429/503 with a Retry-After always wins (we obey
// the server). Retries on 429, 5xx, and transport errors (status 0). 4xx other
// than 429 are terminal (no point retrying a bad request/auth — auth is handled
// by re-auth, not retry).
func (e ExpoRetry) Next(attempt, status int, retryAfter time.Duration) (time.Duration, bool) {
	if attempt >= e.MaxTries {
		return 0, false
	}
	retriable := status == 0 || status == http.StatusTooManyRequests || status >= 500
	if !retriable {
		return 0, false
	}
	if retryAfter > 0 {
		return capDelay(retryAfter, e.Max), true
	}
	// Exponential: base * 2^(attempt-1), capped, plus optional jitter.
	delay := e.Base
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= e.Max {
			delay = e.Max
			break
		}
	}
	delay = capDelay(delay, e.Max)
	if e.Jitter != nil {
		delay += time.Duration(float64(delay) * e.Jitter())
		delay = capDelay(delay, e.Max)
	}
	return delay, true
}

func capDelay(d, max time.Duration) time.Duration {
	if max > 0 && d > max {
		return max
	}
	return d
}

// ParseRetryAfter reads a Retry-After header (delta-seconds or HTTP-date).
// Returns 0 if absent/unparseable. now is injected for date-form testing.
func ParseRetryAfter(h http.Header, now time.Time) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
