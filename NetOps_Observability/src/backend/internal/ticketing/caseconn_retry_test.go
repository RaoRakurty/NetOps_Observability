// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_retry_test.go — the bounded retry. The properties that matter are
// that it STOPS (bounded attempts), that it does not retry things a retry
// cannot fix, that the jitter spreads two callers apart deterministically, and
// that a provider's Retry-After beats our own curve.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func fastPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 3, Base: time.Millisecond, Cap: 4 * time.Millisecond}
}

func TestRetryIsBoundedAndReturnsTheLastError(t *testing.T) {
	calls := 0
	boom := errors.New("upstream 503")
	_, err := withRetry(context.Background(), fastPolicy(), "key-1", func(context.Context) (int, error) {
		calls++
		return 0, boom
	})
	if calls != 3 {
		t.Fatalf("attempts = %d, want exactly MaxAttempts", calls)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the last upstream error", err)
	}
}

func TestRetryStopsOnTheFirstSuccess(t *testing.T) {
	calls := 0
	got, err := withRetry(context.Background(), fastPolicy(), "key-1", func(context.Context) (string, error) {
		calls++
		if calls < 2 {
			return "", errors.New("transient")
		}
		return "ok", nil
	})
	if err != nil || got != "ok" || calls != 2 {
		t.Fatalf("got %q after %d calls: %v", got, calls, err)
	}
}

func TestRetryRefusesToRetryWhatARetryCannotFix(t *testing.T) {
	for name, err := range map[string]error{
		"permanent rejection": PermanentDeliveryError{errors.New("400 bad payload")},
		"entitlement refusal": EntitlementError{Vendor: "juniper", Code: "607", VendorMsg: "warranty only"},
		"oversize bundle":     AttachTooLargeError{Transport: "jira", Size: 2, Limit: 1},
		"unsupported":         ErrUnsupported,
		"not configured":      ErrNotConfigured,
		"not onboarded":       ErrNotOnboarded,
		"no human approval":   ErrNotApproved,
	} {
		t.Run(name, func(t *testing.T) {
			if retryable(err) {
				t.Fatalf("%v must be terminal", err)
			}
			calls := 0
			_, gotErr := withRetry(context.Background(), fastPolicy(), "k", func(context.Context) (int, error) {
				calls++
				return 0, err
			})
			if calls != 1 {
				t.Fatalf("attempts = %d, want exactly one", calls)
			}
			if gotErr == nil {
				t.Fatal("the terminal error must be returned")
			}
		})
	}
	// A plain transport failure IS retryable.
	if !retryable(errors.New("connection reset")) {
		t.Error("a transport failure should be retried")
	}
}

func TestRetryHonoursRetryAfterOverItsOwnCurve(t *testing.T) {
	p := RetryPolicy{MaxAttempts: 3, Base: time.Second, Cap: 10 * time.Second}
	got := retryDelay(p, RateLimitedError{After: 3 * time.Second}, 1, "k")
	if got != 3*time.Second {
		t.Fatalf("delay = %v, want the provider's Retry-After", got)
	}
	// …but never past our own ceiling: a hostile header must not park the call.
	got = retryDelay(p, RateLimitedError{After: time.Hour}, 1, "k")
	if got != 10*time.Second {
		t.Fatalf("delay = %v, want it capped at the policy ceiling", got)
	}
}

func TestBackoffJitterIsDeterministicAndSpreadsCallersApart(t *testing.T) {
	p := RetryPolicy{MaxAttempts: 5, Base: time.Second, Cap: time.Minute}

	// Deterministic: the same key and attempt always give the same delay, so a
	// restart resumes the same schedule and a test can assert exact values.
	first, again := caseBackoff(p, 2, "tenant-a"), caseBackoff(p, 2, "tenant-a")
	if first != again {
		t.Fatalf("backoff must be deterministic — no math/rand: %v then %v", first, again)
	}
	// Spread: two different callers at the same attempt must not march in
	// lockstep back onto a recovering vendor.
	if other := caseBackoff(p, 2, "tenant-b"); first == other {
		t.Fatalf("two keys at the same attempt both waited %v; the jitter is not spreading callers", other)
	}
	// Monotonic-ish and bounded: attempt 1 ≤ attempt 3, and everything stays
	// inside [base, 1.5 × cap].
	one, three := caseBackoff(p, 1, "k"), caseBackoff(p, 3, "k")
	if three < one {
		t.Errorf("attempt 3 (%v) backs off less than attempt 1 (%v)", three, one)
	}
	for attempt := 1; attempt <= 40; attempt++ {
		d := caseBackoff(p, attempt, "k")
		if d < p.Base || d > time.Duration(1.5*float64(p.Cap)) {
			t.Fatalf("attempt %d delay %v is outside [%v, 1.5×%v]", attempt, d, p.Base, p.Cap)
		}
	}
}

func TestRetryStopsWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	_, err := withRetry(ctx, RetryPolicy{MaxAttempts: 20, Base: 20 * time.Millisecond, Cap: time.Second},
		"k", func(context.Context) (int, error) {
			calls++
			return 0, errors.New("still failing")
		})
	if err == nil {
		t.Fatal("want an error once the context is done")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want it to wrap context.Canceled", err)
	}
	if calls > 3 {
		t.Errorf("kept retrying past cancellation: %d calls", calls)
	}
}

func TestAttachRetryReopensTheBundleEachAttempt(t *testing.T) {
	// An io.Reader cannot be replayed, so a retry that reused it would upload a
	// truncated file. Every attempt must call Open() again.
	opens, closes := 0, 0
	bundle := countingBundle(&opens, &closes, 4)
	attempts := 0
	_, err := attachWithRetry(context.Background(), fastPolicy(), bundle,
		func(context.Context, readCloser) (AttachResult, error) {
			attempts++
			return AttachResult{}, errors.New("transient 503")
		}, "digest")
	if err == nil {
		t.Fatal("want the transient failure to surface after the attempts are spent")
	}
	if attempts != 3 || opens != 3 {
		t.Fatalf("attempts=%d opens=%d, want 3 of each", attempts, opens)
	}
	if closes != opens {
		t.Fatalf("closed %d of %d readers — a failing attempt must not leak one", closes, opens)
	}
}

func TestAttachRetrySucceedsOnASecondAttemptWithFullBytes(t *testing.T) {
	opens, closes := 0, 0
	bundle := countingBundle(&opens, &closes, 8)
	attempts := 0
	res, err := attachWithRetry(context.Background(), fastPolicy(), bundle,
		func(_ context.Context, rc readCloser) (AttachResult, error) {
			attempts++
			buf := make([]byte, 16)
			n, _ := rc.Read(buf)
			if n != 8 {
				t.Errorf("attempt %d read %d bytes, want the whole bundle", attempts, n)
			}
			if attempts < 2 {
				return AttachResult{}, errors.New("transient")
			}
			return AttachResult{Transport: "test"}, nil
		}, "digest")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if res.SHA256 != "digest" || res.At.IsZero() {
		t.Errorf("result should be stamped with the digest and a time: %+v", res)
	}
	if opens != 2 || closes != 2 {
		t.Errorf("opens=%d closes=%d, want 2 of each", opens, closes)
	}
}

// countingBundle builds a Bundle whose reader records opens and closes, so a
// test can prove the retry re-reads from source and never leaks a reader.
func countingBundle(opens, closes *int, size int) Bundle {
	return Bundle{
		Name: "b.zip", ContentType: "application/zip", Size: int64(size), SHA256: "digest",
		Open: func() (io.ReadCloser, error) {
			*opens++
			return &countingReader{Reader: bytes.NewReader(bytes.Repeat([]byte("b"), size)), closes: closes}, nil
		},
	}
}

type countingReader struct {
	*bytes.Reader
	closes *int
}

func (c *countingReader) Close() error { *c.closes++; return nil }
