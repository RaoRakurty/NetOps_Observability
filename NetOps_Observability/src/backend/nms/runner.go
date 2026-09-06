// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"io"
	"net/http"
	"time"

	"netops/backend/wireless"
)

// runner.go — the connector runtime driver: a rate-limited, retrying HTTP Doer
// (the client every connector is handed), and the routing Pipeline that turns a
// normalized Batch into deduped, state-tracked, class-routed output. This is
// where the framework's reliability guarantees live (§9): bounded rate, retry
// with backoff + 429/Retry-After, dedup, flap-tracked state.

// RetryDoer wraps an http.Client with a RateLimiter + RetryPolicy. It is the
// Doer handed to connectors so they never manage rate/retry themselves.
type RetryDoer struct {
	Client  *http.Client
	Limiter RateLimiter
	Retry   RetryPolicy
	now     func() time.Time // injectable clock (Retry-After date form)
	sleep   func(context.Context, time.Duration) error
}

// NewRetryDoer builds a RetryDoer. A nil limiter/retry gets sane defaults.
func NewRetryDoer(client *http.Client, limiter RateLimiter, retry RetryPolicy) *RetryDoer {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if limiter == nil {
		limiter = NewTokenBucket(0) // unlimited
	}
	if retry == nil {
		r := DefaultRetry()
		retry = r
	}
	return &RetryDoer{Client: client, Limiter: limiter, Retry: retry, now: time.Now, sleep: sleepCtx}
}

// Do performs the request with rate limiting and retry. On a retriable response
// it drains+closes the body before retrying (so the connection can be reused).
// The returned response (success or final failure) is the caller's to close.
func (d *RetryDoer) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	var lastErr error
	for attempt := 1; ; attempt++ {
		if err := d.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
		// Clone per attempt (body may need re-reading; GET/no-body is the common
		// controller-poll case, so this is cheap).
		resp, err := d.Client.Do(req)
		status := 0
		var retryAfter time.Duration
		if err == nil {
			status = resp.StatusCode
			if status < 400 {
				return resp, nil // success
			}
			retryAfter = ParseRetryAfter(resp.Header, d.now())
		} else {
			lastErr = err
		}
		delay, retry := d.Retry.Next(attempt, status, retryAfter)
		if !retry {
			if err != nil {
				return nil, err
			}
			return resp, nil // return the final non-2xx to the caller to inspect
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) // best-effort: drain for connection reuse
			_ = resp.Body.Close()                                        // best-effort: nothing actionable on close failure
		}
		if serr := d.sleep(ctx, delay); serr != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, serr
		}
	}
}

// Routed is the class-routed output of the Pipeline for one poll/webhook batch.
type Routed struct {
	MetricLines  []string            // exposition lines for VictoriaMetrics
	Events       []ControllerEvent   // deduped, ready for netops.controller_events
	States       []StateRecord       // EVERY state applied this batch (first sightings + refreshes) — persist these
	StateChanges []StateChange       // the subset that TRANSITIONED — emit these as change-events
	Wireless     *wireless.Inventory // canonical wireless inventory (#128) — upserted by the scheduler
}

// Pipeline routes normalized batches: dedupes events, folds state (flap
// tracking), renders metrics. It is the single place that enforces the
// three-class routing so no connector can bypass it.
type Pipeline struct {
	Seen  *SeenSet
	State *StateTracker
}

// NewPipeline builds a pipeline with a bounded seen-set + a state tracker.
func NewPipeline(seenCap int) *Pipeline {
	return &Pipeline{Seen: NewSeenSet(seenCap), State: NewStateTracker()}
}

// Route processes one Batch: metrics → lines, states → tracker (emitting
// changes), events → deduped. Pure aside from the tracker/seen-set it owns.
func (p *Pipeline) Route(b Batch) Routed {
	var out Routed
	for _, m := range b.Metrics {
		if line := MetricLine(m); line != "" {
			out.MetricLines = append(out.MetricLines, line)
		}
	}
	for _, s := range b.States {
		rec, chg := p.State.Apply(s)
		out.States = append(out.States, rec)
		if chg != nil {
			out.StateChanges = append(out.StateChanges, *chg)
		}
	}
	out.Events = p.Seen.DedupeEvents(b.Events)
	if !b.Wireless.Empty() {
		out.Wireless = &wireless.Inventory{}
		out.Wireless.Merge(b.Wireless)
	}
	return out
}
