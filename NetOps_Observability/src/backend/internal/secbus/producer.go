package secbus

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"sync/atomic"
	"time"

	"netops/backend/internal/secfindings"
)

// TopicSecurityEvidence is the bus topic the security evidence lane produces
// onto, in the netops.* convention. kafka-init pre-creates it (see the topic
// list in deployment/docker/docker-compose.yml), and producing rides the
// aggregator's prefixed netops.* bus-bridge grant. NOTE: the correlation
// principal's consume ACLs (deployment/docker/kafka/apply-acls.sh) do NOT yet
// cover this topic — its enumerated topic list stops at the pre-security lanes.
// When the consumer (T2b) lands, add netops.security there, or an enforced
// broker (allow.everyone.if.no.acl.found=false) will deny the reads.
const TopicSecurityEvidence = "netops.security"

// Record is one bus record from a producer's point of view — a partition Key and
// a JSON-serializable Value. It mirrors the shape the Vector bus-bridge producer
// (produceJSON/proxyRecord in package backend) accepts, WITHOUT importing it:
// the wiring layer adapts []secbus.Record → []proxyRecord in one line, so this
// package stays a leaf that nothing core depends on (removable-module rule).
type Record struct {
	Key   string `json:"key,omitempty"`
	Value any    `json:"value"`
}

// Publisher is the injected bus transport (§5 interfaces for external deps). Its
// single implementation in production is a thin adapter over the existing
// Vector bus-bridge produceJSON; tests inject a fake. It returns the number of
// records the bridge accepted, or an error. Publish MUST honor ctx cancellation.
type Publisher interface {
	Publish(ctx context.Context, topic string, recs []Record) (int, error)
}

// PublisherFunc adapts a bare function to Publisher, so the wiring layer can bind
// produceJSON without either side importing the other's concrete type.
type PublisherFunc func(ctx context.Context, topic string, recs []Record) (int, error)

// Publish implements Publisher.
func (f PublisherFunc) Publish(ctx context.Context, topic string, recs []Record) (int, error) {
	return f(ctx, topic, recs)
}

// Metrics is the producer's observability surface (§10). Counters are atomic so
// the producer holds no mutable package-level state and is safe to share.
type Metrics struct {
	published atomic.Int64 // findings successfully produced onto the bus
	retries   atomic.Int64 // transient-failure retry attempts made
	skipped   atomic.Int64 // findings that could not ground (converter refused)
	dropped   atomic.Int64 // findings dropped after exhausting retries (fail-safe)
}

// MetricsSnapshot is an immutable read of the counters for a health/metrics
// endpoint. Plain ints — no live pointers escape.
type MetricsSnapshot struct {
	Published int64 `json:"published"`
	Retries   int64 `json:"retries"`
	Skipped   int64 `json:"skipped"`
	Dropped   int64 `json:"dropped"`
}

// Snapshot returns a consistent-enough read of the counters (each atomic).
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		Published: m.published.Load(),
		Retries:   m.retries.Load(),
		Skipped:   m.skipped.Load(),
		Dropped:   m.dropped.Load(),
	}
}

// Producer publishes security evidence events onto TopicSecurityEvidence via an
// injected Publisher, with bounded retry (backoff + full jitter), idempotent
// event identity (stable native_id → deterministic signal_id downstream) and
// FAIL-SAFE behavior: on persistent failure it drops-to-error with a metric and
// a log line rather than blocking the caller (§9 reliability, §10 observability).
type Producer struct {
	pub     Publisher
	topic   string
	maxTry  int           // total attempts per batch (>=1)
	base    time.Duration // base backoff before jitter
	maxWait time.Duration // per-backoff cap
	metrics *Metrics

	// Injected for determinism/testability — never mutable package globals.
	sleep  func(context.Context, time.Duration) error
	jitter func() float64 // in [0,1); full-jitter multiplier
}

// Option configures a Producer.
type Option func(*Producer)

// WithRetry sets the total attempt count and backoff schedule. attempts < 1 is
// clamped to 1 (at least one try); a non-positive base/cap keeps the default.
func WithRetry(attempts int, base, maxWait time.Duration) Option {
	return func(p *Producer) {
		if attempts >= 1 {
			p.maxTry = attempts
		}
		if base > 0 {
			p.base = base
		}
		if maxWait > 0 {
			p.maxWait = maxWait
		}
	}
}

// WithMetrics binds an external Metrics (e.g. one shared with a health endpoint).
func WithMetrics(m *Metrics) Option {
	return func(p *Producer) {
		if m != nil {
			p.metrics = m
		}
	}
}

// withClock injects sleep + jitter (used by tests for determinism).
func withClock(sleep func(context.Context, time.Duration) error, jitter func() float64) Option {
	return func(p *Producer) {
		if sleep != nil {
			p.sleep = sleep
		}
		if jitter != nil {
			p.jitter = jitter
		}
	}
}

// NewProducer builds a Producer over the injected Publisher. A nil Publisher is
// rejected (fail closed) — there is no implicit global transport.
func NewProducer(pub Publisher, opts ...Option) (*Producer, error) {
	if pub == nil {
		return nil, errors.New("secbus: nil Publisher")
	}
	// Per-producer rng, seeded once — NOT the math/rand global (no shared mutable
	// state, and deterministically overridable in tests via withClock).
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404 -- retry backoff jitter, not a security context
	p := &Producer{
		pub:     pub,
		topic:   TopicSecurityEvidence,
		maxTry:  4,
		base:    200 * time.Millisecond,
		maxWait: 5 * time.Second,
		metrics: &Metrics{},
		sleep:   sleepCtx,
		jitter:  rng.Float64,
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Metrics exposes the producer's counters (for a health/metrics surface).
func (p *Producer) Metrics() *Metrics { return p.metrics }

// Publish converts findings to evidence events and produces them onto the topic,
// keyed by tenant so a tenant's evidence stays ordered and co-partitions with
// its other lanes. Findings that cannot ground are SKIPPED (counted), never
// guessed. Returns the number of records produced. A persistent transport
// failure returns an error after the bounded retry AND has already dropped-to-
// error (metric + log) — the caller may log it but is never blocked unboundedly.
//
// §3a: each record's partition key and the event's TenantID both come from the
// finding's stamped TenantID; there is no path to override it from a request.
func (p *Producer) Publish(ctx context.Context, findings []secfindings.Finding) (int, error) {
	recs := make([]Record, 0, len(findings))
	for _, f := range findings {
		ev, err := FromFinding(f)
		if err != nil {
			p.metrics.skipped.Add(1)
			log.Printf("secbus: skip ungroundable finding (control=%q): %v", f.ControlID, err)
			continue
		}
		recs = append(recs, Record{Key: ev.TenantID, Value: ev})
	}
	if len(recs) == 0 {
		return 0, nil
	}
	n, err := p.produceWithRetry(ctx, recs)
	if err != nil {
		// Fail-safe: the batch is dropped-to-error, observably, never retried
		// forever and never blocking the caller.
		p.metrics.dropped.Add(int64(len(recs)))
		log.Printf("secbus: dropping %d security evidence record(s) after %d attempt(s): %v",
			len(recs), p.maxTry, err)
		return 0, err
	}
	p.metrics.published.Add(int64(n))
	return n, nil
}

// produceWithRetry runs the bounded retry loop: exponential backoff with FULL
// jitter, capped, aborting immediately on context cancellation. At-least-once by
// design; the event's deterministic native_id makes a redelivery idempotent
// downstream, so a retry after a partial/uncertain failure is safe.
func (p *Producer) produceWithRetry(ctx context.Context, recs []Record) (int, error) {
	var lastErr error
	backoff := p.base
	for attempt := 0; attempt < p.maxTry; attempt++ {
		if attempt > 0 {
			p.metrics.retries.Add(1)
			wait := p.jitteredBackoff(backoff)
			if err := p.sleep(ctx, wait); err != nil {
				return 0, err // ctx cancelled/expired mid-backoff — fail fast
			}
			if backoff < p.maxWait {
				backoff *= 2
				if backoff > p.maxWait {
					backoff = p.maxWait
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, err := p.pub.Publish(ctx, p.topic, recs)
		if err == nil {
			return n, nil
		}
		lastErr = err
		// A cancelled context is terminal, not transient — stop retrying.
		if ctx.Err() != nil {
			return 0, err
		}
	}
	return 0, lastErr
}

// jitteredBackoff applies full jitter: a uniform draw in [0, backoff], capped.
func (p *Producer) jitteredBackoff(backoff time.Duration) time.Duration {
	if backoff > p.maxWait {
		backoff = p.maxWait
	}
	if backoff <= 0 {
		return 0
	}
	return time.Duration(p.jitter() * float64(backoff))
}

// sleepCtx sleeps for d or until ctx is done, returning ctx.Err() if it fires.
// A non-positive duration is a no-op (still cheap to honor cancellation).
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
