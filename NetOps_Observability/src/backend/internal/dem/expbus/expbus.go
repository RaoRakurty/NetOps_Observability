// Package expbus is the DEM experience-event lane's producer: a bounded,
// backpressure-aware writer that carries validated ExperienceEvents and
// BusinessEvents from the ingest routes onto the platform's existing event bus.
//
// WHY IT IS A SEPARATE PACKAGE. internal/dem/experience declares the shapes and
// the EventSink seam and deliberately "never learns about Kafka or ClickHouse".
// The integrator, for its part, is the root package, which CLAUDE.md §2 forbids
// from holding business logic — and a bounded queue with a retrying drain loop
// is business logic. So the lane lives here: a leaf that imports the shapes,
// exposes a transport seam of its own, and is removable without touching either
// neighbour.
//
// THE CONTRACT (§9 reliability). A beacon must never block a browser and must
// never be dropped in silence:
//
//   - the queue is BOUNDED, in batches and in events;
//   - a write to a full queue returns [ErrBusy] immediately — the route answers
//     503 with a Retry-After, which is honest backpressure the producer can act
//     on, rather than a 202 for data that went nowhere;
//   - the drain retries with exponential backoff and FULL JITTER, and a batch
//     that exhausts its attempts is counted and logged, never silently lost;
//   - offsets on the topic commit only after ClickHouse acks (the router's
//     global acknowledgements), so a storage outage back-pressures into the
//     retained topic rather than discarding a user's bad minute.
//
// §3a. This package never decides who owns an event. Every record it accepts
// has already had its tenant stamped from the caller's credential by the ingest
// route; [Queue] refuses a record with no concrete tenant rather than
// publishing one the router would have to guess at.
package expbus

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"netops/backend/internal/dem/experience"
)

// Topic is the bus lane. kafka-init pre-creates it in every compose file and
// vector-router is its only consumer (deployment/docker/kafka/apply-acls.sh).
// Producing rides the aggregator's prefixed netops.* bus-bridge grant, exactly
// as the security and BGP evidence lanes do.
const Topic = "netops.experience"

// Record types. ONE topic carries both shapes and this field is the only thing
// the router splits on, so the two constants are a wire contract: changing one
// without the router's `experience_split` route silently sends every event to
// the wrong table.
const (
	RecordExperienceEvent = "experience_event"
	RecordBusinessEvent   = "business_event"
)

// ErrBusy is returned when the queue is full. It is a REFUSAL, not a drop: the
// caller is expected to turn it into a 503 with a Retry-After so the producer
// learns to slow down. Silently accepting and discarding would make the lane
// look healthy while a tenant's evidence disappeared.
//
// It IS experience.ErrIngestBusy rather than a sibling of it: the HTTP layer
// maps that one sentinel onto 503, and two "the queue is full" errors that are
// not errors.Is-equal is precisely how a busy queue starts answering 400.
var ErrBusy = experience.ErrIngestBusy

// ErrClosed is returned once the drain has stopped.
var ErrClosed = errors.New("the experience ingest queue is closed")

// Record is one bus record from a producer's point of view — a partition Key
// and a JSON-serializable Value. It mirrors the shape the Vector bus-bridge
// producer accepts WITHOUT importing it, so this package stays a leaf that
// nothing core depends on (the secbus.Record idiom).
type Record struct {
	Key   string `json:"key,omitempty"`
	Value any    `json:"value"`
}

// Publisher is the injected bus transport (§5: interfaces for external deps).
// Its single production implementation is a one-line adapter over the existing
// bus bridge; tests inject a fake.
type Publisher interface {
	Publish(ctx context.Context, topic string, recs []Record) (int, error)
}

// PublisherFunc adapts a bare function to Publisher.
type PublisherFunc func(ctx context.Context, topic string, recs []Record) (int, error)

// Publish implements Publisher.
func (f PublisherFunc) Publish(ctx context.Context, topic string, recs []Record) (int, error) {
	return f(ctx, topic, recs)
}

// Bounds (§9). Every one of them is a refusal at the boundary, never a silent
// truncation of somebody's data.
const (
	// MaxEventsPerBatch is the largest batch one WriteEvents call may carry.
	// The ingest route caps its request body below this, so a batch that
	// exceeds it is a programming error rather than a large beacon.
	MaxEventsPerBatch = 500
	// DefaultQueueBatches is how many batches may wait to be published.
	DefaultQueueBatches = 256
	// MaxQueuedEvents bounds the queue in EVENTS as well as in batches: 256
	// batches of one event each is a very different memory profile from 256
	// full ones, and only the event bound describes the worst case.
	MaxQueuedEvents = 20000
	// DefaultAttempts / DefaultBackoff / DefaultMaxWait bound one batch's
	// retry envelope: ~7 s of full-jittered backoff, then the batch is dropped
	// LOUDLY. An unbounded retry would wedge the drain behind one poison batch
	// and stall every tenant's lane.
	DefaultAttempts = 4
	DefaultBackoff  = 250 * time.Millisecond
	DefaultMaxWait  = 4 * time.Second
)

// Metrics is the lane's observability surface (§10). Atomics, so the queue
// holds no mutable package-level state and is safe to share with a scrape.
type Metrics struct {
	EventsAccepted  atomic.Int64 // events taken onto the queue
	EventsPublished atomic.Int64 // events the bridge accepted
	EventsRefused   atomic.Int64 // refused with ErrBusy — backpressure, visible
	EventsRejected  atomic.Int64 // failed validation at the sink boundary
	EventsDropped   atomic.Int64 // gave up after exhausting retries
	BatchesQueued   atomic.Int64
	PublishRetries  atomic.Int64
	PublishErrors   atomic.Int64
	QueueDepth      atomic.Int64 // batches currently waiting (gauge)
}

// Snapshot is a plain read for a status endpoint. No live pointers escape.
func (m *Metrics) Snapshot() map[string]int64 {
	if m == nil {
		return map[string]int64{}
	}
	return map[string]int64{
		"events_accepted_total":  m.EventsAccepted.Load(),
		"events_published_total": m.EventsPublished.Load(),
		"events_refused_total":   m.EventsRefused.Load(),
		"events_rejected_total":  m.EventsRejected.Load(),
		"events_dropped_total":   m.EventsDropped.Load(),
		"batches_queued_total":   m.BatchesQueued.Load(),
		"publish_retries_total":  m.PublishRetries.Load(),
		"publish_errors_total":   m.PublishErrors.Load(),
		"queue_depth":            m.QueueDepth.Load(),
	}
}

// envelope is one record on the wire: the validated event, flattened, with the
// router's routing discriminator in front of it. The embedded struct's own JSON
// tags are preserved, so `provenance` and `cohort` stay nested exactly as the
// router's VRL reads them.
type experienceEnvelope struct {
	RecordType string `json:"record_type"`
	experience.ExperienceEvent
}

type businessEnvelope struct {
	RecordType string `json:"record_type"`
	experience.BusinessEvent
}

type batch struct {
	recs   []Record
	events int
}

// Queue is the bounded producer. It satisfies experience.EventSink.
type Queue struct {
	pub     Publisher
	topic   string
	ch      chan batch
	metrics *Metrics
	logWarn func(msg string, fields map[string]any)

	attempts int
	base     time.Duration
	maxWait  time.Duration

	// queuedEvents is the second bound (events, not batches). Guarded by mu
	// because it is decremented by the drain and incremented by many writers.
	mu           sync.Mutex
	queuedEvents int

	closed atomic.Bool

	// Injected for determinism under test — never mutable package globals.
	sleep  func(context.Context, time.Duration) error
	jitter func() float64
}

var _ experience.EventSink = (*Queue)(nil)

// Option configures a Queue.
type Option func(*Queue)

// WithRetry sets the per-batch attempt count and backoff schedule.
func WithRetry(attempts int, base, maxWait time.Duration) Option {
	return func(q *Queue) {
		if attempts >= 1 {
			q.attempts = attempts
		}
		if base > 0 {
			q.base = base
		}
		if maxWait > 0 {
			q.maxWait = maxWait
		}
	}
}

// WithMetrics binds an external Metrics (one shared with a status endpoint).
func WithMetrics(m *Metrics) Option {
	return func(q *Queue) {
		if m != nil {
			q.metrics = m
		}
	}
}

// WithQueueDepth overrides the batch bound. Values outside 1..DefaultQueueBatches
// are clamped: a deeper queue is a longer silent delay, not more safety.
func WithQueueDepth(n int) Option {
	return func(q *Queue) {
		if n >= 1 && n <= DefaultQueueBatches {
			q.ch = make(chan batch, n)
		}
	}
}

// WithSleep / WithJitter make the retry schedule deterministic under test.
func WithSleep(f func(context.Context, time.Duration) error) Option {
	return func(q *Queue) {
		if f != nil {
			q.sleep = f
		}
	}
}

// WithJitter injects the full-jitter multiplier source.
func WithJitter(f func() float64) Option {
	return func(q *Queue) {
		if f != nil {
			q.jitter = f
		}
	}
}

// New builds the lane, failing CLOSED on a missing transport or logger rather
// than returning a sink that would accept events and lose them in silence.
func New(pub Publisher, logWarn func(string, map[string]any), opts ...Option) (*Queue, error) {
	if pub == nil {
		return nil, errors.New("expbus: a publisher is required")
	}
	if logWarn == nil {
		return nil, errors.New("expbus: a logger is required (a dropped batch must be observable)")
	}
	q := &Queue{
		pub: pub, topic: Topic,
		ch:       make(chan batch, DefaultQueueBatches),
		metrics:  &Metrics{},
		logWarn:  logWarn,
		attempts: DefaultAttempts, base: DefaultBackoff, maxWait: DefaultMaxWait,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		// #nosec G404 — retry jitter, not a security decision. crypto/rand here
		// would buy nothing and cost an entropy read per retry.
		jitter: rand.Float64,
	}
	for _, o := range opts {
		o(q)
	}
	return q, nil
}

// Metrics exposes the counter set (for the status surface).
func (q *Queue) Metrics() *Metrics { return q.metrics }

// Depth reports the number of batches waiting.
func (q *Queue) Depth() int {
	if q == nil {
		return 0
	}
	return len(q.ch)
}

// WriteEvents enqueues a validated batch of experience events.
//
// It VALIDATES again at this boundary even though the route already did: this
// is the last place an event can be refused before it becomes a durable row
// under a STRICT tenant policy, and a record with no concrete tenant would land
// as an untagged row that no tenant can ever see (§3 zero trust — never trust
// an upstream, including our own).
func (q *Queue) WriteEvents(ctx context.Context, events []experience.ExperienceEvent) error {
	if q == nil {
		return ErrClosed
	}
	if len(events) == 0 {
		return nil
	}
	if len(events) > MaxEventsPerBatch {
		return fmt.Errorf("expbus: a batch of %d exceeds the %d-event bound", len(events), MaxEventsPerBatch)
	}
	recs := make([]Record, 0, len(events))
	for i := range events {
		e := events[i]
		if err := e.Validate(); err != nil {
			q.metrics.EventsRejected.Add(1)
			return err
		}
		recs = append(recs, Record{
			Key:   e.TenantID, // same tenant, same partition, ordered
			Value: experienceEnvelope{RecordType: RecordExperienceEvent, ExperienceEvent: e},
		})
	}
	return q.enqueue(ctx, recs)
}

// WriteBusinessEvents enqueues a validated batch of business events.
func (q *Queue) WriteBusinessEvents(ctx context.Context, events []experience.BusinessEvent) error {
	if q == nil {
		return ErrClosed
	}
	if len(events) == 0 {
		return nil
	}
	if len(events) > MaxEventsPerBatch {
		return fmt.Errorf("expbus: a batch of %d exceeds the %d-event bound", len(events), MaxEventsPerBatch)
	}
	recs := make([]Record, 0, len(events))
	for i := range events {
		b := events[i]
		if err := b.Validate(); err != nil {
			q.metrics.EventsRejected.Add(1)
			return err
		}
		recs = append(recs, Record{
			Key:   b.TenantID,
			Value: businessEnvelope{RecordType: RecordBusinessEvent, BusinessEvent: b},
		})
	}
	return q.enqueue(ctx, recs)
}

// enqueue takes the batch onto the queue or refuses it. NEVER blocks: a beacon
// route that waits on a busy bus is a browser that waits on a busy bus.
func (q *Queue) enqueue(ctx context.Context, recs []Record) error {
	if q.closed.Load() {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	q.mu.Lock()
	if q.queuedEvents+len(recs) > MaxQueuedEvents {
		q.mu.Unlock()
		q.metrics.EventsRefused.Add(int64(len(recs)))
		return ErrBusy
	}
	q.queuedEvents += len(recs)
	q.mu.Unlock()

	select {
	case q.ch <- batch{recs: recs, events: len(recs)}:
		q.metrics.EventsAccepted.Add(int64(len(recs)))
		q.metrics.BatchesQueued.Add(1)
		q.metrics.QueueDepth.Store(int64(len(q.ch)))
		return nil
	default:
		q.mu.Lock()
		q.queuedEvents -= len(recs)
		q.mu.Unlock()
		q.metrics.EventsRefused.Add(int64(len(recs)))
		return ErrBusy
	}
}

// Run drains the queue until ctx is done. It is the ONLY consumer.
func (q *Queue) Run(ctx context.Context) {
	defer q.closed.Store(true)
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-q.ch:
			q.mu.Lock()
			q.queuedEvents -= b.events
			if q.queuedEvents < 0 {
				q.queuedEvents = 0
			}
			q.mu.Unlock()
			q.metrics.QueueDepth.Store(int64(len(q.ch)))
			q.publish(ctx, b)
		}
	}
}

// DrainOnce publishes exactly one queued batch if there is one, and reports
// whether it did. Exported so a test needs no goroutine and no clock.
func (q *Queue) DrainOnce(ctx context.Context) bool {
	select {
	case b := <-q.ch:
		q.mu.Lock()
		q.queuedEvents -= b.events
		if q.queuedEvents < 0 {
			q.queuedEvents = 0
		}
		q.mu.Unlock()
		q.metrics.QueueDepth.Store(int64(len(q.ch)))
		q.publish(ctx, b)
		return true
	default:
		return false
	}
}

// publish sends one batch with bounded retry (backoff + full jitter). A batch
// that exhausts its attempts is DROPPED LOUDLY: counted and logged with its
// size, because "we lost 300 of a tenant's beacons" is a fact an operator must
// be able to find (§10, no silent failures).
func (q *Queue) publish(ctx context.Context, b batch) {
	wait := q.base
	for attempt := 1; attempt <= q.attempts; attempt++ {
		n, err := q.pub.Publish(ctx, q.topic, b.recs)
		if err == nil {
			q.metrics.EventsPublished.Add(int64(n))
			return
		}
		q.metrics.PublishErrors.Add(1)
		if ctx.Err() != nil {
			break
		}
		if attempt == q.attempts {
			break
		}
		q.metrics.PublishRetries.Add(1)
		d := time.Duration(q.jitter() * float64(wait)) // full jitter
		if serr := q.sleep(ctx, d); serr != nil {
			break
		}
		if wait < q.maxWait {
			wait *= 2
			if wait > q.maxWait {
				wait = q.maxWait
			}
		}
	}
	q.metrics.EventsDropped.Add(int64(b.events))
	q.logWarn("experience events could not be published to the bus and were dropped — those users' evidence is gone, not delayed",
		map[string]any{"events": b.events, "topic": q.topic, "attempts": q.attempts})
}
