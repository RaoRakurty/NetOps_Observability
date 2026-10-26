// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

// scheduler.go — the NMS poll runtime (#95 P3b, extracted P2 W4.17). A single
// supervised loop (ticketing-sweeper idiom) that, each tick, lists every
// ENABLED integration across all tenants (platform scope), hands the due ones
// to a bounded worker pool, and fans the class-routed outputs to their sinks:
//
//	controller_metric → Sinks.EmitMetrics (VictoriaMetrics Lane 1)
//	controller_event  → Sinks.ProduceEvents (bus → netops.controller_events)
//	controller_state  → ConfigStore.UpsertStates (PG, flap-tracked)
//	wireless inventory → wireless.Store (#128 canonical inventory)
//
// The transports behind the metric/event lanes are the entrypoint's (env-derived
// VictoriaMetrics URL, the Kafka producer) and arrive as Sinks closures; the
// backfill window is a constructor parameter (NMS_BACKFILL stays with the
// caller). Per-integration Pipelines are long-lived so dedup (SeenSet) and flap
// tracking survive across ticks.
//
// Isolation of one controller from another (NMS-first T1):
//   - worker pool: NMS_POLL_WORKERS integrations poll at once, dispatched
//     round-robin by tenant, so one tenant's slow controller cannot hold
//     another tenant's poll behind it (the loop used to be serial);
//   - per-integration deadline min(interval, NMS_POLL_DEADLINE): a hung
//     controller costs one worker for at most that long; streams it never
//     reached are recorded skipped_deadline;
//   - inFlight: one integration never runs twice at once ("Poll now" during a
//     scheduled poll answers busy);
//   - circuit breaker (breaker.go) and a persistent per-integration rate
//     bucket (the bucket used to be rebuilt every cycle, so the limit never
//     carried across cycles).
//
// Health of every integration is exported on the api scrape (health.go).

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/wireless"
)

const (
	defaultPollInterval = 5 * time.Minute
	minPollInterval     = 30 * time.Second
	pipelineSeenCap     = 32768 // > one cycle of any stream (vManage events: ~350/h with cursor queries)

	// DefaultBackfill is the poll lookback when the caller configures none
	// (main resolves NMS_BACKFILL against it).
	DefaultBackfill = 15 * time.Minute

	// DefaultPollWorkers is the pool size when the caller configures none
	// (NMS_POLL_WORKERS); MaxPollWorkers bounds it.
	DefaultPollWorkers = 4
	MaxPollWorkers     = 16
	// DefaultPollDeadline caps one integration's cycle (NMS_POLL_DEADLINE);
	// the effective deadline is min(interval, this).
	DefaultPollDeadline = 120 * time.Second

	// pollDialTimeout bounds TCP connect and TLS handshake to a controller:
	// an unroutable controller fails in seconds, not the 30 s request timeout.
	pollDialTimeout = 10 * time.Second
	// sinkTimeout bounds one cycle's fan-out to the sinks. The sinks run on
	// the runtime context, NOT the poll deadline: data fetched just before the
	// deadline must still be delivered.
	sinkTimeout = 30 * time.Second
	// recordTimeout bounds the run-history write and the health seed read.
	recordTimeout = 10 * time.Second
)

// errCircuitOpen is the run error while an integration's breaker is open.
var errCircuitOpen = errors.New("circuit open: polling suspended after repeated failures; a single login probe follows the cooldown")

// Sinks are the entrypoint-owned transports the runtime fans routed output to.
// Best-effort per lane: a nil or failing sink is logged and never blocks the
// others (metrics loss must not stop events, and vice versa).
type Sinks struct {
	// EmitMetrics pushes Prometheus exposition lines. Nil = no metrics backend
	// configured — skipped, not an error.
	EmitMetrics func(ctx context.Context, lines []string) error
	// ProduceEvents publishes controller events to the bus keyed per tenant
	// (per-tenant ordering) and returns the count produced.
	ProduceEvents func(ctx context.Context, tenant string, events []ControllerEvent) (int64, error)
}

// rateBucket is an integration's persistent limiter and the rate it was
// built for (rebuilt only when the rate changes).
type rateBucket struct {
	rate float64
	b    *TokenBucket
}

// Runtime is the supervised NMS poll scheduler.
type Runtime struct {
	store ConfigStore
	reg   *Registry
	sinks Sinks
	// backfill is the poll lookback for integrations without a checkpoint.
	backfill time.Duration
	// wireless receives canonical-inventory discoveries (#128) from wireless
	// connectors (Routed.Wireless). Nil = inventory discarded with a warning —
	// never silently (main wires it whenever the runtime exists).
	wireless wireless.Store

	client         *http.Client // strict TLS (default)
	insecureClient *http.Client // per-integration opt-in for self-signed controllers

	// resolver joins controller device keys to inventory devices (nil = off).
	resolver DeviceResolver

	workers  int
	deadline time.Duration
	health   *HealthMetrics
	now      func() time.Time
	jitter   func() float64 // breaker cooldown jitter, [0,1)

	mu       sync.Mutex
	pipes    map[string]*Pipeline   // tenant\x00id → long-lived pipeline
	lastRun  map[string]time.Time   // tenant\x00id → last poll start
	sessions map[string]Session     // tenant\x00id → cached controller session (reused until expiry)
	buckets  map[string]*rateBucket // tenant\x00id → persistent rate limiter
	breakers map[string]*Breaker    // tenant\x00id → circuit breaker
	inFlight map[string]bool        // tenant\x00id → a cycle is running now
	tickN    int                    // dispatch counter (rotates the tenant order)
}

// newPollTransport builds a controller transport with bounded connect and
// handshake. insecure = the per-integration tls_skip_verify opt-in.
func newPollTransport(insecure bool) *http.Transport {
	dialer := &net.Dialer{Timeout: pollDialTimeout, KeepAlive: 30 * time.Second}
	var t *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		t = dt.Clone()
	} else {
		t = &http.Transport{}
	}
	t.DialContext = dialer.DialContext
	t.TLSHandshakeTimeout = pollDialTimeout
	if insecure {
		// Unchanged from before: the opt-in client never used a proxy.
		t.Proxy = nil
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 — explicit per-integration operator opt-in
	}
	return t
}

// NewRuntime builds the scheduler over a config store, the entrypoint's sinks
// and the poll backfill window.
func NewRuntime(store ConfigStore, sinks Sinks, backfill time.Duration) *Runtime {
	if backfill <= 0 {
		backfill = DefaultBackfill
	}
	strict := &http.Client{Timeout: 30 * time.Second, Transport: newPollTransport(false)}
	// Controllers in labs/enterprises commonly present self-signed certs; this
	// client is used ONLY for integrations that explicitly set tls_skip_verify.
	// Default remains strict verification (§3 zero-trust).
	insecure := &http.Client{Timeout: 30 * time.Second, Transport: newPollTransport(true)}
	reg := NewRegistry()
	return &Runtime{
		store:          store,
		reg:            reg,
		sinks:          sinks,
		backfill:       backfill,
		client:         strict,
		insecureClient: insecure,
		workers:        DefaultPollWorkers,
		deadline:       DefaultPollDeadline,
		health:         NewHealthMetrics(reg.Vendors()),
		now:            time.Now,
		jitter:         randJitter,
		pipes:          map[string]*Pipeline{},
		lastRun:        map[string]time.Time{},
		sessions:       map[string]Session{},
		buckets:        map[string]*rateBucket{},
		breakers:       map[string]*Breaker{},
		inFlight:       map[string]bool{},
	}
}

// ClampPollWorkers bounds a configured pool size: ≤0 → the default, else
// [1, MaxPollWorkers].
func ClampPollWorkers(n int) int {
	switch {
	case n <= 0:
		return DefaultPollWorkers
	case n > MaxPollWorkers:
		return MaxPollWorkers
	}
	return n
}

// SetPoolOptions configures the worker pool size (clamped) and the poll
// deadline cap (≤0 keeps the default). Call before Run.
func (rt *Runtime) SetPoolOptions(workers int, deadline time.Duration) {
	rt.workers = ClampPollWorkers(workers)
	if deadline > 0 {
		rt.deadline = deadline
	}
}

// SetWirelessStore wires the #128 canonical-inventory sink.
func (rt *Runtime) SetWirelessStore(ws wireless.Store) { rt.wireless = ws }

// SetDeviceResolver installs the controller→inventory device join. Call before
// Start: pipelines pick it up when they are first built.
func (rt *Runtime) SetDeviceResolver(r DeviceResolver) { rt.resolver = r }

// Registry exposes the connector registry (vendor list / spec lookups).
func (rt *Runtime) Registry() *Registry { return rt.reg }

// Store exposes the config store the runtime polls from.
func (rt *Runtime) Store() ConfigStore { return rt.store }

// WriteMetrics renders the connector-health series (health.go) for the api's
// own /metrics scrape.
func (rt *Runtime) WriteMetrics(w io.Writer) { rt.health.WriteMetrics(w) }

// pollInterval is an integration's effective interval (floored; a sub-floor
// value falls back to the default, never a hot loop).
func pollInterval(ic Integration) time.Duration {
	interval := time.Duration(ic.PollIntervalS) * time.Second
	if interval < minPollInterval {
		interval = defaultPollInterval
	}
	return interval
}

// deadlineFor is the per-cycle deadline: min(interval, the configured cap).
func (rt *Runtime) deadlineFor(interval time.Duration) time.Duration {
	if rt.deadline > 0 && rt.deadline < interval {
		return rt.deadline
	}
	return interval
}

// Run drives the scheduler until ctx is done. tick is how often due-ness is
// re-evaluated, NOT the poll rate — each integration polls on its own
// poll_interval_s (floored at 30s). The worker goroutines are started here
// and joined before Run returns, so the caller's supervised worker
// ("nms-scheduler") covers them on shutdown.
func (rt *Runtime) Run(ctx context.Context, tick time.Duration) {
	jobs := make(chan Integration, rt.workers)
	wg := rt.startWorkers(ctx, jobs)
	defer func() {
		close(jobs)
		wg.Wait()
	}()
	// Non-blocking hand-off: a full queue means every worker is busy; the
	// integration stays due and is offered again next tick.
	send := func(ic Integration) bool {
		select {
		case jobs <- ic:
			return true
		default:
			return false
		}
	}
	rt.dispatch(ctx, send) // seed immediately so an enabled integration isn't idle a full tick
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rt.dispatch(ctx, send)
		}
	}
}

// startWorkers launches the pool over jobs. Each worker owns the claim the
// dispatcher took for the integration it receives and releases it.
func (rt *Runtime) startWorkers(ctx context.Context, jobs <-chan Integration) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := 0; i < rt.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ic := range jobs {
				key := Key(ic.Tenant, ic.ID)
				if ctx.Err() == nil {
					rt.pollClaimed(ctx, ic, false)
				}
				rt.release(key)
			}
		}()
	}
	return &wg
}

// tickOnce dispatches one tick through a fresh pool and waits for every cycle
// it started — the synchronous form (tests, and any caller that needs "one
// pass, done").
func (rt *Runtime) tickOnce(ctx context.Context) {
	jobs := make(chan Integration)
	wg := rt.startWorkers(ctx, jobs)
	rt.dispatch(ctx, func(ic Integration) bool {
		select {
		case jobs <- ic:
			return true
		case <-ctx.Done():
			return false
		}
	})
	close(jobs)
	wg.Wait()
}

// dispatch lists the enabled integrations, prunes state for the ones that
// left, and offers every due, idle integration to send — tenants interleaved.
func (rt *Runtime) dispatch(ctx context.Context, send func(Integration) bool) {
	ints, err := rt.store.ListEnabled(ctx)
	if err != nil {
		applog.Error("nms", "list enabled integrations", map[string]any{"error": err.Error()})
		return
	}
	rt.syncEnabled(ctx, ints)
	for _, ic := range rt.dispatchOrder(ints) {
		if ctx.Err() != nil {
			return
		}
		key := Key(ic.Tenant, ic.ID)
		if rt.isInFlight(key) || !rt.due(ic) {
			continue
		}
		if !rt.claim(key) {
			continue // "Poll now" took it between the checks
		}
		if !send(ic) {
			rt.release(key)
			rt.mu.Lock()
			delete(rt.lastRun, key) // still due: offer it again next tick
			rt.mu.Unlock()
			return // the queue is full; the rest wait for the next tick
		}
	}
}

// dispatchOrder interleaves tenants (round-robin, the starting tenant rotating
// every tick) and, within a tenant, puts the longest-waiting integration
// first — so neither a tenant with many integrations nor list order can keep
// another tenant's poll at the back of the queue.
func (rt *Runtime) dispatchOrder(ints []Integration) []Integration {
	rt.mu.Lock()
	rot := rt.tickN
	rt.tickN++
	last := make(map[string]time.Time, len(ints))
	for _, ic := range ints {
		last[Key(ic.Tenant, ic.ID)] = rt.lastRun[Key(ic.Tenant, ic.ID)]
	}
	rt.mu.Unlock()

	byTenant := map[string][]Integration{}
	for _, ic := range ints {
		byTenant[ic.Tenant] = append(byTenant[ic.Tenant], ic)
	}
	tenants := make([]string, 0, len(byTenant))
	for t, list := range byTenant {
		tenants = append(tenants, t)
		sort.SliceStable(list, func(i, j int) bool {
			li, lj := last[Key(list[i].Tenant, list[i].ID)], last[Key(list[j].Tenant, list[j].ID)]
			if !li.Equal(lj) {
				return li.Before(lj)
			}
			return list[i].ID < list[j].ID
		})
	}
	sort.Strings(tenants)
	if n := len(tenants); n > 0 {
		r := rot % n
		tenants = append(tenants[r:], tenants[:r]...)
	}
	out := make([]Integration, 0, len(ints))
	for round := 0; len(out) < len(ints); round++ {
		for _, t := range tenants {
			if list := byTenant[t]; round < len(list) {
				out = append(out, list[round])
			}
		}
	}
	return out
}

// streamLabel bounds a stream name to the connector's declared streams.
func streamLabel(spec ConnectorSpec, stream string) string {
	for _, s := range spec.Streams {
		if s == stream {
			return stream
		}
	}
	return streamLabelUnknown
}

// syncEnabled reconciles per-integration state with the enabled set: health
// series appear (seeded from the store) and disappear with their
// integrations, and the scheduler's own maps are pruned in the same pass so a
// deleted or disabled integration leaves nothing behind. inFlight is never
// pruned — a running cycle releases its own claim.
func (rt *Runtime) syncEnabled(ctx context.Context, ints []Integration) {
	keep := make(map[string]bool, len(ints))
	enabled := make([]enabledIntegration, 0, len(ints))
	for _, ic := range ints {
		keep[Key(ic.Tenant, ic.ID)] = true
		ei := enabledIntegration{Tenant: ic.Tenant, ID: ic.ID, Vendor: ic.Vendor, Interval: pollInterval(ic)}
		if conn, ok := rt.reg.Get(ic.Vendor); ok && conn.Spec().Poll {
			spec := conn.Spec()
			for _, s := range spec.EffectiveStreams(ic.Streams) {
				ei.Streams = append(ei.Streams, streamLabel(spec, s))
			}
		}
		if !rt.health.Known(ic.Tenant, ic.ID) {
			ei.LastSuccess = rt.seedLastSuccess(ctx, ic)
		}
		enabled = append(enabled, ei)
	}
	rt.health.Sync(enabled)

	rt.mu.Lock()
	defer rt.mu.Unlock()
	for k := range rt.pipes {
		if !keep[k] {
			delete(rt.pipes, k)
		}
	}
	for k := range rt.lastRun {
		if !keep[k] {
			delete(rt.lastRun, k)
		}
	}
	for k := range rt.sessions {
		if !keep[k] {
			delete(rt.sessions, k)
		}
	}
	for k := range rt.buckets {
		if !keep[k] {
			delete(rt.buckets, k)
		}
	}
	for k := range rt.breakers {
		if !keep[k] {
			delete(rt.breakers, k)
		}
	}
}

// seedLastSuccess reads the integration's persisted last success (its own
// tenant's scope) so the health registry survives an api restart. A read
// failure seeds nothing and is logged: the integration then reads as never
// succeeded until its next good cycle (warning, not page).
func (rt *Runtime) seedLastSuccess(ctx context.Context, ic Integration) time.Time {
	sctx, cancel := context.WithTimeout(ctx, recordTimeout)
	defer cancel()
	h, ok, err := rt.store.Health(sctx, ic.Tenant, false, ic.ID)
	if err != nil {
		applog.Warn("nms", "health seed unread", map[string]any{"tenant": ic.Tenant, "integration": ic.ID, "error": err.Error()})
		return time.Time{}
	}
	if !ok {
		return time.Time{}
	}
	return h.LastSuccess
}

// due reports whether an integration's poll interval has elapsed (and marks it
// started — a failed run still waits a full interval; retry-with-backoff lives
// INSIDE the run via RetryDoer, not by hammering the controller every tick).
func (rt *Runtime) due(ic Integration) bool {
	interval := pollInterval(ic)
	key := Key(ic.Tenant, ic.ID)
	now := rt.now()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if last, ok := rt.lastRun[key]; ok && now.Sub(last) < interval {
		return false
	}
	rt.lastRun[key] = now
	return true
}

func (rt *Runtime) isInFlight(key string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.inFlight[key]
}

// claim marks a cycle running for key; false when one already is.
func (rt *Runtime) claim(key string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.inFlight[key] {
		return false
	}
	rt.inFlight[key] = true
	return true
}

func (rt *Runtime) release(key string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.inFlight, key)
}

// pipeline returns the long-lived per-integration pipeline (dedup + flap state).
func (rt *Runtime) pipeline(ic Integration) *Pipeline {
	key := Key(ic.Tenant, ic.ID)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	p, ok := rt.pipes[key]
	if !ok {
		p = NewPipeline(pipelineSeenCap)
		if conn, found := rt.reg.Get(ic.Vendor); found && rt.resolver != nil {
			p.Resolver, p.KeyKind = rt.resolver, conn.Spec().DeviceKeyKind
		}
		rt.pipes[key] = p
	}
	return p
}

// bucket returns the integration's persistent rate limiter, rebuilt only when
// the rate it should enforce changes.
func (rt *Runtime) bucket(key string, rate float64) *TokenBucket {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rb, ok := rt.buckets[key]; ok && rb.rate == rate {
		return rb.b
	}
	b := NewTokenBucket(rate)
	rt.buckets[key] = &rateBucket{rate: rate, b: b}
	return b
}

// breaker returns the integration's circuit breaker (cooldown base = its
// current interval).
func (rt *Runtime) breaker(key string, interval time.Duration) *Breaker {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b, ok := rt.breakers[key]
	if !ok {
		b = NewBreaker(interval, rt.now, rt.jitter)
		rt.breakers[key] = b
		return b
	}
	b.SetBase(interval)
	return b
}

// session returns the integration's cached controller session (zero if none).
func (rt *Runtime) session(key string) Session {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.sessions[key]
}

// storeSession caches the session a poll cycle ended with; a failed cycle
// drops the cache so the next attempt performs a fresh login rather than
// retrying a session of unknown state.
func (rt *Runtime) storeSession(key string, s Session, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if err != nil {
		delete(rt.sessions, key)
		return
	}
	rt.sessions[key] = s
}

func (rt *Runtime) httpClient(ic Integration) *http.Client {
	if ic.TLSSkipVerify {
		return rt.insecureClient
	}
	return rt.client
}

// HTTPClient returns the client an integration's controller calls must use
// (strict TLS unless the integration explicitly opted into tls_skip_verify).
// The "Test connection" API composes its auth probe with it.
func (rt *Runtime) HTTPClient(ic Integration) *http.Client { return rt.httpClient(ic) }

// IngestBatch routes one transformed webhook batch through the integration's
// long-lived pipeline (dedup + flap state — the SAME state the poll path uses)
// and fans the routed output to the sinks. Returns the count of events
// produced.
func (rt *Runtime) IngestBatch(ctx context.Context, ic Integration, batch Batch) int64 {
	rep := rt.sinkRouted(ctx, ic, rt.pipeline(ic).Route(batch))
	for _, lane := range rep.failedLanes() {
		rt.health.RecordSinkFailure(ic.Tenant, ic.ID, ic.Vendor, lane)
	}
	return rep.produced
}

// PollIntegration executes one poll cycle for one integration, records the
// outcome, and returns the run record (the "Poll now" API returns it to the
// operator). Marks lastRun so a manual poll also resets the scheduler's
// interval. A cycle of the same integration already running answers
// RunStatusBusy (not recorded). A manual poll of an integration whose breaker
// is open is admitted as the half-open login probe — the operator who just
// fixed a password must not wait out the cooldown.
func (rt *Runtime) PollIntegration(ctx context.Context, ic Integration) RunRecord {
	key := Key(ic.Tenant, ic.ID)
	if !rt.claim(key) {
		return RunRecord{Tenant: ic.Tenant, IntegrationID: ic.ID, Status: RunStatusBusy,
			Error: "a poll of this integration is already running"}
	}
	defer rt.release(key)
	return rt.pollClaimed(ctx, ic, true)
}

// pollOutcome is what one cycle produced, before it is turned into a record.
type pollOutcome struct {
	polled     bool // false: webhook-only integration, nothing to poll
	events     int64
	streams    []StreamResult
	runErr     error // the cycle failed before (or instead of) its streams
	sinkErrs   map[string]error
	authFailed bool
	devices    *deviceCounts
}

// pollClaimed runs one cycle for an integration the caller has claimed.
func (rt *Runtime) pollClaimed(ctx context.Context, ic Integration, manual bool) RunRecord {
	started := rt.now().UTC()
	runID := fmt.Sprintf("%d-%s", started.UnixMilli(), randHex(4))
	key := Key(ic.Tenant, ic.ID)
	rt.mu.Lock()
	rt.lastRun[key] = started
	rt.mu.Unlock()

	interval := pollInterval(ic)
	pctx, cancel := context.WithTimeout(ctx, rt.deadlineFor(interval))
	out := rt.pollOnce(pctx, ctx, ic, interval, manual)
	cancel()

	rec := RunRecord{Tenant: ic.Tenant, IntegrationID: ic.ID, RunID: runID, Started: started,
		Events: out.events, Streams: out.streams}
	rec.Finished = rt.now().UTC()
	rec.Status, rec.Error = runStatus(out)
	if rec.Status != RunStatusOK {
		applog.Warn("nms", "poll cycle did not fully deliver", map[string]any{
			"tenant": ic.Tenant, "integration": ic.ID, "vendor": ic.Vendor, "status": rec.Status, "error": rec.Error})
	}
	if out.polled {
		rt.health.Record(ic.Tenant, ic.ID, ic.Vendor, interval, runHealth{
			Streams:    labelStreams(rt.reg, ic.Vendor, out.streams),
			Duration:   rec.Finished.Sub(started),
			Finished:   rec.Finished,
			Delivered:  delivered(out),
			Failed:     rec.Status == RunStatusError,
			AuthFailed: out.authFailed,
			SinkFailed: sinkReport{failed: out.sinkErrs}.failedLanes(),
			Devices:    out.devices,
			Circuit:    rt.breaker(key, interval).State(),
		})
	}
	rctx, rcancel := context.WithTimeout(ctx, recordTimeout)
	defer rcancel()
	if rerr := rt.store.RecordRun(rctx, rec); rerr != nil {
		applog.Error("nms", "record run", map[string]any{"integration": ic.ID, "error": rerr.Error()})
	}
	return rec
}

// labelStreams copies stream results with their names bounded to the
// connector's declared streams (health labels only; the record keeps names).
func labelStreams(reg *Registry, vendor string, in []StreamResult) []StreamResult {
	conn, ok := reg.Get(vendor)
	if !ok {
		return nil
	}
	out := make([]StreamResult, len(in))
	for i, s := range in {
		s.Stream = streamLabel(conn.Spec(), s.Stream)
		out[i] = s
	}
	return out
}

// delivered: at least one stream returned data AND the lanes correlation
// reads (metrics, events) accepted it. A state/device/wireless sink refusal
// marks the run partial but is not ingest silence (those lanes are storage;
// "storage refusing writes" is its own page condition).
func delivered(out pollOutcome) bool {
	if out.runErr != nil || out.sinkErrs[LaneMetrics] != nil || out.sinkErrs[LaneEvents] != nil {
		return false
	}
	for _, s := range out.streams {
		if s.Status == ResultOK {
			return true
		}
	}
	return false
}

// runStatus folds an outcome into ok | partial | error and the record's
// error text.
func runStatus(out pollOutcome) (string, string) {
	if !out.polled {
		if out.runErr != nil {
			return RunStatusError, out.runErr.Error()
		}
		return RunStatusOK, ""
	}
	if out.runErr != nil {
		return RunStatusError, boundedErrorText(out.runErr)
	}
	var okN int
	var parts []string
	for _, s := range out.streams {
		if s.Status == ResultOK {
			okN++
			continue
		}
		msg := s.Status
		if s.Error != "" {
			msg = s.Error
		}
		parts = append(parts, s.Stream+": "+msg)
	}
	var errText string
	if len(parts) > 0 {
		errText = "stream errors: " + strings.Join(parts, "; ")
	}
	for _, lane := range (sinkReport{failed: out.sinkErrs}).failedLanes() {
		if errText != "" {
			errText += "; "
		}
		errText += "sink " + lane + ": " + boundedErrorText(out.sinkErrs[lane])
	}
	switch {
	case len(out.streams) > 0 && okN == 0:
		return RunStatusError, errText
	case errText != "":
		return RunStatusPartial, errText
	}
	return RunStatusOK, ""
}

// allStreams reports every stream of the cycle with one status (the cycle
// failed as a whole before any stream ran).
func allStreams(streams []string, status string, err error) []StreamResult {
	out := make([]StreamResult, 0, len(streams))
	for _, s := range streams {
		out = append(out, StreamResult{Stream: s, Status: status, Error: boundedErrorText(err)})
	}
	return out
}

// pollOnce runs one cycle: breaker admission, credentials, the (probe) login,
// RunPollSession under pctx (the deadline), then the sinks under ctx (the
// runtime context, so data fetched just inside the deadline still lands).
func (rt *Runtime) pollOnce(pctx, ctx context.Context, ic Integration, interval time.Duration, manual bool) pollOutcome {
	conn, ok := rt.reg.Get(ic.Vendor)
	if !ok {
		return pollOutcome{polled: false, runErr: fmt.Errorf("unknown vendor %q", ic.Vendor)}
	}
	spec := conn.Spec()
	if !spec.Poll {
		return pollOutcome{polled: false} // webhook-only integration: nothing to poll, not an error
	}
	out := pollOutcome{polled: true}
	streams := spec.EffectiveStreams(ic.Streams)
	key := Key(ic.Tenant, ic.ID)

	br := rt.breaker(key, interval)
	if manual {
		br.ForceProbe()
	}
	allowed, probe := br.Admit()
	if !allowed {
		out.runErr = errCircuitOpen
		out.streams = allStreams(streams, ResultCircuitOpen, nil)
		return out
	}

	creds, _, err := rt.store.Credentials(pctx, ic.Tenant, ic.ID)
	if err != nil {
		// A local store failure says nothing about the controller: the
		// breaker is left as it is.
		out.runErr = fmt.Errorf("resolve credentials: %w", err)
		out.streams = allStreams(streams, ResultError, out.runErr)
		return out
	}
	do := NewRetryDoer(rt.httpClient(ic), rt.bucket(key, spec.RatePerSec), DefaultRetry())
	cfg := IntegrationConfig{
		Tenant: ic.Tenant, IntegrationID: ic.ID, Vendor: ic.Vendor,
		BaseURL: ic.BaseURL, Streams: streams,
		Backfill: rt.backfill,
		Creds:    creds,
	}
	// Reuse the integration's cached controller session until it expires (or a
	// 401 refreshes it inside the run) — steady 30-60s polls must not log in to
	// the controller every cycle. An errored run clears the cache so the next
	// attempt starts from a clean login.
	cached := rt.session(key)
	if probe {
		// Half-open: exactly one login. Success closes the breaker and the
		// cycle proceeds with the fresh session; failure re-opens it.
		sess, aerr := conn.Auth().Authenticate(pctx, cfg.BaseURL, cfg.Creds, do)
		if aerr != nil {
			aerr = fmt.Errorf("%w: breaker probe: %w", ErrAuthFailed, aerr)
			result, trip := classifyPollError(aerr)
			br.Record(trip)
			rt.storeSession(key, Session{}, aerr)
			out.runErr = aerr
			out.authFailed = result == ResultAuthFailed
			out.streams = allStreams(streams, result, aerr)
			return out
		}
		br.Record(false)
		cached = sess
	}
	res, sess, err := RunPollSession(pctx, conn, cfg, do, rt.store.Checkpoints(), rt.pipeline(ic), cached)
	rt.storeSession(key, sess, err)
	if err != nil {
		result, trip := classifyPollError(err)
		br.Record(trip)
		out.runErr = err
		out.authFailed = result == ResultAuthFailed
		out.streams = allStreams(streams, result, err)
		return out
	}
	out.streams = res.Streams
	anyOK, anyTrip := false, false
	for _, s := range res.Streams {
		switch s.Status {
		case ResultOK:
			anyOK = true
		case ResultAuthFailed:
			out.authFailed = true
			anyTrip = true
		default:
			if _, trip := classifyPollError(res.Errors[s.Stream]); trip {
				anyTrip = true
			}
		}
	}
	br.Record(!anyOK && anyTrip)

	sctx, scancel := context.WithTimeout(ctx, sinkTimeout)
	defer scancel()
	rep := rt.sinkRouted(sctx, ic, res.Routed)
	out.events = rep.produced
	out.sinkErrs = rep.failed
	if res.Routed.DevicesComplete {
		dc := &deviceCounts{reported: len(res.Routed.Devices)}
		for _, d := range res.Routed.Devices {
			if d.Reachable == "unreachable" {
				dc.unreachable++
			}
		}
		out.devices = dc
	}
	return out
}

// sinkReport is one fan-out's result: events produced and the lanes that
// refused their share (first error per lane).
type sinkReport struct {
	produced int64
	failed   map[string]error
}

func (r *sinkReport) fail(lane string, err error) {
	if r.failed == nil {
		r.failed = map[string]error{}
	}
	if _, seen := r.failed[lane]; !seen {
		r.failed[lane] = err
	}
}

// failedLanes lists the refusing lanes in the closed lane order.
func (r sinkReport) failedLanes() []string {
	var out []string
	for _, lane := range SinkLanes() {
		if r.failed[lane] != nil {
			out = append(out, lane)
		}
	}
	return out
}

// sinkRouted fans one Routed batch to the sinks. Best-effort per lane — a
// failed sink is logged and never blocks the others. Returns the count of
// events produced and the lanes that refused (counted on the health series
// and marked on the run, so a refused write is never recorded as a clean run).
func (rt *Runtime) sinkRouted(ctx context.Context, ic Integration, routed Routed) sinkReport {
	var rep sinkReport
	if len(routed.MetricLines) > 0 && rt.sinks.EmitMetrics != nil {
		if err := rt.sinks.EmitMetrics(ctx, routed.MetricLines); err != nil {
			applog.Warn("nms", "metric sink", map[string]any{"integration": ic.ID, "error": err.Error()})
			rep.fail(LaneMetrics, err)
		}
	}
	// #128 Phase 3: wireless state transitions (ap_join/radio_oper) synthesize
	// normalized events onto the SAME controller_events lane — correlation
	// evidence, not a parallel wireless pipeline. Non-wireless state kinds are
	// untouched.
	events := routed.Events
	spec := ConnectorSpec{Vendor: ic.Vendor, SourceSystem: ic.Vendor}
	if conn, ok := rt.reg.Get(ic.Vendor); ok {
		spec = conn.Spec()
	}
	if len(routed.StateChanges) > 0 {
		events = append(events,
			WirelessStateChangeEvents(spec, ic.Tenant, ic.ID, routed.StateChanges)...)
		events = append(events,
			SDWANStateChangeEvents(spec, ic.Tenant, ic.ID, routed.StateChanges)...)
	}
	if err := stampControllerInstance(events, spec, ic); err != nil {
		// Events still flow; they only lack the controller-instance context.
		applog.Warn("nms", "controller instance not derivable from base URL", map[string]any{"integration": ic.ID, "error": err.Error()})
	}
	if n := canonicalSeverities(events); n > 0 {
		applog.Warn("nms", "non-canonical event severity mapped (connector bug)", map[string]any{"integration": ic.ID, "vendor": ic.Vendor, "events": n})
	}
	if len(events) > 0 {
		if rt.sinks.ProduceEvents == nil {
			applog.Warn("nms", "event sink not wired; events dropped", map[string]any{"integration": ic.ID})
			rep.fail(LaneEvents, errors.New("event sink not wired"))
		} else if n, err := rt.sinks.ProduceEvents(ctx, ic.Tenant, events); err != nil {
			applog.Warn("nms", "event sink", map[string]any{"integration": ic.ID, "error": err.Error()})
			rep.fail(LaneEvents, err)
		} else {
			rep.produced = n
		}
	}
	if len(routed.States) > 0 {
		if err := rt.store.UpsertStates(ctx, ic.Tenant, ic.ID, routed.States); err != nil {
			applog.Warn("nms", "state sink", map[string]any{"integration": ic.ID, "error": err.Error()})
			rep.fail(LaneStates, err)
		}
	}
	// Controller-sourced inventory (inventory.go): fifth sink. Applied ONLY for
	// a complete snapshot; the owner is the integration's, never the batch's.
	if routed.DevicesComplete {
		if err := rt.store.ReplaceDevices(ctx, ic.Tenant, ic.ID, routed.Devices, time.Now().UTC()); err != nil {
			applog.Warn("nms", "device inventory not stored", map[string]any{"integration": ic.ID, "error": err.Error()})
			rep.fail(LaneDevices, err)
		}
	}
	// Wireless canonical inventory (#128): fourth sink, same best-effort-per-
	// lane contract. Tenant comes from the integration record, never the batch.
	if inv := routed.Wireless; !inv.Empty() {
		if rt.wireless == nil {
			applog.Warn("nms", "wireless inventory discarded: no store wired", map[string]any{"integration": ic.ID})
		} else {
			for _, c := range inv.Controllers {
				c.TenantID = ic.Tenant
				if err := rt.wireless.UpsertController(ctx, c); err != nil {
					applog.Warn("nms", "wireless controller sink", map[string]any{"integration": ic.ID, "error": err.Error()})
					rep.fail(LaneWireless, err)
				}
			}
			for _, ap := range inv.APs {
				ap.TenantID = ic.Tenant
				if err := rt.wireless.UpsertAP(ctx, ap); err != nil {
					applog.Warn("nms", "wireless ap sink", map[string]any{"integration": ic.ID, "error": err.Error()})
					rep.fail(LaneWireless, err)
				}
			}
			if len(inv.Radios) > 0 {
				if err := rt.wireless.UpsertRadios(ctx, ic.Tenant, inv.Radios); err != nil {
					applog.Warn("nms", "wireless radio sink", map[string]any{"integration": ic.ID, "error": err.Error()})
					rep.fail(LaneWireless, err)
				}
			}
			for _, wl := range inv.WLANs {
				wl.TenantID = ic.Tenant
				if err := rt.wireless.UpsertWLAN(ctx, wl); err != nil {
					applog.Warn("nms", "wireless wlan sink", map[string]any{"integration": ic.ID, "error": err.Error()})
					rep.fail(LaneWireless, err)
				}
			}
			for _, bs := range inv.BSSIDs {
				bs.TenantID = ic.Tenant
				if err := rt.wireless.UpsertBSSID(ctx, bs); err != nil {
					applog.Warn("nms", "wireless bssid sink", map[string]any{"integration": ic.ID, "error": err.Error()})
					rep.fail(LaneWireless, err)
				}
			}
		}
	}
	return rep
}

// randHex returns nBytes of hex-encoded randomness (run-id salt; a failed
// entropy read degrades to a timestamp-only id, never a panic).
func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail (Go 1.24+ aborts instead)
	return hex.EncodeToString(b)
}
