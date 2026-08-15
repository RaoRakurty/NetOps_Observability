package nms

// scheduler.go — the NMS poll runtime (#95 P3b, extracted P2 W4.17). A single
// supervised loop (ticketing-sweeper idiom) that, each tick, lists every
// ENABLED integration across all tenants (platform scope), runs the due ones
// through RunPollSession, and fans the class-routed outputs to their sinks:
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

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/wireless"
)

const (
	defaultPollInterval = 5 * time.Minute
	minPollInterval     = 30 * time.Second
	pipelineSeenCap     = 4096

	// DefaultBackfill is the poll lookback when the caller configures none
	// (main resolves NMS_BACKFILL against it).
	DefaultBackfill = 15 * time.Minute
)

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

	mu       sync.Mutex
	pipes    map[string]*Pipeline // tenant\x00id → long-lived pipeline
	lastRun  map[string]time.Time // tenant\x00id → last poll start
	sessions map[string]Session   // tenant\x00id → cached controller session (reused until expiry)
}

// NewRuntime builds the scheduler over a config store, the entrypoint's sinks
// and the poll backfill window.
func NewRuntime(store ConfigStore, sinks Sinks, backfill time.Duration) *Runtime {
	if backfill <= 0 {
		backfill = DefaultBackfill
	}
	strict := &http.Client{Timeout: 30 * time.Second}
	// Controllers in labs/enterprises commonly present self-signed certs; this
	// client is used ONLY for integrations that explicitly set tls_skip_verify.
	// Default remains strict verification (§3 zero-trust).
	insecure := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 — explicit per-integration operator opt-in
		},
	}
	return &Runtime{
		store:          store,
		reg:            NewRegistry(),
		sinks:          sinks,
		backfill:       backfill,
		client:         strict,
		insecureClient: insecure,
		pipes:          map[string]*Pipeline{},
		lastRun:        map[string]time.Time{},
		sessions:       map[string]Session{},
	}
}

// SetWirelessStore wires the #128 canonical-inventory sink.
func (rt *Runtime) SetWirelessStore(ws wireless.Store) { rt.wireless = ws }

// Registry exposes the connector registry (vendor list / spec lookups).
func (rt *Runtime) Registry() *Registry { return rt.reg }

// Store exposes the config store the runtime polls from.
func (rt *Runtime) Store() ConfigStore { return rt.store }

// Run drives the scheduler until ctx is done. tick is how often due-ness is
// re-evaluated, NOT the poll rate — each integration polls on its own
// poll_interval_s (floored at 30s).
func (rt *Runtime) Run(ctx context.Context, tick time.Duration) {
	rt.tickOnce(ctx) // seed immediately so an enabled integration isn't idle a full tick
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rt.tickOnce(ctx)
		}
	}
}

func (rt *Runtime) tickOnce(ctx context.Context) {
	ints, err := rt.store.ListEnabled(ctx)
	if err != nil {
		applog.Error("nms", "list enabled integrations", map[string]any{"error": err.Error()})
		return
	}
	for _, ic := range ints {
		if ctx.Err() != nil {
			return
		}
		if !rt.due(ic) {
			continue
		}
		_ = rt.PollIntegration(ctx, ic) // failures are logged and recorded on the RunRecord inside
	}
}

// due reports whether an integration's poll interval has elapsed (and marks it
// started — a failed run still waits a full interval; retry-with-backoff lives
// INSIDE the run via RetryDoer, not by hammering the controller every tick).
func (rt *Runtime) due(ic Integration) bool {
	interval := time.Duration(ic.PollIntervalS) * time.Second
	if interval < minPollInterval {
		interval = defaultPollInterval
	}
	key := Key(ic.Tenant, ic.ID)
	now := time.Now()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if last, ok := rt.lastRun[key]; ok && now.Sub(last) < interval {
		return false
	}
	rt.lastRun[key] = now
	return true
}

// pipeline returns the long-lived per-integration pipeline (dedup + flap state).
func (rt *Runtime) pipeline(key string) *Pipeline {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	p, ok := rt.pipes[key]
	if !ok {
		p = NewPipeline(pipelineSeenCap)
		rt.pipes[key] = p
	}
	return p
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
	return rt.sinkRouted(ctx, ic, rt.pipeline(Key(ic.Tenant, ic.ID)).Route(batch))
}

// PollIntegration executes one poll cycle for one integration, records the
// outcome, and returns the run record (the scheduler discards it; the "Poll
// now" API returns it to the operator). Marks lastRun so a manual poll also
// resets the scheduler's interval.
func (rt *Runtime) PollIntegration(ctx context.Context, ic Integration) RunRecord {
	started := time.Now().UTC()
	runID := fmt.Sprintf("%d-%s", started.UnixMilli(), randHex(4))
	rt.mu.Lock()
	rt.lastRun[Key(ic.Tenant, ic.ID)] = started
	rt.mu.Unlock()

	rec := RunRecord{Tenant: ic.Tenant, IntegrationID: ic.ID, RunID: runID, Started: started}
	events, err := rt.pollOnce(ctx, ic)
	rec.Finished = time.Now().UTC()
	rec.Events = events
	if err != nil {
		rec.Status = "error"
		rec.Error = err.Error()
		applog.Warn("nms", "poll cycle failed", map[string]any{
			"tenant": ic.Tenant, "integration": ic.ID, "vendor": ic.Vendor, "error": err.Error()})
	} else {
		rec.Status = "ok"
	}
	if rerr := rt.store.RecordRun(ctx, rec); rerr != nil {
		applog.Error("nms", "record run", map[string]any{"integration": ic.ID, "error": rerr.Error()})
	}
	return rec
}

// pollOnce runs RunPollSession and sinks the routed output. Returns the number of
// controller events emitted. Partial stream failures surface in the error while
// successful streams' output still flows (RunPollSession contract).
func (rt *Runtime) pollOnce(ctx context.Context, ic Integration) (int64, error) {
	conn, ok := rt.reg.Get(ic.Vendor)
	if !ok {
		return 0, fmt.Errorf("unknown vendor %q", ic.Vendor)
	}
	spec := conn.Spec()
	if !spec.Poll {
		return 0, nil // webhook-only integration: nothing to poll, not an error
	}
	creds, _, err := rt.store.Credentials(ctx, ic.Tenant, ic.ID)
	if err != nil {
		return 0, fmt.Errorf("resolve credentials: %w", err)
	}
	streams := ic.Streams
	if len(streams) == 0 {
		streams = spec.Streams
	}
	do := NewRetryDoer(rt.httpClient(ic), NewTokenBucket(spec.RatePerSec), DefaultRetry())
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
	key := Key(ic.Tenant, ic.ID)
	res, sess, err := RunPollSession(ctx, conn, cfg, do, rt.store.Checkpoints(), rt.pipeline(key), rt.session(key))
	rt.storeSession(key, sess, err)
	if err != nil {
		return 0, err
	}
	n := rt.sinkRouted(ctx, ic, res.Routed)
	if len(res.Errors) > 0 {
		parts := make([]string, 0, len(res.Errors))
		for stream, serr := range res.Errors {
			parts = append(parts, stream+": "+serr.Error())
		}
		return n, fmt.Errorf("stream errors: %s", strings.Join(parts, "; "))
	}
	return n, nil
}

// sinkRouted fans one Routed batch to the sinks. Best-effort per lane — a
// failed sink is logged and never blocks the others. Returns the count of
// events produced.
func (rt *Runtime) sinkRouted(ctx context.Context, ic Integration, routed Routed) int64 {
	if len(routed.MetricLines) > 0 && rt.sinks.EmitMetrics != nil {
		if err := rt.sinks.EmitMetrics(ctx, routed.MetricLines); err != nil {
			applog.Warn("nms", "metric sink", map[string]any{"integration": ic.ID, "error": err.Error()})
		}
	}
	var produced int64
	// #128 Phase 3: wireless state transitions (ap_join/radio_oper) synthesize
	// normalized events onto the SAME controller_events lane — correlation
	// evidence, not a parallel wireless pipeline. Non-wireless state kinds are
	// untouched.
	events := routed.Events
	if len(routed.StateChanges) > 0 {
		events = append(events,
			WirelessStateChangeEvents(ic.Tenant, ic.ID, ic.Vendor, routed.StateChanges)...)
	}
	if len(events) > 0 {
		if rt.sinks.ProduceEvents == nil {
			applog.Warn("nms", "event sink not wired; events dropped", map[string]any{"integration": ic.ID})
		} else if n, err := rt.sinks.ProduceEvents(ctx, ic.Tenant, events); err != nil {
			applog.Warn("nms", "event sink", map[string]any{"integration": ic.ID, "error": err.Error()})
		} else {
			produced = n
		}
	}
	if len(routed.States) > 0 {
		if err := rt.store.UpsertStates(ctx, ic.Tenant, ic.ID, routed.States); err != nil {
			applog.Warn("nms", "state sink", map[string]any{"integration": ic.ID, "error": err.Error()})
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
				}
			}
			for _, ap := range inv.APs {
				ap.TenantID = ic.Tenant
				if err := rt.wireless.UpsertAP(ctx, ap); err != nil {
					applog.Warn("nms", "wireless ap sink", map[string]any{"integration": ic.ID, "error": err.Error()})
				}
			}
			if len(inv.Radios) > 0 {
				if err := rt.wireless.UpsertRadios(ctx, ic.Tenant, inv.Radios); err != nil {
					applog.Warn("nms", "wireless radio sink", map[string]any{"integration": ic.ID, "error": err.Error()})
				}
			}
			for _, wl := range inv.WLANs {
				wl.TenantID = ic.Tenant
				if err := rt.wireless.UpsertWLAN(ctx, wl); err != nil {
					applog.Warn("nms", "wireless wlan sink", map[string]any{"integration": ic.ID, "error": err.Error()})
				}
			}
			for _, bs := range inv.BSSIDs {
				bs.TenantID = ic.Tenant
				if err := rt.wireless.UpsertBSSID(ctx, bs); err != nil {
					applog.Warn("nms", "wireless bssid sink", map[string]any{"integration": ic.ID, "error": err.Error()})
				}
			}
		}
	}
	return produced
}

// randHex returns nBytes of hex-encoded randomness (run-id salt; a failed
// entropy read degrades to a timestamp-only id, never a panic).
func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail (Go 1.24+ aborts instead)
	return hex.EncodeToString(b)
}
