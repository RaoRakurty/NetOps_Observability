package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"netops/backend/nms"
)

// nms_scheduler.go — the NMS poll runtime (#95 P3b). A single supervised loop
// (ticketing-sweeper idiom) that, each tick, lists every ENABLED integration
// across all tenants (platform scope), runs the due ones through nms.RunPoll,
// and fans the three class-routed outputs to their sinks:
//
//   controller_metric → VictoriaMetrics /api/v1/import/prometheus (Lane 1)
//   controller_event  → Redpanda pandaproxy → netops.controller_events
//   controller_state  → controller_state_current (PG, flap-tracked)
//
// Dormant unless FEATURE_NMS_INTEGRATIONS=true. Per-integration Pipelines are
// long-lived so dedup (SeenSet) and flap tracking survive across ticks.

const (
	nmsDefaultPollInterval = 5 * time.Minute
	nmsMinPollInterval     = 30 * time.Second
	nmsDefaultBackfill     = 15 * time.Minute
	nmsPipelineSeenCap     = 4096
)

type nmsRuntime struct {
	store nmsConfigStore
	reg   *nms.Registry

	client         *http.Client // strict TLS (default)
	insecureClient *http.Client // per-integration opt-in for self-signed controllers

	mu      sync.Mutex
	pipes   map[string]*nms.Pipeline // tenant\x00id → long-lived pipeline
	lastRun map[string]time.Time     // tenant\x00id → last poll start
}

func newNMSRuntime(store nmsConfigStore) *nmsRuntime {
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
	return &nmsRuntime{
		store:          store,
		reg:            nms.NewRegistry(),
		client:         strict,
		insecureClient: insecure,
		pipes:          map[string]*nms.Pipeline{},
		lastRun:        map[string]time.Time{},
	}
}

// Run drives the scheduler until ctx is done. tick is how often due-ness is
// re-evaluated, NOT the poll rate — each integration polls on its own
// poll_interval_s (floored at 30s).
func (rt *nmsRuntime) Run(ctx context.Context, tick time.Duration) {
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

func (rt *nmsRuntime) tickOnce(ctx context.Context) {
	ints, err := rt.store.ListEnabled(ctx)
	if err != nil {
		logError("nms", "list enabled integrations", map[string]any{"error": err.Error()})
		return
	}
	for _, ic := range ints {
		if ctx.Err() != nil {
			return
		}
		if !rt.due(ic) {
			continue
		}
		rt.runOne(ctx, ic)
	}
}

// due reports whether an integration's poll interval has elapsed (and marks it
// started — a failed run still waits a full interval; retry-with-backoff lives
// INSIDE the run via RetryDoer, not by hammering the controller every tick).
func (rt *nmsRuntime) due(ic nmsIntegration) bool {
	interval := time.Duration(ic.PollIntervalS) * time.Second
	if interval < nmsMinPollInterval {
		interval = nmsDefaultPollInterval
	}
	key := nmsKey(ic.Tenant, ic.ID)
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
func (rt *nmsRuntime) pipeline(key string) *nms.Pipeline {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	p, ok := rt.pipes[key]
	if !ok {
		p = nms.NewPipeline(nmsPipelineSeenCap)
		rt.pipes[key] = p
	}
	return p
}

func (rt *nmsRuntime) httpClient(ic nmsIntegration) *http.Client {
	if ic.TLSSkipVerify {
		return rt.insecureClient
	}
	return rt.client
}

// runOne executes one poll cycle for one integration and records the outcome.
func (rt *nmsRuntime) runOne(ctx context.Context, ic nmsIntegration) {
	started := time.Now().UTC()
	runID := fmt.Sprintf("%d-%s", started.UnixMilli(), randHex(4))

	rec := nmsRunRecord{Tenant: ic.Tenant, IntegrationID: ic.ID, RunID: runID, Started: started}
	events, err := rt.pollOnce(ctx, ic)
	rec.Finished = time.Now().UTC()
	rec.Events = events
	if err != nil {
		rec.Status = "error"
		rec.Error = err.Error()
		logWarn("nms", "poll cycle failed", map[string]any{
			"tenant": ic.Tenant, "integration": ic.ID, "vendor": ic.Vendor, "error": err.Error()})
	} else {
		rec.Status = "ok"
	}
	if rerr := rt.store.RecordRun(ctx, rec); rerr != nil {
		logError("nms", "record run", map[string]any{"integration": ic.ID, "error": rerr.Error()})
	}
}

// pollOnce runs nms.RunPoll and sinks the routed output. Returns the number of
// controller events emitted. Partial stream failures surface in the error while
// successful streams' output still flows (RunPoll contract).
func (rt *nmsRuntime) pollOnce(ctx context.Context, ic nmsIntegration) (int64, error) {
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
	do := nms.NewRetryDoer(rt.httpClient(ic), nms.NewTokenBucket(spec.RatePerSec), nms.DefaultRetry())
	cfg := nms.IntegrationConfig{
		Tenant: ic.Tenant, IntegrationID: ic.ID, Vendor: ic.Vendor,
		BaseURL: ic.BaseURL, Streams: streams,
		Backfill: durationOr("NMS_BACKFILL", nmsDefaultBackfill),
		Creds:    creds,
	}
	res, err := nms.RunPoll(ctx, conn, cfg, do, rt.store.Checkpoints(), rt.pipeline(nmsKey(ic.Tenant, ic.ID)))
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

// sinkRouted fans one Routed batch to the three sinks. Best-effort per lane —
// a failed sink is logged and never blocks the others (metrics loss must not
// stop events, and vice versa). Returns the count of events produced.
func (rt *nmsRuntime) sinkRouted(ctx context.Context, ic nmsIntegration, routed nms.Routed) int64 {
	if len(routed.MetricLines) > 0 {
		if err := nmsEmitMetrics(ctx, routed.MetricLines); err != nil {
			logWarn("nms", "metric sink", map[string]any{"integration": ic.ID, "error": err.Error()})
		}
	}
	var produced int64
	if len(routed.Events) > 0 {
		recs := make([]proxyRecord, 0, len(routed.Events))
		for _, ev := range routed.Events {
			recs = append(recs, proxyRecord{Key: ic.Tenant, Value: ev}) // tenant key: per-tenant ordering
		}
		if _, err := produceJSON(ctx, nms.TopicControllerEvents, recs); err != nil {
			logWarn("nms", "event sink", map[string]any{"integration": ic.ID, "error": err.Error()})
		} else {
			produced = int64(len(recs))
		}
	}
	if len(routed.StateChanges) > 0 {
		if err := rt.store.UpsertStates(ctx, ic.Tenant, ic.ID, routed.StateChanges); err != nil {
			logWarn("nms", "state sink", map[string]any{"integration": ic.ID, "error": err.Error()})
		}
	}
	return produced
}

// nmsEmitMetrics pushes Prometheus exposition lines to VictoriaMetrics
// (same lane as collectors/poller.go emitMetrics; that helper is unexported in
// a sibling package, so the ~15 lines are mirrored here).
func nmsEmitMetrics(ctx context.Context, lines []string) error {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", ""))
	if base == "" {
		return nil // no metrics backend configured — not an error
	}
	url := strings.TrimRight(base, "/") + "/api/v1/import/prometheus"
	body := strings.Join(lines, "\n") + "\n"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("victoria import: status %d", resp.StatusCode)
	}
	return nil
}
