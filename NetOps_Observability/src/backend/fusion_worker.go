package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"netops/backend/appid"
	"netops/backend/appid/adapter"
)

// evStr reads a string field from a raw event map (package-main helper; the adapter
// package has its own unexported equivalent).
func evStr(ev map[string]any, key string) string {
	if v, ok := ev[key]; ok && v != nil {
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	return ""
}

// fusion_worker.go — #81 Fusion Layer Phase 4b runtime worker. Mirrors the
// ngfw_resolver poll pattern (no Kafka client; the engine is Go): a background loop
// pulls recent vendor app events from a source, runs the adapters → observations,
// persists them, fuses per conversation, persists the identities, and records metrics.
// Idempotent (deterministic ids) so each cycle / replay is safe. Opt-in + default-off.

// FusionSource yields raw vendor events observed since a time. Pluggable: OpenSearch
// in production, a fixture in tests/demos.
type FusionSource interface {
	Name() string
	Fetch(ctx context.Context, since time.Time) ([]map[string]any, error)
}

// fusionMetrics is the worker's operational counters (§14). No high-cardinality labels
// (no tenant/flow ids) — only vendor + band buckets.
type fusionMetrics struct {
	mu               sync.Mutex
	Cycles           int64
	Observations     int64
	Identities       int64
	ByVendor         map[string]int64
	ByBand           map[string]int64
	Unknown          int64
	Conflict         int64
	DeadLetter       int64
	Unsupported      int64
	Emitted          int64 // identities published to the correlation topic (P5b)
	EmitErrors       int64 // emit attempts that failed (best-effort; CH persist still holds)
	LastError        string
	LastCycleUnixSec int64
}

func newFusionMetrics() *fusionMetrics {
	return &fusionMetrics{ByVendor: map[string]int64{}, ByBand: map[string]int64{}}
}

func (m *fusionMetrics) snapshot() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	bv := map[string]int64{}
	for k, v := range m.ByVendor {
		bv[k] = v
	}
	bb := map[string]int64{}
	for k, v := range m.ByBand {
		bb[k] = v
	}
	return map[string]any{
		"cycles": m.Cycles, "observations": m.Observations, "identities": m.Identities,
		"by_vendor": bv, "by_band": bb, "unknown": m.Unknown, "conflict": m.Conflict,
		"dead_letter": m.DeadLetter, "unsupported": m.Unsupported,
		"emitted": m.Emitted, "emit_errors": m.EmitErrors,
		"last_error": m.LastError, "last_cycle_unix": m.LastCycleUnixSec,
	}
}

// appIdentityTopic is the versioned correlation feed for fused application identity
// (AD-4). The Python engine (main.py) consumes it as an enrichment evidence lane.
const appIdentityTopic = "netops.app.identities.v1"

// fusionWorker is the pipeline orchestrator. persist/emit funcs are injectable for tests.
type fusionWorker struct {
	reg        *adapter.Registry
	source     FusionSource
	canon      func(vendor, app string) string
	persistObs func(context.Context, []appid.ApplicationObservation) error
	persistID  func(context.Context, []appid.FusedIdentity) error
	emitID     func(context.Context, []appid.FusedIdentity) (int, error)
	window     time.Duration
	catVer     int
	metrics    *fusionMetrics
}

func newFusionWorker(src FusionSource) *fusionWorker {
	return &fusionWorker{
		reg: adapter.New(), source: src,
		persistObs: insertObservations, persistID: insertIdentities,
		emitID: emitIdentities,
		window: 10 * time.Minute, catVer: 1, metrics: newFusionMetrics(),
	}
}

// identityEvent maps a fused identity to the netops.app.identities.v1 wire contract
// consumed by correlation's app_identity_from_event(). Returns ok=false for an
// identity with no nameable app ("unknown"/empty) — those carry no enrichment value
// and the consumer would dead-letter them, so they are never emitted (unknown stays
// first-class in the catalog/CH, just not pushed as correlation evidence).
func identityEvent(fi appid.FusedIdentity) (map[string]any, bool) {
	app := strings.TrimSpace(fi.App)
	if app == "" || strings.EqualFold(app, "unknown") {
		return nil, false
	}
	// Distinct evidence sources, in deterministic order (the verdict ranks them).
	seen := map[string]bool{}
	sources := make([]string, 0, len(fi.Signals))
	for _, s := range fi.Signals {
		v := string(s.Source)
		if v != "" && !seen[v] {
			seen[v] = true
			sources = append(sources, v)
		}
	}
	ev := map[string]any{
		"tenant_id":       fi.TenantID,
		"app":             app,
		"band":            string(fi.Band),
		"state":           string(fi.State),
		"evidence_score":  fi.EvidenceScore,
		"sources":         sources,
		"fusion_version":  fi.FusionVersion,
		"catalog_version": fi.CatalogVersion,
		"ts":              fi.FusedAt.UTC().Format(time.RFC3339),
	}
	// Optional provenance / scope — only when present (keeps the wire dict lean and
	// the consumer's honest defaults intact).
	put := func(k, v string) {
		if v != "" {
			ev[k] = v
		}
	}
	put("canonical_app_id", fi.CanonicalAppID)
	put("provider", fi.Provider)
	put("component", fi.Component)
	put("dst_ip", fi.Scope.DstIP)
	put("proto", fi.Scope.Proto)
	put("flow_id", fi.Scope.FlowID)
	put("session_id", fi.Scope.SessionID)
	if fi.Scope.DstPort != 0 {
		ev["dst_port"] = fi.Scope.DstPort
	}
	return ev, true
}

// emitIdentities publishes nameable fused identities to the correlation topic via the
// Bus bridge emit (P5b, via Vector → Kafka). Best-effort: returns the count actually produced. The
// partition key is the tenant, so one tenant's identities stay ordered. Skipped
// (returns 0) when the topic transport is disabled — offline-safe.
func emitIdentities(ctx context.Context, ids []appid.FusedIdentity) (int, error) {
	recs := make([]proxyRecord, 0, len(ids))
	for _, fi := range ids {
		ev, ok := identityEvent(fi)
		if !ok {
			continue
		}
		recs = append(recs, proxyRecord{Key: fi.TenantID, Value: ev})
	}
	return produceJSON(ctx, appIdentityTopic, recs)
}

// cycle runs one pass deterministically at `now`. Returns the persisted identity count.
// A malformed event dead-letters (counted, never crashes); a persistence error aborts
// the cycle and is reported (the next cycle retries — idempotent writes make it safe).
func (w *fusionWorker) cycle(ctx context.Context, now time.Time) (int, error) {
	raw, err := w.source.Fetch(ctx, now.Add(-w.window))
	if err != nil {
		w.recordErr(err)
		return 0, err
	}
	obs := make([]appid.ApplicationObservation, 0, len(raw))
	for _, ev := range raw {
		tenant := evStr(ev, "tenant_id")
		res, name := w.reg.Parse(ev, tenant, now)
		switch {
		case name == "":
			w.bump(func(m *fusionMetrics) { m.Unsupported++ })
		case res.Err != nil:
			w.bump(func(m *fusionMetrics) { m.DeadLetter++ })
			log.Printf("fusion: dead-letter (%s): %v", name, res.Err)
		case !res.OK:
			// recognized but no app identity on this record — not an error.
		default:
			obs = append(obs, res.Obs)
			w.bump(func(m *fusionMetrics) { m.ByVendor[res.Obs.Vendor]++ })
		}
	}
	if err := w.persistObs(ctx, obs); err != nil {
		w.recordErr(err)
		return 0, err
	}
	ids := appid.FuseBatch(obs, appid.BatchContext{Now: now, CatalogVersion: w.catVer, Canon: w.canon})
	if err := w.persistID(ctx, ids); err != nil {
		w.recordErr(err)
		return 0, err
	}
	// Emit to the correlation feed — BEST-EFFORT (§9/§10). The ClickHouse persist
	// above is the source of truth; the topic is only the enrichment lane for the
	// engine. A transport failure is counted + logged, never an aborted cycle (the
	// next cycle re-emits — the consumer is idempotent on deterministic signal_id).
	if w.emitID != nil {
		if n, err := w.emitID(ctx, ids); err != nil {
			w.bump(func(m *fusionMetrics) { m.EmitErrors++ })
			log.Printf("fusion: identity emit error: %v", err)
		} else {
			w.bump(func(m *fusionMetrics) { m.Emitted += int64(n) })
		}
	}
	w.bump(func(m *fusionMetrics) {
		m.Cycles++
		m.Observations += int64(len(obs))
		m.Identities += int64(len(ids))
		for _, fi := range ids {
			m.ByBand[string(fi.Band)]++
			switch fi.State {
			case appid.StateUnknown:
				m.Unknown++
			case appid.StateConflicted:
				m.Conflict++
			}
		}
		m.LastCycleUnixSec = now.Unix()
	})
	return len(ids), nil
}

func (w *fusionWorker) bump(f func(*fusionMetrics)) {
	w.metrics.mu.Lock()
	f(w.metrics)
	w.metrics.mu.Unlock()
}

func (w *fusionWorker) recordErr(err error) {
	w.bump(func(m *fusionMetrics) { m.LastError = err.Error() })
}

// start runs the supervised periodic worker (initial pass + interval ticker). §10 — a
// cycle error is logged + retried next tick, never a silent task death.
func (w *fusionWorker) start(ctx context.Context) {
	interval := envDurationSeconds("FUSION_INTERVAL_S", 120)
	go func() {
		if _, err := w.cycle(ctx, time.Now().UTC()); err != nil {
			log.Printf("fusion: initial cycle error: %v", err)
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := w.cycle(ctx, time.Now().UTC()); err != nil {
					log.Printf("fusion: cycle error: %v", err)
				}
			}
		}
	}()
}

func envDurationSeconds(key string, def int) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := parseIntStrict(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(def) * time.Second
}

// handleFusionStatus serves GET /api/appid/fusion/status — the worker's operational
// metrics (§14). Auth-gated; no per-tenant data (counts + buckets only).
func (s *server) handleFusionStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	m := map[string]any{"enabled": envOr("FUSION_WORKER_ENABLED", "") == "true", "adapters": adapter.New().Names()}
	if s.fusion != nil {
		m["metrics"] = s.fusion.metrics.snapshot()
	}
	writeJSON(w, http.StatusOK, m)
}

// ── OpenSearch source (production) ────────────────────────────────────────────
// openSearchSource pulls recent vendor app events from the syslog indices and returns
// each _source flattened to dotted keys (so the adapters' .fgt.app-style lookups work).
type openSearchSource struct{}

func (openSearchSource) Name() string { return "opensearch" }

func (openSearchSource) Fetch(ctx context.Context, since time.Time) ([]map[string]any, error) {
	body := map[string]any{
		"size": 5000,
		"sort": []any{map[string]any{"timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}},
		"query": map[string]any{"bool": map[string]any{
			// any vendor app classifier field present
			"should": []any{
				map[string]any{"exists": map[string]any{"field": "app_id"}},
				map[string]any{"exists": map[string]any{"field": "fgt.app"}},
				map[string]any{"exists": map[string]any{"field": "app"}},
				map[string]any{"exists": map[string]any{"field": "WebApplication"}},
				map[string]any{"exists": map[string]any{"field": "application_name"}},
			},
			"minimum_should_match": 1,
			"filter":               []any{map[string]any{"range": map[string]any{"timestamp": map[string]string{"gte": since.UTC().Format(time.RFC3339)}}}},
		}},
	}
	resp, err := openSearch("POST", "/netops-syslog-*/_search", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, nil // no index / transient — empty, not fatal
	}
	var parsed struct {
		Hits struct {
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(parsed.Hits.Hits))
	for _, h := range parsed.Hits.Hits {
		flat := map[string]any{}
		flattenJSON("", h.Source, flat)
		out = append(out, flat)
	}
	return out, nil
}

// flattenJSON flattens nested objects to dotted keys (and keeps leaf scalars), so an
// adapter that reads "fgt.app" finds it whether the doc nested it or not.
func flattenJSON(prefix string, m map[string]any, out map[string]any) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok {
			flattenJSON(key, sub, out)
		} else {
			out[key] = v
		}
	}
}
