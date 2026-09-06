// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package quarantine

// metrics.go — F-11 D6: the quarantine observability families
// (registered in internal/secobs/vocab.go, epic F-11):
//
//	netops_sec_quarantine_depth           gauge    current envelope count
//	netops_sec_quarantine_oldest_seconds  gauge    age of the oldest envelope
//	netops_sec_quarantine_restored_total  counter  re-attribution outcomes
//
// Depth and age come from ONE OpenSearch query (exact total + min(received_at)
// aggregation — a single atomic snapshot instead of a _count/_search pair that
// could straddle a delete), sampled lazily on metrics render and cached for
// refreshInterval so a scrape never hammers the index. On a failed sample the
// gauges are ABSENT: an absent series is a visible failure, a zero reads as an
// empty quarantine ("a zero is a lie" — internal/secobs/metrics.go).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// FetchFn is the injected OpenSearch call, shaped after the api's openSearch
// helper (method, path, JSON-marshalable body) so the root package wires it
// with a single identifier.
type FetchFn func(method, path string, body any) (*http.Response, error)

// refreshInterval bounds how often a metrics render may hit OpenSearch. A
// failed sample is cached for the same interval — retry storms against a down
// store help nobody.
const refreshInterval = 60 * time.Second

// Metrics emits the F-11 families. Same repo idiom as the other writers: a
// Write method called from the api's /metrics handler (nil-guarded there),
// no client library, HELP/TYPE before samples.
type Metrics struct {
	fetch FetchFn
	now   func() time.Time

	mu            sync.Mutex
	sampledAt     time.Time
	sampleOK      bool
	depth         int64
	oldestSeconds float64

	restored atomic.Int64
	failed   atomic.Int64
}

// NewMetrics builds the writer. now is injectable for tests; pass nil for
// time.Now.
func NewMetrics(fetch FetchFn, now func() time.Time) *Metrics {
	if now == nil {
		now = time.Now
	}
	return &Metrics{fetch: fetch, now: now}
}

// RecordRestore counts one re-attribution run's outcomes.
func (m *Metrics) RecordRestore(restored, failed int) {
	m.restored.Add(int64(restored))
	m.failed.Add(int64(failed))
}

// sample returns the cached depth/age, refreshing from OpenSearch when the
// cache is older than refreshInterval. ok=false means the last refresh failed
// and the gauges must not be emitted.
func (m *Metrics) sample() (depth int64, oldestSeconds float64, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if !m.sampledAt.IsZero() && now.Sub(m.sampledAt) < refreshInterval {
		return m.depth, m.oldestSeconds, m.sampleOK
	}
	m.sampledAt = now
	m.sampleOK = false
	d, oldest, err := m.query()
	if err != nil {
		// §10 no silent failures: the absence of the gauges is the alertable
		// signal (QuarantineAttributionStalled goes blind, absent() catches
		// it); nothing more to record here without a logger dependency.
		return 0, 0, false
	}
	m.depth = d
	m.oldestSeconds = 0
	if oldest != nil {
		if age := now.Sub(time.UnixMilli(int64(*oldest))).Seconds(); age > 0 {
			m.oldestSeconds = age
		}
	}
	m.sampleOK = true
	return m.depth, m.oldestSeconds, true
}

// query performs the single snapshot search: exact total (= depth) plus the
// min received_at aggregation (epoch millis).
func (m *Metrics) query() (depth int64, oldestMillis *float64, err error) {
	resp, err := m.fetch(http.MethodPost, "/netops-quarantine-*/_search", map[string]any{
		"size":             0,
		"track_total_hits": true,
		"aggs": map[string]any{
			"oldest_received": map[string]any{"min": map[string]any{"field": "received_at"}},
		},
	})
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, nil, fmt.Errorf("quarantine sampler: opensearch status %d", resp.StatusCode)
	}
	var body osSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, nil, fmt.Errorf("quarantine sampler: decode: %w", err)
	}
	return body.Hits.Total.Value, body.Aggregations.OldestReceived.Value, nil
}

// Write emits the families. Gauges only when the sample is trustworthy; the
// restore counters always (they are process-local truth and both outcome
// series are pre-declared so rate() has a base).
func (m *Metrics) Write(w io.Writer) {
	if depth, oldest, ok := m.sample(); ok {
		fmt.Fprintf(w, "# HELP netops_sec_quarantine_depth Sealed unattributable events currently held in netops-quarantine-* (F-11).\n")
		fmt.Fprintf(w, "# TYPE netops_sec_quarantine_depth gauge\n")
		fmt.Fprintf(w, "netops_sec_quarantine_depth %d\n", depth)
		fmt.Fprintf(w, "# HELP netops_sec_quarantine_oldest_seconds Age of the oldest quarantined event; 0 when the quarantine is empty (F-11).\n")
		fmt.Fprintf(w, "# TYPE netops_sec_quarantine_oldest_seconds gauge\n")
		fmt.Fprintf(w, "netops_sec_quarantine_oldest_seconds %.0f\n", oldest)
	}
	fmt.Fprintf(w, "# HELP netops_sec_quarantine_restored_total Quarantined events processed by operator re-attribution, by outcome.\n")
	fmt.Fprintf(w, "# TYPE netops_sec_quarantine_restored_total counter\n")
	fmt.Fprintf(w, "netops_sec_quarantine_restored_total{outcome=%q} %d\n", "restored", m.restored.Load())
	fmt.Fprintf(w, "netops_sec_quarantine_restored_total{outcome=%q} %d\n", "failed", m.failed.Load())
}
