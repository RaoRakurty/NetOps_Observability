// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// metrics.go — what the bridge holds and what it could not take.
//
// netops_nms_iface_bridge_rows{source,outcome} is a GAUGE over the last cycle:
// rows standing in the merged bridge (bridged), how the two sources compared
// (agreed, conflict_won, conflict_lost), addresses two devices of one owner
// share, and — for the NMS source — the records of each integration's last
// poll that reached no row (device_unresolved, device_ambiguous, internal_vpn,
// unidentifying_address, truncated) and devices aged out (stale). No tenant,
// device or integration label: the series is platform plumbing.

// metricPairs is the closed, zero-filled label set, in exposition order.
func metricPairs() []StatKey {
	pairs := []StatKey{}
	for _, o := range []string{MergeBridged, MergeConflictWon, MergeConflictLost, MergeSharedAddr} {
		pairs = append(pairs, StatKey{SourceSNMP, o})
	}
	for _, o := range []string{
		MergeBridged, MergeAgreed, MergeConflictWon, MergeConflictLost, MergeSharedAddr,
		OutcomeDeviceUnresolved, OutcomeDeviceAmbiguous, OutcomeInternalVPN, OutcomeUnidentifying,
		OutcomeTruncated, OutcomeStale,
	} {
		pairs = append(pairs, StatKey{SourceNMS, o})
	}
	return pairs
}

// Metrics is the bridge's exposition state. Safe for concurrent use.
type Metrics struct {
	mu   sync.Mutex
	rows map[StatKey]int

	readFailures    atomic.Uint64
	publishFailures atomic.Uint64
	lastPublish     atomic.Int64 // unix seconds of the last successful publish
}

// NewMetrics returns zeroed metrics.
func NewMetrics() *Metrics { return &Metrics{rows: map[StatKey]int{}} }

// Set replaces the gauge with one cycle's merge stats, the store's last-poll
// ingest counts, and the snapshot's prunes.
func (m *Metrics) Set(merge map[StatKey]int, ingest map[string]int, snap SnapshotStats) {
	next := make(map[StatKey]int, len(merge)+len(ingest)+2)
	for k, v := range merge {
		next[k] = v
	}
	for outcome, v := range ingest {
		next[StatKey{SourceNMS, outcome}] += v
	}
	next[StatKey{SourceNMS, OutcomeStale}] += snap.Stale
	next[StatKey{SourceNMS, OutcomeTruncated}] += snap.Truncated
	m.mu.Lock()
	m.rows = next
	m.mu.Unlock()
}

// ReadFailed counts a cycle that could not read a bridge half.
func (m *Metrics) ReadFailed() { m.readFailures.Add(1) }

// PublishFailed counts a cycle whose NMS rows were not stored.
func (m *Metrics) PublishFailed() { m.publishFailures.Add(1) }

// Published stamps a successful publish (unix seconds).
func (m *Metrics) Published(unix int64) { m.lastPublish.Store(unix) }

// Rows returns one gauge value (tests and the api's health view).
func (m *Metrics) Rows(source, outcome string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows[StatKey{source, outcome}]
}

// WriteMetrics renders the series (Prometheus exposition).
func (m *Metrics) WriteMetrics(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	rows := make(map[StatKey]int, len(m.rows))
	for k, v := range m.rows {
		rows[k] = v
	}
	m.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_nms_iface_bridge_rows Interface bridge rows of the last cycle, by source and outcome (bridged = standing in the merged address/ifIndex maps).\n")
	fmt.Fprintf(w, "# TYPE netops_nms_iface_bridge_rows gauge\n")
	for _, p := range metricPairs() {
		fmt.Fprintf(w, "netops_nms_iface_bridge_rows{source=%q,outcome=%q} %d\n", p.Source, p.Outcome, rows[p])
	}
	fmt.Fprintf(w, "# HELP netops_nms_iface_bridge_failures_total Interface bridge cycles that failed, by stage.\n")
	fmt.Fprintf(w, "# TYPE netops_nms_iface_bridge_failures_total counter\n")
	fmt.Fprintf(w, "netops_nms_iface_bridge_failures_total{stage=\"read\"} %d\n", m.readFailures.Load())
	fmt.Fprintf(w, "netops_nms_iface_bridge_failures_total{stage=\"publish\"} %d\n", m.publishFailures.Load())
	fmt.Fprintf(w, "# HELP netops_nms_iface_bridge_last_publish_timestamp_seconds When the NMS interface rows were last stored.\n")
	fmt.Fprintf(w, "# TYPE netops_nms_iface_bridge_last_publish_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "netops_nms_iface_bridge_last_publish_timestamp_seconds %d\n", m.lastPublish.Load())
}
