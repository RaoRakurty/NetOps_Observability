// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// metrics.go — the module's Prometheus surface (§10: every service emits
// metrics; no silent failures). Every counter here answers a question an
// operator would actually ask during an incident: did the evaluator run, did it
// fail to measure, did it suppress a page, did the evidence reach the bus.

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics is the evaluator's counter set. Counters are atomic, so the evaluator
// holds no mutable package-level state (§5 no globals).
type Metrics struct {
	Runs              atomic.Int64
	RunsSkipped       atomic.Int64 // a tick that found the previous run still going
	RunErrors         atomic.Int64
	PrefixesEvaluated atomic.Int64
	ObserveErrors     atomic.Int64 // an upstream measurement that did not answer
	PeerErrors        atomic.Int64
	SightingErrors    atomic.Int64
	AlertsNotified    atomic.Int64
	AlertsResolved    atomic.Int64
	AlertsSuppressed  atomic.Int64 // held back by the cool-down (NOT lost: visible here)
	// MeasurementLost counts the notices sent because an OPEN incident stopped
	// being measured. It is NOT a resolution: the incident is still open and
	// still unproven, and this counter is how an operator sees the difference
	// between "it cleared" and "we went blind" (review 2026-09-08).
	MeasurementLost atomic.Int64
	// PeerStateUnmeasured counts peer reports that carried no measured state
	// (the documented "unknown"). Those peers are neither paged for nor
	// resolved, so this counter is the only place their number is visible
	// (review 2026-09-08).
	PeerStateUnmeasured atomic.Int64
	BogonSightings      atomic.Int64
	BogonFeedErrors     atomic.Int64
	// BaselinesRecorded counts first-seen origin baselines written. It is the
	// counter that says the detection in tracker 281 is actually arming: a
	// watchlist with prefixes and a flat zero here means every prefix is still
	// in its undetectable first-observation state.
	BaselinesRecorded atomic.Int64

	// Evidence is the bus producer's own counter block.
	Evidence EvidenceMetrics
}

// NewMetrics builds an empty counter set.
func NewMetrics() *Metrics { return &Metrics{} }

// Snapshot is a plain read of the counters for a status endpoint. No live
// pointers escape.
func (m *Metrics) Snapshot() map[string]int64 {
	if m == nil {
		return map[string]int64{}
	}
	ev := m.Evidence.Snapshot()
	return map[string]int64{
		"runs_total":                      m.Runs.Load(),
		"runs_skipped_total":              m.RunsSkipped.Load(),
		"run_errors_total":                m.RunErrors.Load(),
		"prefixes_evaluated_total":        m.PrefixesEvaluated.Load(),
		"observe_errors_total":            m.ObserveErrors.Load(),
		"peer_errors_total":               m.PeerErrors.Load(),
		"sighting_errors_total":           m.SightingErrors.Load(),
		"alerts_notified_total":           m.AlertsNotified.Load(),
		"alerts_resolved_total":           m.AlertsResolved.Load(),
		"alerts_suppressed_total":         m.AlertsSuppressed.Load(),
		"measurement_lost_total":          m.MeasurementLost.Load(),
		"peer_state_unmeasured_total":     m.PeerStateUnmeasured.Load(),
		"bogon_sightings_total":           m.BogonSightings.Load(),
		"bogon_feed_errors_total":         m.BogonFeedErrors.Load(),
		"origin_baselines_recorded_total": m.BaselinesRecorded.Load(),
		"evidence_published_total":        ev.Published,
		"evidence_retries_total":          ev.Retries,
		"evidence_skipped_total":          ev.Skipped,
		"evidence_dropped_total":          ev.Dropped,
	}
}

// metricHelp pairs each counter with its HELP line. Declared as data so a new
// counter cannot ship without one.
var metricHelp = [][2]string{
	{"runs_total", "BGP watchlist evaluation passes completed"},
	{"runs_skipped_total", "Evaluation ticks skipped because the previous pass was still running"},
	{"run_errors_total", "Evaluation passes that failed for a tenant"},
	{"prefixes_evaluated_total", "Watched prefixes classified"},
	{"observe_errors_total", "Prefix measurements the upstream did not answer (classified unknown, never clean)"},
	{"peer_errors_total", "BGP peer-state reads that failed"},
	{"sighting_errors_total", "Live-feed sighting reads that failed"},
	{"alerts_notified_total", "BGP alerts dispatched to the notification channels"},
	{"alerts_resolved_total", "BGP alerts resolved (the condition cleared)"},
	{"alerts_suppressed_total", "BGP alerts held back by the per-incident cool-down"},
	{"measurement_lost_total", "Open BGP incidents that stopped being measured (a notice went out; the incident was NOT resolved)"},
	{"peer_state_unmeasured_total", "BGP peer reports carrying no measured state (never counted as up, and they never resolve a peer-down alert)"},
	{"bogon_sightings_total", "Distinct bogon prefixes observed on a tenant's live feeds"},
	{"bogon_feed_errors_total", "Full-bogons feed refreshes that failed (the embedded set still stands)"},
	{"origin_baselines_recorded_total", "First-seen origin baselines recorded (a prefix without one cannot show a fully propagated origin change)"},
	{"evidence_published_total", "BGP evidence records accepted by the bus"},
	{"evidence_retries_total", "Bus produce retry attempts"},
	{"evidence_skipped_total", "Incidents that could not be shaped as an evidence event"},
	{"evidence_dropped_total", "Evidence records dropped after exhausting the bounded retry"},
}

// Write emits the exposition text at scrape time, in a fixed order so a scrape
// is byte-stable.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	snap := m.Snapshot()
	for _, row := range metricHelp {
		name := "netops_bgpwatch_" + row[0]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, row[1], name, name, snap[row[0]])
	}
}
