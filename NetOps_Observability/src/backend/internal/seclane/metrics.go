// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// metrics.go — the security lane's Prometheus surface (§10).
//
// The per-tenant label is `tenant_seg` (the sanitized index segment — the same
// token the storage layer uses). A tenant label on a metrics endpoint is
// normally a §3a leak (the secapi read-API counters are deliberately unlabelled
// for exactly that reason), and it is admissible HERE only because the
// platform's /metrics is platform-owner-only at the edge (nginx SR-008) and the
// platform owner is cross-tenant by definition. The series set is still CAPPED
// (metricMaxTenants, deterministically sorted) so a tenant explosion cannot blow
// up a scrape.

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// metricMaxTenants bounds the per-tenant series set on /metrics.
const metricMaxTenants = 200

// durBuckets are the scan-duration histogram upper bounds, in seconds.
var durBuckets = []float64{1, 5, 15, 30, 60, 120, 300, 600}

// Metrics counts the lane's runs, emissions and losses. Safe for concurrent use.
type Metrics struct {
	mu sync.Mutex

	runs      map[string]int64   // "tenantSeg\x00outcome" → runs
	emitted   map[string]int64   // evidence class → findings published
	lastScan  map[string]int64   // tenantSeg → unix seconds of the last completed run
	lastDur   map[string]float64 // tenantSeg → last run duration, seconds
	durBucket []int64            // cumulative-by-construction counts, aligned with durBuckets
	durSum    float64
	durCount  int64

	truncated    int64 // findings dropped by the per-run cap
	emitFailures int64 // batches that exhausted the producer's bounded retry
	deadLettered int64 // records preserved in a dead-letter sink
	lost         int64 // records with NO durable copy anywhere (the 189 contract)
	ungroundable int64 // findings the bus seam refused to ground (never guessed)

	// findings-on-change (episodes.go) — closed label sets, written in full.
	transitions map[string]int64 // "transition\x00outcome" → records
	unchanged   int64            // re-confirmed verdicts kept off the engine's lane
	seeded      map[string]int64 // seed source → episodes seeded silently
	pruned      int64            // episodes dropped after EpisodePruneAfter unassessed
	stateErrors map[string]int64 // op (load|seed|commit) → failures
}

// The closed label vocabularies of the findings-on-change series.
var (
	transitionLabels = []string{"appear", "change", "clear"}
	outcomeLabels    = []string{"emitted", "dead_lettered", "lost", outcomeWithheld}
	seedLabels       = []string{SeedSourceIndex, SeedSourceScan}
	stateOpLabels    = []string{"load", "seed", "commit"}
)

// NewMetrics builds the counter set.
func NewMetrics() *Metrics {
	return &Metrics{
		runs:      map[string]int64{},
		emitted:   map[string]int64{},
		lastScan:  map[string]int64{},
		lastDur:   map[string]float64{},
		durBucket: make([]int64, len(durBuckets)),

		transitions: map[string]int64{},
		seeded:      map[string]int64{},
		stateErrors: map[string]int64{},
	}
}

func inLabels(v string, set []string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// RecordTransitions counts n transition records by (transition, outcome).
// Values outside the closed vocabularies are dropped, so a label can never be
// widened by a caller.
func (m *Metrics) RecordTransitions(transition, outcome string, n int64) {
	if m == nil || n <= 0 || !inLabels(transition, transitionLabels) || !inLabels(outcome, outcomeLabels) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transitions[transition+"\x00"+outcome] += n
}

// AddUnchanged counts verdicts re-confirmed without change (audit topic only).
func (m *Metrics) AddUnchanged(n int64) { m.bump(func(x *Metrics) { x.unchanged += n }, n) }

// AddPruned counts episodes dropped after going unassessed too long.
func (m *Metrics) AddPruned(n int64) { m.bump(func(x *Metrics) { x.pruned += n }, n) }

// AddSeeded counts episodes seeded silently, by seed source. A seed of zero
// episodes still counts nothing; the seed itself is visible in the log.
func (m *Metrics) AddSeeded(source string, n int64) {
	if m == nil || n <= 0 || !inLabels(source, seedLabels) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seeded[source] += n
}

// AddStateError counts one episode-state failure by operation.
func (m *Metrics) AddStateError(op string) {
	if m == nil || !inLabels(op, stateOpLabels) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateErrors[op]++
}

// RecordRun records one completed (or skipped) run.
func (m *Metrics) RecordRun(seg, outcome string, at time.Time, dur time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[seg+"\x00"+outcome]++
	if outcome == OutcomeSkipped {
		return // a skipped run has no duration and did not move the clock
	}
	m.lastScan[seg] = at.UTC().Unix()
	secs := dur.Seconds()
	m.lastDur[seg] = secs
	m.durSum += secs
	m.durCount++
	for i, ub := range durBuckets {
		if secs <= ub {
			m.durBucket[i]++
		}
	}
}

// RecordEmitted counts findings published, by evidence class.
func (m *Metrics) RecordEmitted(class string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emitted[class] += int64(n)
}

func (m *Metrics) bump(f func(*Metrics), n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

// AddTruncated counts findings the per-run cap dropped.
func (m *Metrics) AddTruncated(n int64) { m.bump(func(x *Metrics) { x.truncated += n }, n) }

// AddEmitFailure counts batches that exhausted their bounded retry.
func (m *Metrics) AddEmitFailure(n int64) { m.bump(func(x *Metrics) { x.emitFailures += n }, n) }

// AddDeadLettered counts records preserved in a dead-letter sink.
func (m *Metrics) AddDeadLettered(n int64) { m.bump(func(x *Metrics) { x.deadLettered += n }, n) }

// AddLost counts records with no durable copy anywhere.
func (m *Metrics) AddLost(n int64) { m.bump(func(x *Metrics) { x.lost += n }, n) }

// AddUngroundable counts findings the bus seam refused to ground.
func (m *Metrics) AddUngroundable(n int64) { m.bump(func(x *Metrics) { x.ungroundable += n }, n) }

// Snapshot returns a flat read of the totals (status endpoint + tests).
func (m *Metrics) Snapshot() map[string]int64 {
	out := map[string]int64{}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var runs int64
	for _, v := range m.runs {
		runs += v
	}
	out["scan_runs_total"] = runs
	out["findings_truncated_total"] = m.truncated
	out["emit_failures_total"] = m.emitFailures
	out["dead_lettered_total"] = m.deadLettered
	out["lost_total"] = m.lost
	out["ungroundable_total"] = m.ungroundable
	for _, c := range evidenceClasses {
		out["emitted_"+c] = m.emitted[c]
	}
	for _, tr := range transitionLabels {
		for _, o := range outcomeLabels {
			out["transition_"+tr+"_"+o] = m.transitions[tr+"\x00"+o]
		}
	}
	out["unchanged_suppressed_total"] = m.unchanged
	out["episodes_pruned_total"] = m.pruned
	for _, s := range seedLabels {
		out["episodes_seeded_"+s] = m.seeded[s]
	}
	for _, op := range stateOpLabels {
		out["episode_state_errors_"+op] = m.stateErrors[op]
	}
	return out
}

// RunsFor returns the run count for one (tenant segment, outcome) pair.
func (m *Metrics) RunsFor(seg, outcome string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[seg+"\x00"+outcome]
}

// Write emits the lane's series in Prometheus text format.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprint(w, "# HELP netops_security_scan_runs_total Security lane scan runs, by tenant segment and outcome.\n")
	fmt.Fprint(w, "# TYPE netops_security_scan_runs_total counter\n")
	keys := make([]string, 0, len(m.runs))
	for k := range m.runs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i >= metricMaxTenants*4 {
			break
		}
		seg, outcome, _ := strings.Cut(k, "\x00")
		fmt.Fprintf(w, "netops_security_scan_runs_total{tenant_seg=%q,outcome=%q} %d\n", seg, outcome, m.runs[k])
	}

	fmt.Fprint(w, "# HELP netops_security_findings_emitted_total Security findings published onto the bus, by evidence class.\n")
	fmt.Fprint(w, "# TYPE netops_security_findings_emitted_total counter\n")
	for _, c := range evidenceClasses {
		fmt.Fprintf(w, "netops_security_findings_emitted_total{class=%q} %d\n", c, m.emitted[c])
	}

	fmt.Fprint(w, "# HELP netops_security_scan_duration_seconds Security lane scan duration.\n")
	fmt.Fprint(w, "# TYPE netops_security_scan_duration_seconds histogram\n")
	for i, ub := range durBuckets {
		fmt.Fprintf(w, "netops_security_scan_duration_seconds_bucket{le=\"%g\"} %d\n", ub, m.durBucket[i])
	}
	fmt.Fprintf(w, "netops_security_scan_duration_seconds_bucket{le=\"+Inf\"} %d\n", m.durCount)
	fmt.Fprintf(w, "netops_security_scan_duration_seconds_sum %g\n", m.durSum)
	fmt.Fprintf(w, "netops_security_scan_duration_seconds_count %d\n", m.durCount)

	segs := make([]string, 0, len(m.lastScan))
	for seg := range m.lastScan {
		segs = append(segs, seg)
	}
	sort.Strings(segs)
	if len(segs) > metricMaxTenants {
		segs = segs[:metricMaxTenants]
	}
	fmt.Fprint(w, "# HELP netops_security_last_scan_timestamp_seconds Unix time of the last completed security scan, by tenant segment.\n")
	fmt.Fprint(w, "# TYPE netops_security_last_scan_timestamp_seconds gauge\n")
	for _, seg := range segs {
		fmt.Fprintf(w, "netops_security_last_scan_timestamp_seconds{tenant_seg=%q} %d\n", seg, m.lastScan[seg])
	}
	fmt.Fprint(w, "# HELP netops_security_last_scan_duration_seconds Duration of the last completed security scan, by tenant segment.\n")
	fmt.Fprint(w, "# TYPE netops_security_last_scan_duration_seconds gauge\n")
	for _, seg := range segs {
		fmt.Fprintf(w, "netops_security_last_scan_duration_seconds{tenant_seg=%q} %g\n", seg, m.lastDur[seg])
	}

	writeCounter(w, "netops_security_findings_truncated_total",
		"Findings dropped by the per-run per-tenant cap.", m.truncated)
	writeCounter(w, "netops_security_emit_failures_total",
		"Bus batches that exhausted their bounded retry.", m.emitFailures)
	writeCounter(w, "netops_security_dead_lettered_total",
		"Security evidence records preserved in a dead-letter sink.", m.deadLettered)
	writeCounter(w, "netops_security_lost_total",
		"Security evidence records with NO durable copy anywhere.", m.lost)
	writeCounter(w, "netops_security_ungroundable_total",
		"Findings the bus seam refused to ground (never guessed).", m.ungroundable)

	fmt.Fprint(w, "# HELP netops_security_transitions_total Finding-episode transitions sent to the correlation engine (netops.security), by transition and outcome.\n")
	fmt.Fprint(w, "# TYPE netops_security_transitions_total counter\n")
	for _, tr := range transitionLabels {
		for _, o := range outcomeLabels {
			fmt.Fprintf(w, "netops_security_transitions_total{transition=%q,outcome=%q} %d\n", tr, o, m.transitions[tr+"\x00"+o])
		}
	}
	writeCounter(w, "netops_security_unchanged_suppressed_total",
		"Verdicts re-confirmed without change: stored for audit, not re-sent to the correlation engine.", m.unchanged)
	fmt.Fprint(w, "# HELP netops_security_episodes_seeded_total Finding episodes seeded silently when change tracking started, by seed source.\n")
	fmt.Fprint(w, "# TYPE netops_security_episodes_seeded_total counter\n")
	for _, s := range seedLabels {
		fmt.Fprintf(w, "netops_security_episodes_seeded_total{source=%q} %d\n", s, m.seeded[s])
	}
	writeCounter(w, "netops_security_episodes_pruned_total",
		"Open finding episodes dropped without a clear after their source went unassessed too long.", m.pruned)
	fmt.Fprint(w, "# HELP netops_security_episode_state_errors_total Finding-episode state failures, by operation.\n")
	fmt.Fprint(w, "# TYPE netops_security_episode_state_errors_total counter\n")
	for _, op := range stateOpLabels {
		fmt.Fprintf(w, "netops_security_episode_state_errors_total{op=%q} %d\n", op, m.stateErrors[op])
	}
}

func writeCounter(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}
