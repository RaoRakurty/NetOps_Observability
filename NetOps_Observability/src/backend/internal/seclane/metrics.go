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
}

// NewMetrics builds the counter set.
func NewMetrics() *Metrics {
	return &Metrics{
		runs:      map[string]int64{},
		emitted:   map[string]int64{},
		lastScan:  map[string]int64{},
		lastDur:   map[string]float64{},
		durBucket: make([]int64, len(durBuckets)),
	}
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
}

func writeCounter(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}
