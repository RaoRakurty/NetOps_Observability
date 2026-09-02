package secapi

// metrics.go — netops_security_findings_queries_total{op}.
//
// The counter is process-wide and NOT tenant-labelled on purpose (the
// rcafeedback precedent): a per-tenant label on a /metrics endpoint that is not
// itself tenant-scoped would leak tenant existence and cardinality to anyone who
// can scrape it. §3a is about data surfaces; the same principle applies to
// telemetry about those surfaces.

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Ops is the closed label vocabulary — one entry per read surface. A closed set
// (rather than a free-form string) is what keeps /metrics cardinality bounded no
// matter what a handler passes.
var Ops = []string{
	"list",
	"get",
	"facets",
	"trend",
	"posture",
	"exposure_stories",
	"rules",
	"views",
}

// Metrics counts findings queries by operation. Safe for concurrent use.
type Metrics struct {
	// One counter per entry of Ops, indexed identically, so Write emits a
	// stable series set INCLUDING zeros — an absent series and a zero series
	// mean different things to an alert.
	counts []atomic.Int64
}

// NewMetrics builds the counter set.
func NewMetrics() *Metrics { return &Metrics{counts: make([]atomic.Int64, len(Ops))} }

// Inc records one query. An op outside Ops is DROPPED rather than bucketed into
// a wrong series: the call sites pass constants, so this is unreachable in
// practice, and silently mislabelling would be worse than a gap.
func (m *Metrics) Inc(op string) {
	if m == nil {
		return
	}
	for i, o := range Ops {
		if o == op {
			m.counts[i].Add(1)
			return
		}
	}
}

// Snapshot returns the current per-op totals (test seam; no locking games).
func (m *Metrics) Snapshot() map[string]int64 {
	out := map[string]int64{}
	if m == nil {
		return out
	}
	for i, o := range Ops {
		out[o] = m.counts[i].Load()
	}
	return out
}

// Write emits the counter family in Prometheus text format.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	fmt.Fprintf(w, "# HELP netops_security_findings_queries_total Security findings API queries, by operation.\n")
	fmt.Fprintf(w, "# TYPE netops_security_findings_queries_total counter\n")
	for i, o := range Ops {
		fmt.Fprintf(w, "netops_security_findings_queries_total{op=%q} %d\n", o, m.counts[i].Load())
	}
}
