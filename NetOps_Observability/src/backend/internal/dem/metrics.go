package dem

// metrics.go — the module's own counter block (§10: every service emits
// metrics, no silent failures). Each counter answers a question an operator
// would actually ask: is anyone declaring targets, is the prober picking them
// up, and is the score query failing silently.

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics is the module's counter set. Counters are atomic, so the package
// holds no mutable package-level state (§5 no globals).
type Metrics struct {
	TargetsCreated   atomic.Int64
	TargetsUpdated   atomic.Int64
	TargetsDeleted   atomic.Int64
	ScoresServed     atomic.Int64
	QueryErrors      atomic.Int64
	TargetsProjected atomic.Int64 // targets handed to the prober's work queue
	ProjectErrors    atomic.Int64
}

// NewMetrics builds an empty counter set.
func NewMetrics() *Metrics { return &Metrics{} }

// Snapshot is a plain read of the counters for a status endpoint.
func (m *Metrics) Snapshot() map[string]int64 {
	if m == nil {
		return map[string]int64{}
	}
	return map[string]int64{
		"targets_created_total":   m.TargetsCreated.Load(),
		"targets_updated_total":   m.TargetsUpdated.Load(),
		"targets_deleted_total":   m.TargetsDeleted.Load(),
		"scores_served_total":     m.ScoresServed.Load(),
		"query_errors_total":      m.QueryErrors.Load(),
		"targets_projected_total": m.TargetsProjected.Load(),
		"project_errors_total":    m.ProjectErrors.Load(),
	}
}

// metricHelp pairs each counter with its HELP line. Declared as data so a new
// counter cannot ship without one.
var metricHelp = [][2]string{
	{"targets_created_total", "Experience targets declared"},
	{"targets_updated_total", "Experience targets edited or paused"},
	{"targets_deleted_total", "Experience targets removed"},
	{"scores_served_total", "Experience score responses served"},
	{"query_errors_total", "Experience score computations abandoned because the metrics store did not answer"},
	{"targets_projected_total", "Targets published to the prober's work queue"},
	{"project_errors_total", "Work-queue publications that failed (the prober keeps its previous list)"},
}

// Write emits the exposition text at scrape time, in a fixed order so a scrape
// is byte-stable.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	snap := m.Snapshot()
	for _, row := range metricHelp {
		name := "netops_dem_" + row[0]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, row[1], name, name, snap[row[0]])
	}
}
