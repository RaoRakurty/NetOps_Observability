package experience

// metrics.go — the module's self-observability counters (Phase Q).
//
// They answer "is the experience layer itself doing its job", which the 2026-09-02
// outage taught is a different question from "is the container healthy". They
// are exposed on the platform's /metrics endpoint through the same Write hook
// internal/dem's counters use, so a DEM lane that stops serving is visible in
// the same place every other engine's liveness is.

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Counters is the module's metric block. Every field is a monotonic counter;
// nothing here resets, so a scrape gap is a gap in the rate, not a reset.
type Counters struct {
	ViewsServed      atomic.Int64
	QueryErrors      atomic.Int64
	JourneysCreated  atomic.Int64
	JourneysUpdated  atomic.Int64
	JourneysDeleted  atomic.Int64
	ChangesRecorded  atomic.Int64
	IncidentsDerived atomic.Int64
	PacketsBuilt     atomic.Int64
	PacketsRejected  atomic.Int64
}

// NewCounters builds an empty block.
func NewCounters() *Counters { return &Counters{} }

// Snapshot returns the current values, for tests and for a debug endpoint.
func (c *Counters) Snapshot() map[string]int64 {
	if c == nil {
		return map[string]int64{}
	}
	return map[string]int64{
		"dem_experience_views_served_total":        c.ViewsServed.Load(),
		"dem_experience_query_errors_total":        c.QueryErrors.Load(),
		"dem_experience_journeys_created_total":    c.JourneysCreated.Load(),
		"dem_experience_journeys_updated_total":    c.JourneysUpdated.Load(),
		"dem_experience_journeys_deleted_total":    c.JourneysDeleted.Load(),
		"dem_experience_changes_recorded_total":    c.ChangesRecorded.Load(),
		"dem_experience_incidents_derived_total":   c.IncidentsDerived.Load(),
		"dem_experience_ai_packets_built_total":    c.PacketsBuilt.Load(),
		"dem_experience_ai_packets_rejected_total": c.PacketsRejected.Load(),
	}
}

// metricHelp is the HELP line for each counter, kept beside the counter so a
// new one cannot ship undocumented.
var metricHelp = [][2]string{
	{"dem_experience_views_served_total", "Digital Experience aggregation views assembled and served"},
	{"dem_experience_query_errors_total", "Digital Experience views whose metrics query failed (the view then reports not-measured, never a zero)"},
	{"dem_experience_journeys_created_total", "Journey definitions created"},
	{"dem_experience_journeys_updated_total", "Journey definitions updated"},
	{"dem_experience_journeys_deleted_total", "Journey definitions deleted"},
	{"dem_experience_changes_recorded_total", "Change events recorded through the DEM change feed"},
	{"dem_experience_incidents_derived_total", "Experience incidents derived from evidence"},
	{"dem_experience_ai_packets_built_total", "AI investigator evidence packets built"},
	{"dem_experience_ai_packets_rejected_total", "AI investigator answers rejected for citing evidence that was not supplied"},
}

// Write renders the block in Prometheus exposition format.
func (c *Counters) Write(w io.Writer) {
	if c == nil {
		return
	}
	snap := c.Snapshot()
	for _, h := range metricHelp {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", h[0], h[1], h[0], h[0], snap[h[0]])
	}
}
