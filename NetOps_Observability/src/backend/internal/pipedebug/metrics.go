// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// metrics.go — the debugger's own /metrics gauges.
//
// WHY THEY EXIST AT ALL. Three independent mechanisms bring a raised log level
// back down (the module's own timer, the CLI on exit, the CLI on Ctrl-C), and
// all three live INSIDE the thing that might be wedged. The external watchdog
// (scripts/stack-watchdog.sh, problem class DEBUG_LEVEL_STUCK) is the fourth,
// and it can only see what /metrics exports. These four gauges are that view.
//
// EVERY GAUGE IS EXPORTED EVEN WHEN ITS VALUE IS ZERO, and that is the whole
// design of this file. If a gauge were omitted while nothing was raised, an api
// that predates this feature and an api with nothing raised would look
// identical to the watchdog — and "the check could not run" would be read as
// "the check passed", which is the exact inversion the 2026-09-02 post-mortem
// is about. Absence therefore means one thing only: this build has no debugger,
// or it is not being scraped. The watchdog reports that as an unproven gap.

import (
	"fmt"
	"strings"
	"time"
)

// LevelReader is the part of a LevelSwitch /metrics needs.
type LevelReader interface {
	Current() Level
	RevertAt() time.Time
}

// MetricNames are the series this file exports. They are named here so the
// watchdog's queries and the api's exporter cannot drift apart silently — the
// same reason the UI-query contract is a table.
const (
	MetricLevelActive   = "netops_debug_level_active"
	MetricLevelRevertAt = "netops_debug_level_revert_at_seconds"
	MetricParseActive   = "netops_debug_parse_marker_active"
	MetricParseRevertAt = "netops_debug_parse_marker_revert_at_seconds"
)

// RenderMetrics writes the four gauges in Prometheus text format.
//
// `levels` is keyed by module so a future runtime-switchable module joins the
// export by being added to the map — the watchdog's `max()` over the series
// picks it up with no change on either side.
func RenderMetrics(levels map[Module]LevelReader, parse ParseSwitch) string {
	var b strings.Builder
	b.WriteString("# HELP " + MetricLevelActive + " 1 when the pipeline debugger has a module's runtime log level raised to debug, 0 when it is at its shipped level. Always exported, so an absent series means this build has no debugger rather than nothing being raised.\n")
	b.WriteString("# TYPE " + MetricLevelActive + " gauge\n")
	var revertLines strings.Builder
	revertLines.WriteString("# HELP " + MetricLevelRevertAt + " Unix time at which a raised log level auto-reverts; 0 when nothing is raised or NO auto-revert is armed (which is the more serious condition).\n")
	revertLines.WriteString("# TYPE " + MetricLevelRevertAt + " gauge\n")

	for _, m := range Modules {
		lr, ok := levels[m]
		if !ok {
			continue
		}
		active := 0
		if lr.Current() == LevelDebug {
			active = 1
		}
		revert := int64(0)
		if r := lr.RevertAt(); !r.IsZero() {
			revert = r.UTC().Unix()
		}
		fmt.Fprintf(&b, "%s{module=%q} %d\n", MetricLevelActive, string(m), active)
		fmt.Fprintf(&revertLines, "%s{module=%q} %d\n", MetricLevelRevertAt, string(m), revert)
	}
	b.WriteString(revertLines.String())

	armed, until := 0, int64(0)
	if parse != nil {
		if _, u, on := parse.Active(); on {
			armed = 1
			if !u.IsZero() {
				until = u.UTC().Unix()
			}
		}
	}
	b.WriteString("# HELP " + MetricParseActive + " 1 when the parser decision-trace filter is armed for a real (unmarked) record, 0 otherwise. Injected records carry their own marker and are traced without arming this.\n")
	b.WriteString("# TYPE " + MetricParseActive + " gauge\n")
	fmt.Fprintf(&b, "%s %d\n", MetricParseActive, armed)
	b.WriteString("# HELP " + MetricParseRevertAt + " Unix time at which the armed parser decision-trace filter auto-disarms; 0 when it is not armed.\n")
	b.WriteString("# TYPE " + MetricParseRevertAt + " gauge\n")
	fmt.Fprintf(&b, "%s %d\n", MetricParseRevertAt, until)
	return b.String()
}
