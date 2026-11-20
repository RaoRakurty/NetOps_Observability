// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seasonal

// estate.go — the estate-wide seasonal question (tracker 337 N-H6 step 3):
// "what stands out against its usual level for the time". It is answered from the
// hourly roll-up (netops.series_hourly), so it can only cover the metrics the
// roll-up keeps. RolledMetrics is that list, keyed by catalog metric name to
// the entity type a series of it describes; the api's roll-up worker
// (path_health_baselines.go seasonalRollMetrics) must keep exactly these, and a
// root test pins the two together.

import (
	"sort"
	"time"
)

// RolledMetrics maps each rolled-up catalog metric to its entity type.
var RolledMetrics = map[string]string{
	"cpu_util_pct":       "device",
	"mem_util_pct":       "device",
	"if_in_bps":          "interface",
	"if_out_bps":         "interface",
	"if_in_errors":       "interface",
	"if_out_errors":      "interface",
	"if_in_discards":     "interface",
	"if_out_discards":    "interface",
	"circuit_loss_pct":   "circuit",
	"circuit_latency_ms": "circuit",
	"circuit_jitter_ms":  "circuit",
	"circuit_qoe":        "circuit",
}

// EstateMetrics returns the rolled-up metrics for one entity type ("" = all),
// sorted, so a read and its provenance are deterministic.
func EstateMetrics(entity string) []string {
	var out []string
	for m, e := range RolledMetrics {
		if entity == "" || e == entity {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// RefHours returns the hours an estate answer reads for the judged hour h:
// h itself, then every daily and weekly reference hour (a reference 7 days
// back is both the first week and the seventh day, and is listed once),
// nearest first after h.
func RefHours(h time.Time) []time.Time {
	seen := map[int64]bool{h.Unix(): true}
	out := []time.Time{h}
	add := func(offs []time.Duration) {
		for _, off := range offs {
			t := h.Add(-off)
			if !seen[t.Unix()] {
				seen[t.Unix()] = true
				out = append(out, t)
			}
		}
	}
	add(DayOffsets())
	add(WeekOffsets())
	return out
}
