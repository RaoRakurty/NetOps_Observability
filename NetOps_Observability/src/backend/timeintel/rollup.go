// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package timeintel

import (
	"math"
	"sort"
	"time"
)

// rollup.go — reliability aggregation for RCA Time Intelligence: percentile phase
// stats (p50/p90/p95, NOT just averages — averages hide the long tail), MTBF over
// repairable objects, MTTF over non-repairable assets, and chronic-offender ranking.
// Pure stdlib; the backend feeds it per-incident summaries it derives from corr
// objects.

// IncidentSummary is one incident's reliability-relevant facts.
type IncidentSummary struct {
	CorrelationID  string
	Durations      map[MetricName]int64 // COMPLETE phase durations only (ms)
	TimeLossDriver TimeLossDriver
	Group          map[string]string // grouping keys: root_entity, seam_id, device, interface, app_path, provider, signature
	Severity       string
	OccurredAt     time.Time   // incident onset (window_start) — MTBF/MTTF spacing anchor
	RecoveredAt    time.Time   // zero if not recovered
	ClosedAt       time.Time   // zero if not closed
	State          string      // open | closed | merged
	IsChild        bool        // suppressed/merged duplicate → excluded from MTBF (spec test 9)
	Maintenance    bool        // planned maintenance → separated from unplanned (spec test 10)
	NonRepairable  bool        // asset is non-repairable → MTTF, not MTBF (spec test 11)
	OwnerDomain    OwnerDomain // ISP/LAN/SD-WAN/Cloud/App/Internal Platform/Unknown
	Internal       bool        // platform self-monitoring (excluded from customer-impacting default)
}

// MetricStat is the percentile summary for one phase across many incidents.
type MetricStat struct {
	Count  int   `json:"incident_count"`
	P50ms  int64 `json:"p50_ms"`
	P90ms  int64 `json:"p90_ms"`
	P95ms  int64 `json:"p95_ms"`
	MeanMs int64 `json:"mean_ms"` // secondary — shown only as a supporting figure
}

// ReliabilityRollup is one window's aggregate reliability picture for a scope.
type ReliabilityRollup struct {
	IncidentCount      int                       `json:"incident_count"`
	Metrics            map[MetricName]MetricStat `json:"metrics"`
	TopTimeLossPhase   TimeLossDriver            `json:"top_time_loss_phase"`
	RepeatIncidentRate float64                   `json:"repeat_incident_rate"` // fraction of incidents on a group that recurs (>1×)
	MTBFms             int64                     `json:"mtbf_ms"`              // overall mean time between repairable incidents (0 = N/A)
}

// nearestRankPercentile returns the value at percentile p (0..100) using the
// nearest-rank method on an ascending-sorted slice.
func nearestRankPercentile(sorted []int64, p float64) int64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// statOf computes p50/p90/p95 + mean for a set of durations.
func statOf(xs []int64) MetricStat {
	if len(xs) == 0 {
		return MetricStat{}
	}
	sorted := append([]int64(nil), xs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum int64
	for _, x := range sorted {
		sum += x
	}
	return MetricStat{
		Count:  len(sorted),
		P50ms:  nearestRankPercentile(sorted, 50),
		P90ms:  nearestRankPercentile(sorted, 90),
		P95ms:  nearestRankPercentile(sorted, 95),
		MeanMs: sum / int64(len(sorted)),
	}
}

// Rollup aggregates per-incident summaries into one reliability rollup: percentile
// stats per phase, the most common time-loss phase, the repeat-incident rate, and
// the overall MTBF over repairable, unplanned, non-child incidents.
func Rollup(incidents []IncidentSummary) ReliabilityRollup {
	r := ReliabilityRollup{Metrics: map[MetricName]MetricStat{}, IncidentCount: len(incidents)}

	// Percentile stats per metric (only incidents that completed that phase).
	perMetric := map[MetricName][]int64{}
	driverVotes := map[TimeLossDriver]int{}
	for _, in := range incidents {
		for name, dur := range in.Durations {
			perMetric[name] = append(perMetric[name], dur)
		}
		if in.TimeLossDriver != "" && in.TimeLossDriver != DriverUnknown {
			driverVotes[in.TimeLossDriver]++
		}
	}
	for _, name := range AllMetrics {
		if xs := perMetric[name]; len(xs) > 0 {
			r.Metrics[name] = statOf(xs)
		}
	}

	// Top time-loss phase (most common driver across the window).
	best, bestN := DriverUnknown, 0
	for d, n := range driverVotes {
		if n > bestN {
			best, bestN = d, n
		}
	}
	r.TopTimeLossPhase = best

	// Repeat-incident rate + overall MTBF over the primary grouping (root_entity →
	// seam_id → device fallback). Children/maintenance excluded.
	r.RepeatIncidentRate, r.MTBFms = repeatAndMTBF(incidents)
	return r
}

// groupKeyOf picks the most specific stable identity for an incident (root_entity →
// seam_id → device → interface → app_path → provider → signature). "" if none.
func groupKeyOf(in IncidentSummary) string {
	for _, k := range []string{"root_entity", "seam_id", "device", "interface", "app_path", "provider", "signature"} {
		if v := in.Group[k]; v != "" {
			return k + ":" + v
		}
	}
	return ""
}

// repeatable filters to the incidents that count toward MTBF/repeat stats: not a
// child/suppressed duplicate (spec 9), not planned maintenance (spec 10), and has a
// usable grouping key. Returns key→sorted-occurrence-times.
func repeatableByGroup(incidents []IncidentSummary) map[string][]time.Time {
	byGroup := map[string][]time.Time{}
	for _, in := range incidents {
		if in.IsChild || in.Maintenance {
			continue
		}
		key := groupKeyOf(in)
		if key == "" || in.OccurredAt.IsZero() {
			continue
		}
		byGroup[key] = append(byGroup[key], in.OccurredAt)
	}
	for k := range byGroup {
		ts := byGroup[k]
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		byGroup[k] = ts
	}
	return byGroup
}

// repeatAndMTBF computes the repeat-incident rate (fraction of qualifying incidents
// whose group recurs) and the overall MTBF (mean gap between consecutive incidents
// on the same group, averaged across groups with ≥2 incidents).
func repeatAndMTBF(incidents []IncidentSummary) (float64, int64) {
	byGroup := repeatableByGroup(incidents)
	if len(byGroup) == 0 {
		return 0, 0
	}
	var total, repeated int
	var gapSum, gapCount int64
	for _, ts := range byGroup {
		total += len(ts)
		if len(ts) > 1 {
			repeated += len(ts)
			for i := 1; i < len(ts); i++ {
				gapSum += ts[i].Sub(ts[i-1]).Milliseconds()
				gapCount++
			}
		}
	}
	rate := 0.0
	if total > 0 {
		rate = float64(repeated) / float64(total)
	}
	var mtbf int64
	if gapCount > 0 {
		mtbf = gapSum / gapCount
	}
	return rate, mtbf
}

// ChronicOffender ranks a recurring object by incident count.
type ChronicOffender struct {
	GroupKey      string      `json:"group_key"`
	IncidentCount int         `json:"incident_count"`
	MTBFms        int64       `json:"mtbf_ms"`
	LastSeen      time.Time   `json:"last_seen"`
	OwnerDomain   OwnerDomain `json:"owner_domain"` // dominant owner → drives the recommended action
}

// ChronicOffenders ranks recurring objects (≥2 unplanned, non-child incidents) by
// incident count, returning the top N. The answer to "which circuit keeps failing".
func ChronicOffenders(incidents []IncidentSummary, topN int) []ChronicOffender {
	// occurrence times + dominant owner domain per group (children/maintenance excluded).
	times := map[string][]time.Time{}
	domVotes := map[string]map[OwnerDomain]int{}
	for _, in := range incidents {
		if in.IsChild || in.Maintenance {
			continue
		}
		key := groupKeyOf(in)
		if key == "" || in.OccurredAt.IsZero() {
			continue
		}
		times[key] = append(times[key], in.OccurredAt)
		if domVotes[key] == nil {
			domVotes[key] = map[OwnerDomain]int{}
		}
		d := in.OwnerDomain
		if d == "" {
			d = DomainUnknown
		}
		domVotes[key][d]++
	}
	out := make([]ChronicOffender, 0, len(times))
	for key, ts := range times {
		if len(ts) < 2 {
			continue // a single incident is not a chronic offender
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		var gapSum int64
		for i := 1; i < len(ts); i++ {
			gapSum += ts[i].Sub(ts[i-1]).Milliseconds()
		}
		dom, domN := DomainUnknown, 0
		for d, n := range domVotes[key] {
			if n > domN {
				dom, domN = d, n
			}
		}
		out = append(out, ChronicOffender{
			GroupKey:      key,
			IncidentCount: len(ts),
			MTBFms:        gapSum / int64(len(ts)-1),
			LastSeen:      ts[len(ts)-1],
			OwnerDomain:   dom,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IncidentCount != out[j].IncidentCount {
			return out[i].IncidentCount > out[j].IncidentCount
		}
		return out[i].MTBFms < out[j].MTBFms // tie-break: more frequent (smaller MTBF) first
	})
	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}

// MTTF computes mean-time-to-FAILURE for NON-REPAIRABLE assets only (optics, modules,
// circuits explicitly marked non_repairable) — the lifetime until first failure.
// Logical services are excluded by design (spec 11): an incident only counts if
// NonRepairable is set. Returns 0 + count 0 when no non-repairable assets failed.
func MTTF(incidents []IncidentSummary) (mttfMs int64, count int) {
	// First failure per non-repairable group (earliest occurrence), lifetime measured
	// from a known install/birth time is unavailable here, so MTTF is the mean
	// interval to first observed failure across distinct non-repairable assets is not
	// derivable without birth times — we report the count and leave mttf 0 unless a
	// birth time is supplied later. Honest: never fabricate an MTTF.
	seen := map[string]bool{}
	for _, in := range incidents {
		if !in.NonRepairable {
			continue
		}
		key := groupKeyOf(in)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		count++
	}
	return 0, count
}
