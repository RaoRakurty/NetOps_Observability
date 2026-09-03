package timeintel

// reliability_derive.go — the reliability-rollup derivations (Phase-2 W4.2,
// extracted from package main's timeintel_reliability.go): snapshot→summary
// projection with the dimension filters, and the affected-blob grouping keys
// (shared by the backfill worker). The http filter parsing, the store/live
// reads and the handlers stay in main.

import (
	"encoding/json"
	"strings"
)

type Filters struct {
	Owner     string // customer | isp | cloud_provider | ...
	Provider  string
	Device    string
	Signature string // root_cause_signature (top_hypothesis)
}

// includeInternalFrom reads the "Include internal/platform events" toggle (default
// OFF — customer-impacting incidents only).
func SummariesFromSnapshots(rows []MetricRow, f Filters, includeInternal bool) []IncidentSummary {
	out := make([]IncidentSummary, 0, len(rows))
	for _, row := range rows {
		if row.Internal && !includeInternal {
			continue
		}
		group := row.Group
		if group == nil {
			group = map[string]string{}
		}
		owner := strings.ToLower(strings.TrimSpace(row.Owner))
		if f.Owner != "" && owner != f.Owner {
			continue
		}
		if f.Provider != "" && group["provider"] != f.Provider {
			continue
		}
		if f.Device != "" && group["device"] != f.Device {
			continue
		}
		if f.Signature != "" && group["signature"] != f.Signature {
			continue
		}
		durs := map[MetricName]int64{}
		for _, m := range row.Metrics {
			// TTD is excluded from rollups: the snapshot (backfill) path does not run
			// the per-object min(ingest_ts) query (N+1), so it derives no `detected`
			// stamp at all and ttd is already INCOMPLETE (DeriveLifecycle no longer
			// falls back to the onset, which used to make it a misleading complete 0).
			// The name check is kept as belt-and-braces: it states the exclusion
			// instead of relying on another package's incompleteness to imply it.
			if m.Complete && m.Name != MetricTTD {
				durs[m.Name] = m.DurationMs
			}
		}
		out = append(out, IncidentSummary{
			CorrelationID:  row.CorrelationID,
			Durations:      durs,
			TimeLossDriver: TimeLossDriver(row.Bottleneck),
			Group:          group,
			OccurredAt:     row.OccurredAt,
			State:          row.State,
			IsChild:        strings.EqualFold(row.State, "merged"),
			Maintenance:    row.Maintenance,
			OwnerDomain:    OwnerDomain(row.OwnerDomain),
			Internal:       row.Internal,
		})
	}
	return out
}

// reliabilityLiveScanCap bounds the FALLBACK live ClickHouse scan (cold start
// only); the primary snapshot path is bounded by timeIntelBackfillCap instead.
func GroupKeysFromAffected(blob string) map[string]string {
	g := map[string]string{}
	blob = strings.TrimSpace(blob)
	if blob == "" || blob == "{}" {
		return g
	}
	var a struct {
		Devices    []string `json:"devices"`
		Interfaces []string `json:"interfaces"`
		Paths      []string `json:"paths"`
	}
	if err := json.Unmarshal([]byte(blob), &a); err != nil {
		return g
	}
	if len(a.Devices) > 0 {
		g["device"] = a.Devices[0]
		g["root_entity"] = a.Devices[0]
	}
	if len(a.Interfaces) > 0 {
		g["interface"] = a.Interfaces[0]
	}
	if len(a.Paths) > 0 {
		g["app_path"] = a.Paths[0]
	}
	return g
}

// handleReliabilityRollups serves GET /api/reliability/rollups.
