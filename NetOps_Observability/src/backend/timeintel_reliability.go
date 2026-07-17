package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"netops/backend/timeintel"
)

// timeintel_reliability.go — RCA Time Intelligence reliability rollups:
//   GET /api/reliability/rollups            (percentile phase stats, MTBF, repeat rate, top time-loss phase)
//   GET /api/reliability/trends             (the same rollup bucketed over time)
//   GET /api/reliability/chronic-offenders  (recurring objects ranked by incident count)
//
// All three aggregate per-incident time decompositions over a window. The
// PRIMARY source is the persisted incident_time_metrics snapshot store (#84 tail:
// populated by timeintel_backfill.go, tenant-scoped in the store itself — RLS via
// withTenant on PG, tenant filter in the mem store), read via ListWindow which
// windows/dedupes/bounds IN the database. Snapshots outlive the ClickHouse TTL and
// lift the old 5000-row live-scan cap that silently under-reported large windows.
// The live ClickHouse derivation remains ONLY as a fallback for cold start (the
// first backfill pass hasn't run yet — mem store after a restart, or a fresh
// install). Percentiles (p50/p90/p95), NOT just averages.

// reliabilityFilters are the optional scoping filters (network-specific dimensions).
type reliabilityFilters struct {
	Owner     string // customer | isp | cloud_provider | ...
	Provider  string
	Device    string
	Severity  string
	Signature string // root_cause_signature (top_hypothesis)
}

// includeInternalFrom reads the "Include internal/platform events" toggle (default
// OFF — customer-impacting incidents only).
func includeInternalFrom(r *http.Request) bool {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include_internal")))
	return v == "1" || v == "true" || v == "yes"
}

func reliabilityFiltersFrom(r *http.Request) reliabilityFilters {
	q := r.URL.Query()
	return reliabilityFilters{
		Owner:     strings.ToLower(strings.TrimSpace(q.Get("owner"))),
		Provider:  strings.TrimSpace(q.Get("provider")),
		Device:    strings.TrimSpace(q.Get("device")),
		Severity:  strings.ToLower(strings.TrimSpace(q.Get("severity"))),
		Signature: strings.TrimSpace(q.Get("signature")),
	}
}

// incidentSummariesResult carries the summaries plus honest provenance: which
// source produced them, the bound that applied, and whether it was hit.
type incidentSummariesResult struct {
	Incidents []timeintel.IncidentSummary
	Source    string // "snapshots" (persisted store) | "live_scan" (CH fallback)
	ScanCap   int    // the row bound that applied to the read
	Capped    bool   // the raw read filled the bound → older incidents beyond it
}

// buildIncidentSummaries resolves the per-incident summaries for a window.
// Primary: persisted snapshots via ListWindow (tenant-scoped in the store, §3a;
// window + dedupe + bound applied in the database). Fallback: the live ClickHouse
// derivation — only when the snapshot store has no rows yet (cold start before the
// first backfill pass) or errors (logged, never silent).
func (s *server) buildIncidentSummaries(r *http.Request, sinceSeconds int, f reliabilityFilters, includeInternal bool) (incidentSummariesResult, error) {
	if s.incidentTimeMetrics != nil {
		if claims, ok := userFrom(r.Context()); ok {
			tenant, cross := principalTenant(claims)
			since := time.Now().UTC().Add(-time.Duration(sinceSeconds) * time.Second)
			rows, err := s.incidentTimeMetrics.ListWindow(r.Context(), tenant, cross, since, timeIntelCalcVersion, timeIntelBackfillCap)
			switch {
			case err != nil:
				// Observable, not silent: fall back to the live derivation so the
				// dashboard stays up, but say so in the log.
				log.Printf("reliability rollup: snapshot read failed, falling back to live scan: %v", err)
			case len(rows) > 0:
				return incidentSummariesResult{
					Incidents: summariesFromSnapshots(rows, f, includeInternal),
					Source:    "snapshots",
					ScanCap:   timeIntelBackfillCap,
					Capped:    len(rows) >= timeIntelBackfillCap,
				}, nil
			}
			// len(rows) == 0 → cold start (backfill hasn't produced rows yet): live fallback.
		}
	}
	incs, err := s.buildIncidentSummariesLive(r, sinceSeconds, f, includeInternal)
	if err != nil {
		return incidentSummariesResult{}, err
	}
	return incidentSummariesResult{
		Incidents: incs,
		Source:    "live_scan",
		ScanCap:   reliabilityLiveScanCap,
		Capped:    len(incs) >= reliabilityLiveScanCap,
	}, nil
}

// summariesFromSnapshots converts persisted snapshot rows to rollup inputs,
// applying the customer-impacting default (internal excluded) and the dimension
// filters. Pure — no IO. TTD is excluded for the same honesty reason as the live
// path: the batch derivation has no per-object ingest time, so detection falls
// back to onset → a misleading 0.
func summariesFromSnapshots(rows []incidentTimeMetricRow, f reliabilityFilters, includeInternal bool) []timeintel.IncidentSummary {
	out := make([]timeintel.IncidentSummary, 0, len(rows))
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
		durs := map[timeintel.MetricName]int64{}
		for _, m := range row.Metrics {
			if m.Complete && m.Name != timeintel.MetricTTD {
				durs[m.Name] = m.DurationMs
			}
		}
		out = append(out, timeintel.IncidentSummary{
			CorrelationID:  row.CorrelationID,
			Durations:      durs,
			TimeLossDriver: timeintel.TimeLossDriver(row.Bottleneck),
			Group:          group,
			OccurredAt:     row.OccurredAt,
			State:          row.State,
			IsChild:        strings.EqualFold(row.State, "merged"),
			OwnerDomain:    timeintel.OwnerDomain(row.OwnerDomain),
			Internal:       row.Internal,
		})
	}
	return out
}

// reliabilityLiveScanCap bounds the FALLBACK live ClickHouse scan (cold start
// only); the primary snapshot path is bounded by timeIntelBackfillCap instead.
const reliabilityLiveScanCap = 5000

// buildIncidentSummariesLive is the cold-start FALLBACK: loads corr objects in the
// window (tenant-scoped via chRows/chTenantScope) and turns each into a
// timeintel.IncidentSummary: derive lifecycle (engine facts; detection falls back
// to onset here — per-object ingest queries would be N+1), compute phase durations
// + the time-loss driver, and extract grouping keys for MTBF / chronic offenders.
// Maintenance/child classification: merged objects are children.
func (s *server) buildIncidentSummariesLive(r *http.Request, sinceSeconds int, f reliabilityFilters, includeInternal bool) ([]timeintel.IncidentSummary, error) {
	// Qualify with a table alias so WHERE references the real DateTime64 column, not
	// the toString() SELECT alias of the same name (which would be String → type
	// mismatch — the same gotcha handleCorrelations documents).
	// Reads the corr_current hot projection (#100): owner is a narrow engine-derived
	// column there, so this path never touches the hypotheses blob. The previous
	// shape — JSONExtractString(hypotheses) through corr_objects_latest — dragged
	// the ~5.7KB blob through the view's LIMIT 1 BY fold and memory-killed at
	// storm size.
	sql := `
SELECT toString(o.correlation_id) AS correlation_id,
       ` + chISO("o.window_start") + ` AS window_start,
       ` + chISO("o.created_at") + `   AS created_at,
       o.verdict_tier             AS verdict_tier,
       o.top_confidence           AS top_confidence,
       o.top_hypothesis           AS top_hypothesis,
       o.evidence_missing         AS evidence_missing,
       o.affected                 AS affected,
       o.state                    AS state,
       o.owner                    AS owner
  FROM netops.corr_current AS o FINAL
 WHERE o.window_start >= now() - INTERVAL ` + intToString(sinceSeconds) + ` SECOND
 ORDER BY o.window_start ASC
 LIMIT ` + intToString(reliabilityLiveScanCap) + `
 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		return nil, err
	}
	out := make([]timeintel.IncidentSummary, 0, len(rows))
	for _, o := range rows {
		owner := strings.ToLower(strings.TrimSpace(asString(o["owner"])))
		sig := asString(o["top_hypothesis"])
		facts := corrTimeFacts{
			WindowStart:     parseCHTime(o["window_start"]),
			CreatedAt:       parseCHTime(o["created_at"]),
			VerdictTier:     asString(o["verdict_tier"]),
			Owner:           owner,
			EvidenceMissing: evidenceMissingFromBlob(asString(o["evidence_missing"])),
			Confidence:      asFloat(o["top_confidence"]),
		}
		group := groupKeysFromAffected(asString(o["affected"]))
		if owner != "" {
			group["provider"] = owner
		}
		if sig != "" {
			group["signature"] = sig
		}
		ownerDomain, internal := timeintel.ClassifyOwnerDomain(owner, group)

		// Customer-impacting default: internal/platform self-monitoring is excluded
		// unless explicitly included (the dashboard's "Include internal/platform" toggle).
		if internal && !includeInternal {
			continue
		}

		// Filters (applied after grouping extraction).
		if f.Owner != "" && owner != f.Owner {
			continue
		}
		if f.Provider != "" && group["provider"] != f.Provider {
			continue
		}
		if f.Device != "" && group["device"] != f.Device {
			continue
		}
		if f.Signature != "" && sig != f.Signature {
			continue
		}

		lc := deriveLifecycle(facts, itsmTimeFacts{})
		metrics := timeintel.ComputeTimeMetrics(lc, timeIntelCalcVersion, time.Now().UTC())
		durs := map[timeintel.MetricName]int64{}
		for _, m := range metrics {
			// TTD is excluded from rollups: the batch path doesn't run the per-object
			// min(ingest_ts) query (N+1), so detection falls back to onset → a
			// misleading 0. Detection latency is shown per-incident (Time Impact card),
			// where the ingest query runs. Everything else rolls up honestly.
			if m.Complete && m.Name != timeintel.MetricTTD {
				durs[m.Name] = m.DurationMs
			}
		}
		driver, _ := timeintel.DeriveTimeLossDriver(lc, timeintel.DriverContext{EvidenceMissing: facts.EvidenceMissing, Owner: owner})

		out = append(out, timeintel.IncidentSummary{
			CorrelationID:  asString(o["correlation_id"]),
			Durations:      durs,
			TimeLossDriver: driver,
			Group:          group,
			OccurredAt:     facts.WindowStart,
			State:          asString(o["state"]),
			IsChild:        strings.EqualFold(asString(o["state"]), "merged"),
			OwnerDomain:    ownerDomain,
			Internal:       internal,
		})
	}
	return out, nil
}

// groupKeysFromAffected extracts MTBF grouping keys from the corr object's affected
// JSON ({devices,interfaces,paths}). First of each → the stable object identity.
func groupKeysFromAffected(blob string) map[string]string {
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
func (s *server) handleReliabilityRollups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	since := intQuery(r, "since", 30*86400, 3600, 365*86400)
	res, err := s.buildIncidentSummaries(r, since, reliabilityFiltersFrom(r), includeInternalFrom(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	rollup := timeintel.Rollup(res.Incidents)
	mttf, mttfCount := timeintel.MTTF(res.Incidents)
	writeJSON(w, http.StatusOK, map[string]any{
		"window_seconds":      since,
		"rollup":              rollup,
		"by_owner_domain":     timeintel.RollupByDomain(res.Incidents),
		"mttf_ms":             mttf,
		"mttf_asset_count":    mttfCount,
		"calculation_version": timeIntelCalcVersion,
		"include_internal":    includeInternalFrom(r),
		"source":              res.Source,  // snapshots (persisted) | live_scan (cold-start fallback)
		"scan_cap":            res.ScanCap, // bound of the source that served this window
		"capped":              res.Capped,  // info, not error — surfaced cleanly in the UI
	})
}

// handleReliabilityTrends serves GET /api/reliability/trends — the same per-incident
// summaries, bucketed by time, each bucket run through Rollup so the dashboard can
// chart MTTI / MTTR-Recovery / MTTD / MTTA p50/p90 over time. One CH read; bucketing
// + percentiles in-process.
func (s *server) handleReliabilityTrends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	since := intQuery(r, "since", 30*86400, 86400, 365*86400)
	bucket := intQuery(r, "bucket", 86400, 3600, 30*86400) // default daily
	res, err := s.buildIncidentSummaries(r, since, reliabilityFiltersFrom(r), includeInternalFrom(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	byBucket := map[int64][]timeintel.IncidentSummary{}
	for _, in := range res.Incidents {
		if in.OccurredAt.IsZero() {
			continue
		}
		b := (in.OccurredAt.Unix() / int64(bucket)) * int64(bucket)
		byBucket[b] = append(byBucket[b], in)
	}
	keys := make([]int64, 0, len(byBucket))
	for k := range byBucket {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	type bucketRow struct {
		BucketStart   time.Time                                     `json:"bucket_start"`
		IncidentCount int                                           `json:"incident_count"`
		Metrics       map[timeintel.MetricName]timeintel.MetricStat `json:"metrics"`
		RepeatRate    float64                                       `json:"repeat_incident_rate"`
		MTBFms        int64                                         `json:"mtbf_ms"`
	}
	rows := make([]bucketRow, 0, len(keys))
	for _, k := range keys {
		ro := timeintel.Rollup(byBucket[k])
		rows = append(rows, bucketRow{
			BucketStart: time.Unix(k, 0).UTC(), IncidentCount: ro.IncidentCount,
			Metrics: ro.Metrics, RepeatRate: ro.RepeatIncidentRate, MTBFms: ro.MTBFms,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window_seconds": since,
		"bucket_seconds": bucket,
		"buckets":        rows,
		"source":         res.Source,
	})
}

// handleReliabilityChronicOffenders serves GET /api/reliability/chronic-offenders.
func (s *server) handleReliabilityChronicOffenders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	since := intQuery(r, "since", 30*86400, 3600, 365*86400)
	topN := intQuery(r, "top", 10, 1, 100)
	res, err := s.buildIncidentSummaries(r, since, reliabilityFiltersFrom(r), includeInternalFrom(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window_seconds": since,
		"offenders":      timeintel.ChronicOffenders(res.Incidents, topN),
		"source":         res.Source,
	})
}
