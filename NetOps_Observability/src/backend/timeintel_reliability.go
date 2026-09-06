// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/chschema"
	"netops/backend/maintenance"
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

// timeintel.Filters are the optional scoping filters (network-specific dimensions).
func includeInternalFrom(r *http.Request) bool {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include_internal")))
	return v == "1" || v == "true" || v == "yes"
}

func reliabilityFiltersFrom(r *http.Request) timeintel.Filters {
	q := r.URL.Query()
	return timeintel.Filters{
		Owner:     strings.ToLower(strings.TrimSpace(q.Get("owner"))),
		Provider:  strings.TrimSpace(q.Get("provider")),
		Device:    strings.TrimSpace(q.Get("device")),
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
func (s *server) buildIncidentSummaries(r *http.Request, sinceSeconds int, f timeintel.Filters, includeInternal bool) (incidentSummariesResult, error) {
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
					Incidents: timeintel.SummariesFromSnapshots(rows, f, includeInternal),
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
const reliabilityLiveScanCap = 5000

// buildIncidentSummariesLive is the cold-start FALLBACK: loads corr objects in the
// window (tenant-scoped via chRows/chTenantScope) and turns each into a
// timeintel.IncidentSummary: derive lifecycle (engine facts; detection falls back
// to onset here — per-object ingest queries would be N+1), compute phase durations
// + the time-loss driver, and extract grouping keys for MTBF / chronic offenders.
// Maintenance/child classification: merged objects are children.
func (s *server) buildIncidentSummariesLive(r *http.Request, sinceSeconds int, f timeintel.Filters, includeInternal bool) ([]timeintel.IncidentSummary, error) {
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
       ` + chschema.ISO("o.window_start") + ` AS window_start,
       ` + chschema.ISO("o.window_end") + `   AS window_end,
       ` + chschema.ISO("o.created_at") + `   AS created_at,
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
	// Maintenance stamp (item 121): only resolvable for a scoped caller — the
	// cross-tenant live scan mixes tenants, and windows are strictly per-tenant.
	// One window read for the whole scan (the caller is a single tenant).
	callerClaims, _ := userFrom(r.Context())
	callerTenant, callerCross := principalTenant(callerClaims)
	var callerWindows []maintenance.Window
	if !callerCross && s.maintWindows != nil {
		var werr error
		if callerWindows, werr = s.maintWindows.List(r.Context(), callerTenant, false); werr != nil {
			logWarn("timeintel", "maintenance window read failed — live-scan rows stay unstamped", errf(werr))
		}
	}
	out := make([]timeintel.IncidentSummary, 0, len(rows))
	for _, o := range rows {
		owner := strings.ToLower(strings.TrimSpace(asString(o["owner"])))
		sig := asString(o["top_hypothesis"])
		facts := timeintel.CorrTimeFacts{
			WindowStart:     parseCHTime(o["window_start"]),
			CreatedAt:       parseCHTime(o["created_at"]),
			VerdictTier:     asString(o["verdict_tier"]),
			Owner:           owner,
			EvidenceMissing: evidenceMissingFromBlob(asString(o["evidence_missing"])),
			Confidence:      asFloat(o["top_confidence"]),
			// Engine lifecycle → engine-inferred recovery when no ITSM workflow is
			// linked (DeriveLifecycle's v2 mapping). state was already selected; only
			// window_end is new, and corr_current is the NARROW projection.
			State:     asString(o["state"]),
			WindowEnd: parseCHTime(o["window_end"]),
		}
		group := timeintel.GroupKeysFromAffected(asString(o["affected"]))
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

		lc := timeintel.DeriveLifecycle(facts, timeintel.ITSMTimeFacts{})
		metrics := timeintel.ComputeTimeMetrics(lc, timeIntelCalcVersion, time.Now().UTC())
		durs := map[timeintel.MetricName]int64{}
		for _, m := range metrics {
			// TTD is excluded from rollups: the batch path doesn't run the per-object
			// min(ingest_ts) query (N+1), so facts.FirstIngest is unknown here and
			// DeriveLifecycle stamps no `detected` — ttd is already INCOMPLETE (it used
			// to fall back to the onset and report a misleading complete 0). Detection
			// latency is shown per-incident (Time Impact card), where the ingest query
			// runs. The name check is kept as belt-and-braces: it states the exclusion
			// rather than relying on another package's incompleteness to imply it.
			if m.Complete && m.Name != timeintel.MetricTTD {
				durs[m.Name] = m.DurationMs
			}
		}
		driver, _ := timeintel.DeriveTimeLossDriver(lc, timeintel.DriverContext{EvidenceMissing: facts.EvidenceMissing, Owner: owner})

		maint := false
		for i := range callerWindows {
			if callerWindows[i].Covers(facts.WindowStart, group["device"], "", "") {
				maint = true
				break
			}
		}
		out = append(out, timeintel.IncidentSummary{
			CorrelationID:  asString(o["correlation_id"]),
			Durations:      durs,
			TimeLossDriver: driver,
			Group:          group,
			OccurredAt:     facts.WindowStart,
			State:          asString(o["state"]),
			IsChild:        strings.EqualFold(asString(o["state"]), "merged"),
			Maintenance:    maint,
			OwnerDomain:    ownerDomain,
			Internal:       internal,
		})
	}
	return out, nil
}

// groupKeysFromAffected extracts MTBF grouping keys from the corr object's affected
// JSON ({devices,interfaces,paths}). First of each → the stable object identity.
func (s *server) handleReliabilityRollups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	since, errSince := intQuery(r, "since", 30*86400, 3600, 365*86400)
	if errSince != nil {
		writeError(w, http.StatusBadRequest, errSince)
		return
	}
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
	since, errSince := intQuery(r, "since", 30*86400, 86400, 365*86400)
	if errSince != nil {
		writeError(w, http.StatusBadRequest, errSince)
		return
	}
	bucket, errBucket := intQuery(r, "bucket", 86400, 3600, 30*86400) // default daily
	if errBucket != nil {
		writeError(w, http.StatusBadRequest, errBucket)
		return
	}
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
	since, errSince := intQuery(r, "since", 30*86400, 3600, 365*86400)
	if errSince != nil {
		writeError(w, http.StatusBadRequest, errSince)
		return
	}
	topN, errTopN := intQuery(r, "top", 10, 1, 100)
	if errTopN != nil {
		writeError(w, http.StatusBadRequest, errTopN)
		return
	}
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
