package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"netops/backend/internal/platformdb"
	"strings"
	"time"

	"netops/backend/internal/chschema"
	"netops/backend/timeintel"
)

// timeintel_backfill.go — RCA Time Intelligence #84 tail: the backfill that
// POPULATES incident_time_metrics. The live per-incident view DERIVES phase
// metrics from corr objects on read (no engine change); this worker computes the
// same decomposition for every corr object in a window and persists it as a
// durable, RLS-scoped snapshot. The reliability rollups READ these snapshots
// (timeintel_reliability.go, ListWindow) — persisted rows outlive the CH TTL,
// lift the old 5000-row live-scan cap, and carry the grounded seam_type plus the
// rollup grouping facts (owner/state/internal/group_keys, migration 0027) without
// re-parsing the hypotheses blob.
//
// Two backends like every other store (CLAUDE.md §3a): in-memory (default,
// tenant-filtered IN the store) and Postgres (tenant_iso FORCE-RLS via withTenant).
// Tenant is stamped from the corr object's own tenant_id (the data), never a
// request body — the worker spans tenants but each row is written default-closed
// under its own scope.

// The snapshot store moved to timeintel/metrics_store.go (Phase-2 W1.5).
// Aliases keep the worker, reliability rollups and handler source-compatible.
type (
	incidentTimeMetricRow    = timeintel.MetricRow
	incidentTimeMetricsStore = timeintel.MetricsStore
)

const timeIntelBackfillCap = timeintel.SnapshotCap

// newIncidentTimeMetricsStore selects pg under STORE_BACKEND=postgres, else in-memory.
func newIncidentTimeMetricsStore() incidentTimeMetricsStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return timeintel.NewPGMetricsStore(ps.DB())
	}
	return timeintel.NewMemMetricsStore()
}

// ── the backfill worker ───────────────────────────────────────────────────────

const (
	// timeIntelBackfillLookback bounds how far back a single backfill pass scans.
	timeIntelBackfillLookback = 30 * 24 * time.Hour
)

// backfillIncidentTimeMetrics scans corr objects across ALL tenants (worker scope)
// and upserts one computed snapshot per object, each stamped + RLS-written under
// its OWN tenant. Returns the number of rows written. No-op when the metrics store
// or ClickHouse isn't available.
func (s *server) backfillIncidentTimeMetrics(ctx context.Context, lookback time.Duration) (int, error) {
	if s.incidentTimeMetrics == nil {
		return 0, nil
	}
	if lookback <= 0 {
		lookback = timeIntelBackfillLookback
	}
	secs := int(lookback / time.Second)
	// Extract owner + seam_type server-side (JSONExtractString) instead of pulling
	// the whole hypotheses blob per object — at scale the blobs would blow past the
	// read cap and truncate. tenant_id leads so each row is written to its own scope.
	//
	// Bounded read (2026-07-09 incident, part 2): even JSONExtractString(o.hypotheses)
	// through corr_objects_latest forces the ~5.7KB blob through the view's full-table
	// LIMIT-1-BY sort on every ticker run. Fold narrow keys first; extract from the
	// blob only for the ≤cap picked (id, version) pairs.
	sql := `
WITH picked AS (
     SELECT correlation_id, version, window_start FROM (
          SELECT tenant_id, correlation_id, version, window_start
            FROM netops.corr_objects
           ORDER BY tenant_id, correlation_id, version DESC
           LIMIT 1 BY tenant_id, correlation_id
     )
      WHERE window_start >= now() - INTERVAL ` + intToString(secs) + ` SECOND
      ORDER BY window_start ASC
      LIMIT ` + intToString(timeIntelBackfillCap) + `
)
SELECT toString(o.tenant_id)      AS tenant_id,
       toString(o.correlation_id) AS correlation_id,
       ` + chschema.ISO("o.window_start") + ` AS window_start,
       ` + chschema.ISO("o.created_at") + `   AS created_at,
       o.verdict_tier             AS verdict_tier,
       o.top_confidence           AS top_confidence,
       o.top_hypothesis           AS top_hypothesis,
       o.evidence_missing         AS evidence_missing,
       o.affected                 AS affected,
       o.state                    AS state,
       JSONExtractString(o.hypotheses,'ranking','hypotheses',1,'verdict','owner') AS owner,
       JSONExtractString(o.hypotheses,'grounding_context','seams',1,'seam_type')  AS seam_type
  FROM netops.corr_objects AS o
 WHERE (o.correlation_id, o.version) IN (SELECT correlation_id, version FROM picked)
 ORDER BY o.window_start ASC
 FORMAT JSON`
	rows, err := chWorkerQuery(ctx, sql)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	written := 0
	for _, o := range rows {
		corrID := strings.TrimSpace(asString(o["correlation_id"]))
		if corrID == "" {
			continue
		}
		owner := strings.ToLower(strings.TrimSpace(asString(o["owner"])))
		sig := asString(o["top_hypothesis"])
		facts := timeintel.CorrTimeFacts{
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
		row := timeintel.DeriveMetricRow(
			asString(o["tenant_id"]), corrID, timeIntelCalcVersion,
			facts, group, asString(o["seam_type"]), asString(o["state"]), now)
		if err := s.incidentTimeMetrics.Upsert(ctx, row); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// startIncidentTimeMetricsBackfill runs the backfill on a ticker. Started only when
// a metrics store exists; cadence TIMEINTEL_BACKFILL_INTERVAL (default 15m, 0/off
// disables). The first pass runs after one interval so startup isn't perturbed.
func (s *server) startIncidentTimeMetricsBackfill(ctx context.Context) {
	if s.incidentTimeMetrics == nil {
		return
	}
	interval := envDuration("TIMEINTEL_BACKFILL_INTERVAL", 15*time.Minute)
	if interval <= 0 {
		return // explicitly disabled
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				if _, err := s.backfillIncidentTimeMetrics(cctx, timeIntelBackfillLookback); err != nil {
					log.Printf("timeintel backfill: %v", err)
				}
				cancel()
			}
		}
	}()
}

// ── HTTP: /api/reliability/time-metrics ───────────────────────────────────────

// handleReliabilityTimeMetrics serves the persisted phase-metric snapshots.
//
//	GET  — list the CALLER's own snapshots (tenant-scoped, default-closed).
//	POST — trigger a backfill pass. This recomputes across ALL tenants, so it is
//	       platform-admin only (CLAUDE.md §3a: a cross-tenant worker operation is
//	       platform-global plumbing, not per-tenant data).
func (s *server) handleReliabilityTimeMetrics(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if _, ok := s.requirePlatformAdmin(w, r); !ok {
			return
		}
		if s.incidentTimeMetrics == nil {
			writeError(w, http.StatusConflict, errors.New("metrics store unavailable"))
			return
		}
		lookback := timeIntelBackfillLookback
		if d := strings.TrimSpace(r.URL.Query().Get("lookback")); d != "" {
			if pd, err := time.ParseDuration(d); err == nil && pd > 0 {
				lookback = pd
			}
		}
		n, err := s.backfillIncidentTimeMetrics(r.Context(), lookback)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"written": n, "lookback": lookback.String()})
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		if s.incidentTimeMetrics == nil {
			writeJSON(w, http.StatusOK, map[string]any{"snapshots": []incidentTimeMetricRow{}})
			return
		}
		tenant, cross := principalTenant(claims)
		// Fail closed (F-71/F-74 rule): a malformed or over-cap limit used to be
		// discarded, so a caller asking for MORE silently received the default.
		limit, lerr := intQuery(r, "limit", 500, 1, timeIntelBackfillCap)
		if lerr != nil {
			writeError(w, http.StatusBadRequest, lerr)
			return
		}
		rowsOut, err := s.incidentTimeMetrics.List(r.Context(), tenant, cross, limit)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": rowsOut})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}
