package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"netops/backend/timeintel"
)

// timeintel_backfill.go — RCA Time Intelligence #84 tail: the backfill that
// POPULATES incident_time_metrics. The live per-incident view and the reliability
// rollups DERIVE phase metrics from corr objects on read (no engine change); this
// worker computes the same decomposition for every corr object in a window and
// persists it as a durable, RLS-scoped snapshot — so rollups can read persisted
// rows beyond the live ClickHouse scan cap (5000) and outlive the CH TTL, and so
// the grounded seam_type is carried without re-parsing the hypotheses blob.
//
// Two backends like every other store (CLAUDE.md §3a): in-memory (default,
// tenant-filtered IN the store) and Postgres (tenant_iso FORCE-RLS via withTenant).
// Tenant is stamped from the corr object's own tenant_id (the data), never a
// request body — the worker spans tenants but each row is written default-closed
// under its own scope.

// incidentTimeMetricRow is one persisted phase-metrics snapshot per
// (tenant, correlation_id, calculation_version) — the durable twin of what the
// live per-incident view derives (timeIntelResponse).
type incidentTimeMetricRow struct {
	TenantID      string                 `json:"-"` // never serialized (caller's own scope)
	CorrelationID string                 `json:"correlation_id"`
	CalcVersion   string                 `json:"calculation_version"`
	OccurredAt    time.Time              `json:"occurred_at"`
	OwnerDomain   string                 `json:"owner_domain"`
	SeamType      string                 `json:"seam_type,omitempty"`
	Bottleneck    string                 `json:"current_bottleneck"`
	Metrics       []timeintel.TimeMetric `json:"metrics"`
	CalculatedAt  time.Time              `json:"calculated_at"`
}

type incidentTimeMetricsStore interface {
	// Upsert writes one snapshot, idempotent on the PK (re-backfill is safe).
	Upsert(ctx context.Context, row incidentTimeMetricRow) error
	// List returns the most recent snapshots for the caller, tenant-scoped
	// (default-closed unless cross). Newest first, bounded by limit.
	List(ctx context.Context, tenant string, cross bool, limit int) ([]incidentTimeMetricRow, error)
}

// newIncidentTimeMetricsStore selects pg under STORE_BACKEND=postgres, else in-memory.
func newIncidentTimeMetricsStore() incidentTimeMetricsStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgIncidentTimeMetricsStore{db: ps.db}
	}
	return &memIncidentTimeMetricsStore{by: map[string]incidentTimeMetricRow{}}
}

// ── derivation (pure, no IO) ──────────────────────────────────────────────────

// deriveIncidentTimeMetricRow computes the persisted snapshot for one corr object
// from its engine-side facts — the SAME lifecycle/metric/driver derivation the live
// per-incident view and rollups use (deriveLifecycle → ComputeTimeMetrics →
// DeriveTimeLossDriver), so a backfilled row equals the live computation. seamType
// is the grounded seam type (may be ""); group carries the owner/identity keys for
// owner-domain classification.
func deriveIncidentTimeMetricRow(tenant, corrID, version string, facts corrTimeFacts, group map[string]string, seamType string, now time.Time) incidentTimeMetricRow {
	lc := deriveLifecycle(facts, itsmTimeFacts{})
	metrics := timeintel.ComputeTimeMetrics(lc, version, now)
	ownerDomain, _ := timeintel.ClassifyOwnerDomain(facts.Owner, group)
	driver, _ := timeintel.DeriveTimeLossDriver(lc, timeintel.DriverContext{
		EvidenceMissing: facts.EvidenceMissing, Owner: facts.Owner,
	})
	return incidentTimeMetricRow{
		TenantID:      normTenant(tenant),
		CorrelationID: corrID,
		CalcVersion:   version,
		OccurredAt:    facts.WindowStart,
		OwnerDomain:   string(ownerDomain),
		SeamType:      strings.TrimSpace(seamType),
		Bottleneck:    string(driver),
		Metrics:       metrics,
		CalculatedAt:  now,
	}
}

// ── the backfill worker ───────────────────────────────────────────────────────

const (
	// timeIntelBackfillLookback bounds how far back a single backfill pass scans.
	timeIntelBackfillLookback = 30 * 24 * time.Hour
	// timeIntelBackfillCap bounds rows per pass (a multiple of the live rollup cap;
	// the whole point of the table is to persist beyond the live read window).
	timeIntelBackfillCap = 20000
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
	sql := `
SELECT toString(o.tenant_id)      AS tenant_id,
       toString(o.correlation_id) AS correlation_id,
       toString(o.window_start)   AS window_start,
       toString(o.created_at)     AS created_at,
       o.verdict_tier             AS verdict_tier,
       o.top_confidence           AS top_confidence,
       o.top_hypothesis           AS top_hypothesis,
       o.evidence_missing         AS evidence_missing,
       o.affected                 AS affected,
       JSONExtractString(o.hypotheses,'ranking','hypotheses',1,'verdict','owner') AS owner,
       JSONExtractString(o.hypotheses,'grounding_context','seams',1,'seam_type')  AS seam_type
  FROM netops.corr_objects_latest AS o
 WHERE o.window_start >= now() - INTERVAL ` + intToString(secs) + ` SECOND
 ORDER BY o.window_start ASC
 LIMIT ` + intToString(timeIntelBackfillCap) + `
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
		row := deriveIncidentTimeMetricRow(
			asString(o["tenant_id"]), corrID, timeIntelCalcVersion,
			facts, group, asString(o["seam_type"]), now)
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

// ── in-memory backend ─────────────────────────────────────────────────────────

type memIncidentTimeMetricsStore struct {
	mu sync.RWMutex
	by map[string]incidentTimeMetricRow // key: tenant\x1fcorrID\x1fversion
}

func (m *memIncidentTimeMetricsStore) key(tenant, corrID, version string) string {
	return normTenant(tenant) + "\x1f" + corrID + "\x1f" + version
}

func (m *memIncidentTimeMetricsStore) Upsert(_ context.Context, row incidentTimeMetricRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row.TenantID = normTenant(row.TenantID)
	m.by[m.key(row.TenantID, row.CorrelationID, row.CalcVersion)] = row
	return nil
}

func (m *memIncidentTimeMetricsStore) List(_ context.Context, tenant string, cross bool, limit int) ([]incidentTimeMetricRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := normTenant(tenant)
	out := []incidentTimeMetricRow{}
	for _, row := range m.by {
		if !cross && row.TenantID != t { // default-closed tenant filter
			continue
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via withTenant) ────────────────────

type pgIncidentTimeMetricsStore struct{ db *pgDB }

func (s *pgIncidentTimeMetricsStore) Upsert(ctx context.Context, row incidentTimeMetricRow) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	metricsJSON, err := json.Marshal(row.Metrics)
	if err != nil {
		return err
	}
	if len(metricsJSON) == 0 {
		metricsJSON = []byte("[]")
	}
	calc := row.CalculatedAt
	if calc.IsZero() {
		calc = time.Now().UTC()
	}
	// Writer is tenant-scoped (owner stamped from the corr object's tenant_id);
	// WITH CHECK enforces the row's tenant matches the bound scope.
	return s.db.withTenant(ctx, row.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO incident_time_metrics
  (tenant_id, correlation_id, calculation_version, occurred_at, owner_domain,
   current_bottleneck, seam_type, metrics, calculated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (tenant_id, correlation_id, calculation_version)
DO UPDATE SET occurred_at = EXCLUDED.occurred_at, owner_domain = EXCLUDED.owner_domain,
              current_bottleneck = EXCLUDED.current_bottleneck, seam_type = EXCLUDED.seam_type,
              metrics = EXCLUDED.metrics, calculated_at = EXCLUDED.calculated_at`,
			normTenant(row.TenantID), row.CorrelationID, row.CalcVersion, nullableTime(row.OccurredAt),
			row.OwnerDomain, row.Bottleneck, row.SeamType, string(metricsJSON), calc)
		return err
	})
}

func (s *pgIncidentTimeMetricsStore) List(ctx context.Context, tenant string, cross bool, limit int) ([]incidentTimeMetricRow, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if limit <= 0 || limit > timeIntelBackfillCap {
		limit = 500
	}
	out := []incidentTimeMetricRow{}
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, correlation_id, calculation_version, occurred_at, owner_domain,
       current_bottleneck, seam_type, metrics, calculated_at
  FROM incident_time_metrics
 ORDER BY occurred_at DESC NULLS LAST
 LIMIT `+intToString(limit))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row incidentTimeMetricRow
			var occurred *time.Time
			var metricsRaw []byte
			if err := rows.Scan(&row.TenantID, &row.CorrelationID, &row.CalcVersion, &occurred,
				&row.OwnerDomain, &row.Bottleneck, &row.SeamType, &metricsRaw, &row.CalculatedAt); err != nil {
				return err
			}
			if occurred != nil {
				row.OccurredAt = *occurred
			}
			if len(metricsRaw) > 0 {
				_ = json.Unmarshal(metricsRaw, &row.Metrics)
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// nullableTime returns nil for a zero time so a NULL is stored (not 0001-01-01).
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
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
		limit := 500
		if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= timeIntelBackfillCap {
				limit = n
			}
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
