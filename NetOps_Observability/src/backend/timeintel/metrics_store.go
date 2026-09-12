// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package timeintel

// metrics_store.go — the persisted phase-metrics snapshot store (RCA Time
// Intelligence #84 tail), extracted from package main (Phase-2 W1.5). One row
// per (tenant, correlation_id, calculation_version) — the durable twin of the
// live per-incident derivation; the reliability rollups read these snapshots
// so they never live-scan ClickHouse. Two backends like every store (§3a):
// in-memory (tenant-filtered IN the store) and Postgres (tenant_iso FORCE-RLS
// via WithTenant). The backfill worker, its ticker and the HTTP surface stay
// in main — they hold srv and the ClickHouse worker read.

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// SnapshotCap bounds rows per backfill pass and per rollup read (a multiple of
// the live rollup cap; the whole point of the table is to persist beyond the
// live read window).
const SnapshotCap = 20000

// MetricRow is one persisted phase-metrics snapshot per
// (tenant, correlation_id, calculation_version) — the durable twin of what the
// live per-incident view derives (timeIntelResponse).
type MetricRow struct {
	TenantID      string       `json:"-"` // never serialized (caller's own scope)
	CorrelationID string       `json:"correlation_id"`
	CalcVersion   string       `json:"calculation_version"`
	OccurredAt    time.Time    `json:"occurred_at"`
	OwnerDomain   string       `json:"owner_domain"`
	SeamType      string       `json:"seam_type,omitempty"`
	Bottleneck    string       `json:"current_bottleneck"`
	Metrics       []TimeMetric `json:"metrics"`
	CalculatedAt  time.Time    `json:"calculated_at"`
	// Rollup-source fields (migration 0027): everything the reliability rollups
	// need so they can read snapshots instead of a capped live ClickHouse scan.
	Owner    string            `json:"owner,omitempty"`      // raw seam owner (isp/cloud_provider/…) — owner filter
	State    string            `json:"state,omitempty"`      // open|closed|merged — merged children excluded from MTBF
	Internal bool              `json:"internal"`             // platform self-monitoring (excluded by default)
	Group    map[string]string `json:"group_keys,omitempty"` // device/interface/provider/signature/… grouping keys
	// Maintenance (migration 0031): occurred_at fell inside a covering
	// maintenance window — MTBF/chronic-offender math separates it from
	// unplanned downtime (IncidentSummary.Maintenance, spec test 10).
	Maintenance bool `json:"maintenance"`
}

type MetricsStore interface {
	// Upsert writes one snapshot, idempotent on the PK (re-backfill is safe).
	Upsert(ctx context.Context, row MetricRow) error
	// List returns the most recent snapshots for the caller, tenant-scoped
	// (default-closed unless cross). Newest first, bounded by limit.
	List(ctx context.Context, tenant string, cross bool, limit int) ([]MetricRow, error)
	// ListWindow is the reliability-rollup read: tenant-scoped (default-closed
	// unless cross), bounded to snapshots with occurred_at >= since, deduped to
	// ONE row per correlation_id (preferring preferVersion, then the freshest
	// calculated_at — so a calc-version bump never double-counts an incident),
	// newest occurred_at first, hard-bounded by limit.
	ListWindow(ctx context.Context, tenant string, cross bool, since time.Time, preferVersion string, limit int) ([]MetricRow, error)
}

// ── derivation (pure, no IO) ──────────────────────────────────────────────────

// DeriveMetricRow computes the persisted snapshot for one corr object
// from its engine-side facts — the SAME lifecycle/metric/driver derivation the live
// per-incident view and rollups use (DeriveLifecycle → ComputeTimeMetrics →
// DeriveTimeLossDriver), so a backfilled row equals the live computation. seamType
// is the grounded seam type (may be ""); group carries the owner/identity keys for
// owner-domain classification, MTBF grouping and dimension filters; state is the
// corr object state (open|closed|merged — merged = child, excluded from MTBF).
func DeriveMetricRow(tenant, corrID, version string, facts CorrTimeFacts, group map[string]string, seamType, state string, maintenance bool, now time.Time) MetricRow {
	// `state` is a PARAMETER of this derivation and it also lands in MetricRow.State,
	// so it is stamped onto the facts here rather than trusted to be set twice. That
	// makes one source of truth: a caller can never persist State="closed" while
	// deriving a lifecycle whose engine-inferred recovery never saw the close.
	facts.State = strings.ToLower(strings.TrimSpace(state))
	lc := DeriveLifecycle(facts, ITSMTimeFacts{})
	metrics := ComputeTimeMetrics(lc, version, now)
	ownerDomain, internal := ClassifyOwnerDomain(facts.Owner, group)
	driver, _ := DeriveTimeLossDriver(lc, DriverContext{
		EvidenceMissing: facts.EvidenceMissing, Owner: facts.Owner,
	})
	return MetricRow{
		TenantID:      normTenant(tenant),
		CorrelationID: corrID,
		CalcVersion:   version,
		OccurredAt:    facts.WindowStart,
		OwnerDomain:   string(ownerDomain),
		SeamType:      strings.TrimSpace(seamType),
		Bottleneck:    string(driver),
		Metrics:       metrics,
		CalculatedAt:  now,
		Owner:         facts.Owner,
		State:         facts.State, // normalized once, above
		Internal:      internal,
		Group:         group,
		Maintenance:   maintenance,
	}
}

// ── in-memory backend ─────────────────────────────────────────────────────────

// Bounds for the in-memory backend (§9: all stores bounded — measured defect,
// storm-s08 2026-09-01). On the file backend the backfill fold used to
// accumulate EVERY snapshot it ever derived in the map below: 259,999 rows
// folded over 13 catch-up passes put ~800 MiB of anonymous memory (~3 KB/row:
// 8 TimeMetrics + group keys + strings + map overhead) into a 565 MiB
// container, and the 918k-object backlog would have needed ~2.7 GiB. The PG
// backend was never affected — its rows live in Postgres and every read is
// LIMIT-bounded in SQL.
//
// The bound is derived from what the READS can return, so eviction can never
// change an answer:
//
//   - MemRowCapPerTenant = SnapshotCap. Every read is capped at SnapshotCap
//     rows per call: the snapshots handler clamps List's limit to
//     [1, SnapshotCap], and the reliability rollups call ListWindow with
//     exactly SnapshotCap. Both serve NEWEST-first with honest capping, so
//     keeping the newest SnapshotCap rows per tenant (by occurred_at) yields
//     the same answers as an unbounded store for every reachable query. (One
//     documented edge: during a calc-version transition, duplicate versions of
//     one incident count twice against the raw-row cap, so the deduped
//     ListWindow horizon can shrink by the duplicate count. The fold writes a
//     single version, and this backend is restart-ephemeral, so the shrink is
//     transient and bounded.)
//   - MemRetention matches the widest window any consumer can request (the
//     rollup handlers clamp `since` to <= 365 days), plus a day of slack. A
//     row older than that is unreadable through every surface, so compaction
//     drops it before it drops anything readable.
//
// Eviction is amortized: a tenant is compacted only when it runs
// memCompactSlack rows past the cap, so resident rows per tenant are bounded
// by MemRowCapPerTenant+memCompactSlack and the sort cost is paid once per
// slack-many upserts, not per upsert.
const (
	// MemRowCapPerTenant bounds resident rows per tenant in MemMetricsStore.
	MemRowCapPerTenant = SnapshotCap
	// MemRetention bounds row age in MemMetricsStore (366d: the 365d consumer
	// window clamp plus slack).
	MemRetention = 366 * 24 * time.Hour
	// memCompactSlack is the compaction hysteresis (rows past the cap before a
	// tenant is compacted back down to it).
	memCompactSlack = 1024
)

// NewMemMetricsStore builds the in-memory backend, bounded by
// MemRowCapPerTenant and MemRetention (see the const block above).
func NewMemMetricsStore() *MemMetricsStore {
	return &MemMetricsStore{
		by:        map[string]MetricRow{},
		perTenant: map[string]int{},
		rowCap:    MemRowCapPerTenant,
		retention: MemRetention,
		now:       time.Now,
	}
}

// NewPGMetricsStore wraps the platform DB pool (FORCE-RLS backend).
func NewPGMetricsStore(db *platformdb.DB) *PGMetricsStore { return &PGMetricsStore{db: db} }

type MemMetricsStore struct {
	mu        sync.RWMutex
	by        map[string]MetricRow // key: tenant\x1fcorrID\x1fversion
	perTenant map[string]int       // resident rows per tenant (drives compaction)
	rowCap    int                  // max rows kept per tenant (<=0 disables, tests only)
	retention time.Duration        // max row age by occurred_at (<=0 disables)
	now       func() time.Time     // injectable clock (retention tests)
	evicted   int64                // rows evicted since construction (observability)
}

func (m *MemMetricsStore) key(tenant, corrID, version string) string {
	return normTenant(tenant) + "\x1f" + corrID + "\x1f" + version
}

func (m *MemMetricsStore) Upsert(_ context.Context, row MetricRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row.TenantID = normTenant(row.TenantID)
	k := m.key(row.TenantID, row.CorrelationID, row.CalcVersion)
	// Idempotent on the PK: overwriting an existing row never grows the count,
	// so a re-backfill of the same page cannot trigger (or skew) eviction.
	if _, exists := m.by[k]; !exists {
		m.perTenant[row.TenantID]++
	}
	m.by[k] = row
	m.compactLocked(row.TenantID)
	return nil
}

// Evicted reports how many rows compaction has dropped since construction —
// the store's own evidence that the bound is doing work (§10: observable).
func (m *MemMetricsStore) Evicted() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.evicted
}

// compactLocked bounds one tenant's resident rows. Caller holds mu.
//
// Two phases, cheapest-first: rows older than the retention window are
// unreadable through every consumer surface (the rollup handlers clamp
// `since` to <= 365d < MemRetention) and go first; if the tenant is still over
// the cap, the OLDEST rows by occurred_at go until it fits. Reads serve
// newest-first with honest capping, so what is dropped is exactly what no
// bounded read would have returned anyway. A zero occurred_at sorts as oldest
// (it is unreadable through any since-window) but is exempt from the retention
// phase so a sparse tenant's zero-stamped rows don't vanish for free.
func (m *MemMetricsStore) compactLocked(tenant string) {
	if m.rowCap <= 0 || m.perTenant[tenant] <= m.rowCap+memCompactSlack {
		return
	}
	var cutoff time.Time
	if m.retention > 0 {
		cutoff = m.now().UTC().Add(-m.retention)
	}
	type keyAge struct {
		key      string
		occurred time.Time
		calc     time.Time
	}
	keep := make([]keyAge, 0, m.perTenant[tenant])
	for k, r := range m.by {
		if r.TenantID != tenant {
			continue
		}
		if !cutoff.IsZero() && !r.OccurredAt.IsZero() && r.OccurredAt.Before(cutoff) {
			delete(m.by, k)
			m.evicted++
			continue
		}
		keep = append(keep, keyAge{key: k, occurred: r.OccurredAt, calc: r.CalculatedAt})
	}
	if excess := len(keep) - m.rowCap; excess > 0 {
		sort.Slice(keep, func(i, j int) bool { // oldest first; zero occurred_at oldest of all
			a, b := keep[i], keep[j]
			if a.occurred.IsZero() != b.occurred.IsZero() {
				return a.occurred.IsZero()
			}
			if !a.occurred.Equal(b.occurred) {
				return a.occurred.Before(b.occurred)
			}
			return a.calc.Before(b.calc)
		})
		for _, e := range keep[:excess] {
			delete(m.by, e.key)
			m.evicted++
		}
		keep = keep[excess:]
	}
	if len(keep) == 0 {
		delete(m.perTenant, tenant) // no unbounded tenant-name residue
		return
	}
	m.perTenant[tenant] = len(keep)
}

func (m *MemMetricsStore) List(_ context.Context, tenant string, cross bool, limit int) ([]MetricRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := normTenant(tenant)
	out := []MetricRow{}
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

func (m *MemMetricsStore) ListWindow(_ context.Context, tenant string, cross bool, since time.Time, preferVersion string, limit int) ([]MetricRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := normTenant(tenant)
	// Dedupe: one row per correlation_id, preferring preferVersion then the freshest
	// calculated_at — a calc-version bump must never double-count an incident.
	best := map[string]MetricRow{}
	for _, row := range m.by {
		if !cross && row.TenantID != t { // default-closed tenant filter (§3a)
			continue
		}
		if !since.IsZero() && row.OccurredAt.Before(since) {
			continue
		}
		cur, seen := best[row.TenantID+"\x1f"+row.CorrelationID]
		if !seen {
			best[row.TenantID+"\x1f"+row.CorrelationID] = row
			continue
		}
		curPref, rowPref := cur.CalcVersion == preferVersion, row.CalcVersion == preferVersion
		if (rowPref && !curPref) || (rowPref == curPref && row.CalculatedAt.After(cur.CalculatedAt)) {
			best[row.TenantID+"\x1f"+row.CorrelationID] = row
		}
	}
	out := make([]MetricRow, 0, len(best))
	for _, row := range best {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via withTenant) ────────────────────

type PGMetricsStore struct{ db *platformdb.DB }

func (s *PGMetricsStore) Upsert(ctx context.Context, row MetricRow) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	metricsJSON, err := json.Marshal(row.Metrics)
	if err != nil {
		return err
	}
	if len(metricsJSON) == 0 {
		metricsJSON = []byte("[]")
	}
	group := row.Group
	if group == nil {
		group = map[string]string{}
	}
	groupJSON, err := json.Marshal(group)
	if err != nil {
		return err
	}
	calc := row.CalculatedAt
	if calc.IsZero() {
		calc = time.Now().UTC()
	}
	// Writer is tenant-scoped (owner stamped from the corr object's tenant_id);
	// WITH CHECK enforces the row's tenant matches the bound scope.
	return s.db.WithTenant(ctx, row.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO incident_time_metrics
  (tenant_id, correlation_id, calculation_version, occurred_at, owner_domain,
   current_bottleneck, seam_type, metrics, calculated_at, owner, state, internal, group_keys, maintenance)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (tenant_id, correlation_id, calculation_version)
DO UPDATE SET occurred_at = EXCLUDED.occurred_at, owner_domain = EXCLUDED.owner_domain,
              current_bottleneck = EXCLUDED.current_bottleneck, seam_type = EXCLUDED.seam_type,
              metrics = EXCLUDED.metrics, calculated_at = EXCLUDED.calculated_at,
              owner = EXCLUDED.owner, state = EXCLUDED.state,
              internal = EXCLUDED.internal, group_keys = EXCLUDED.group_keys,
              maintenance = EXCLUDED.maintenance`,
			normTenant(row.TenantID), row.CorrelationID, row.CalcVersion, nullableTime(row.OccurredAt),
			row.OwnerDomain, row.Bottleneck, row.SeamType, string(metricsJSON), calc,
			row.Owner, row.State, row.Internal, string(groupJSON), row.Maintenance)
		return err
	})
}

func (s *PGMetricsStore) List(ctx context.Context, tenant string, cross bool, limit int) ([]MetricRow, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if limit <= 0 || limit > SnapshotCap {
		limit = 500
	}
	out := []MetricRow{}
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, correlation_id, calculation_version, occurred_at, owner_domain,
       current_bottleneck, seam_type, metrics, calculated_at, owner, state, internal, group_keys, maintenance
  FROM incident_time_metrics
 ORDER BY occurred_at DESC NULLS LAST
 LIMIT `+strconv.Itoa(limit))
		if err != nil {
			return err
		}
		defer rows.Close()
		var scanErr error
		out, scanErr = scanMetricRows(rows)
		return scanErr
	})
	return out, err
}

// ListWindow is the rollup read: aggregate scoping in the DATABASE (RLS tenant
// scope + occurred_at window + one-row-per-incident dedupe + hard bound), so the
// API never live-scans ClickHouse for rollups and never loads unbounded history.
func (s *PGMetricsStore) ListWindow(ctx context.Context, tenant string, cross bool, since time.Time, preferVersion string, limit int) ([]MetricRow, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if limit <= 0 || limit > SnapshotCap {
		limit = SnapshotCap
	}
	out := []MetricRow{}
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// DISTINCT ON dedupes to one snapshot per (tenant, incident), preferring the
		// current calculation version, then the freshest computation — a calc-version
		// bump never double-counts. Outer ORDER BY keeps the most RECENT incidents
		// when the window holds more than the bound (honest capping, newest first).
		rows, err := tx.Query(ctx, `
SELECT * FROM (
    SELECT DISTINCT ON (tenant_id, correlation_id)
           tenant_id, correlation_id, calculation_version, occurred_at, owner_domain,
           current_bottleneck, seam_type, metrics, calculated_at, owner, state, internal, group_keys, maintenance
      FROM incident_time_metrics
     WHERE occurred_at >= $1
     ORDER BY tenant_id, correlation_id, (calculation_version = $2) DESC, calculated_at DESC
) d
 ORDER BY occurred_at DESC NULLS LAST
 LIMIT `+strconv.Itoa(limit), since, preferVersion)
		if err != nil {
			return err
		}
		defer rows.Close()
		var scanErr error
		out, scanErr = scanMetricRows(rows)
		return scanErr
	})
	return out, err
}

// scanMetricRows scans the shared 14-column snapshot row shape.
func scanMetricRows(rows pgx.Rows) ([]MetricRow, error) {
	out := []MetricRow{}
	for rows.Next() {
		var row MetricRow
		var occurred *time.Time
		var metricsRaw, groupRaw []byte
		if err := rows.Scan(&row.TenantID, &row.CorrelationID, &row.CalcVersion, &occurred,
			&row.OwnerDomain, &row.Bottleneck, &row.SeamType, &metricsRaw, &row.CalculatedAt,
			&row.Owner, &row.State, &row.Internal, &groupRaw, &row.Maintenance); err != nil {
			return out, err
		}
		if occurred != nil {
			row.OccurredAt = *occurred
		}
		if len(metricsRaw) > 0 {
			if err := json.Unmarshal(metricsRaw, &row.Metrics); err != nil {
				return out, err
			}
		}
		if len(groupRaw) > 0 {
			if err := json.Unmarshal(groupRaw, &row.Group); err != nil {
				return out, err
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// nullableTime returns nil for a zero time so a NULL is stored (not 0001-01-01).
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
