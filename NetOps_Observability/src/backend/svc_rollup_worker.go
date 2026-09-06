// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// svc_rollup_worker.go — #69 P2 scheduled flow→service attribution roll-up
// (front-page.md §3). Populates netops.svc_flow_rollup_1m WITHOUT a
// materialized view: an MV over netops.flows re-evaluates the tenant row
// policy on every INSERT and breaks ingestion (the flows_hourly regression —
// see flows_services.go and init.sql). Instead, each tick this worker:
//
//   1. loads the latest selector version of every active service (bounded),
//   2. reads the per-tenant idempotency checkpoint — max(minute) of the
//      rows the LIVE roller wrote (rolled_by='live'). Deriving the checkpoint
//      from the rollup table itself (rather than a separate checkpoint row in
//      CH or PG) was chosen deliberately: it cannot drift from the data, needs
//      no new table/migration, and a failed insert simply retries the same
//      window next tick. SummingMergeTree is NOT idempotent for re-inserts, so
//      minutes ≤ checkpoint are never re-rolled,
//   3. per tenant, INSERT..SELECTs the closed minutes (checkpoint, lastClosed]
//      from netops.flows — ONE statement per tenant (all services UNION ALL'd)
//      so a mid-tenant failure can't advance the checkpoint past a service
//      that was skipped — stamping tenant_id from the SERVICE ROW and
//      selector_version from the version that attributed it.
//
// TENANT ISOLATION (§3a — never mix tenants in one attributed row): each
// tenant's statement runs at tenant_scope=<tenant> (the flows row policy
// bounds the scan server-side: own tagged rows + untagged), and the untagged
// share is further narrowed to the tenant's OWN device addresses — the same
// app-layer clause the read-time endpoint uses (addrTenantClauseFor). A tenant
// with no visible devices attributes only its own tagged rows.
//
// Reliability (§9): bounded work per tick (service/minute caps), a timeout on
// every query, and exponential backoff + jitter after a failed tick. Failures
// are logged (never silent) and retried — inserts that never happened leave
// the checkpoint untouched, so nothing is skipped.
//
// Opt-in: FEATURE_SVC_FLOW_ROLLUP=true; interval SVC_ROLLUP_INTERVAL (seconds,
// default 60).

import (
	"context"
	"log"
	"math/rand"
	"time"

	"netops/backend/internal/servicecat"
)

const (
	svcRollupMaxServices       = 200 // selector sets loaded per tick (global cap)
	svcRollupMaxSvcPerTenant   = 50  // services per tenant statement (statement-size bound)
	svcRollupMaxMinutesPerTick = 15  // catch-up window per tenant per tick
	svcRollupQueryTimeout      = 30 * time.Second
	svcRollupMaxBackoff        = 10 * time.Minute
)

// chScopedExec POSTs one statement to ClickHouse at an EXPLICIT tenant scope.
// The rollup worker uses it with the owning tenant's scope so the flows row
// policy bounds the INSERT..SELECT's read server-side (defense in depth under
// the app-layer address clause). Mirrors chWorkerExec, which is fixed at
// __all__.
//
// Routed through chhttp, which gains this path the two things it lacked: a
// server-side execution ceiling (it set no max_execution_time, so a runaway
// INSERT..SELECT was bounded only by the client) and classification, so the
// caller can tell insert backpressure from a schema fault.
type svcRollupWorker struct {
	listSets   func(ctx context.Context, limit int) ([]svcSelectorSet, error)
	query      func(ctx context.Context, scope, sql string) ([]map[string]any, error) // checkpoint read (__all__)
	exec       func(ctx context.Context, scope, body string) error                    // per-tenant INSERT
	addrClause func(tenant string) (clause string, empty bool)                        // app-layer untagged bound
	now        func() time.Time

	failures int // consecutive failed ticks → backoff
	nextTry  time.Time
}

func newSvcRollupWorker(s *server) *svcRollupWorker {
	return &svcRollupWorker{
		listSets: s.services.ActiveSelectorSets,
		query: func(ctx context.Context, scope, sql string) ([]map[string]any, error) {
			return s.chRowsScope(ctx, scope, sql, "worker:svc-rollup")
		},
		exec: chScopedExec,
		addrClause: func(tenant string) (string, bool) {
			// Same visibility primitive the read-time endpoint uses, driven by a
			// synthesized tenant-scoped principal (a background worker has no
			// request claims). Non-platform principals bypass the operator-
			// visibility restriction path by construction.
			clause, empty := s.addrTenantClauseFor(jwtClaims{Sub: "svc-rollup-worker", Role: RoleOperator, Tenant: tenant}, "src_addr", "dst_addr")
			return clause, empty
		},
		now: func() time.Time { return time.Now().UTC() },
	}
}

// checkpoints reads the last LIVE-rolled minute per tenant (unix seconds).
// rolled_by='live' only: an audited backfill of an old window must never
// fast-forward the live roller.
func (w *svcRollupWorker) checkpoints(ctx context.Context) (map[string]int64, error) {
	rows, err := w.query(ctx, "__all__",
		`SELECT tenant_id, toUnixTimestamp(max(minute)) AS m FROM netops.svc_flow_rollup_1m WHERE rolled_by = 'live' GROUP BY tenant_id FORMAT JSON`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		t, _ := r["tenant_id"].(string)
		out[t] = int64(asFloat(r["m"]))
	}
	return out, nil
}

// tick runs one bounded pass. Returns the number of per-tenant statements
// executed; any error is returned after processing the remaining tenants
// (one broken tenant must not starve the rest).
func (w *svcRollupWorker) tick(ctx context.Context) (int, error) {
	sets, err := w.listSets(ctx, svcRollupMaxServices)
	if err != nil {
		return 0, err
	}
	if len(sets) == 0 {
		return 0, nil // no catalog → nothing to attribute (honest no-op)
	}
	byTenant := map[string][]svcSelectorSet{}
	var tenants []string
	for _, set := range sets {
		if _, seen := byTenant[set.TenantID]; !seen {
			tenants = append(tenants, set.TenantID)
		}
		if len(byTenant[set.TenantID]) < svcRollupMaxSvcPerTenant {
			byTenant[set.TenantID] = append(byTenant[set.TenantID], set)
		} else if len(byTenant[set.TenantID]) == svcRollupMaxSvcPerTenant {
			log.Printf("svc-rollup: tenant %q exceeds %d services per tick; extra services roll up on later ticks", set.TenantID, svcRollupMaxSvcPerTenant)
		}
	}
	cps, err := w.checkpoints(ctx)
	if err != nil {
		return 0, err
	}
	lastClosed := w.now().Truncate(time.Minute).Add(-time.Minute) // newest fully-closed minute
	ran := 0
	var firstErr error
	for _, tenant := range tenants {
		from := lastClosed.Add(-time.Duration(svcRollupMaxMinutesPerTick-1) * time.Minute) // cold start: bounded, no unbounded catch-up
		if cp, ok := cps[tenant]; ok {
			cpMin := time.Unix(cp, 0).UTC().Truncate(time.Minute)
			if !cpMin.Before(lastClosed) {
				continue // already rolled — idempotency guard (never re-insert a minute)
			}
			next := cpMin.Add(time.Minute)
			if next.After(from) {
				from = next // resume exactly after the checkpoint
			} // else: further behind than the cap → roll the newest capped window
			// (older gap is skipped deliberately: bounded work beats unbounded
			// catch-up; an operator can close the gap with an explicit backfill).
		}
		clause, empty := w.addrClause(tenant)
		if empty {
			clause = "" // no visible devices → tagged rows only (default-closed)
		}
		sql, n := servicecat.RollupInsertSQL(tenant, byTenant[tenant], from, lastClosed, clause, "live")
		if n == 0 {
			continue // no service with a usable selector predicate
		}
		qctx, cancel := context.WithTimeout(ctx, svcRollupQueryTimeout)
		err := w.exec(qctx, tenant, sql)
		cancel()
		if err != nil {
			log.Printf("svc-rollup: tenant %q insert failed (window %s..%s, %d services): %v",
				tenant, from.Format(time.RFC3339), lastClosed.Format(time.RFC3339), n, err)
			if firstErr == nil {
				firstErr = err
			}
			continue // checkpoint untouched → this window retries next tick
		}
		ran++
	}
	return ran, firstErr
}

// backoffAfterFailure schedules the next attempt with exponential backoff and
// ±20% jitter (reliability rule: retry with backoff + jitter, never a hot loop
// against a down ClickHouse/Postgres).
func (w *svcRollupWorker) backoffAfterFailure(interval time.Duration) {
	w.failures++
	d := interval << w.failures
	if d > svcRollupMaxBackoff || d <= 0 {
		d = svcRollupMaxBackoff
	}
	jitter := time.Duration(rand.Int63n(int64(d)/5 + 1)) //nolint:gosec // scheduling jitter, not crypto
	w.nextTry = w.now().Add(d - d/10 + jitter)
}

// run is the supervised loop (ticker pattern, matching the repo's workers).
func (w *svcRollupWorker) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if w.now().Before(w.nextTry) {
				continue // backing off after a failure
			}
			if _, err := w.tick(ctx); err != nil {
				w.backoffAfterFailure(interval)
			} else {
				w.failures = 0
				w.nextTry = time.Time{}
			}
		}
	}
}

// startSvcFlowRollup wires the worker. Requires the Postgres-backed service
// catalog and a configured ClickHouse; logs (never silently no-ops) when a
// prerequisite is missing.
func (s *server) startSvcFlowRollup(ctx context.Context) {
	if s.services == nil {
		log.Printf("svc-rollup: FEATURE_SVC_FLOW_ROLLUP set but the service catalog requires the PostgreSQL backend — worker not started")
		return
	}
	if envOr("CLICKHOUSE_URL", "") == "" {
		log.Printf("svc-rollup: FEATURE_SVC_FLOW_ROLLUP set but CLICKHOUSE_URL is empty — worker not started")
		return
	}
	interval := envDurationSeconds("SVC_ROLLUP_INTERVAL", 60)
	logInfo("svc-rollup", "service flow rollup enabled", map[string]any{"interval": interval.String()})
	go newSvcRollupWorker(s).run(ctx, interval)
}
