package main

// svc_backfill.go — #69 §3.3 explicit selector backfill.
//
//	POST /api/services/{id}/selectors/{version}/backfill?from=&to=
//
// CONTRACT (front-page.md §3.3 "selector edits never rewrite history;
// reclassification is an intentional, audited act"):
//   - The backfill INSERTS rollup rows for the window stamped with the
//     REQUESTED selector_version and rolled_by='backfill'. It never deletes or
//     rewrites prior rows — history is truth. ALTER TABLE ... DELETE was
//     rejected deliberately: it is a heavyweight table-rewriting mutation on a
//     live SummingMergeTree and would destroy the "rows attributed under v3
//     stay v3" audit trail besides.
//   - Readers resolve overlap latest-selector-version-wins per (tenant,
//     service, minute) — see svcRollupLatestVersionSQL, the ONE sanctioned
//     read shape over this table.
//   - rolled_by='backfill' keeps these rows out of the live roller's
//     checkpoint (max(minute) of rolled_by='live'), so backfilling a recent
//     window can never make the live roller skip minutes.
//
// Authz: infrastructure:admin (per-tenant data — a tenant admin may backfill
// its OWN services; cross-tenant service ids 404 via RLS). The invocation is
// explicitly audit-logged with the window + version (beyond the generic
// mutating-request audit middleware).
//
// Bounded: window capped (SVC_BACKFILL_MAX_DAYS, default 30), chunked in 6h
// statements each under its own timeout, and at most svcBackfillMaxConcurrent
// backfills run at once (409 when busy). Tenant isolation is identical to the
// live roller: the scan runs at the OWNING tenant's scope, bounded to that
// tenant's tagged rows + its own devices' untagged rows.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"
)

const (
	svcBackfillDefaultMaxDays = 30
	svcBackfillChunk          = 6 * time.Hour
	svcBackfillMaxConcurrent  = 2
	svcBackfillChunkTimeout   = 60 * time.Second
	svcBackfillOverallTimeout = 30 * time.Minute
)

// svcBackfillSlots bounds concurrent backfills process-wide (bounded queues rule).
var svcBackfillSlots = make(chan struct{}, svcBackfillMaxConcurrent)

// svcBackfillWindow validates the from/to query params. Pure + unit-tested.
func svcBackfillWindow(fromS, toS string, now time.Time, maxDays int) (from, to time.Time, err error) {
	if fromS == "" || toS == "" {
		return from, to, errors.New("from and to are required (RFC3339)")
	}
	from, err = time.Parse(time.RFC3339, fromS)
	if err != nil {
		return from, to, errors.New("from: invalid RFC3339 timestamp")
	}
	to, err = time.Parse(time.RFC3339, toS)
	if err != nil {
		return from, to, errors.New("to: invalid RFC3339 timestamp")
	}
	from, to = from.UTC().Truncate(time.Minute), to.UTC().Truncate(time.Minute)
	if !from.Before(to) {
		return from, to, errors.New("from must be before to")
	}
	if to.After(now) {
		return from, to, errors.New("to must not be in the future")
	}
	if to.Sub(from) > time.Duration(maxDays)*24*time.Hour {
		return from, to, errors.New("window exceeds the " + strconv.Itoa(maxDays) + "-day backfill cap")
	}
	return from, to, nil
}

// serveSelectorBackfill handles POST /api/services/{id}/selectors/{version}/backfill.
func (s *server) serveSelectorBackfill(w http.ResponseWriter, r *http.Request, serviceID, versionS string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelAdmin)
	if !ok {
		return
	}
	version, err := strconv.Atoi(versionS)
	if err != nil || version < 1 {
		writeError(w, http.StatusBadRequest, errors.New("invalid selector version"))
		return
	}
	maxDays, _ := strconv.Atoi(envOr("SVC_BACKFILL_MAX_DAYS", strconv.Itoa(svcBackfillDefaultMaxDays)))
	if maxDays < 1 || maxDays > 366 {
		maxDays = svcBackfillDefaultMaxDays
	}
	from, to, err := svcBackfillWindow(r.URL.Query().Get("from"), r.URL.Query().Get("to"), time.Now().UTC(), maxDays)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.services == nil {
		writeError(w, http.StatusNotImplemented, errServiceStoreOff)
		return
	}
	tenant, cross := principalTenant(claims)
	// Existence + tenancy: RLS hides another tenant's service → honest 404,
	// never revealing the id exists.
	svc, found, err := s.services.GetService(r.Context(), tenant, cross, serviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	sels, err := s.services.ListSelectors(r.Context(), tenant, cross, serviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var spec map[string]any
	verFound := false
	for _, sel := range sels {
		if sel.Version == version {
			spec, verFound = sel.Spec, true
			break
		}
	}
	if !verFound {
		writeError(w, http.StatusNotFound, errors.New("selector version not found"))
		return
	}
	if _, usable := buildSelectorCondition(spec); !usable {
		writeError(w, http.StatusBadRequest, errors.New("selector version has no usable predicate — nothing to attribute"))
		return
	}
	select {
	case svcBackfillSlots <- struct{}{}:
	default:
		writeError(w, http.StatusConflict, errors.New("too many backfills in flight — retry later"))
		return
	}

	// Audit the invocation explicitly (beyond the generic mutating-request
	// middleware): who reclassified what window under which version.
	if s.audit != nil {
		s.audit.Record(AuditEvent{
			Actor: claims.Sub, Tenant: tenant, Cross: cross,
			Method: r.Method, Path: r.URL.Path, Status: http.StatusAccepted, Decision: "allow",
			Detail: map[string]any{
				"action": "selector_backfill", "service_id": serviceID, "selector_version": version,
				"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339),
			},
		})
	}

	// Tenant stamping comes from the SERVICE ROW (never the request); the scan
	// bound uses the owning tenant's own devices, exactly like the live roller.
	set := svcSelectorSet{TenantID: svc.TenantID, ServiceID: serviceID, Version: version, Spec: spec}
	clause := ""
	if c, empty := s.addrTenantClauseFor(jwtClaims{Sub: "svc-backfill", Role: RoleOperator, Tenant: svc.TenantID}, "src_addr", "dst_addr"); !empty {
		clause = c
	}
	chunks := 0
	for t := from; t.Before(to); t = t.Add(svcBackfillChunk) {
		chunks++
	}
	go s.runSelectorBackfill(set, from, to, clause) // #nosec G118 -- deliberately detached: 202-Accepted background job must outlive the request; bounded by svcBackfillSlots

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "started", "service_id": serviceID, "selector_version": version,
		"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "chunks": chunks,
	})
}

// runSelectorBackfill executes the chunked inserts in the background. Errors
// abort the remaining window (a re-run would double-count already-inserted
// chunks in SummingMergeTree) and are logged loudly with the resume point —
// the operator re-invokes the endpoint from there; each chunk is one atomic
// statement, so the boundary is clean.
func (s *server) runSelectorBackfill(set svcSelectorSet, from, to time.Time, addrClause string) {
	defer func() { <-svcBackfillSlots }()
	ctx, cancel := context.WithTimeout(context.Background(), svcBackfillOverallTimeout)
	defer cancel()
	for start := from; start.Before(to); start = start.Add(svcBackfillChunk) {
		end := start.Add(svcBackfillChunk)
		if end.After(to) {
			end = to
		}
		// svcRollupInsertSQL's window is inclusive of the last minute bucket.
		sql, n := svcRollupInsertSQL(set.TenantID, []svcSelectorSet{set}, start, end.Add(-time.Minute), addrClause, "backfill")
		if n == 0 {
			log.Printf("svc-backfill: service %s v%d: selector yielded no predicate mid-run — aborting", set.ServiceID, set.Version)
			return
		}
		qctx, qcancel := context.WithTimeout(ctx, svcBackfillChunkTimeout)
		err := chScopedExec(qctx, set.TenantID, sql)
		qcancel()
		if err != nil {
			log.Printf("svc-backfill: service %s v%d failed at chunk %s (done %s..%s): %v — re-invoke with from=%s to resume",
				set.ServiceID, set.Version, start.Format(time.RFC3339), from.Format(time.RFC3339), start.Format(time.RFC3339), err, start.Format(time.RFC3339))
			return
		}
	}
	log.Printf("svc-backfill: service %s v%d complete (%s..%s)", set.ServiceID, set.Version, from.Format(time.RFC3339), to.Format(time.RFC3339))
}

// svcRollupLatestVersionSQL is the sanctioned latest-version-wins read over the
// rollup: per minute, sum each selector_version's rows (SummingMergeTree parts
// may be pre-merge), then keep the highest version's total. serviceID must be
// isUUIDToken-validated and tenantID store-sourced. FORMAT JSON appended by
// the caller's helper.
func svcRollupLatestVersionSQL(tenantID, serviceID string, since time.Time) string {
	return `SELECT toUnixTimestamp(minute) AS minute_ts, argMax(b, selector_version) AS bytes, argMax(f, selector_version) AS flows FROM (
  SELECT minute, selector_version, sum(bytes) AS b, sum(flows) AS f
    FROM netops.svc_flow_rollup_1m
   WHERE service_id = toUUID(` + sqlStringLiteral(serviceID) + `)
     AND tenant_id = ` + sqlStringLiteral(tenantID) + `
     AND minute >= toDateTime(` + strconv.FormatInt(since.Unix(), 10) + `)
   GROUP BY minute, selector_version)
GROUP BY minute ORDER BY minute_ts FORMAT JSON`
}
