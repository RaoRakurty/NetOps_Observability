package main

// Correlations inspector API (#67 build ⑦ follow-up) — the first owner-facing
// surface for Correlation Engine v2 objects. Read-only: the engine owns the
// object lifecycle; these handlers only render what ClickHouse holds, plus a
// replay proxy to the correlation service (design §5: the Go API fronts the
// internal replay endpoint with authz).
//
//   GET /api/correlations              latest version of every object
//   GET /api/correlations/{id}         one object + its edges (latest version)
//   GET /api/correlations/{id}/replay  drift report from the correlation service
//
// Tenant isolation is enforced by the ClickHouse row policies via the
// tenant_scope setting (proxyClickHouse/chTenantScope), same as flows/findings.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// chRows runs one tenant-scoped ClickHouse query and returns the parsed JSON
// rows — the composable sibling of proxyClickHouse for handlers that combine
// multiple result sets into one response. The scope is derived from the request
// principal (chTenantScope); chRowsScope is the request-free form background jobs
// (the auto-ticketing sweeper, #78 P3) use with an explicit scope.
func (s *server) chRows(r *http.Request, sql string) ([]map[string]any, error) {
	return s.chRowsScope(r.Context(), chTenantScope(r), sql, "api:"+r.URL.Path)
}

// chRowsScope runs one ClickHouse query at an explicit tenant_scope ("__all__"
// for cross-tenant background jobs, a tenant id for one tenant, "__none__" to
// see nothing). The row policies enforce isolation server-side regardless of the
// caller's SQL — same defense-in-depth as chRows. The optional trailing comment
// stamps system.query_log.log_comment for per-caller read-budget attribution
// (#100); callers that pass nothing are tagged as generic background work.
func (s *server) chRowsScope(ctx context.Context, scope, sql string, comment ...string) ([]map[string]any, error) {
	return chSelect(ctx, scope, sql, comment...)
}

// chSelect is the request-free, server-free form of the same tenant-scoped read —
// the one stores (which hold no *server) use. chRowsScope delegates to it, so there
// is exactly ONE ClickHouse read path carrying tenant_scope, log_comment and the
// #101 workload profile.
func chSelect(ctx context.Context, scope, sql string, comment ...string) ([]map[string]any, error) {
	base := envOr("CLICKHOUSE_URL", "http://clickhouse:8123")
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("tenant_scope", scope)
	tag := "worker:generic"
	if len(comment) > 0 && comment[0] != "" {
		tag = comment[0]
	}
	q.Set("log_comment", tag)
	// #101 workload fairness: same profile routing as proxyClickHouse.
	if p := chWorkloadProfile(tag); p != "" {
		q.Set("profile", p)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader([]byte(sql)))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(envOr("CLICKHOUSE_USER", "netops"), envOr("CLICKHOUSE_PASSWORD", ""))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := backendHTTPClient(20 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickhouse: %s", strings.TrimSpace(string(body)))
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// isUUIDToken allowlists a canonical UUID string before it is interpolated
// into ClickHouse SQL or a proxied URL (SR-011 discipline: shape-validate,
// never quote-escape).
func isUUIDToken(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			default:
				return false
			}
		}
	}
	return true
}

func (s *server) handleCorrelations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	limit := intQuery(r, "limit", 100, 1, 500)
	since := durationQuery(r, "since", 24*time.Hour)
	// The created_at bound prunes the base-table scan BEFORE the latest-version
	// fold; state/tier apply AFTER it (they describe the latest version, and
	// pushing them into the base scan would surface a stale version whose state
	// happens to match). Equivalent to filtering corr_objects_latest: versions
	// are append-only in time, so the max-created_at row in the window IS the
	// object's latest version, and an object whose latest version predates the
	// window has no in-window rows at all.
	sinceCond := "created_at >= now() - INTERVAL " + intToString(int(since.Seconds())) + " SECOND"
	latestConds := []string{"1"}
	if st := strings.TrimSpace(r.URL.Query().Get("state")); st != "" {
		if !isAlphaToken(st) {
			writeError(w, http.StatusBadRequest, errors.New("invalid state"))
			return
		}
		latestConds = append(latestConds, "state = '"+st+"'")
	}
	if tier := strings.TrimSpace(r.URL.Query().Get("tier")); tier != "" {
		if !isAlphaToken(tier) {
			writeError(w, http.StatusBadRequest, errors.New("invalid tier"))
			return
		}
		latestConds = append(latestConds, "verdict_tier = '"+tier+"'")
	}
	// Keyset pagination (owner directive: DON'T HIDE — a capped list must offer
	// the rest). The cursor is the house (ts DESC, id DESC) keyset over
	// (created_at, correlation_id), same wire form as the events feed cursor.
	// An invalid cursor is ignored (first page) — fail-open to page 1, never 500.
	if cur := strings.TrimSpace(r.URL.Query().Get("cursor")); cur != "" {
		if ms, cid, ok := decodeFeedCursor(cur); ok {
			ets := time.UnixMilli(ms).UTC().Format("2006-01-02 15:04:05.000")
			latestConds = append(latestConds,
				"(created_at < '"+ets+"' OR (created_at = '"+ets+"' AND toString(correlation_id) < '"+cid+"'))")
		}
	}
	// Triage enrichment (left-table badges): edge count + grounding kinds from
	// corr_edges; the top hypothesis's verdict coverage (planes / owner /
	// low-authority / debug-excluded) comes from the projection's narrow badge
	// columns, written by the engine at persist time. All read-only.
	rows, err := s.chRows(r, correlationsListSQL(sinceCond, latestConds, limit))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// next_cursor only on a FULL page (house style, cloud_signals.go): a short
	// page IS the end of the window — never dangle a cursor that returns nothing.
	next := ""
	if len(rows) == limit {
		last := rows[len(rows)-1]
		ms, _ := strconv.ParseInt(fmt.Sprintf("%v", last["created_at_ms"]), 10, 64)
		if cid := fmt.Sprintf("%v", last["correlation_id"]); ms > 0 && isUUIDToken(cid) {
			next = encodeFeedCursor(ms, cid)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows, "next_cursor": next})
}

// correlationsListSQL builds the Command Center correlation list query. Pure so
// bounded_io_test.go can assert its shape stays within the #100 budget rules.
//
// Bounded read (2026-07-09 incident): the edges aggregation is scoped to the
// picked objects — the previous shape GROUP BY'd the ENTIRE corr_edges table
// (771k rows, ~1.5 GiB hash of groupUniqArray strings) to decorate ≤limit
// rows, and concurrent Command Center polls pinned ClickHouse.
//
// Narrow pick (#100 hardening): the whole page is served from the corr_current
// HOT projection — one narrow row per object, O(active objects) not O(history),
// triage badges included as narrow columns so the ~5.7KB hypotheses blob is
// NEVER read here (JSONExtract'ing it keyed still dragged ~1.3 GiB of blob
// granules per page at storm size — measured over the 100 MiB endpoint
// budget). The only history touch is app_impact, a tiny (~84B avg) column
// fetched keyed by the picked (id, version) pairs. FINAL is cheap by
// construction (the projection holds only current state); ANY LEFT JOIN
// guards the app_impact fetch against duplicate (id, version) history rows
// (engine restarts reset the in-memory version counter, so v1 can exist twice).
func correlationsListSQL(sinceCond string, latestConds []string, limit int) string {
	return `
WITH picked AS (
     SELECT correlation_id, version, created_at
       FROM netops.corr_current FINAL
      WHERE ` + sinceCond + `
        AND ` + strings.Join(latestConds, " AND ") + `
      ORDER BY created_at DESC, correlation_id DESC
      LIMIT ` + intToString(limit) + `
)
SELECT toString(c.correlation_id)  AS correlation_id,
       c.version                    AS version,
       c.state                      AS state,
       ` + chISO("c.window_start") + ` AS window_start,
       ` + chISO("c.window_end") + `   AS window_end,
       c.top_hypothesis             AS top_hypothesis,
       c.top_confidence             AS top_confidence,
       c.verdict_tier               AS verdict_tier,
       c.evidence_missing           AS evidence_missing,
       c.affected                   AS affected,
       coalesce(a.app_impact, '{}') AS app_impact,
       c.signal_count               AS signal_count,
       c.node_count                 AS node_count,
       c.engine_version             AS engine_version,
       c.catalog_version            AS catalog_version,
       ` + chISO("c.created_at") + ` AS created_at,
       toUnixTimestamp64Milli(c.created_at) AS created_at_ms,
       coalesce(e.edge_count, 0)    AS edge_count,
       coalesce(e.grounding, 'none') AS grounding,
       c.plane_count                AS plane_count,
       c.owner                      AS owner,
       c.debug_excluded > 0         AS debug_excluded,
       c.low_authority > 0          AS low_authority,
       c.chaos_fixture              AS chaos_fixture
  FROM netops.corr_current AS c FINAL
  LEFT JOIN (
       SELECT correlation_id, version, count() AS edge_count,
              arrayStringConcat(arraySort(groupUniqArray(grounding_kind)), '+') AS grounding
         FROM netops.corr_edges
        WHERE (correlation_id, version) IN (SELECT correlation_id, version FROM picked)
        GROUP BY correlation_id, version
  ) AS e ON e.correlation_id = c.correlation_id AND e.version = c.version
  ANY LEFT JOIN (
       SELECT correlation_id, version, app_impact
         FROM netops.corr_objects
        WHERE ` + sinceCond + `
          AND (correlation_id, version) IN (SELECT correlation_id, version FROM picked)
  ) AS a ON a.correlation_id = c.correlation_id AND a.version = c.version
 WHERE (c.correlation_id, c.version) IN (SELECT correlation_id, version FROM picked)
 ORDER BY c.created_at DESC, c.correlation_id DESC
 FORMAT JSON`
	// NOTE: ORDER BY must qualify c.created_at — the SELECT aliases
	// toString(c.created_at) AS created_at, and a bare created_at would hit
	// the String alias, ordering lexically instead of temporally.
}

// handleCorrelationStats serves GET /api/correlations/stats — the cheap CH
// aggregates behind the Front Page "RCA coverage" panel (#69 panel 5). Honest by
// construction: a low actionable/confirmed ratio is *displayed*, that's the point.
// Tenant-scoped by the corr_objects row policy (chTenantScope). One row, one query:
// the open-object counts span ALL open objects (an open issue may be old), while
// the window counts (confirmed/total/signatures) are bounded inside countIf so the
// two views don't fight over a single WHERE clause.
func (s *server) handleCorrelationStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	since := durationQuery(r, "since", 7*24*time.Hour)
	win := intToString(int(since.Seconds()))
	sql := `
SELECT countIf(state='open')                                          AS open,
       countIf(state='open' AND verdict_tier='confirmed')             AS open_confirmed,
       countIf(state='open' AND verdict_tier='suspected')             AS open_suspected,
       countIf(state='open' AND verdict_tier='undetermined')          AS open_undetermined,
       countIf(state='open' AND top_confidence >= 0.5)                AS open_actionable,
       countIf(created_at >= now() - INTERVAL ` + win + ` SECOND)                              AS total_window,
       countIf(created_at >= now() - INTERVAL ` + win + ` SECOND AND verdict_tier='confirmed') AS confirmed_window,
       uniqExactIf(top_hypothesis, top_hypothesis != 'undetermined'
                   AND created_at >= now() - INTERVAL ` + win + ` SECOND)                       AS signatures_seen
  FROM netops.corr_current FINAL
 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	row := map[string]any{}
	if len(rows) > 0 {
		row = rows[0]
	}
	num := func(k string) float64 {
		switch v := row[k].(type) {
		case float64:
			return v
		case string:
			f, _ := strconv.ParseFloat(v, 64)
			return f
		}
		return 0
	}
	open := num("open")
	totalWin := num("total_window")
	pct := func(n, d float64) float64 {
		if d <= 0 {
			return 0
		}
		return (n / d) * 100
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"open":               open,
		"open_confirmed":     num("open_confirmed"),
		"open_suspected":     num("open_suspected"),
		"open_undetermined":  num("open_undetermined"),
		"actionable_pct":     pct(num("open_actionable"), open),
		"confirmed_7d_pct":   pct(num("confirmed_window"), totalWin),
		"total_window":       totalWin,
		"signatures_matched": num("signatures_seen"),
		"window_days":        int(since.Hours() / 24),
	})
}

// correlationsSummarySQL builds the tenant-scoped window rollup behind the
// Correlations page stat-chip row: REAL COUNTs over corr_current (never the
// capped list length) — total in window, split by verdict tier and by state.
// state='merged' rows are engine tombstones (an ongoing condition re-detected
// and folded into its open object, #111) — NOT candidates. They are excluded
// from total/tier/closed and disclosed separately as `merged` (don't-hide:
// the page shows "N merged duplicates" instead of silently dropping them).
// Pure so its bounded shape is unit-testable. extraConds are pre-validated
// (allowlisted) filter clauses; pass nil for the unfiltered rollup.
func correlationsSummarySQL(sinceCond string, extraConds []string) string {
	conds := append([]string{sinceCond}, extraConds...)
	return `
SELECT countIf(state != 'merged')                                     AS total,
       countIf(verdict_tier = 'confirmed' AND state != 'merged')      AS confirmed,
       countIf(verdict_tier = 'suspected' AND state != 'merged')      AS suspected,
       countIf(verdict_tier = 'undetermined' AND state != 'merged')   AS undetermined,
       countIf(state = 'open')                                        AS open,
       countIf(state NOT IN ('open', 'merged'))                       AS closed,
       countIf(state = 'merged')                                      AS merged
  FROM netops.corr_current FINAL
 WHERE ` + strings.Join(conds, " AND ") + `
 FORMAT JSON`
}

// handleCorrelationsSummary serves GET /api/correlations/summary — the honest
// companion to the capped /api/correlations list (owner directive: the page must
// show how many objects EXIST, not how many one page holds). Same bounded window
// + optional state filter as the list; tenant isolation via the corr_current row
// policy (chRows → chTenantScope), identical to every other correlations read.
func (s *server) handleCorrelationsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	since := durationQuery(r, "since", 24*time.Hour)
	sinceCond := "created_at >= now() - INTERVAL " + intToString(int(since.Seconds())) + " SECOND"
	var extra []string
	if st := strings.TrimSpace(r.URL.Query().Get("state")); st != "" {
		if !isAlphaToken(st) {
			writeError(w, http.StatusBadRequest, errors.New("invalid state"))
			return
		}
		extra = append(extra, "state = '"+st+"'")
	}
	rows, err := s.chRows(r, correlationsSummarySQL(sinceCond, extra))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	row := map[string]any{}
	if len(rows) > 0 {
		row = rows[0]
	}
	num := func(k string) int64 {
		switch v := row[k].(type) {
		case float64:
			return int64(v)
		case string:
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
		return 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":          num("total"),
		"confirmed":      num("confirmed"),
		"suspected":      num("suspected"),
		"undetermined":   num("undetermined"),
		"open":           num("open"),
		"closed":         num("closed"),
		"merged":         num("merged"),
		"window_seconds": int(since.Seconds()),
	})
}

// handleCorrelationByID serves GET /api/correlations/{id} (object + edges) and
// GET /api/correlations/{id}/replay (drift report, proxied).
func (s *server) handleCorrelationByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/correlations/")
	id, sub, _ := strings.Cut(rest, "/")
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid correlation id"))
		return
	}
	// Manual lifecycle-event writes (#84 P1d) — POST/DELETE, own auth (write) + audit.
	if sub == "time-events" || strings.HasPrefix(sub, "time-events/") {
		s.handleCorrelationTimeEvents(w, r, id, strings.TrimPrefix(strings.TrimPrefix(sub, "time-events"), "/"))
		return
	}
	// RCA auto-ticketing subresources (#78 P3) — GET tickets, POST ticket[/sync],
	// own auth (read/write) inside the handler since they mix GET + POST.
	if sub == "tickets" || sub == "ticket" || sub == "ticket/sync" {
		s.handleCorrelationTickets(w, r, id, sub)
		return
	}
	// RCA-document promotion (#113 point 3) — GET status / POST promote /
	// DELETE revoke; own auth (read/write) + audit inside the handler.
	if sub == "rca-promotion" {
		s.handleRcaPromotion(w, r, id)
		return
	}
	// Postmortem action items (Phase 1, spec §3/§7) — tenant-scoped register;
	// own auth (read/write) + audit inside the handler (mixed methods).
	if sub == "actions" || strings.HasPrefix(sub, "actions/") {
		s.handleRcaActionItems(w, r, id, strings.TrimPrefix(strings.TrimPrefix(sub, "actions"), "/"))
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	switch sub {
	case "":
		s.serveCorrelationDetail(w, r, id)
	case "timeline":
		s.serveCorrelationTimeline(w, r, id)
	case "rca-path-view":
		s.serveRcaPathView(w, r, id)
	case "rca-report":
		s.serveRcaReport(w, r, id)
	case "time-metrics":
		s.serveCorrelationTimeMetrics(w, r, id)
	case "replay":
		s.proxyCorrelationReplay(w, r, id)
	default:
		writeError(w, http.StatusNotFound, errors.New("unknown subresource"))
	}
}

// isDatetimeToken allowlists a ClickHouse DateTime64 string ("2026-06-14
// 05:11:39.836") before interpolation — these come from our own DB, but
// shape-validate per SR-011 rather than quote-escape.
func isDatetimeToken(s string) bool {
	if len(s) < 10 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c == '-', c == ':', c == '.', c == ' ', c == 'T', c == 'Z':
		default:
			return false
		}
	}
	return true
}

// serveCorrelationTimeline renders the RCA Inspector's primary view: the FULL
// window slice of signals for one object (corr_signals_archive — every signal in
// the window, attached or not), each enriched with its evidence role(s) from
// corr_evidence so the UI can answer "what happened first/next, which planes
// agree, which signals contradict, what the engine attached vs ignored, how
// certain the timing is". Read-only; the engine owns all of this.
//
// Bounded scan: corr_signals_archive is ordered by (tenant_id, ts, signal_id),
// so the query is constrained to the object's [window_start, window_end] (the
// order key) AND archived_for/version — never a full-table scan.
func (s *server) serveCorrelationTimeline(w http.ResponseWriter, r *http.Request, id string) {
	version := intQuery(r, "version", 0, 0, 1<<30)
	meta, sigRows, evRows, edgeRows, status, err := s.loadCorrSlice(r.Context(), chTenantScope(r), id, version)
	if err != nil {
		writeError(w, status, err)
		return
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	counts := mergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)

	writeJSON(w, http.StatusOK, map[string]any{
		"correlation_id":   id,
		"version":          meta["version"],
		"window_start":     meta["window_start"],
		"window_end":       meta["window_end"],
		"trigger_signal":   trigger,
		"verdict_tier":     meta["verdict_tier"],
		"top_hypothesis":   meta["top_hypothesis"],
		"top_confidence":   meta["top_confidence"],
		"evidence_missing": meta["evidence_missing"],
		"signals":          sigRows,
		"evidence":         evRows,
		"edges":            edgeRows,
		"counts":           counts,
		// Service Path Graph (frozen contract §7): the ORDERED spine for this object,
		// computed SERVER-SIDE. The renderer lays this out; it never derives hop order
		// from entity_id strings or node degree again. nil/spine_available=false is an
		// honest "no measured path for this object" — the UI says so, it does not
		// invent a star.
		"path": s.rcaPathBlock(r.Context(), r, id, fmt.Sprintf("%v", meta["verdict_tier"]), fmt.Sprintf("%v", meta["top_hypothesis"])),
	})
}

// loadCorrSlice loads one correlation object's window slice — meta (version,
// window, verdict, trigger, missing-evidence), the full archived signal slice,
// the evidence rows, and the edges of that version. Shared by the timeline and
// rca-path-view endpoints so the (bounded, RLS-scoped) read SQL lives once.
// Returns an HTTP status + error for the caller to surface.
func (s *server) loadCorrSlice(ctx context.Context, scope, id string, version int) (map[string]any, []map[string]any, []map[string]any, []map[string]any, int, error) {
	verCond := ""
	if version > 0 {
		verCond = " AND version = " + intToString(version)
	}
	// 1) Object meta: version + window bounds + verdict + missing evidence + trigger.
	metaSQL := `
SELECT version, tenant_id, state,
       coalesce(toString(merged_into), '') AS merged_into,
       ` + chISO("window_start") + ` AS window_start,
       ` + chISO("window_end") + `   AS window_end,
       toString(trigger_signal) AS trigger_signal,
       verdict_tier, top_hypothesis, top_confidence, evidence_missing,
       hypotheses, affected, layer_coverage, app_impact, attribution
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'` + verCond + `
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	metaRows, err := s.chRowsScope(ctx, scope, metaSQL)
	if err != nil {
		return nil, nil, nil, nil, http.StatusBadGateway, err
	}
	if len(metaRows) == 0 {
		return nil, nil, nil, nil, http.StatusNotFound, errors.New("correlation object not found")
	}
	meta := metaRows[0]
	ver := fmt.Sprintf("%v", meta["version"])
	ws, _ := meta["window_start"].(string)
	we, _ := meta["window_end"].(string)
	if !isDatetimeToken(ws) || !isDatetimeToken(we) {
		return nil, nil, nil, nil, http.StatusBadGateway, errors.New("malformed object window")
	}
	// The window bounds arrive RFC 3339 UTC on the wire (chISO, S3); re-render
	// them as ClickHouse-native zone-less UTC literals for the range filter
	// below — the `ts` there must stay the raw DateTime column (pruning + no
	// dependence on how CH resolves alias-vs-column in WHERE).
	wsT, weT := parseCHTime(ws), parseCHTime(we)
	if wsT.IsZero() || weT.IsZero() {
		return nil, nil, nil, nil, http.StatusBadGateway, errors.New("malformed object window")
	}
	wsQ := wsT.UTC().Format("2006-01-02 15:04:05.000")
	weQ := weT.UTC().Format("2006-01-02 15:04:05.000")

	// 1b) Resolve the archive slice version. The object's `version` increments on
	// every persist, but each window slice is archived under its own
	// `archived_version` — the two are NOT 1:1 (the object can be a version ahead
	// of its latest archived slice, and legacy rows carry version 0). Use the
	// greatest archived_version for this object (≤ the requested object version),
	// i.e. the most recent complete slice — never an empty exact-match.
	avCond := ""
	if version > 0 {
		avCond = " AND archived_version <= " + intToString(version)
	}
	avSQL := `SELECT max(archived_version) AS av FROM netops.corr_signals_archive
 WHERE archived_for = '` + id + `'` + avCond + ` FORMAT JSON`
	avRows, err := s.chRowsScope(ctx, scope, avSQL)
	if err != nil {
		return nil, nil, nil, nil, http.StatusBadGateway, err
	}
	// Numeric, not toString(): a function wrapped around the column defeats
	// granule pruning and forces evaluating every row the archived_for index
	// let through (2026-07-09 read-path incident).
	archiveVer := 0
	if len(avRows) > 0 && avRows[0]["av"] != nil {
		switch v := avRows[0]["av"].(type) {
		case float64:
			archiveVer = int(v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				archiveVer = n
			}
		}
	}

	// 2) Full window slice (attached or not), ordered by event time = the cascade.
	sigSQL := `
SELECT toString(signal_id)  AS signal_id,
       ` + chISO("ts") + `         AS ts_iso,
       ` + chISO("ingest_ts") + `  AS ingest_ts_iso,
       source, kind, observer_type, observer_id, collection_path, modality_class,
       source_clock_quality AS clock_quality,
       entity_type, entity_id, entity_tokens, severity,
       value, baseline, deviation, metric_name, attrs,
       JSONExtractFloat(attrs, 'onset_uncertainty_s') AS onset_uncertainty_s,
       JSONExtractString(attrs, 'phase')              AS phase,
       JSONExtractString(attrs, 'clear_ts')           AS clear_ts,
       JSONExtractString(attrs, 'probe_scope')        AS probe_scope,
       JSONExtractString(attrs, 'probe_authority')    AS probe_authority,
       JSONExtractString(attrs, 'classification_source') AS classification_source
  FROM netops.corr_signals_archive
 WHERE archived_for = '` + id + `' AND archived_version = ` + intToString(archiveVer) + `
   AND ts >= '` + wsQ + `' AND ts <= '` + weQ + `'
 ORDER BY ts ASC, signal_id ASC
 FORMAT JSON`
	sigRows, err := s.chRowsScope(ctx, scope, sigSQL)
	if err != nil {
		return nil, nil, nil, nil, http.StatusBadGateway, err
	}
	// De-shadowed aliases (see the SELECT): expose them under their wire names.
	// Conditional so stores that already return `ts` directly stay untouched.
	for _, row := range sigRows {
		if v, ok := row["ts_iso"]; ok {
			row["ts"] = v
			delete(row, "ts_iso")
		}
		if v, ok := row["ingest_ts_iso"]; ok {
			row["ingest_ts"] = v
			delete(row, "ingest_ts_iso")
		}
	}

	// 3) Evidence rows for this version (signal → role/subject); joined in Go so
	//    every signal carries an authoritative attached flag + its role(s).
	evSQL := `
SELECT toString(signal_id) AS signal_id, subject_kind, subject_id, role, note
  FROM netops.corr_evidence
 WHERE correlation_id = '` + id + `' AND toString(version) = '` + ver + `'
 FORMAT JSON`
	evRows, err := s.chRowsScope(ctx, scope, evSQL)
	if err != nil {
		return nil, nil, nil, nil, http.StatusBadGateway, err
	}

	// 4) Edges of this exact version — the authoritative graph membership. A
	//    signal is "attached" iff its episode (entity_type:entity_id:kind) is a
	//    node on an edge; the engine writes evidence only at the edge level, so
	//    per-signal linkage is DERIVED here at read time (no engine change).
	edgeSQL := `
SELECT from_node, to_node, grounding_kind, grounding_ref,
       round(weight,4) AS weight, direction_conf, direction_basis
  FROM netops.corr_edges
 WHERE correlation_id = '` + id + `' AND toString(version) = '` + ver + `'
 ORDER BY from_node, to_node
 FORMAT JSON`
	edgeRows, err := s.chRowsScope(ctx, scope, edgeSQL)
	if err != nil {
		return nil, nil, nil, nil, http.StatusBadGateway, err
	}
	// normalize the window strings onto meta so callers don't re-cast.
	meta["window_start"] = ws
	meta["window_end"] = we
	return meta, sigRows, evRows, edgeRows, http.StatusOK, nil
}

// signalNodeKey reconstructs the engine's graph-node key for a signal exactly as
// build_nodes() does in engine.py: entity_type:entity_id:kind. Faithful because
// the archive stores the same entity_type enum value the engine used.
func signalNodeKey(sig map[string]any) string {
	return fmt.Sprintf("%v:%v:%v", sig["entity_type"], sig["entity_id"], sig["kind"])
}

// groundingTokens mirrors engine.py Node.tokens(): the identity tokens the
// grounding gate intersects to admit an edge — entity_id, declared entity_tokens,
// the device part of a 'device:iface' id, and the endpoints of an 'a->b' path id.
// Used here ONLY to EXPLAIN (read-side) why a concurrent signal did or didn't
// share grounding with the graph — never to admit edges.
func groundingTokens(sig map[string]any) map[string]bool {
	toks := map[string]bool{}
	id := fmt.Sprintf("%v", sig["entity_id"])
	if id != "" {
		toks[id] = true
	}
	switch et := sig["entity_tokens"].(type) {
	case []any:
		for _, t := range et {
			toks[fmt.Sprintf("%v", t)] = true
		}
	case []string:
		for _, t := range et {
			toks[t] = true
		}
	}
	if i := strings.Index(id, ":"); i > 0 {
		toks[id[:i]] = true
	}
	if strings.Contains(id, "->") {
		for _, p := range strings.Split(id, "->") {
			if p != "" {
				toks[p] = true
			}
		}
	}
	return toks
}

// missingOrUnknownIdentity flags a signal the engine could never ground because
// its entity is absent or unresolved (it can't share a token with anything).
func missingOrUnknownIdentity(id string) bool {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "", "unknown", "-", "none", "null":
		return true
	}
	return false
}

var _roleWord = map[string]string{
	"supports": "supporting", "contradicts": "contradicting", "discriminates": "discriminating",
}
var _roleRank = map[string]int{"supports": 1, "discriminates": 2, "contradicts": 3}

// mergeTimelineEvidence enriches the window signal slice IN PLACE with each
// signal's authoritative linkage to the object's causal graph, and returns the
// count rollup the Inspector summary uses. The engine records evidence only at
// the EDGE level, so per-signal linkage is DERIVED here at read time from the
// graph membership — it reports the engine's recorded reasoning, it never
// re-decides causality:
//
//   - attached  → the signal's episode is a node on ≥1 edge (or the singleton
//     trigger episode). Carries link_role (supporting/contradicting/
//     discriminating, from edge evidence) + the grounded edges it sits on.
//   - recovery  → a *_clear event; build_nodes() drops clears, so they are never
//     causal nodes (link_reason states exactly that).
//   - malformed → entity identity missing/unknown; can share no grounding token.
//   - unlinked  → concurrent-not-linked. link_reason distinguishes "shares a
//     topology/seam token but no edge met threshold" from "no shared token at
//     all" (faithful to the grounding gate; this is read-side explanation only).
//
// Pure (no I/O) so the join is unit-tested independently of ClickHouse.
func mergeTimelineEvidence(sigRows, evRows, edgeRows []map[string]any, trigger string) map[string]any {
	// Signal-level evidence (currently engine writes none; kept for forward-compat).
	evBySignal := map[string][]map[string]any{}
	byRole := map[string]int{}
	for _, e := range evRows {
		sid := fmt.Sprintf("%v", e["signal_id"])
		evBySignal[sid] = append(evBySignal[sid], e)
		byRole[fmt.Sprintf("%v", e["role"])]++
	}

	// Edge-evidence role per edge (subject_id = "from->to"). The engine emits only
	// 'supports' today; contradicting/discriminating light up automatically here
	// if it ever records them, with no UI change.
	edgeRoleBySubject := map[string]string{}
	for _, e := range evRows {
		if fmt.Sprintf("%v", e["subject_kind"]) == "edge" {
			edgeRoleBySubject[fmt.Sprintf("%v", e["subject_id"])] = fmt.Sprintf("%v", e["role"])
		}
	}

	// Graph membership: node keys on an edge, the grounded edges per node, the
	// grounding-kind rollup, and the strongest evidence role touching each node.
	attachedNodes := map[string]bool{}
	edgesByNode := map[string][]map[string]any{}
	roleByNode := map[string]string{}
	byGrounding := map[string]int{}
	for _, e := range edgeRows {
		from := fmt.Sprintf("%v", e["from_node"])
		to := fmt.Sprintf("%v", e["to_node"])
		attachedNodes[from] = true
		attachedNodes[to] = true
		byGrounding[fmt.Sprintf("%v", e["grounding_kind"])]++
		role := edgeRoleBySubject[from+"->"+to]
		if role == "" {
			role = "supports"
		}
		for _, n := range []string{from, to} {
			if _roleRank[role] > _roleRank[roleByNode[n]] {
				roleByNode[n] = role
			}
		}
		base := map[string]any{
			"grounding_kind": e["grounding_kind"], "grounding_ref": e["grounding_ref"],
			"weight": e["weight"], "direction_basis": e["direction_basis"],
		}
		fwd := map[string]any{"peer": to}
		rev := map[string]any{"peer": from}
		for k, v := range base {
			fwd[k] = v
			rev[k] = v
		}
		edgesByNode[from] = append(edgesByNode[from], fwd)
		edgesByNode[to] = append(edgesByNode[to], rev)
	}
	// A singleton object has 0 edges; its one episode is still "attached" (it IS
	// the object). Promote the trigger signal's node key so its signals render
	// linked rather than orphaned.
	for _, sig := range sigRows {
		if fmt.Sprintf("%v", sig["signal_id"]) == trigger {
			attachedNodes[signalNodeKey(sig)] = true
			break
		}
	}

	// Pass 1: tokens of the graph (the attached episodes), so a concurrent signal
	// can be told "shares a token with the graph but no edge met threshold" vs
	// "no shared seam/topology token at all" — faithful to the grounding gate.
	graphTokens := map[string]bool{}
	for _, sig := range sigRows {
		if attachedNodes[signalNodeKey(sig)] {
			for t := range groundingTokens(sig) {
				graphTokens[t] = true
			}
		}
	}

	byModality := map[string]int{}
	attachedByModality := map[string]int{}
	attachedObservers := map[string]bool{}
	byStatus := map[string]int{}
	attached, recovery, unlinked := 0, 0, 0
	for _, sig := range sigRows {
		sid := fmt.Sprintf("%v", sig["signal_id"])
		kind := fmt.Sprintf("%v", sig["kind"])
		modality := fmt.Sprintf("%v", sig["modality_class"])
		entityID := fmt.Sprintf("%v", sig["entity_id"])
		nodeKey := signalNodeKey(sig)
		sig["evidence"] = evBySignal[sid] // nil → null
		sig["is_trigger"] = sid == trigger
		sig["linked_edges"] = nil
		sig["link_role"] = ""
		byModality[modality]++

		switch {
		case attachedNodes[nodeKey]:
			links := edgesByNode[nodeKey]
			role := roleByNode[nodeKey]
			if role == "" {
				role = "supports"
			}
			sig["attached"] = true
			sig["link_status"] = "attached"
			sig["link_role"] = _roleWord[role]
			sig["linked_edges"] = links
			sig["link_reason"] = attachedReason(links)
			attached++
			attachedByModality[modality]++
			if obs := fmt.Sprintf("%v", sig["observer_id"]); obs != "" {
				attachedObservers[obs] = true
			}
			byStatus["attached/"+_roleWord[role]]++
		case strings.HasSuffix(kind, "_clear"):
			sig["attached"] = false
			sig["link_status"] = "recovery"
			sig["link_reason"] = "recovery/clear event — clears close an episode and are never causal graph nodes"
			recovery++
			byStatus["recovery"]++
		case missingOrUnknownIdentity(entityID):
			sig["attached"] = false
			sig["link_status"] = "malformed"
			sig["link_reason"] = "entity identity missing/unknown — a signal with no resolvable entity can share no seam or topology token, so the engine cannot ground it"
			unlinked++
			byStatus["malformed"]++
		default:
			sig["attached"] = false
			sig["link_status"] = "unlinked"
			if tokensIntersect(groundingTokens(sig), graphTokens) {
				sig["link_reason"] = "shares a topology/seam token with the graph, but no edge met the attach threshold — the correlation weight fell short (timing too far apart and/or single-modality, so no reinforcement)"
			} else {
				sig["link_reason"] = "no shared seam endpoint or topology token connects this episode to the object's graph — the engine counted it as a topology-gap co-occurrence, never an edge"
			}
			unlinked++
			byStatus["concurrent-not-linked"]++
		}
	}
	return map[string]any{
		"total":                len(sigRows),
		"attached":             attached,
		"unattached":           len(sigRows) - attached,
		"recovery":             recovery,
		"unlinked":             unlinked,
		"attached_observers":   len(attachedObservers),
		"by_modality":          byModality,
		"attached_by_modality": attachedByModality,
		"by_role":              byRole,
		"by_grounding":         byGrounding,
		"by_status":            byStatus,
	}
}

// tokensIntersect reports whether two token sets share any member.
func tokensIntersect(a, b map[string]bool) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for t := range a {
		if b[t] {
			return true
		}
	}
	return false
}

// attachedReason summarizes how a node is linked into the graph from the grounded
// edges it sits on — distinct grounding kinds + refs, e.g.
// "linked via seam sm-f50987032a4d, topo shared:api".
func attachedReason(links []map[string]any) string {
	if len(links) == 0 {
		return "graph node (singleton episode — opened on severity alone)"
	}
	seen := map[string]bool{}
	parts := make([]string, 0, len(links))
	for _, l := range links {
		key := fmt.Sprintf("%v %v", l["grounding_kind"], l["grounding_ref"])
		if seen[key] {
			continue
		}
		seen[key] = true
		parts = append(parts, fmt.Sprintf("%v %v", l["grounding_kind"], l["grounding_ref"]))
	}
	return "linked via " + strings.Join(parts, ", ")
}

// serveCorrelationDetail renders the object's latest version with its edges in
// one response. Two policy-scoped queries; the hypotheses JSON (ranking +
// embedded grounding context) is passed through verbatim for the UI to render.
func (s *server) serveCorrelationDetail(w http.ResponseWriter, r *http.Request, id string) {
	version := intQuery(r, "version", 0, 0, 1<<30)
	verCond := ""
	if version > 0 {
		verCond = " AND version = " + intToString(version)
	}
	objSQL := `
SELECT toString(correlation_id)  AS correlation_id,
       version, state,
       ` + chISO("window_start") + ` AS window_start,
       ` + chISO("window_end") + `   AS window_end,
       toString(trigger_signal)  AS trigger_signal,
       top_hypothesis, top_confidence, verdict_tier,
       hypotheses, evidence_missing, affected,
       signal_count, node_count,
       engine_version, topology_version, catalog_version,
       ` + chISO("created_at") + `   AS created_at
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'` + verCond + `
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	objRows, err := s.chRows(r, objSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if len(objRows) == 0 {
		writeError(w, http.StatusNotFound, errors.New("correlation object not found"))
		return
	}
	ver := fmt.Sprintf("%v", objRows[0]["version"])
	edgeSQL := `
SELECT from_node, to_node, grounding_kind, grounding_ref,
       weight, w_temporal, w_topo, w_reinforce,
       direction_conf, direction_basis
  FROM netops.corr_edges
 WHERE correlation_id = '` + id + `' AND toString(version) = '` + ver + `'
 ORDER BY from_node, to_node
 FORMAT JSON`
	edgeRows, err := s.chRows(r, edgeSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        objRows[0],
		"edges":         edgeRows,
		"ticket_status": s.ticketStatusForObject(r, id),
	})
}

// proxyCorrelationReplay fronts the correlation service's internal replay
// endpoint with platform authz. Replay re-runs the engine over the archived
// window — bounded but not free, hence the longer timeout.
func (s *server) proxyCorrelationReplay(w http.ResponseWriter, r *http.Request, id string) {
	base := envOr("CORRELATION_URL", "http://correlation:8000")
	url := strings.TrimRight(base, "/") + "/correlations/" + id + "/replay"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	client := backendHTTPClient(60 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}
