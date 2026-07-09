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
	return s.chRowsScope(r.Context(), chTenantScope(r), sql)
}

// chRowsScope runs one ClickHouse query at an explicit tenant_scope ("__all__"
// for cross-tenant background jobs, a tenant id for one tenant, "__none__" to
// see nothing). The row policies enforce isolation server-side regardless of the
// caller's SQL — same defense-in-depth as chRows.
func (s *server) chRowsScope(ctx context.Context, scope, sql string) ([]map[string]any, error) {
	base := envOr("CLICKHOUSE_URL", "http://clickhouse:8123")
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("tenant_scope", scope)
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
	// Filter in an inner query: aliasing toString(created_at) AS created_at in
	// the same SELECT would shadow the column in WHERE (String vs DateTime →
	// NO_COMMON_TYPE).
	// Triage enrichment (left-table badges): edge count + grounding kinds from
	// corr_edges, and the top hypothesis's verdict coverage (planes / owner /
	// low-authority / debug-excluded) from the embedded hypotheses JSON. All
	// read-only and derived from what the engine already persisted.
	//
	// Bounded read (2026-07-09 incident): the edges aggregation is scoped to the
	// picked objects — the previous shape GROUP BY'd the ENTIRE corr_edges table
	// (771k rows, ~1.5 GiB hash of groupUniqArray strings) to decorate ≤limit
	// rows, and concurrent Command Center polls pinned ClickHouse.
	const hp = "o.hypotheses,'ranking','hypotheses',1,'verdict'"
	sql := `
WITH picked AS (
     SELECT * FROM (
          SELECT * FROM netops.corr_objects
           WHERE ` + sinceCond + `
           ORDER BY tenant_id, correlation_id, version DESC
           LIMIT 1 BY tenant_id, correlation_id
     )
      WHERE ` + strings.Join(latestConds, " AND ") + `
      ORDER BY created_at DESC
      LIMIT ` + intToString(limit) + `
)
SELECT toString(o.correlation_id)  AS correlation_id,
       o.version                    AS version,
       o.state                      AS state,
       toString(o.window_start)     AS window_start,
       toString(o.window_end)       AS window_end,
       o.top_hypothesis             AS top_hypothesis,
       o.top_confidence             AS top_confidence,
       o.verdict_tier               AS verdict_tier,
       o.evidence_missing           AS evidence_missing,
       o.affected                   AS affected,
       o.app_impact                 AS app_impact,
       o.signal_count               AS signal_count,
       o.node_count                 AS node_count,
       o.engine_version             AS engine_version,
       o.catalog_version            AS catalog_version,
       toString(o.created_at)       AS created_at,
       coalesce(e.edge_count, 0)    AS edge_count,
       coalesce(e.grounding, 'none') AS grounding,
       length(JSONExtract(` + hp + `,'modality_coverage','Array(String)'))           AS plane_count,
       JSONExtractString(` + hp + `,'owner')                                          AS owner,
       length(JSONExtract(` + hp + `,'excluded_debug_probes','Array(String)')) > 0    AS debug_excluded,
       length(JSONExtract(` + hp + `,'low_authority_probe_scopes','Array(String)')) > 0 AS low_authority
  FROM picked AS o
  LEFT JOIN (
       SELECT correlation_id, version, count() AS edge_count,
              arrayStringConcat(arraySort(groupUniqArray(grounding_kind)), '+') AS grounding
         FROM netops.corr_edges
        WHERE (correlation_id, version) IN (SELECT correlation_id, version FROM picked)
        GROUP BY correlation_id, version
  ) AS e ON e.correlation_id = o.correlation_id AND e.version = o.version
 ORDER BY o.created_at DESC
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
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
  FROM netops.corr_objects_latest
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
		case c >= '0' && c <= '9', c == '-', c == ':', c == '.', c == ' ':
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
SELECT version,
       toString(window_start)   AS window_start,
       toString(window_end)     AS window_end,
       toString(trigger_signal) AS trigger_signal,
       verdict_tier, top_hypothesis, top_confidence, evidence_missing,
       hypotheses, affected, layer_coverage, app_impact
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
       toString(ts)         AS ts,
       toString(ingest_ts)  AS ingest_ts,
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
   AND ts >= '` + ws + `' AND ts <= '` + we + `'
 ORDER BY ts ASC, signal_id ASC
 FORMAT JSON`
	sigRows, err := s.chRowsScope(ctx, scope, sigSQL)
	if err != nil {
		return nil, nil, nil, nil, http.StatusBadGateway, err
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
       toString(window_start)    AS window_start,
       toString(window_end)      AS window_end,
       toString(trigger_signal)  AS trigger_signal,
       top_hypothesis, top_confidence, verdict_tier,
       hypotheses, evidence_missing, affected,
       signal_count, node_count,
       engine_version, topology_version, catalog_version,
       toString(created_at)      AS created_at
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
