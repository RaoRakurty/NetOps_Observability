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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// chRows runs one tenant-scoped ClickHouse query and returns the parsed JSON
// rows — the composable sibling of proxyClickHouse for handlers that combine
// multiple result sets into one response.
func (s *server) chRows(r *http.Request, sql string) ([]map[string]any, error) {
	base := envOr("CLICKHOUSE_URL", "http://clickhouse:8123")
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("tenant_scope", chTenantScope(r))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, u.String(), bytes.NewReader([]byte(sql)))
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
	conds := []string{
		"created_at >= now() - INTERVAL " + intToString(int(since.Seconds())) + " SECOND",
	}
	if st := strings.TrimSpace(r.URL.Query().Get("state")); st != "" {
		if !isAlphaToken(st) {
			writeError(w, http.StatusBadRequest, errors.New("invalid state"))
			return
		}
		conds = append(conds, "state = '"+st+"'")
	}
	if tier := strings.TrimSpace(r.URL.Query().Get("tier")); tier != "" {
		if !isAlphaToken(tier) {
			writeError(w, http.StatusBadRequest, errors.New("invalid tier"))
			return
		}
		conds = append(conds, "verdict_tier = '"+tier+"'")
	}
	// Filter in an inner query: aliasing toString(created_at) AS created_at in
	// the same SELECT would shadow the column in WHERE (String vs DateTime →
	// NO_COMMON_TYPE).
	sql := `
SELECT toString(correlation_id)  AS correlation_id,
       version,
       state,
       toString(window_start)    AS window_start,
       toString(window_end)      AS window_end,
       top_hypothesis,
       top_confidence,
       verdict_tier,
       evidence_missing,
       affected,
       signal_count,
       node_count,
       engine_version,
       catalog_version,
       toString(created_at)      AS created_at
  FROM (
       SELECT * FROM netops.corr_objects_latest
        WHERE ` + strings.Join(conds, " AND ") + `
        ORDER BY created_at DESC
        LIMIT ` + intToString(limit) + `
  )
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
}

// handleCorrelationByID serves GET /api/correlations/{id} (object + edges) and
// GET /api/correlations/{id}/replay (drift report, proxied).
func (s *server) handleCorrelationByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/correlations/")
	id, sub, _ := strings.Cut(rest, "/")
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid correlation id"))
		return
	}
	switch sub {
	case "":
		s.serveCorrelationDetail(w, r, id)
	case "timeline":
		s.serveCorrelationTimeline(w, r, id)
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
       verdict_tier, top_hypothesis, top_confidence, evidence_missing
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'` + verCond + `
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	metaRows, err := s.chRows(r, metaSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if len(metaRows) == 0 {
		writeError(w, http.StatusNotFound, errors.New("correlation object not found"))
		return
	}
	meta := metaRows[0]
	ver := fmt.Sprintf("%v", meta["version"])
	ws, _ := meta["window_start"].(string)
	we, _ := meta["window_end"].(string)
	if !isDatetimeToken(ws) || !isDatetimeToken(we) {
		writeError(w, http.StatusBadGateway, errors.New("malformed object window"))
		return
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
       JSONExtractString(attrs, 'clear_ts')           AS clear_ts
  FROM netops.corr_signals_archive
 WHERE archived_for = '` + id + `' AND toString(archived_version) = '` + ver + `'
   AND ts >= '` + ws + `' AND ts <= '` + we + `'
 ORDER BY ts ASC, signal_id ASC
 FORMAT JSON`
	sigRows, err := s.chRows(r, sigSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	// 3) Evidence rows for this version (signal → role/subject); joined in Go so
	//    every signal carries an authoritative attached flag + its role(s).
	evSQL := `
SELECT toString(signal_id) AS signal_id, subject_kind, subject_id, role, note
  FROM netops.corr_evidence
 WHERE correlation_id = '` + id + `' AND toString(version) = '` + ver + `'
 FORMAT JSON`
	evRows, err := s.chRows(r, evSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	counts := mergeTimelineEvidence(sigRows, evRows, trigger)

	writeJSON(w, http.StatusOK, map[string]any{
		"correlation_id":   id,
		"version":          meta["version"],
		"window_start":     ws,
		"window_end":       we,
		"trigger_signal":   trigger,
		"verdict_tier":     meta["verdict_tier"],
		"top_hypothesis":   meta["top_hypothesis"],
		"top_confidence":   meta["top_confidence"],
		"evidence_missing": meta["evidence_missing"],
		"signals":          sigRows,
		"evidence":         evRows,
		"counts":           counts,
	})
}

// mergeTimelineEvidence joins the window signal slice with the evidence rows in
// place: each signal gets an authoritative `attached` flag, its `evidence` rows
// (role/subject), and `is_trigger`. Returns the count rollup the Inspector uses
// to answer "what was attached vs ignored, which planes, what contradicts".
// Pure (no I/O) so the join is unit-tested independently of ClickHouse.
func mergeTimelineEvidence(sigRows, evRows []map[string]any, trigger string) map[string]any {
	evBySignal := map[string][]map[string]any{}
	byRole := map[string]int{}
	for _, e := range evRows {
		sid := fmt.Sprintf("%v", e["signal_id"])
		evBySignal[sid] = append(evBySignal[sid], e)
		byRole[fmt.Sprintf("%v", e["role"])]++
	}
	byModality := map[string]int{}
	attached := 0
	for _, sig := range sigRows {
		sid := fmt.Sprintf("%v", sig["signal_id"])
		ev := evBySignal[sid]
		sig["attached"] = len(ev) > 0
		sig["evidence"] = ev // nil → null when unattached
		sig["is_trigger"] = sid == trigger
		if len(ev) > 0 {
			attached++
		}
		byModality[fmt.Sprintf("%v", sig["modality_class"])]++
	}
	return map[string]any{
		"total":       len(sigRows),
		"attached":    attached,
		"unattached":  len(sigRows) - attached,
		"by_modality": byModality,
		"by_role":     byRole,
	}
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
	writeJSON(w, http.StatusOK, map[string]any{"object": objRows[0], "edges": edgeRows})
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
