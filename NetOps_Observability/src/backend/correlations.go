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
	avRows, err := s.chRows(r, avSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	archiveVer := "0"
	if len(avRows) > 0 && avRows[0]["av"] != nil {
		archiveVer = fmt.Sprintf("%v", avRows[0]["av"])
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
 WHERE archived_for = '` + id + `' AND toString(archived_version) = '` + archiveVer + `'
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
	edgeRows, err := s.chRows(r, edgeSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	counts := mergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)

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
		"edges":            edgeRows,
		"counts":           counts,
	})
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
