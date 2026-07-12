package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/pathgraph"
)

// path_graph_api.go — §7 of the frozen contract:
//
//	GET /api/rca/{correlation_id}/path
//
// returns the ORDERED SPINE, its typed edges, its server-computed boundaries and
// its off-spine evidence branches. THE BACKEND DECIDES HOP ORDER. The UI is a dumb
// layout of this payload: it must not compute order, must not lay out from node
// degree, and must not fall back to a star. If there is no spine, the payload says
// so (spine_available=false + a reason) and the UI says so too — it does not invent
// one.
//
// The same payload is embedded in the RCA read model (the correlation timeline's
// `path` block), which is where the renderer picks it up.

// pathFreshness is the window inside which an observation may anchor a LIVE verdict
// (§8 stale observations). Beyond it the payload is still rendered — as history —
// with anchors_live_verdict=false.
func pathFreshness() time.Duration {
	if s := envOr("PATH_GRAPH_FRESHNESS_S", ""); s != "" {
		if n := parsePositiveInt(s); n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 15 * time.Minute
}

// pickSpineObservation chooses the observation whose spine the RCA shows, from a
// newest-first candidate list. Fresh observations (within the live-verdict window)
// are preferred as a group; within the group the MOST COMPLETE measured view (most
// hops) wins and ties go to the newest — so a client-side vantage that sees the
// whole LAN→WAN→cloud path outranks the co-located prober's constant, shorter
// re-measurements, and a single-vantage deployment degrades to plain newest. When
// nothing is fresh, the newest historical observation is served (still rendered,
// marked stale by the caller). Returns nil when the list is empty.
func pickSpineObservation(cands []pathgraph.PathObservation, now time.Time, freshness time.Duration) *pathgraph.PathObservation {
	if len(cands) == 0 {
		return nil
	}
	pool := make([]pathgraph.PathObservation, 0, len(cands))
	for _, c := range cands {
		if now.Sub(c.ObservedAt) <= freshness {
			pool = append(pool, c)
		}
	}
	if len(pool) == 0 {
		return &cands[0] // nothing fresh: newest history
	}
	best := 0
	for i := 1; i < len(pool); i++ {
		if pool[i].HopCount > pool[best].HopCount { // list is newest-first, so > keeps the newest on ties
			best = i
		}
	}
	return &pool[best]
}

func parsePositiveInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0
		}
	}
	return n
}

// corrPathRef is the correlation → path linkage: which measured path does this RCA
// object concern? An interface (not a hardcoded ClickHouse call) because it is an
// external dependency of this handler, and because a test must be able to drive the
// handler without a live ClickHouse (CLAUDE.md §5).
type corrPathRef interface {
	// PathRefFor returns the destination address (and protocol/vantage when the
	// object knows them) of the path the correlation object is about. ok=false when
	// the object is not path-shaped — a legitimate, honest answer.
	PathRefFor(ctx context.Context, scope, correlationID string) (ref pathQueryRef, ok bool, err error)
}

type pathQueryRef struct {
	DstAddress string
	Protocol   string
	VantageID  string
	Tenant     string
}

// chCorrPathRef is the production implementation: it reads the object's attached
// PATH entity (entity_type='path', entity_id "src->dst") from the correlation
// engine's own evidence — the engine already grounds the object on the probe path,
// so we consume its statement instead of re-deriving one.
type chCorrPathRef struct{ s *server }

func (c chCorrPathRef) PathRefFor(ctx context.Context, scope, id string) (pathQueryRef, bool, error) {
	if !isUUIDToken(id) {
		return pathQueryRef{}, false, errors.New("invalid correlation id")
	}
	sql := `SELECT entity_id, tenant_id
  FROM netops.corr_signals_archive
 WHERE archived_for = '` + id + `' AND entity_type = 'path' AND entity_id != ''
 ORDER BY ts DESC
 LIMIT 1
 FORMAT JSON`
	rows, err := chSelect(ctx, scope, sql, "api:/api/rca/path")
	if err != nil {
		return pathQueryRef{}, false, err
	}
	if len(rows) == 0 {
		return pathQueryRef{}, false, nil
	}
	entity := str(rows[0]["entity_id"])
	_, dst, found := strings.Cut(entity, "->")
	if !found {
		return pathQueryRef{}, false, nil
	}
	return pathQueryRef{DstAddress: strings.TrimSpace(dst), Tenant: str(rows[0]["tenant_id"])}, true, nil
}

// pathSpineResponse is the §7 payload plus the honest "no spine" case.
type pathSpineResponse struct {
	CorrelationID  string `json:"correlation_id"`
	SpineAvailable bool   `json:"spine_available"`
	Reason         string `json:"reason,omitempty"`
	*pathgraph.Spine
}

// handleRcaPath serves GET /api/rca/{correlation_id}/path.
func (s *server) handleRcaPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/rca/")
	id, sub, _ := strings.Cut(rest, "/")
	if sub != "path" {
		writeError(w, http.StatusNotFound, errors.New("unknown subresource"))
		return
	}
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid correlation id"))
		return
	}
	tenant, cross := principalTenant(claims)
	resp, status, err := s.rcaPathSpine(r.Context(), tenant, cross, chTenantScope(r), id, r.URL.Query().Get("data_class"))
	if err != nil {
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// rcaPathSpine is the whole §7 read path, shared by the standalone endpoint and by
// the RCA timeline embed. It is where the §1 data-class rule is applied:
// customer/default reads see ONLY live records; a non-live class can be requested
// ONLY by a platform (cross-tenant) principal, and never becomes the default.
func (s *server) rcaPathSpine(ctx context.Context, tenant string, cross bool, scope, correlationID, dataClassParam string) (pathSpineResponse, int, error) {
	out := pathSpineResponse{CorrelationID: correlationID}
	if s.pathGraph == nil {
		out.Reason = "path graph storage is not enabled"
		return out, http.StatusOK, nil
	}
	classes := liveOnly()
	if dc := strings.TrimSpace(dataClassParam); dc != "" {
		if !cross {
			// A tenant principal may never widen its own data-class window: synthetic /
			// replay / lab evidence can never produce a customer-confirmed verdict (§1).
			return out, http.StatusForbidden, errors.New("data_class selection is platform-only")
		}
		if !pathgraph.ValidDataClass(dc) {
			return out, http.StatusBadRequest, fmt.Errorf("invalid data_class %q", dc)
		}
		classes = []string{dc}
	}

	locator := s.corrPath
	if locator == nil {
		locator = chCorrPathRef{s}
	}
	ref, ok, err := locator.PathRefFor(ctx, scope, correlationID)
	if err != nil {
		return out, http.StatusBadGateway, err
	}
	if !ok || ref.DstAddress == "" {
		out.Reason = "this correlation object is not path-shaped (no measured path entity is attached)"
		return out, http.StatusOK, nil
	}

	// Pick WHICH vantage's spine to serve. Newest-first alone is wrong with
	// multiple vantages: the co-located prober re-measures constantly, so its
	// (shorter, WAN-edge-started) path is always newest and a client-side LAN
	// vantage would never render — the exact view the spine exists to show (§10:
	// the path starts at the client). Rule: among FRESH observations of this
	// destination, the most complete measured view (most hops) wins; ties go to
	// the newest. With one vantage this degrades to plain newest.
	cands, err := s.pathGraph.ListObservations(ctx, tenant, cross, ObservationFilter{
		DstAddress: ref.DstAddress, Protocol: ref.Protocol, VantageID: ref.VantageID,
		DataClasses: classes, Limit: 20,
	})
	if err != nil {
		return out, http.StatusBadGateway, err
	}
	pick := pickSpineObservation(cands, time.Now().UTC(), pathFreshness())
	if pick == nil {
		out.Reason = "no " + strings.Join(classes, "/") + " path observation exists for " + ref.DstAddress
		return out, http.StatusOK, nil
	}
	obs, hops, def, found, err := s.pathGraph.LatestObservation(ctx, tenant, cross, ObservationFilter{
		PathID: pick.PathID, DstAddress: ref.DstAddress, VantageID: pick.VantageID,
		DataClasses: classes, Limit: 1,
	})
	if err != nil {
		return out, http.StatusBadGateway, err
	}
	if !found {
		out.Reason = "no " + strings.Join(classes, "/") + " path observation exists for " + ref.DstAddress
		return out, http.StatusOK, nil
	}

	spine := s.buildSpineFor(ctx, tenant, cross, correlationID, obs, hops, def)
	out.Spine = &spine
	out.SpineAvailable = len(spine.Spine) > 0
	return out, http.StatusOK, nil
}

// buildSpineFor assembles the §7 payload for one observation: the client endpoint,
// the ordered hops, the rank-2/4 service tail, and the rank-6 supporting relations.
func (s *server) buildSpineFor(ctx context.Context, tenant string, cross bool, correlationID string,
	obs pathgraph.PathObservation, hops []pathgraph.PathHop, def pathgraph.PathDefinition) pathgraph.Spine {

	client := pathgraph.Endpoint{
		Address: def.SrcAddress, NetworkContext: def.NetworkContext, Kind: pathgraph.KindClient,
		ResolutionMethod: pathgraph.MethodUnresolved, Confidence: pathgraph.ConfUnknown,
		EvidenceRef: obs.ProvenanceID,
	}
	// The registered src endpoint (if we have one) carries the resolved binding.
	if eps, err := s.pathGraph.ListEndpoints(ctx, tenant, cross); err == nil {
		for _, ep := range eps {
			if ep.EndpointID == def.SrcEndpointRef {
				client = ep
				break
			}
		}
	}

	in := pathgraph.SpineInput{
		CorrelationID: correlationID, Observation: obs, Hops: hops, Client: client,
		Supporting: map[int][]pathgraph.SupportingRel{},
		Now:        time.Now().UTC(), Freshness: pathFreshness(),
	}

	// A partial run dies before the seam's far side can answer, so the on-path
	// disambiguation can never stamp the seam — exactly the moment the NOC needs
	// it. This path's OWN latest complete observation is honest evidence of which
	// seam its terminal hop sits on; passed as a hint, rendered as inferred support.
	if obs.Status != pathgraph.StatusComplete {
		in.SeamHint = s.seamHintFromHistory(ctx, tenant, cross, obs, hops)
	}

	// Re-derive the rank-4/2 service tail and the rank-6 support from the CURRENT
	// fact base, at the observation's timestamp. This is deliberate: the spine is a
	// read model over an immutable observation, so the binding is evaluated in the
	// observation's own time window (§6.2) rather than frozen at ingest.
	src := s.pathFacts
	if src == nil {
		src = serverPathFacts{s}
	}
	if facts, nc, err := src.Facts(ctx, tenant, obs.ObservedAt); err == nil {
		in.SessionSourceAvailable = facts.SessionSourceAvailable
		q := pathgraph.Query{
			TenantID: tenant, Address: def.DstAddress, NetworkContext: nc.Of(def.DstAddress),
			At: obs.ObservedAt, IncludeNonLive: obs.DataClass != pathgraph.DataClassLive,
		}
		in.Service = facts.ServiceOf(q)
		for _, h := range hops {
			if h.State != pathgraph.HopResponding {
				continue
			}
			res := facts.Resolve(pathgraph.Query{
				TenantID: tenant, Address: h.ObservedAddress, NetworkContext: h.NetworkContext,
				At: obs.ObservedAt, IncludeNonLive: obs.DataClass != pathgraph.DataClassLive,
			})
			if len(res.Supporting) > 0 {
				in.Supporting[h.HopIndex] = res.Supporting
			}
		}
	}
	return pathgraph.BuildSpine(in)
}

// seamHintFromHistory finds the seam stamped on the current run's terminal
// responding address by this SAME path's most recent COMPLETE observation. Same
// path_id ⇒ same identity (tenant, endpoints, vantage, protocol, context — §2.2),
// and same data class as the run being served, so a live spine is never hinted
// from synthetic history. Returns nil when there is no prior complete run, when
// its hops don't stamp a seam at that address, or when the current run has no
// responding hop — an absent hint is an honest answer, never guessed.
func (s *server) seamHintFromHistory(ctx context.Context, tenant string, cross bool,
	obs pathgraph.PathObservation, hops []pathgraph.PathHop) *pathgraph.SeamHint {

	var terminal string
	for i := len(hops) - 1; i >= 0; i-- {
		if hops[i].State == pathgraph.HopResponding && hops[i].ObservedAddress != "" {
			terminal = strings.ToLower(strings.TrimSpace(hops[i].ObservedAddress))
			break
		}
	}
	if terminal == "" {
		return nil
	}
	prior, priorHops, _, found, err := s.pathGraph.LatestObservation(ctx, tenant, cross, ObservationFilter{
		PathID: obs.PathID, Status: pathgraph.StatusComplete,
		DataClasses: []string{obs.DataClass}, Limit: 1,
	})
	if err != nil || !found {
		return nil
	}
	for _, h := range priorHops {
		if h.SeamID == "" || h.State != pathgraph.HopResponding {
			continue
		}
		if strings.ToLower(strings.TrimSpace(h.ObservedAddress)) == terminal {
			return &pathgraph.SeamHint{
				SeamID: h.SeamID, Transformation: h.Transformation,
				EvidenceRef: firstNonEmptyStr(prior.ProvenanceID, prior.ObservationID),
				ObservedAt:  prior.ObservedAt, DataClass: prior.DataClass,
			}
		}
	}
	return nil
}

// rcaPathBlock returns the §7 payload for embedding in the RCA read model (the
// correlation timeline). Errors are swallowed into a nil block on purpose: the
// timeline must render with or without a path, and an absent spine is stated, never
// faked.
func (s *server) rcaPathBlock(ctx context.Context, r *http.Request, correlationID string) any {
	claims, ok := userFrom(ctx)
	if !ok {
		return nil
	}
	tenant, cross := principalTenant(claims)
	resp, status, err := s.rcaPathSpine(ctx, tenant, cross, chTenantScope(r), correlationID, "")
	if err != nil || status != http.StatusOK {
		return nil
	}
	return resp
}
