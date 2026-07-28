package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/seam"
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
	// A merged/wide object can carry path entities to SEVERAL destinations;
	// "newest single row" picked an arbitrary one (a netbox case answered with
	// 1.1.1.1's path). Rank candidates instead: prefer a destination the object
	// itself names in its affected set, then the dominant (most-grounded) path.
	sql := `SELECT entity_id, any(tenant_id) AS tenant_id, count() AS n, max(ts) AS last
  FROM netops.corr_signals_archive
 WHERE archived_for = '` + id + `' AND entity_type = 'path' AND entity_id != ''
 GROUP BY entity_id
 ORDER BY n DESC, last DESC
 LIMIT 20
 FORMAT JSON`
	rows, err := chSelect(ctx, scope, sql, "api:/api/rca/path")
	if err != nil {
		return pathQueryRef{}, false, err
	}
	if len(rows) == 0 {
		return pathQueryRef{}, false, nil
	}
	subjects := map[string]bool{}
	if aff, aerr := chSelect(ctx, scope, `SELECT affected FROM netops.corr_current FINAL
 WHERE correlation_id = '`+id+`' LIMIT 1 FORMAT JSON`, "api:/api/rca/path"); aerr == nil && len(aff) > 0 {
		var a struct {
			Services []string `json:"services"`
		}
		if json.Unmarshal([]byte(str(aff[0]["affected"])), &a) == nil {
			for _, svc := range a.Services {
				subjects[strings.TrimSpace(svc)] = true
			}
		}
	}
	pick := -1
	for i, row := range rows {
		_, dst, found := strings.Cut(str(row["entity_id"]), "->")
		if !found {
			continue
		}
		if pick < 0 {
			pick = i // dominant path = default
		}
		if subjects[strings.TrimSpace(dst)] {
			pick = i // the object's own subject wins
			break
		}
	}
	if pick < 0 {
		return pathQueryRef{}, false, nil
	}
	_, dst, _ := strings.Cut(str(rows[pick]["entity_id"]), "->")
	return pathQueryRef{DstAddress: strings.TrimSpace(dst), Tenant: str(rows[pick]["tenant_id"])}, true, nil
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
	classes := pathgraph.LiveOnly()
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
	cands, err := s.pathGraph.ListObservations(ctx, tenant, cross, pathgraph.ObservationFilter{
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
	obs, hops, def, found, err := s.pathGraph.LatestObservation(ctx, tenant, cross, pathgraph.ObservationFilter{
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
	spine := pathgraph.BuildSpine(in)
	s.stampSpineCloudIdentity(ctx, tenant, &spine)
	return spine
}

// spineIPIdentity is one declared-inventory claim on an address: the cloud
// provider that owns it and the best human name for it.
type spineIPIdentity struct {
	provider string
	name     string
}

// stampSpineCloudIdentity annotates spine nodes whose address is claimed by
// DECLARED inventory: the cloud provider (aws|azure|gcp — drives the provider
// mark in the canvas) and a human display name, so a hop reads
// "correlix-aws-app-host-01", never a bare IP with a vague type line.
// Evidence-based only — cloud NIC/EIP bindings and the tenant's own device
// inventory; an address nothing claims stays exactly as measured.
func (s *server) stampSpineCloudIdentity(ctx context.Context, tenant string, spine *pathgraph.Spine) {
	if spine == nil || len(spine.Spine) == 0 {
		return
	}
	byIP := map[string]spineIPIdentity{}
	if s.cloud != nil {
		if res, err := s.cloud.ListResources(ctx, tenant, false); err == nil {
			for _, r := range res {
				p := strings.ToLower(string(r.Provider))
				name := r.ResourceName
				if name == "" {
					name = r.AppName
				}
				if p == "" && name == "" {
					continue
				}
				for _, ip := range r.PrivateIPs {
					byIP[ip] = spineIPIdentity{provider: p, name: name}
				}
				for _, ip := range r.PublicIPs {
					byIP[ip] = spineIPIdentity{provider: p, name: name}
				}
			}
		}
	}
	// The device inventory names win where both claim an address: an operator's
	// device record is the more specific identity (and covers non-cloud hops).
	if s.discovery != nil {
		for _, d := range s.discovery.Devices() {
			if d.Address == "" || d.Name == "" || deviceTenant(d) != tenant {
				continue
			}
			id := byIP[d.Address]
			id.name = d.Name
			byIP[d.Address] = id
		}
	}
	if len(byIP) == 0 {
		return
	}
	for i := range spine.Spine {
		n := &spine.Spine[i]
		if n.Address == "" {
			continue
		}
		id, ok := byIP[n.Address]
		if !ok {
			continue
		}
		if id.provider != "" {
			n.Provider = id.provider
		}
		// Name the hop only when it has no better identity than its address
		// or a raw resource id (an operator reads names, not i-0abc… strings).
		if id.name != "" && (n.Label == "" || n.Label == n.Address || n.Label == n.EntityRef) {
			n.Label = id.name
		}
	}
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
	prior, priorHops, _, found, err := s.pathGraph.LatestObservation(ctx, tenant, cross, pathgraph.ObservationFilter{
		PathID: obs.PathID, Status: pathgraph.StatusComplete,
		DataClasses: []string{obs.DataClass}, Limit: 1,
	})
	if err != nil {
		// The observation store did not answer. An absent hint stays absent (a
		// hint is never guessed), but "no prior complete run" and "we could not
		// look" are different facts — the second one is now visible (§10).
		logWarn("path.graph", "seam-hint history read failed — the hint is reported ABSENT, not derived",
			map[string]any{"path_id": obs.PathID, "tenant": tenant, "err": err.Error()})
		return nil
	}
	if !found {
		return nil // answered: no prior complete run to derive a hint from
	}
	var seams []seam.Seam
	if s.seams != nil {
		if inv, serr := s.seams.List(ctx, tenant, cross, "active", ""); serr == nil {
			seams = inv
		}
	}
	return seamHintFrom(prior, priorHops, terminal, seams)
}

// seamHintFrom derives the hint from two evidenced facts and nothing else. Pure.
//
// Rule (a) — direct: the prior complete run stamped a seam on the SAME address the
// current run dies at (a LAN vantage sees the tunnel-start hop when healthy).
//
// Rule (b) — endpoint: the prior run proves WHICH seam this path crosses (exactly
// one seam id among its hop stamps — two would be ambiguous, so no hint), and the
// seam inventory states the terminal address is one of that seam's endpoints (a
// co-located vantage never sees its own edge as a hop when healthy, but the dying
// run terminates on it). The transformation follows the side the inventory names,
// tunnel types only — same rule as ingest's transformAt.
func seamHintFrom(prior pathgraph.PathObservation, priorHops []pathgraph.PathHop, terminal string, seams []seam.Seam) *pathgraph.SeamHint {
	hint := func(seamID, transformation string) *pathgraph.SeamHint {
		return &pathgraph.SeamHint{
			SeamID: seamID, Transformation: transformation,
			EvidenceRef: firstNonEmptyStr(prior.ProvenanceID, prior.ObservationID),
			ObservedAt:  prior.ObservedAt, DataClass: prior.DataClass,
		}
	}
	crossed := "" // the ONE seam this path is known to cross ("" = none, "*" = ambiguous)
	for _, h := range priorHops {
		if h.SeamID == "" || h.State != pathgraph.HopResponding {
			continue
		}
		if strings.ToLower(strings.TrimSpace(h.ObservedAddress)) == terminal {
			return hint(h.SeamID, h.Transformation) // rule (a)
		}
		if crossed != "" && crossed != h.SeamID {
			crossed = "*"
		} else if crossed != "*" {
			crossed = h.SeamID
		}
	}
	if crossed == "" || crossed == "*" {
		return nil
	}
	for _, side := range buildSeamIndex(seams)[terminal] {
		if side.SeamID != crossed {
			continue
		}
		transformation := pathgraph.TransformNone
		if tunnelSeamTypes[side.SeamType] {
			if side.Near {
				transformation = pathgraph.TransformTunnelIngress
			} else {
				transformation = pathgraph.TransformTunnelEgress
			}
		}
		return hint(crossed, transformation) // rule (b)
	}
	return nil
}

// rcaPathBlock returns the §7 payload for embedding in the RCA read model (the
// correlation timeline). Errors are swallowed into a nil block on purpose: the
// timeline must render with or without a path, and an absent spine is stated, never
// faked.
func (s *server) rcaPathBlock(ctx context.Context, r *http.Request, correlationID, verdictTier, topHyp string) any {
	claims, ok := userFrom(ctx)
	if !ok {
		return nil
	}
	tenant, cross := principalTenant(claims)
	resp, status, err := s.rcaPathSpine(ctx, tenant, cross, chTenantScope(r), correlationID, "")
	if err != nil || status != http.StatusOK {
		return nil
	}
	stampSpineFault(resp.Spine, verdictTier, topHyp)
	// Discovery-driven canonical device roles on the hops that resolve to a
	// CALLER-VISIBLE managed device (tenant-scoped index; device_roles.go). The
	// path view uses these to place devices into canonical segments; hops that
	// resolve to nothing stay role-less (unknown stays absent).
	if resp.Spine != nil && len(resp.Spine.Spine) > 0 {
		stampSpineRoles(resp.Spine.Spine, s.deviceRoleIndex(ctx, claims))
	}
	return resp
}

// pathFaultFamilies: hypothesis families whose fault IS the path — only these
// paint a drop point red. An app-layer fault must never redden the network path.
var pathFaultFamilies = []string{
	"underlay", "tunnel", "ipsec", "connectivity", "path", "egress",
	"middle-mile", "dia", "wan-edge", "link", "uplink",
}

// stampSpineFault marks WHERE the measurement stopped — and separately, whether
// THIS case blames that point. Two different statements, never conflated:
//
//	"last_response"  — a MEASUREMENT FACT: this partial run's last answering hop.
//	                   Always stated (an operator must never have to guess where
//	                   a trace died), carries no blame.
//	"broken"/"suspected" — a CAUSAL ATTRIBUTION: the case's verdict is a
//	                   path-family fault, so the drop point IS the case's break.
//
// An application-layer fault therefore shows where the path stopped answering
// without the network being accused of it (the earlier gate threw the fact away
// with the blame — owner-caught, 2026-07-13).
func stampSpineFault(sp *pathgraph.Spine, verdictTier, topHyp string) {
	if sp == nil || len(sp.Spine) == 0 {
		return
	}
	if sp.Status == pathgraph.StatusComplete {
		return // the path reached its target — nothing stopped on it
	}
	mark := "last_response" // the honest default: fact without blame
	family := false
	low := strings.ToLower(topHyp)
	for _, f := range pathFaultFamilies {
		if strings.Contains(low, f) {
			family = true
			break
		}
	}
	if family {
		switch strings.ToLower(verdictTier) {
		case "confirmed":
			mark = "broken"
		case "suspected":
			mark = "suspected"
		}
	}
	// the drop point = the last responding hop (everything after it is dark)
	for i := len(sp.Spine) - 1; i >= 0; i-- {
		if sp.Spine[i].State == string(pathgraph.HopResponding) {
			sp.Spine[i].Fault = mark
			return
		}
	}
}
