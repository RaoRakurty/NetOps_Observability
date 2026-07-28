package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netops/backend/pathgraph"
)

// path_graph_enrichment.go — the Go→Python hand-off of the Service Path Graph.
//
// The correlation engine's NEW edge-admission gate (which replaced token overlap)
// reads this file: PATH_GRAPH_FILE, default /data/enrichment/path_graph.json, under
// TENANT_ENRICHMENT_DIR — the same shared-volume mechanism as seams.json
// (startSeamEnrichment). The AUTHORITATIVE consumer contract is
// src/correlation/path_graph.py :: PathGraphView.from_dict, and this exporter is
// written against it field-for-field:
//
//	{ "endpoints":[…], "observations":[…], "service_bindings":[…],
//	  "nat_sessions":[…], "routes":[…], "freshness_s":900, "contract_version":1 }
//
// THREE THINGS THAT WILL SILENTLY BREAK THE ENGINE IF CHANGED CARELESSLY:
//
//  1. resolution_method VOCABULARY. Python's RANK{} maps unknown methods to rank 7
//     (candidate). So "flow_nat_stitch" and "shared_token" are the wire names —
//     pathgraph/resolve.go uses exactly those. A rename on either side silently
//     demotes real observations to coincidences.
//  2. TIMESTAMP FORMAT. Python's _dt() strips "T"/"Z" and parses
//     "%Y-%m-%d %H:%M:%S[.%f]" — an RFC3339 UTC "…Z" stamp round-trips, a numeric
//     "+00:00" offset does NOT. Everything here is emitted UTC/Z.
//  3. EMPTY TENANT = INERT. PathGraphView.for_tenant() DROPS objects whose
//     tenant_id is "" (fail-closed: there are no "global" path objects). An
//     untagged export is therefore invisible to the engine — we log that loudly
//     rather than let it look like a working integration.
//
// Exported at platform scope (every tenant's objects in one file, each carrying its
// immutable tenant_id); the engine's for_tenant() is what enforces §9 on the Python
// side, exactly as it does for seams.

// pathGraphExport is the top-level file shape (PathGraphView.from_dict).
type pathGraphExport struct {
	Endpoints       []pgEndpoint       `json:"endpoints"`
	Observations    []pgObservation    `json:"observations"`
	ServiceBindings []pgServiceBinding `json:"service_bindings"`
	NatSessions     []pgNatSession     `json:"nat_sessions"`
	Routes          []pgRouteRelation  `json:"routes"`
	FreshnessS      float64            `json:"freshness_s"`
	ContractVersion int                `json:"contract_version"`
}

// pgProvenance mirrors Provenance.from_dict (§1).
type pgProvenance struct {
	TenantID     string `json:"tenant_id"`
	ProducerID   string `json:"producer_id"`
	ProvenanceID string `json:"provenance_id"`
	DataClass    string `json:"data_class"`
	Environment  string `json:"environment"`
	ScenarioID   string `json:"scenario_id"`
	RunID        string `json:"run_id"`
}

func pgProv(p pathgraph.Provenance) pgProvenance {
	return pgProvenance{
		TenantID: p.TenantID, ProducerID: p.ProducerID, ProvenanceID: p.ProvenanceID,
		DataClass: p.DataClass, Environment: p.Environment, ScenarioID: p.ScenarioID, RunID: p.RunID,
	}
}

type pgEndpoint struct {
	EndpointID        string       `json:"endpoint_id"`
	TenantID          string       `json:"tenant_id"`
	Address           string       `json:"address"`
	NetworkContext    string       `json:"network_context"`
	Kind              string       `json:"kind"`
	AddressFamily     string       `json:"address_family"`
	ResolvedEntityRef string       `json:"resolved_entity_ref"`
	ResolutionMethod  string       `json:"resolution_method"`
	Confidence        string       `json:"confidence"`
	ValidFrom         string       `json:"valid_from"`
	ValidTo           string       `json:"valid_to"`
	EvidenceRef       string       `json:"evidence_ref"`
	Provenance        pgProvenance `json:"provenance"`
}

type pgDefinition struct {
	PathID         string `json:"path_id"`
	TenantID       string `json:"tenant_id"`
	SrcEndpointRef string `json:"src_endpoint_ref"`
	DstEndpointRef string `json:"dst_endpoint_ref"`
	Direction      string `json:"direction"`
	Protocol       string `json:"protocol"`
	DstPort        int    `json:"dst_port"`
	VantageID      string `json:"vantage_id"`
	NetworkContext string `json:"network_context"`
}

type pgHop struct {
	HopIndex          int     `json:"hop_index"`
	State             string  `json:"state"`
	ObservedAddress   string  `json:"observed_address"`
	ResolvedEntityRef string  `json:"resolved_entity_ref"`
	ResolutionMethod  string  `json:"resolution_method"`
	Confidence        string  `json:"confidence"`
	SeamID            string  `json:"seam_id"`
	RTTms             float64 `json:"rtt_ms"`
	Transformation    string  `json:"transformation"`
	EvidenceRef       string  `json:"evidence_ref"`
	ObservedAt        string  `json:"observed_at"`
	TenantID          string  `json:"tenant_id"`
}

type pgObservation struct {
	ObservationID string       `json:"observation_id"`
	PathID        string       `json:"path_id"`
	TenantID      string       `json:"tenant_id"`
	ObservedAt    string       `json:"observed_at"`
	Method        string       `json:"method"`
	VantageID     string       `json:"vantage_id"`
	Status        string       `json:"status"`
	HopCount      int          `json:"hop_count"`
	Hops          []pgHop      `json:"hops"`
	Provenance    pgProvenance `json:"provenance"`
	Definition    pgDefinition `json:"definition"`
}

// pgServiceBinding is rank 4 (§3): application/service → endpoint. It is the
// Go-side projection of the SAME relationship cloud.AppResourceEdge models
// (owns/runs_on/fronts/…) — the app→resource vocabulary, resolved down to the
// ENDPOINT the service actually listens on, which is what the path graph joins.
type pgServiceBinding struct {
	ServiceRef  string       `json:"service_ref"`
	EndpointRef string       `json:"endpoint_ref"`
	TenantID    string       `json:"tenant_id"`
	EvidenceRef string       `json:"evidence_ref"`
	Confidence  string       `json:"confidence"`
	ValidFrom   string       `json:"valid_from"`
	ValidTo     string       `json:"valid_to"`
	Provenance  pgProvenance `json:"provenance"`
}

type pgNatSession struct {
	TenantID    string       `json:"tenant_id"`
	PreAddress  string       `json:"pre_address"`
	PostAddress string       `json:"post_address"`
	PreContext  string       `json:"pre_context"`
	PostContext string       `json:"post_context"`
	Protocol    string       `json:"protocol"`
	EvidenceRef string       `json:"evidence_ref"`
	ObservedAt  string       `json:"observed_at"`
	Provenance  pgProvenance `json:"provenance"`
}

type pgRouteRelation struct {
	TenantID       string       `json:"tenant_id"`
	FromRef        string       `json:"from_ref"`
	ToRef          string       `json:"to_ref"`
	Relation       string       `json:"relation"`
	NetworkContext string       `json:"network_context"`
	EvidenceRef    string       `json:"evidence_ref"`
	ObservedAt     string       `json:"observed_at"`
	Provenance     pgProvenance `json:"provenance"`
}

// isoZ renders a timestamp the way Python's _dt() can parse it (UTC, Z-suffixed).
// An empty/zero time renders as "" — Python maps that to None (an OPEN window /
// absent time), which is the correct meaning for valid_to.
func isoZ(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func isoZPtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return isoZ(*t)
}

// buildPathGraphExport assembles the engine's view from the store + the fact base.
// PURE given its inputs (unit-tested): the caller does the I/O.
func buildPathGraphExport(eps []pathgraph.Endpoint, defs []pathgraph.PathDefinition,
	obs []pathgraph.PathObservation, hopsOf map[string][]pathgraph.PathHop,
	bindings []pgServiceBinding, routes []pgRouteRelation, freshness time.Duration) pathGraphExport {

	out := pathGraphExport{
		Endpoints: []pgEndpoint{}, Observations: []pgObservation{},
		ServiceBindings: bindings, NatSessions: []pgNatSession{}, Routes: routes,
		FreshnessS: freshness.Seconds(), ContractVersion: pathgraph.ContractVersion,
	}
	if out.ServiceBindings == nil {
		out.ServiceBindings = []pgServiceBinding{}
	}
	if out.Routes == nil {
		out.Routes = []pgRouteRelation{}
	}
	for _, e := range eps {
		out.Endpoints = append(out.Endpoints, pgEndpoint{
			EndpointID: e.EndpointID, TenantID: e.TenantID, Address: e.Address,
			NetworkContext: e.NetworkContext, Kind: e.Kind, AddressFamily: e.AddressFamily,
			ResolvedEntityRef: e.ResolvedEntityRef, ResolutionMethod: e.ResolutionMethod,
			Confidence: e.Confidence, ValidFrom: isoZ(e.ValidFrom), ValidTo: isoZPtr(e.ValidTo),
			EvidenceRef: e.EvidenceRef, Provenance: pgProv(e.Provenance),
		})
	}
	defByID := map[string]pathgraph.PathDefinition{}
	for _, d := range defs {
		defByID[d.PathID] = d
	}
	for _, o := range obs {
		d := defByID[o.PathID]
		hops := hopsOf[o.ObservationID]
		ho := make([]pgHop, 0, len(hops))
		for _, h := range hops {
			ho = append(ho, pgHop{
				HopIndex: h.HopIndex, State: h.State, ObservedAddress: h.ObservedAddress,
				ResolvedEntityRef: h.ResolvedEntityRef, ResolutionMethod: h.ResolutionMethod,
				Confidence: h.Confidence, SeamID: h.SeamID, RTTms: h.RTTms,
				Transformation: h.Transformation, EvidenceRef: h.EvidenceRef,
				ObservedAt: isoZ(h.ObservedAt), TenantID: h.TenantID,
			})
		}
		out.Observations = append(out.Observations, pgObservation{
			ObservationID: o.ObservationID, PathID: o.PathID, TenantID: o.TenantID,
			ObservedAt: isoZ(o.ObservedAt), Method: o.Method, VantageID: o.VantageID,
			Status: o.Status, HopCount: o.HopCount, Hops: ho, Provenance: pgProv(o.Provenance),
			Definition: pgDefinition{
				PathID: d.PathID, TenantID: d.TenantID, SrcEndpointRef: d.SrcEndpointRef,
				DstEndpointRef: d.DstEndpointRef, Direction: d.Direction, Protocol: d.Protocol,
				DstPort: d.DstPort, VantageID: d.VantageID, NetworkContext: d.NetworkContext,
			},
		})
	}
	return out
}

// startPathGraphEnrichment exports the path graph for the correlation engine on a
// timer, mirroring startSeamEnrichment (atomic write, 60s, no-op without the shared
// volume). Only LIVE observations are exported by default: the engine must not be
// able to confirm a customer verdict from lab/synthetic evidence (§1), and the
// simplest way to guarantee that across a process boundary is to not ship it.
// PATH_GRAPH_EXPORT_CLASSES can widen it for a replay/lab rig.
func (s *server) startPathGraphEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" || s.pathGraph == nil {
		return
	}
	write := func() {
		exp, err := s.pathGraphView(ctx)
		if err != nil {
			log.Printf("path-graph-enrichment: build: %v", err)
			return
		}
		data, err := json.Marshal(exp)
		if err != nil {
			log.Printf("path-graph-enrichment: marshal: %v", err)
			return
		}
		if err := writeFileAtomic(filepath.Join(dir, "path_graph.json"), data, 0o644); err != nil {
			log.Printf("path-graph-enrichment: write: %v", err)
			return
		}
		untagged := 0
		for _, o := range exp.Observations {
			if o.TenantID == "" {
				untagged++
			}
		}
		if untagged > 0 {
			// The engine's for_tenant() DROPS empty-tenant objects (fail-closed). Say so:
			// an untagged export looks like a working integration and grounds nothing.
			log.Printf("path-graph-enrichment: WARNING — %d/%d observations carry an EMPTY tenant_id; "+
				"the correlation engine drops those (fail-closed, no 'global' path objects). "+
				"Set PATH_GRAPH_TENANT to the tenant the prober measures for.", untagged, len(exp.Observations))
		}
		log.Printf("path-graph-enrichment: exported %d endpoint(s), %d observation(s), %d service binding(s), %d route(s)",
			len(exp.Endpoints), len(exp.Observations), len(exp.ServiceBindings), len(exp.Routes))
	}
	go func() {
		write()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
}

// pathGraphView assembles the export at PLATFORM scope (cross=true): the file
// carries every tenant's objects, each stamped with its own immutable tenant_id,
// and the engine's PathGraphView.for_tenant() slices it — the same trust model as
// seams.json (the file never leaves the private enrichment volume).
func (s *server) pathGraphView(ctx context.Context) (pathGraphExport, error) {
	classes := pathgraph.LiveOnly()
	if raw := os.Getenv("PATH_GRAPH_EXPORT_CLASSES"); raw != "" {
		classes = nil
		for _, c := range splitAndTrim(raw) {
			if pathgraph.ValidDataClass(c) {
				classes = append(classes, c)
			}
		}
		if len(classes) == 0 {
			classes = pathgraph.LiveOnly() // an unparseable override fails CLOSED, to live-only
		}
	}
	eps, err := s.pathGraph.ListEndpoints(ctx, "", true)
	if err != nil {
		return pathGraphExport{}, err
	}
	defs, err := s.pathGraph.ListPathDefinitions(ctx, "", true)
	if err != nil {
		return pathGraphExport{}, err
	}
	obs, err := s.pathGraph.ListObservations(ctx, "", true, pathgraph.ObservationFilter{
		DataClasses: classes, Limit: pathExportLimit(),
	})
	if err != nil {
		return pathGraphExport{}, err
	}
	// Only the LATEST observation per (path_id) is exported: the engine grounds on
	// the current path, and the full history lives in ClickHouse (queryable, §8).
	// This also bounds the file (§9 reliability: queues/exports are bounded).
	latest := map[string]pathgraph.PathObservation{}
	for _, o := range obs {
		if cur, ok := latest[o.PathID]; !ok || o.ObservedAt.After(cur.ObservedAt) {
			latest[o.PathID] = o
		}
	}
	hopsOf := map[string][]pathgraph.PathHop{}
	picked := make([]pathgraph.PathObservation, 0, len(latest))
	for _, o := range latest {
		_, hops, _, found, err := s.pathGraph.LatestObservation(ctx, o.TenantID, false, pathgraph.ObservationFilter{
			PathID: o.PathID, DataClasses: classes, Limit: 1,
		})
		if err != nil {
			// A store failure must NOT silently shrink the export: the caller
			// writes this file atomically over the one the correlation engine
			// grounds on, so a partial build would DELETE live path facts and
			// look like paths that simply stopped existing. Abandon the build and
			// keep the last good file instead (§10).
			return pathGraphExport{}, fmt.Errorf("path %s: read latest hops: %w", o.PathID, err)
		}
		if !found {
			continue // answered: no current observation for this path
		}
		hopsOf[o.ObservationID] = hops
		picked = append(picked, o)
	}

	// rank-4 service bindings + rank-6 route relations, per tenant, from the same
	// fact base the resolver uses (no second source of truth).
	src := s.pathFacts
	if src == nil {
		src = serverPathFacts{s}
	}
	var bindings []pgServiceBinding
	var routes []pgRouteRelation
	seenTenant := map[string]bool{}
	for _, o := range picked {
		if seenTenant[o.TenantID] {
			continue
		}
		seenTenant[o.TenantID] = true
		facts, nc, err := src.Facts(ctx, o.TenantID, o.ObservedAt)
		if err != nil {
			// Not fatal to the export (the paths themselves are still exported),
			// but this tenant loses its rank-4/6 relations for the cycle — say so
			// rather than exporting a tenant that merely LOOKS unbound (§10).
			logWarn("path.graph", "path facts unavailable for a tenant — its service bindings and routes are omitted from this export",
				map[string]any{"tenant": o.TenantID, "err": err.Error()})
			continue
		}
		epByAddr := map[string]string{} // (address|context) → endpoint_id, this tenant only
		for _, e := range eps {
			if e.TenantID == o.TenantID {
				epByAddr[normTenant(e.Address)+"|"+normTenant(e.NetworkContext)] = e.EndpointID
			}
		}
		for _, ab := range facts.AppBindings {
			epID, ok := epByAddr[normTenant(ab.Address)+"|"+normTenant(ab.NetworkContext)]
			if !ok {
				continue // a binding to an endpoint we never measured is not a path relation
			}
			bindings = append(bindings, pgServiceBinding{
				ServiceRef: ab.Service, EndpointRef: epID, TenantID: ab.TenantID,
				EvidenceRef: ab.EvidenceRef, Confidence: pathgraph.ConfStrong,
				ValidFrom: isoZ(ab.Window.From), ValidTo: isoZPtr(ab.Window.To),
				Provenance: pgProvenance{
					TenantID: ab.TenantID, ProducerID: "app-identity", ProvenanceID: ab.EvidenceRef,
					DataClass: ab.DataClass, Environment: envOr("PATH_GRAPH_ENVIRONMENT", "prod"),
				},
			})
		}
		// rank 2 also expresses service→endpoint (the cloud inventory attributing the
		// resource that OWNS the address) — the same relationship cloud.AppResourceEdge
		// carries (runs_on/owns). Emitted with its own evidence so the engine can tell
		// the two apart.
		for _, nb := range facts.NICBindings {
			if nb.Service == "" {
				continue
			}
			epID, ok := epByAddr[normTenant(nb.Address)+"|"+normTenant(nb.NetworkContext)]
			if !ok {
				continue
			}
			bindings = append(bindings, pgServiceBinding{
				ServiceRef: nb.Service, EndpointRef: epID, TenantID: nb.TenantID,
				EvidenceRef: nb.EvidenceRef, Confidence: pathgraph.ConfAuthoritative,
				ValidFrom: isoZ(nb.Window.From), ValidTo: isoZPtr(nb.Window.To),
				Provenance: pgProvenance{
					TenantID: nb.TenantID, ProducerID: "cloud-inventory", ProvenanceID: nb.EvidenceRef,
					DataClass: nb.DataClass, Environment: envOr("PATH_GRAPH_ENVIRONMENT", "prod"),
				},
			})
		}
		for _, rr := range facts.Routes {
			routes = append(routes, pgRouteRelation{
				TenantID: rr.TenantID, FromRef: firstNonEmptyStr(rr.FromSubnetName, rr.FromSubnet),
				ToRef: rr.ToRef, Relation: routeRelationVerb(rr.ToKind),
				NetworkContext: rr.NetworkContext, EvidenceRef: rr.EvidenceRef,
				ObservedAt: isoZ(rr.ObservedAt),
				Provenance: pgProvenance{
					TenantID: rr.TenantID, ProducerID: "cloud-topology", ProvenanceID: rr.EvidenceRef,
					DataClass: rr.DataClass, Environment: envOr("PATH_GRAPH_ENVIRONMENT", "prod"),
				},
			})
		}
		_ = nc
	}
	return buildPathGraphExport(eps, defs, picked, hopsOf, bindings, routes, pathFreshness()), nil
}

// routeRelationVerb maps a discovered next-hop kind to the engine's relation
// vocabulary (RouteRelation.relation: routes_via | egresses_via | peers_with | …).
// It reuses cloud.AppResourceEdge's verbs rather than inventing a parallel set.
func routeRelationVerb(toKind string) string {
	switch toKind {
	case "internet_gateway", "nat_gateway", "vpn_gateway":
		return "egresses_via"
	default: // nva, vpc_endpoint, …
		return "routes_via"
	}
}

// pathExportLimit bounds the exported observation set (§9: bounded everything).
func pathExportLimit() int {
	if n := parsePositiveInt(envOr("PATH_GRAPH_EXPORT_LIMIT", "")); n > 0 {
		return n
	}
	return 500
}

func splitAndTrim(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
