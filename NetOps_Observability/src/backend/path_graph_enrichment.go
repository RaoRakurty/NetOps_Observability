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

// pathgraph.Export is the top-level file shape (PathGraphView.from_dict).
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
func (s *server) pathGraphView(ctx context.Context) (pathgraph.Export, error) {
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
		return pathgraph.Export{}, err
	}
	defs, err := s.pathGraph.ListPathDefinitions(ctx, "", true)
	if err != nil {
		return pathgraph.Export{}, err
	}
	obs, err := s.pathGraph.ListObservations(ctx, "", true, pathgraph.ObservationFilter{
		DataClasses: classes, Limit: pathExportLimit(),
	})
	if err != nil {
		return pathgraph.Export{}, err
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
			return pathgraph.Export{}, fmt.Errorf("path %s: read latest hops: %w", o.PathID, err)
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
	var bindings []pathgraph.ExportServiceBinding
	var routes []pathgraph.ExportRouteRelation
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
			bindings = append(bindings, pathgraph.ExportServiceBinding{
				ServiceRef: ab.Service, EndpointRef: epID, TenantID: ab.TenantID,
				EvidenceRef: ab.EvidenceRef, Confidence: pathgraph.ConfStrong,
				ValidFrom: pathgraph.ISOZ(ab.Window.From), ValidTo: pathgraph.ISOZPtr(ab.Window.To),
				Provenance: pathgraph.ExportProvenance{
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
			bindings = append(bindings, pathgraph.ExportServiceBinding{
				ServiceRef: nb.Service, EndpointRef: epID, TenantID: nb.TenantID,
				EvidenceRef: nb.EvidenceRef, Confidence: pathgraph.ConfAuthoritative,
				ValidFrom: pathgraph.ISOZ(nb.Window.From), ValidTo: pathgraph.ISOZPtr(nb.Window.To),
				Provenance: pathgraph.ExportProvenance{
					TenantID: nb.TenantID, ProducerID: "cloud-inventory", ProvenanceID: nb.EvidenceRef,
					DataClass: nb.DataClass, Environment: envOr("PATH_GRAPH_ENVIRONMENT", "prod"),
				},
			})
		}
		for _, rr := range facts.Routes {
			routes = append(routes, pathgraph.ExportRouteRelation{
				TenantID: rr.TenantID, FromRef: firstNonEmptyStr(rr.FromSubnetName, rr.FromSubnet),
				ToRef: rr.ToRef, Relation: routeRelationVerb(rr.ToKind),
				NetworkContext: rr.NetworkContext, EvidenceRef: rr.EvidenceRef,
				ObservedAt: pathgraph.ISOZ(rr.ObservedAt),
				Provenance: pathgraph.ExportProvenance{
					TenantID: rr.TenantID, ProducerID: "cloud-topology", ProvenanceID: rr.EvidenceRef,
					DataClass: rr.DataClass, Environment: envOr("PATH_GRAPH_ENVIRONMENT", "prod"),
				},
			})
		}
		_ = nc
	}
	return pathgraph.BuildExport(eps, defs, picked, hopsOf, bindings, routes, pathFreshness()), nil
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
