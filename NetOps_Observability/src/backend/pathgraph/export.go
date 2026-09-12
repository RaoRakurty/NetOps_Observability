// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pathgraph

// export.go — the seams.json enrichment EXPORT schema (Phase-2 W4.12,
// extracted from package main's path_graph_enrichment.go): the wire types the
// Python correlation engine consumes (a frozen cross-language contract) and
// BuildExport, the pure projection from the domain records. The enrichment
// worker and the srv view assembly stay in main.

import (
	"time"
)

type Export struct {
	Endpoints       []ExportEndpoint       `json:"endpoints"`
	Observations    []ExportObservation    `json:"observations"`
	ServiceBindings []ExportServiceBinding `json:"service_bindings"`
	NatSessions     []ExportNatSession     `json:"nat_sessions"`
	Routes          []ExportRouteRelation  `json:"routes"`
	FreshnessS      float64                `json:"freshness_s"`
	ContractVersion int                    `json:"contract_version"`
}

// ExportProvenance mirrors Provenance.from_dict (§1).
type ExportProvenance struct {
	TenantID     string `json:"tenant_id"`
	ProducerID   string `json:"producer_id"`
	ProvenanceID string `json:"provenance_id"`
	DataClass    string `json:"data_class"`
	Environment  string `json:"environment"`
	ScenarioID   string `json:"scenario_id"`
	RunID        string `json:"run_id"`
}

func exportProv(p Provenance) ExportProvenance {
	return ExportProvenance{
		TenantID: p.TenantID, ProducerID: p.ProducerID, ProvenanceID: p.ProvenanceID,
		DataClass: p.DataClass, Environment: p.Environment, ScenarioID: p.ScenarioID, RunID: p.RunID,
	}
}

type ExportEndpoint struct {
	EndpointID        string           `json:"endpoint_id"`
	TenantID          string           `json:"tenant_id"`
	Address           string           `json:"address"`
	NetworkContext    string           `json:"network_context"`
	Kind              string           `json:"kind"`
	AddressFamily     string           `json:"address_family"`
	ResolvedEntityRef string           `json:"resolved_entity_ref"`
	ResolutionMethod  string           `json:"resolution_method"`
	Confidence        string           `json:"confidence"`
	ValidFrom         string           `json:"valid_from"`
	ValidTo           string           `json:"valid_to"`
	EvidenceRef       string           `json:"evidence_ref"`
	Provenance        ExportProvenance `json:"provenance"`
}

type ExportDefinition struct {
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

type ExportHop struct {
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

type ExportObservation struct {
	ObservationID string           `json:"observation_id"`
	PathID        string           `json:"path_id"`
	TenantID      string           `json:"tenant_id"`
	ObservedAt    string           `json:"observed_at"`
	Method        string           `json:"method"`
	VantageID     string           `json:"vantage_id"`
	Status        string           `json:"status"`
	HopCount      int              `json:"hop_count"`
	Hops          []ExportHop      `json:"hops"`
	Provenance    ExportProvenance `json:"provenance"`
	Definition    ExportDefinition `json:"definition"`
}

// ExportServiceBinding is rank 4 (§3): application/service → endpoint. It is the
// Go-side projection of the SAME relationship cloud.AppResourceEdge models
// (owns/runs_on/fronts/…) — the app→resource vocabulary, resolved down to the
// ENDPOINT the service actually listens on, which is what the path graph joins.
type ExportServiceBinding struct {
	ServiceRef  string           `json:"service_ref"`
	EndpointRef string           `json:"endpoint_ref"`
	TenantID    string           `json:"tenant_id"`
	EvidenceRef string           `json:"evidence_ref"`
	Confidence  string           `json:"confidence"`
	ValidFrom   string           `json:"valid_from"`
	ValidTo     string           `json:"valid_to"`
	Provenance  ExportProvenance `json:"provenance"`
}

type ExportNatSession struct {
	TenantID    string           `json:"tenant_id"`
	PreAddress  string           `json:"pre_address"`
	PostAddress string           `json:"post_address"`
	PreContext  string           `json:"pre_context"`
	PostContext string           `json:"post_context"`
	Protocol    string           `json:"protocol"`
	EvidenceRef string           `json:"evidence_ref"`
	ObservedAt  string           `json:"observed_at"`
	Provenance  ExportProvenance `json:"provenance"`
}

type ExportRouteRelation struct {
	TenantID       string           `json:"tenant_id"`
	FromRef        string           `json:"from_ref"`
	ToRef          string           `json:"to_ref"`
	Relation       string           `json:"relation"`
	NetworkContext string           `json:"network_context"`
	EvidenceRef    string           `json:"evidence_ref"`
	ObservedAt     string           `json:"observed_at"`
	Provenance     ExportProvenance `json:"provenance"`
}

// isoZ renders a timestamp the way Python's _dt() can parse it (UTC, Z-suffixed).
// An empty/zero time renders as "" — Python maps that to None (an OPEN window /
// absent time), which is the correct meaning for valid_to.
func ISOZ(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func ISOZPtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return ISOZ(*t)
}

// BuildExport assembles the engine's view from the store + the fact base.
// PURE given its inputs (unit-tested): the caller does the I/O.
func BuildExport(eps []Endpoint, defs []PathDefinition,
	obs []PathObservation, hopsOf map[string][]PathHop,
	bindings []ExportServiceBinding, routes []ExportRouteRelation, freshness time.Duration) Export {

	out := Export{
		Endpoints: []ExportEndpoint{}, Observations: []ExportObservation{},
		ServiceBindings: bindings, NatSessions: []ExportNatSession{}, Routes: routes,
		FreshnessS: freshness.Seconds(), ContractVersion: ContractVersion,
	}
	if out.ServiceBindings == nil {
		out.ServiceBindings = []ExportServiceBinding{}
	}
	if out.Routes == nil {
		out.Routes = []ExportRouteRelation{}
	}
	for _, e := range eps {
		out.Endpoints = append(out.Endpoints, ExportEndpoint{
			EndpointID: e.EndpointID, TenantID: e.TenantID, Address: e.Address,
			NetworkContext: e.NetworkContext, Kind: e.Kind, AddressFamily: e.AddressFamily,
			ResolvedEntityRef: e.ResolvedEntityRef, ResolutionMethod: e.ResolutionMethod,
			Confidence: e.Confidence, ValidFrom: ISOZ(e.ValidFrom), ValidTo: ISOZPtr(e.ValidTo),
			EvidenceRef: e.EvidenceRef, Provenance: exportProv(e.Provenance),
		})
	}
	defByID := map[string]PathDefinition{}
	for _, d := range defs {
		defByID[d.PathID] = d
	}
	for _, o := range obs {
		d := defByID[o.PathID]
		hops := hopsOf[o.ObservationID]
		ho := make([]ExportHop, 0, len(hops))
		for _, h := range hops {
			ho = append(ho, ExportHop{
				HopIndex: h.HopIndex, State: h.State, ObservedAddress: h.ObservedAddress,
				ResolvedEntityRef: h.ResolvedEntityRef, ResolutionMethod: h.ResolutionMethod,
				Confidence: h.Confidence, SeamID: h.SeamID, RTTms: h.RTTms,
				Transformation: h.Transformation, EvidenceRef: h.EvidenceRef,
				ObservedAt: ISOZ(h.ObservedAt), TenantID: h.TenantID,
			})
		}
		out.Observations = append(out.Observations, ExportObservation{
			ObservationID: o.ObservationID, PathID: o.PathID, TenantID: o.TenantID,
			ObservedAt: ISOZ(o.ObservedAt), Method: o.Method, VantageID: o.VantageID,
			Status: o.Status, HopCount: o.HopCount, Hops: ho, Provenance: exportProv(o.Provenance),
			Definition: ExportDefinition{
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
