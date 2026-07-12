package main

import (
	"context"
	"testing"
	"time"

	"netops/backend/pathgraph"
)

// A partial run whose terminal hop is a shared seam endpoint takes its seam from
// THIS path's own last complete observation — and only from it. No prior complete
// run, or a different terminal address, yields NO hint (an honest absence).
func TestSeamHintFromHistory(t *testing.T) {
	_, s := newTestServerState(t)
	s.pathGraph = newMemPathGraphStore()
	ctx := context.Background()
	tenant := "t_hint"
	now := time.Date(2026, 7, 12, 22, 0, 0, 0, time.UTC)

	def := pathgraph.PathDefinition{
		PathID: "pd-hint", SrcAddress: "172.40.40.200", DstAddress: "10.60.10.10",
		Direction: "forward", Protocol: "icmp", VantageID: "lan-vantage-1",
		Provenance: pathgraph.Provenance{TenantID: tenant, DataClass: pathgraph.DataClassLive, ProvenanceID: "pv-def"},
	}
	hop := func(obsID string, ttl int, addr, seam, transform string) pathgraph.PathHop {
		if transform == "" {
			transform = pathgraph.TransformNone
		}
		return pathgraph.PathHop{
			ObservationID: obsID, HopIndex: ttl, State: pathgraph.HopResponding, ObservedAddress: addr,
			SeamID: seam, Transformation: transform, ResolutionMethod: pathgraph.MethodUnresolved,
			Confidence: pathgraph.ConfUnknown, Kind: pathgraph.KindUnknown, EvidenceRef: "pv-" + obsID,
			ObservedAt: now, TenantID: tenant, DataClass: pathgraph.DataClassLive,
		}
	}
	obsOf := func(id, status string, at time.Time) pathgraph.PathObservation {
		return pathgraph.PathObservation{
			ObservationID: id, PathID: def.PathID, ObservedAt: at, Method: pathgraph.MethodTracerouteICMP,
			VantageID: def.VantageID, Status: status, ContractVersion: pathgraph.ContractVersion,
			Provenance: pathgraph.Provenance{TenantID: tenant, DataClass: pathgraph.DataClassLive,
				Environment: "lab", ProvenanceID: "pv-" + id, ProducerID: "test", RunID: "run-" + id},
		}
	}

	// The current partial run: dies at the shared seam endpoint, no seam stamped.
	cur := obsOf("ob-partial", pathgraph.StatusPartial, now)
	curHops := []pathgraph.PathHop{
		hop("ob-partial", 1, "172.40.40.1", "", ""),
		hop("ob-partial", 2, "10.70.245.122", "", ""),
		hop("ob-partial", 3, "10.70.245.122", "", ""),
	}

	// No history yet → no hint.
	if h := s.seamHintFromHistory(ctx, tenant, false, cur, curHops); h != nil {
		t.Fatalf("no prior complete run must yield no hint, got %+v", h)
	}

	// A prior COMPLETE run stamped the seam on the same address.
	prior := obsOf("ob-complete", pathgraph.StatusComplete, now.Add(-10*time.Minute))
	priorHops := []pathgraph.PathHop{
		hop("ob-complete", 1, "172.40.40.1", "", ""),
		hop("ob-complete", 2, "10.70.245.122", "sm-f36b592d4e76", pathgraph.TransformTunnelIngress),
		hop("ob-complete", 3, "10.60.1.10", "sm-f36b592d4e76", pathgraph.TransformTunnelEgress),
		hop("ob-complete", 4, "10.60.10.10", "", ""),
	}
	if err := s.pathGraph.AppendObservation(ctx, def, prior, priorHops); err != nil {
		t.Fatalf("append prior: %v", err)
	}
	// A NEWER partial must not shadow the complete one in the history query.
	if err := s.pathGraph.AppendObservation(ctx, def, cur, curHops); err != nil {
		t.Fatalf("append current: %v", err)
	}

	h := s.seamHintFromHistory(ctx, tenant, false, cur, curHops)
	if h == nil || h.SeamID != "sm-f36b592d4e76" || h.Transformation != pathgraph.TransformTunnelIngress {
		t.Fatalf("hint must come from the prior complete run, got %+v", h)
	}
	if h.EvidenceRef != "pv-ob-complete" {
		t.Fatalf("hint must cite the prior observation, got %q", h.EvidenceRef)
	}

	// A different terminal address takes nothing from history.
	other := []pathgraph.PathHop{hop("ob-partial", 1, "172.40.40.1", "", "")}
	if h := s.seamHintFromHistory(ctx, tenant, false, cur, other); h != nil {
		t.Fatalf("terminal address absent from history must yield no hint, got %+v", h)
	}
}
