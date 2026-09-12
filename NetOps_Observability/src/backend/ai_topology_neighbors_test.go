// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_topology_neighbors_test.go — review 3.9-12: the assistant must never be
// told a device has no neighbours because the FLEET's link set was long.

import (
	"fmt"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/tac"
)

// fleetLinks builds n adjacencies between devices that are NOT the subject, in
// the order a collector would hand them over. Synthetic by construction: the
// shape of the slice is the whole subject of the test, not any device's output.
func fleetLinks(n int) []topoLink {
	out := make([]topoLink, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, topoLink{
			Source: fmt.Sprintf("other-%03d", i), Target: fmt.Sprintf("other-%03d", i+1),
			SourceName: fmt.Sprintf("other-%03d", i), TargetName: fmt.Sprintf("other-%03d", i+1),
			LocalPort: "Et1", RemotePort: "Et2", SourceProto: "lldp", Resolved: true,
		})
	}
	return out
}

// TestAIDeviceNeighbors_SubjectEdgesSurviveALargeFleet is the defect itself. The
// bound used to be applied to the fleet-wide slice BEFORE the subject's edges
// were selected out of it, so a device whose edges sat past the bound came back
// with no neighbours and the assistant reported it as having none.
func TestAIDeviceNeighbors_SubjectEdgesSurviveALargeFleet(t *testing.T) {
	links := fleetLinks(aiTopoMaxNeighbors + 40)
	links = append(links,
		topoLink{Source: "core1", Target: "leaf9", SourceName: "core1", TargetName: "leaf9",
			LocalPort: "Et49", RemotePort: "Et1", SourceProto: "lldp", Resolved: true},
		topoLink{Source: "leaf7", Target: "core1", SourceName: "leaf7", TargetName: "core1",
			LocalPort: "Et2", RemotePort: "Et50", SourceProto: "cdp", Resolved: true},
	)

	got, capped := aiDeviceNeighbors(links, "core1")
	if capped {
		t.Error("capped = true: this device has two adjacencies, nothing was cut")
	}
	if len(got) != 2 {
		t.Fatalf("got %d neighbours, want 2 — the fleet's links spent the bound before this device was looked at", len(got))
	}
	// The edge where the subject is the SOURCE is reported from its own side.
	if got[0].PeerName != "leaf9" || got[0].LocalPort != "Et49" || got[0].PeerPort != "Et1" || got[0].Source != "lldp" {
		t.Errorf("source-side edge = %+v, want leaf9 via Et49→Et1 (lldp)", got[0])
	}
	// The edge where the subject is the TARGET is flipped, so "local" is still
	// the subject's own port.
	if got[1].PeerName != "leaf7" || got[1].LocalPort != "Et50" || got[1].PeerPort != "Et2" || got[1].Source != "cdp" {
		t.Errorf("target-side edge = %+v, want leaf7 via Et50→Et2 (cdp)", got[1])
	}
}

// TestAIDeviceNeighbors_CapAppliesToTheSubjectsOwnEdges proves the bound still
// exists and now measures the right thing.
func TestAIDeviceNeighbors_CapAppliesToTheSubjectsOwnEdges(t *testing.T) {
	links := fleetLinks(50)
	for i := 0; i < aiTopoMaxNeighbors+5; i++ {
		links = append(links, topoLink{
			Source: "core1", Target: fmt.Sprintf("leaf-%03d", i),
			SourceName: "core1", TargetName: fmt.Sprintf("leaf-%03d", i),
			LocalPort: fmt.Sprintf("Et%d", i), RemotePort: "Et1", SourceProto: "lldp", Resolved: true,
		})
	}
	got, capped := aiDeviceNeighbors(links, "core1")
	if !capped {
		t.Error("capped = false, want true: this device's own adjacencies were cut")
	}
	if len(got) != aiTopoMaxNeighbors {
		t.Fatalf("got %d neighbours, want the bound %d", len(got), aiTopoMaxNeighbors)
	}
}

// TestAIDeviceNeighbors_NoEdgesIsHonest: a device that genuinely has no
// adjacencies reports none, and says nothing was cut.
func TestAIDeviceNeighbors_NoEdgesIsHonest(t *testing.T) {
	got, capped := aiDeviceNeighbors(fleetLinks(10), "core1")
	if len(got) != 0 || capped {
		t.Fatalf("got %d neighbours (capped=%v), want none and nothing cut", len(got), capped)
	}
}

// TestAINeighborCapNote_NamesThisDevice guards the wording. The note is read by
// the model and by the operator, and a cap that hides EVERY neighbour of the
// subject must not be described as a partial view of the fleet.
func TestAINeighborCapNote_NamesThisDevice(t *testing.T) {
	low := strings.ToLower(aiNeighborCapNote)
	if !strings.Contains(low, "this device") {
		t.Error("the note does not say the loss is about THIS device")
	}
	if !strings.Contains(low, "incomplete") {
		t.Error("the note does not say the answer is incomplete")
	}
}

// ── the caveat has to reach the bundle too (review 3.9-12, second half) ──────

// TestTACTopologyCarriesTheCoverageCaveat is the half of 3.9-12 the cap fix did
// not close. ai.TopologyContext records what the adapter could NOT see in
// Notes — the neighbour list was cut, the seam register could not be read — and
// tacTopology built the bundle's topology section out of Neighbors/Seams/Paths
// only. A TAC engineer therefore read a neighbour list that looked complete when
// it was not, and a device with no seam line that may simply never have been
// asked. A vendor cannot tell an absent neighbour from an unreported one.
func TestTACTopologyCarriesTheCoverageCaveat(t *testing.T) {
	ctxInfo := ai.TopologyContext{
		DeviceID: "core1", DeviceName: "core1", Site: "lab", Role: "spine",
		Neighbors: []ai.TopologyNeighbor{
			{LocalPort: "Et49", PeerName: "leaf9", PeerPort: "Et1", Source: "lldp"},
		},
		Notes: []string{
			aiNeighborCapNote,
			"  ", // blank notes carry nothing and must not become an empty line
			"the seam register could not be read — seam ownership is UNKNOWN for this answer",
		},
	}

	got := tacTopologyNotes(ctxInfo)

	var coverage []tac.TopologyNote
	for _, n := range got {
		if n.Kind == "coverage" {
			coverage = append(coverage, n)
		}
	}
	if len(coverage) != 2 {
		t.Fatalf("the bundle carries %d coverage notes, want 2 — the caveats were dropped and the section reads as complete: %+v",
			len(coverage), got)
	}
	if coverage[0].Detail != aiNeighborCapNote {
		t.Errorf("the neighbour-cap caveat did not reach the bundle: %q", coverage[0].Detail)
	}
	if !strings.Contains(coverage[1].Detail, "seam register") {
		t.Errorf("the seam-register caveat did not reach the bundle: %q", coverage[1].Detail)
	}
	// A caveat qualifies everything under it, so it is not filed after the data
	// it is a caveat about.
	if got[0].Kind != "coverage" || got[1].Kind != "coverage" {
		t.Errorf("the caveats are not first, so they read as a footnote to a list that already looked complete: %+v", got)
	}
	// And the evidence itself is unchanged.
	if got[2].Kind != "site" || got[3].Kind != "neighbor" || got[3].Ref != "leaf9" {
		t.Errorf("the topology rows were disturbed: %+v", got)
	}
}

// The guard against the caveat becoming noise: an answer that saw everything
// carries no coverage note at all, so a "coverage" line in a bundle always means
// something real was missing.
func TestTACTopologyIsQuietWhenNothingWasMissed(t *testing.T) {
	got := tacTopologyNotes(ai.TopologyContext{
		DeviceID: "core1", Site: "lab", Role: "spine",
		Neighbors: []ai.TopologyNeighbor{{LocalPort: "Et49", PeerName: "leaf9", PeerPort: "Et1", Source: "lldp"}},
	})
	for _, n := range got {
		if n.Kind == "coverage" {
			t.Fatalf("a complete answer invented a coverage caveat: %+v", n)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d notes, want the site line and the one neighbour: %+v", len(got), got)
	}
}
