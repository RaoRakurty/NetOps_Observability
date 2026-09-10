// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_topology_neighbors_test.go — review 3.9-12: the assistant must never be
// told a device has no neighbours because the FLEET's link set was long.

import (
	"fmt"
	"strings"
	"testing"
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
