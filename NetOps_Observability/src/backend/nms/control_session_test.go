// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"os"
	"testing"
	"time"
)

// Tracker 397: a control session the CONTROLLER reported is emitted
// edge-centred on BOTH lanes that carry it — the /dataservice/event lane
// (vmanageEventsTransform) and the polled-state lane (control/connections rows
// → StateTracker → SDWANStateChangeEvents) — and both spell the edge and the
// controller the same way once the inventory resolver has rewritten them.

func controlSessionResolver() *mapResolver {
	return &mapResolver{m: map[string]string{
		"t1|10.255.255.80": "cedge-80-b0afc197",
		"t1|10.255.255.2":  "vsmart-1a2b3c4d",
		"t1|10.255.255.1":  "vmanage-5e6f7a8b",
	}}
}

func controlState(device, peer, peerType, state string, at int64) ControllerState {
	return ControllerState{
		TenantID: "t1", IntegrationID: "i1", SourceSystem: "vmanage",
		EntityKey: device + "-default-" + peer + "-biz-internet", StateKind: "control_conn",
		CurrentState: state, DeviceID: device, PeerID: peer, Time: time.Unix(at, 0),
		Data: map[string]any{"device_name": "x", "peer_system_ip": peer, "peer_type": peerType},
	}
}

func TestControllerRowStateChangeIsEmittedEdgeCentred(t *testing.T) {
	p := NewPipeline(64)
	p.Resolver, p.KeyKind = controlSessionResolver(), KeySystemIP
	p.Route(Batch{States: []ControllerState{controlState("10.255.255.2", "10.255.255.80", "vedge", "up", 100)}})
	r := p.Route(Batch{States: []ControllerState{controlState("10.255.255.2", "10.255.255.80", "vedge", "down", 160)}})
	if len(r.StateChanges) != 1 || r.StateChanges[0].Session == nil {
		t.Fatalf("want one flipped control-session change, got %+v", r.StateChanges)
	}
	evs := SDWANStateChangeEvents(ConnectorSpec{SourceSystem: "vmanage"}, "t1", "i1", r.StateChanges)
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.NormalizedEventType != "controller_control_connection_loss" {
		t.Errorf("kind = %q", e.NormalizedEventType)
	}
	if e.DeviceID != "cedge-80-b0afc197" || e.PeerID != "vsmart-1a2b3c4d" {
		t.Errorf("(device, peer) = (%s, %s), want the edge losing the vSmart", e.DeviceID, e.PeerID)
	}
	h := e.CorrelationHints
	if h["controller_peer_id"] != "10.255.255.2" || h["controller_device_id"] != "10.255.255.80" {
		t.Errorf("native keys not kept (the engine spells the controller by system-ip): %v", h)
	}
	if h["reported_by"] != "10.255.255.2" || h["session_direction"] != "edge_lost_controller" {
		t.Errorf("direction hints missing: %v", h)
	}
	if e.SiteID != "" {
		t.Errorf("SiteID = %q: the record's site is the controller's, not the edge's", e.SiteID)
	}
}

func TestEdgeRowStateChangeKeepsItsShape(t *testing.T) {
	p := NewPipeline(64)
	p.Route(Batch{States: []ControllerState{controlState("10.255.255.80", "10.255.255.2", "vsmart", "up", 100)}})
	r := p.Route(Batch{States: []ControllerState{controlState("10.255.255.80", "10.255.255.2", "vsmart", "down", 160)}})
	if len(r.StateChanges) != 1 || r.StateChanges[0].Session != nil {
		t.Fatalf("an edge's own row must not be flipped: %+v", r.StateChanges)
	}
	e := SDWANStateChangeEvents(ConnectorSpec{SourceSystem: "vmanage"}, "t1", "i1", r.StateChanges)[0]
	if e.DeviceID != "10.255.255.80" || e.PeerID != "10.255.255.2" {
		t.Errorf("(device, peer) = (%s, %s), want unchanged", e.DeviceID, e.PeerID)
	}
	if _, ok := e.CorrelationHints["session_direction"]; ok {
		t.Errorf("unflipped event carries a direction hint: %v", e.CorrelationHints)
	}
}

func TestNonControlStateChangeIsNeverFlipped(t *testing.T) {
	p := NewPipeline(64)
	s := controlState("10.255.255.2", "10.255.255.80", "vedge", "up", 100)
	s.StateKind, s.EntityKey = "bfd", "bfd-key"
	p.Route(Batch{States: []ControllerState{s}})
	s.CurrentState, s.Time = "down", time.Unix(160, 0)
	r := p.Route(Batch{States: []ControllerState{s}})
	if len(r.StateChanges) != 1 || r.StateChanges[0].Session != nil {
		t.Fatalf("a BFD change is not a control session: %+v", r.StateChanges)
	}
}

// TestRecordedDrillEventsResolveLikeTheStateLane: the recorded drill events,
// through the pipeline's canonicalisation, land on the edge's inventory id and
// keep both native system-ips — the same spelling the state lane produces.
func TestRecordedDrillEventsResolveLikeTheStateLane(t *testing.T) {
	raw, err := os.ReadFile("testdata/vmanage_20.6/events_control_connection.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := vmanageEventsTransform("t1", "i1", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(64)
	p.Resolver, p.KeyKind = controlSessionResolver(), KeySystemIP
	r := p.Route(b)
	if len(r.Events) != 4 {
		t.Fatalf("want 4 events, got %d", len(r.Events))
	}
	natives := map[string]string{"vsmart-1a2b3c4d": "10.255.255.2", "vmanage-5e6f7a8b": "10.255.255.1"}
	for _, e := range r.Events {
		if e.DeviceID != "cedge-80-b0afc197" || e.CorrelationHints["controller_device_id"] != "10.255.255.80" {
			t.Errorf("event not on the edge: device=%s hints=%v", e.DeviceID, e.CorrelationHints)
		}
		if want, ok := natives[e.PeerID]; !ok || e.CorrelationHints["controller_peer_id"] != want {
			t.Errorf("peer=%s controller_peer_id=%s, want a controller id + its system-ip", e.PeerID, e.CorrelationHints["controller_peer_id"])
		}
	}
}
