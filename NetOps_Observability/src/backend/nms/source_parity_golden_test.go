// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"netops/backend/models"
)

// E7 source parity — the controller half of a RECORDED real event, exactly as
// the runtime hands it to the bus. The correlation engine's parity test
// (src/correlation/test_source_parity_e7.py) feeds this golden through its
// controller normalizer and compares it with the device's own traps for the
// same event (src/correlation/fixtures/source_parity/), so a change on either
// side of the language boundary fails a test instead of silently diverging.
//
// The event: cEDGE-81 (system-ip 10.255.255.81) BGP to 192.168.200.34 in VPN
// 200 going idle → active, 2026-11-01 17:00:07Z–17:01:03Z, captured read-only
// from the lab vManage 20.6.1. The inventory join maps the system-ip to the
// lab's inventory id, as the api's resolver does.
//
// Regenerate after an intended transform change:
//
//	UPDATE_SOURCE_PARITY=1 go test ./nms/ -run TestSourceParityGolden
const sourceParityGolden = "testdata/source_parity/vmanage_20.6.controller_events.json"

type sourceParityResolver map[string]string

func (r sourceParityResolver) ResolveDevice(_ string, kind KeyKind, key, _ string) (string, bool) {
	if kind != KeySystemIP {
		return "", false
	}
	id, ok := r[key]
	return id, ok
}

func TestSourceParityGoldenVManage206(t *testing.T) {
	checkSourceParityGolden(t, sourceParityResolver{"10.255.255.81": "cedge-81-11060ae2"}, sourceParityGolden)
}

// D5 (tracker 374): the same recorded events, joined by the PRODUCTION
// InventoryResolver against an inventory that also holds the BGP peer. The lab
// inventory has no device owning 192.168.200.34, so this case adds one (an
// interface address of a hypothetical VPN-200 neighbour, sourceParityPeerID);
// everything else is the lab's: cEDGE-81's SNMP id, name, management address and
// controller-reported system-ip. identity.go then rewrites PeerID to the
// neighbour's inventory id and keeps the native IP in
// correlation_hints.controller_peer_id — while the router's own trap for the
// same session keeps the IP. The correlation parity test declares that
// divergence; P6 PR-E canonicalises it (docs/design/P6_CANONICALISATION_PLAN_2026-11-07.md).
const (
	sourceParityPeerGolden = "testdata/source_parity/vmanage_20.6.controller_events_peer_in_inventory.json"
	sourceParityPeerID     = "pe-vpn200-parity"
)

func TestSourceParityGoldenVManage206PeerInInventory(t *testing.T) {
	devs := []models.Device{
		{ID: "cedge-81-11060ae2", Name: "cEDGE-81", Address: "192.168.222.106", TenantID: "t_lab",
			Labels: map[string]string{"system_ip": "10.255.255.81"}},
		{ID: sourceParityPeerID, Name: "PE-VPN200", Address: "192.168.222.250", TenantID: "t_lab"},
	}
	ifs := map[string]map[string]string{sourceParityPeerID: {"192.168.200.34": "Gi0/0/1.200"}}
	r := &InventoryResolver{}
	r.Store(BuildInventoryIndex(devs, nil, ifs))
	got := checkSourceParityGolden(t, r, sourceParityPeerGolden)
	for _, e := range got {
		if e.DeviceID != "cedge-81-11060ae2" || e.PeerID != sourceParityPeerID ||
			e.CorrelationHints["controller_peer_id"] != "192.168.200.34" {
			t.Fatalf("the peer did not resolve as the D5 case requires: device=%q peer=%q hints=%v",
				e.DeviceID, e.PeerID, e.CorrelationHints)
		}
	}
}

// checkSourceParityGolden runs the recorded vManage events through the
// production transform + runtime with resolver r and compares the produced
// controller events with the golden file (regenerated under
// UPDATE_SOURCE_PARITY=1). It returns what was produced.
func checkSourceParityGolden(t *testing.T, r DeviceResolver, golden string) []ControllerEvent {
	t.Helper()
	raw, err := os.ReadFile("testdata/source_parity/vmanage_20.6_events_cedge81_bgp.json")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := VManageAutoTransformer{}.TransformStream("t_lab", "i-parity", "events", raw)
	if err != nil {
		t.Fatal(err)
	}
	var got []ControllerEvent
	sinks := okSinks()
	sinks.ProduceEvents = func(_ context.Context, _ string, evs []ControllerEvent) (int64, error) {
		got = append(got, evs...)
		return int64(len(evs)), nil
	}
	m := NewMemStore()
	rt := NewRuntime(m, sinks, 0)
	rt.SetDeviceResolver(r)
	ic := addIntegration(t, m, "t_lab", "i-parity", "vmanage", "https://vmanage.invalid", 120)
	if n := rt.IngestBatch(context.Background(), ic, batch); n != int64(len(got)) || n == 0 {
		t.Fatalf("produced %d, captured %d", n, len(got))
	}
	for i := range got {
		got[i].IngestTime = time.Time{} // wall clock: the only non-deterministic field
	}
	out, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if os.Getenv("UPDATE_SOURCE_PARITY") == "1" {
		if err := os.WriteFile(golden, out, 0o600); err != nil {
			t.Fatal(err)
		}
		return got
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v — regenerate with UPDATE_SOURCE_PARITY=1", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("the controller events for the recorded event changed — if intended, regenerate with "+
			"UPDATE_SOURCE_PARITY=1 and re-run src/correlation/test_source_parity_e7.py.\ngot:\n%s", out)
	}
	return got
}
