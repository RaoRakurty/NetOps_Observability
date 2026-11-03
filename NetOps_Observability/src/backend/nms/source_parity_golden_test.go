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
	rt.SetDeviceResolver(sourceParityResolver{"10.255.255.81": "cedge-81-11060ae2"})
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
		if err := os.WriteFile(sourceParityGolden, out, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(sourceParityGolden)
	if err != nil {
		t.Fatalf("%v — regenerate with UPDATE_SOURCE_PARITY=1", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("the controller events for the recorded event changed — if intended, regenerate with "+
			"UPDATE_SOURCE_PARITY=1 and re-run src/correlation/test_source_parity_e7.py.\ngot:\n%s", out)
	}
}
