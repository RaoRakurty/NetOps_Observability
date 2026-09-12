// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"testing"
	"time"
)

func wchange(kind, from, to string, flaps int64) StateChange {
	return StateChange{
		Record: StateRecord{
			EntityKey: "ap-abc123", StateKind: kind, CurrentState: to,
			PreviousState: from, LastSeen: time.Unix(1753500000, 0).UTC(),
			FlapCount: flaps, DeviceID: "a8:66:7f:04:00:01",
		},
		From: from, To: to,
	}
}

func TestWirelessStateChangeEvents(t *testing.T) {
	evs := WirelessStateChangeEvents("t1", "int-1", "catalyst_9800", []StateChange{
		wchange("ap_join", "up", "down", 1),
		wchange("ap_join", "down", "up", 1),
		wchange("radio_oper", "up", "down", 1),
		wchange("bfd", "up", "down", 1), // NOT a wireless kind — must be ignored
	})
	if len(evs) != 3 {
		t.Fatalf("want 3 wireless events (bfd ignored), got %d", len(evs))
	}
	if evs[0].NormalizedEventType != "wireless_ap_down" || evs[0].Severity != "high" {
		t.Fatalf("ap down: %+v", evs[0])
	}
	if evs[1].NormalizedEventType != "wireless_ap_up" || evs[1].Severity != "info" {
		t.Fatalf("ap up: %+v", evs[1])
	}
	if evs[1].EvidenceRole != RoleSupporting {
		t.Fatal("a recovery supports; it is not a fault")
	}
	if evs[2].NormalizedEventType != "wireless_radio_down" {
		t.Fatalf("radio down: %+v", evs[2])
	}
	// DeviceID must carry the CANONICAL entity id — the consumer binds to it.
	if evs[0].DeviceID != "ap-abc123" {
		t.Fatalf("DeviceID must be the canonical entity id, got %q", evs[0].DeviceID)
	}
	// Deterministic ids: same transition → same event id + dedupe key.
	again := WirelessStateChangeEvents("t1", "int-1", "catalyst_9800", []StateChange{
		wchange("ap_join", "up", "down", 1),
	})
	if again[0].EventID != evs[0].EventID || again[0].DedupeKey != evs[0].DedupeKey {
		t.Fatal("event identity must be deterministic across cycles")
	}
}

func TestWirelessFlapEscalation(t *testing.T) {
	evs := WirelessStateChangeEvents("t1", "int-1", "catalyst_9800", []StateChange{
		wchange("ap_join", "up", "down", wirelessFlapThreshold),
		wchange("ap_join", "down", "up", wirelessFlapThreshold+1),
	})
	if evs[0].NormalizedEventType != "wireless_ap_join_flap" {
		t.Fatalf("at threshold the down must escalate to flap: %+v", evs[0])
	}
	// Recovery during a flap storm is part of the flap, not a clean clear.
	if evs[1].NormalizedEventType != "wireless_ap_join_flap" || evs[1].Severity != "warn" {
		t.Fatalf("flap-storm recovery: %+v", evs[1])
	}
}

// An unmappable transition must not fabricate a fault.
func TestWirelessUnknownTransitionSilent(t *testing.T) {
	evs := WirelessStateChangeEvents("t1", "int-1", "catalyst_9800", []StateChange{
		wchange("ap_join", "up", "degraded", 1),
	})
	if len(evs) != 0 {
		t.Fatalf("unknown target state must emit nothing, got %+v", evs)
	}
}
