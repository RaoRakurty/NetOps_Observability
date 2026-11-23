// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_recovery_scope_test.go — tracker 443: a recovery is evidence for THIS
// incident only when it is about one of the incident's own entities.
//
// The engine's archive slice keeps every loose `*_clear` inside the object's
// time bounds, tenant-wide (src/correlation/main.py `_archive_slice`), because
// clears are not nodes and the slice is replay-exact without them. Before the
// fix the report's recovery stage read every one of them, so a different
// port's link-up — on the same box or another — marked this incident
// recovered. Tracker 380 made every lane's link / adjacency up a `<kind>_clear`,
// which put far more of them in that pool.

import (
	"strings"
	"testing"
)

// Vendor spellings of "the faulted port" and "a different port on the same box".
// Each lane binds the clear to the fault's entity with the fault's spelling
// (tracker 380: same entity, tokens, native_id), so the scope is vendor-neutral.
var recoveryScopeVendors = []struct {
	name, lane, kind, entityType, faulted, other string
}{
	{"cisco-ios-xe syslog", "control_plane", "link_state_change", "interface", "r1:GigabitEthernet1", "r1:GigabitEthernet2"},
	{"juniper junos syslog", "control_plane", "link_state_change", "interface", "mx1:ge-0/0/1", "mx1:ge-0/0/2"},
	{"nokia sr-os trap", "control_plane", "link_state_change", "interface", "sr1:1/1/1", "sr1:1/1/2"},
	{"arista eos syslog", "control_plane", "link_state_change", "interface", "eos1:Ethernet1", "eos1:Ethernet2"},
	{"sonic portmgrd", "control_plane", "link_state_change", "interface", "sonic1:Ethernet0", "sonic1:Ethernet4"},
	{"bgp peer (any vendor)", "control_plane", "bgp_adjacency_change", "device", "r1:10.0.0.2", "r1:10.0.0.9"},
	{"vmanage relayed alarm", "management_plane", "link_state_change", "interface", "cedge-81:GigabitEthernet1", "cedge-82:GigabitEthernet1"},
}

func recoveryScopeIncident(v struct {
	name, lane, kind, entityType, faulted, other string
}, clearEntity string) []map[string]any {
	return []map[string]any{
		testSig(v.kind, v.lane, "obs-1", v.entityType, v.faulted, "high", "2026-07-12 18:12:00", true, nil),
		testSig(v.kind+"_clear", v.lane, "obs-1", v.entityType, clearEntity, "info", "2026-07-12 18:20:00", false,
			map[string]any{"clear_ts": "2026-07-12 18:20:00"}),
	}
}

func TestRecoveryIgnoresAnotherEntitysClear(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	for _, v := range recoveryScopeVendors {
		t.Run(v.name, func(t *testing.T) {
			rep := buildTestReport(t, meta, recoveryScopeIncident(v, v.other))
			if rep.States.Recovery == "explicitly_confirmed" || rep.States.Recovery == "component_only" ||
				rep.States.Incident == "recovered" || rep.Times.RecoveredAt != "" {
				t.Fatalf("%s's clear recovered the incident on %s: incident=%s recovery=%s recovered_at=%q",
					v.other, v.faulted, rep.States.Incident, rep.States.Recovery, rep.Times.RecoveredAt)
			}
		})
	}
}

func TestRecoveryStillReadsTheIncidentsOwnClear(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	for _, v := range recoveryScopeVendors {
		t.Run(v.name, func(t *testing.T) {
			rep := buildTestReport(t, meta, recoveryScopeIncident(v, v.faulted))
			if rep.States.Incident != "recovered" || rep.States.Recovery != "explicitly_confirmed" {
				t.Fatalf("own clear must recover: incident=%s recovery=%s", rep.States.Incident, rep.States.Recovery)
			}
			if rep.Times.RecoveredAt != "2026-07-12 18:20:00 UTC" {
				t.Fatalf("recovered_at = %q, want the clear's time", rep.Times.RecoveredAt)
			}
		})
	}
}

// The other port's LATER clear must not move the recovery time of an incident
// its own clear already recovered, and must not be counted as its evidence.
func TestRecoveryTimeComesFromTheIncidentsOwnEntities(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	sigs := []map[string]any{
		testSig("link_state_change", "control_plane", "r1", "interface", "r1:Gi1", "high", "2026-07-12 18:12:00", true, nil),
		testSig("link_state_change_clear", "control_plane", "r1", "interface", "r1:Gi1", "info", "2026-07-12 18:15:00", false,
			map[string]any{"clear_ts": "2026-07-12 18:15:00"}),
		testSig("link_state_change_clear", "control_plane", "r1", "interface", "r1:Gi2", "info", "2026-07-12 18:25:00", false,
			map[string]any{"clear_ts": "2026-07-12 18:25:00", "signal_id": "s-other-port"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.Times.RecoveredAt != "2026-07-12 18:15:00 UTC" {
		t.Fatalf("recovered_at = %q, want the incident's own clear (18:15), not another port's (18:25)", rep.Times.RecoveredAt)
	}
}

// A semantic up-state (`*_status` at info, state=up) on another seam is not
// this incident's recovery either.
func TestRecoveryIgnoresAnotherEntitysStateUp(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	down := testSig("ipsec_tunnel_status", "control_plane", "ipsec:gw", "seam", "sm-1", "crit",
		"2026-07-12 18:10:00", true, map[string]any{"attrs": `{"state":"down"}`})
	otherUp := testSig("ipsec_tunnel_status", "control_plane", "ipsec:gw", "seam", "sm-2", "info",
		"2026-07-12 18:30:00", false, map[string]any{"attrs": `{"state":"up"}`})
	rep := buildTestReport(t, meta, []map[string]any{down, otherUp})
	if rep.States.Incident == "recovered" || rep.States.Recovery == "explicitly_confirmed" {
		t.Fatalf("sm-2's up recovered sm-1's incident: %s/%s", rep.States.Incident, rep.States.Recovery)
	}
}

func TestRecoveryEvidenceForIncidentUnit(t *testing.T) {
	anomalous := []map[string]any{
		{"entity_type": "interface", "entity_id": "r1:Gi1", "kind": "link_state_change"},
		{"entity_type": "path", "entity_id": "prober->svc", "kind": "probe_loss"},
	}
	recoveries := []map[string]any{
		{"entity_type": "interface", "entity_id": "r1:Gi1", "kind": "link_state_change_clear"}, // own port
		{"entity_type": "interface", "entity_id": "r1:Gi2", "kind": "link_state_change_clear"}, // other port
		{"entity_type": "device", "entity_id": "r1:Gi1", "kind": "link_state_change_clear"},    // same id, other type
		{"entity_type": "path", "entity_id": "prober->svc", "kind": "probe_loss_clear"},        // own path
		{"entity_type": "interface", "entity_id": "", "kind": "link_state_change_clear"},       // no identity
		{"entity_type": "interface", "kind": "link_state_change_clear"},                        // missing identity
		{"entity_type": "interface", "entity_id": "r1:Gi1", "kind": "if_errors_anomaly_clear"}, // own port, other kind
	}
	got := RecoveryEvidenceForIncident(anomalous, recoveries)
	if len(got) != 3 {
		t.Fatalf("got %d recoveries, want 3 (own port, own path, own port other kind): %v", len(got), got)
	}
	for _, sig := range got {
		if sig["entity_id"] == "r1:Gi2" || sig["entity_type"] == "device" || sig["entity_id"] == "" || sig["entity_id"] == nil {
			t.Fatalf("out-of-scope recovery kept: %v", sig)
		}
	}
	if n := len(RecoveryEvidenceForIncident(nil, recoveries)); n != 0 {
		t.Fatalf("an incident with no anomalous entity has no recovery evidence, got %d", n)
	}
}

// The emitter-side gate applies the same scope: another port's early clear is
// not "recovery evidence preceding later anomalies" for this closed incident,
// while the incident's own early clear still is.
func TestTicketFactConsistencyRecoveryScope(t *testing.T) {
	anom := func(ts string) map[string]any {
		return testSig("link_state_change", "control_plane", "r1", "interface", "r1:Gi1", "high", ts, true, nil)
	}
	clearOn := func(entity, ts string) map[string]any {
		return testSig("link_state_change_clear", "control_plane", "r1", "interface", entity, "info", ts, false,
			map[string]any{"clear_ts": ts, "signal_id": "s-clear-" + entity + "-" + ts})
	}
	other := []map[string]any{anom("2026-07-12 18:00:00"), clearOn("r1:Gi2", "2026-07-12 18:05:00"), anom("2026-07-12 18:20:00")}
	if issues := TicketFactConsistencyIssues("closed", other); len(issues) != 0 {
		t.Fatalf("another port's clear blocked emission: %v", issues)
	}
	own := []map[string]any{anom("2026-07-12 18:00:00"), clearOn("r1:Gi1", "2026-07-12 18:05:00"), anom("2026-07-12 18:20:00")}
	issues := TicketFactConsistencyIssues("closed", own)
	if len(issues) != 1 || !strings.HasPrefix(issues[0], "recovered_before_last_anomaly") {
		t.Fatalf("own early clear must still be caught: %v", issues)
	}
}
