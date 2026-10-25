// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"fmt"
	"time"
)

// sdwan_state_events.go — SD-WAN state TRANSITIONS become correlation events.
//
// Until 2026-10-18 only wireless transitions did (WirelessStateChangeEvents):
// a BFD session or control connection seen flipping by polling only updated the
// state table, so the correlation engine never heard of it. Each transition
// becomes one event on the controller_events lane, typed with the names the
// consumer already binds (src/correlation/controller_events.py).

var sdwanStateEventType = map[string]string{
	"bfd":             "controller_bfd_down",
	"control_conn":    "controller_control_connection_loss",
	"omp":             "controller_control_connection_loss",
	"reachability":    "controller_device_unreachable",
	"bgp":             "controller_alarm",
	"device_health":   "controller_alarm",
	"hardware_health": "controller_alarm",
}

// sdwanBad is the state a transition INTO is a fault.
func sdwanBad(to string) bool {
	switch to {
	case "down", "unreachable", "red", "error":
		return true
	}
	return false
}

// SDWANStateChangeEvents turns SD-WAN state transitions into events.
// Non-SD-WAN kinds are ignored (wireless has its own synthesizer).
//
// A transition into a fault emits the fault kind. A RECOVERY (back to a good
// state) emits the same kind with a "_clear" suffix, the engine's existing
// clear convention (engine.py build_nodes skips *_clear; layers.py strips it).
// Until 2026-10-25 a recovery was emitted under the FAULT kind at info
// severity: it joined the fault's node, stretched its activity window and kept
// the object "seen", so a tunnel that came back looked like one still failing.
//
// Vendor and product come from the connector spec; PATH kinds carry the
// canonical TunnelID both ends share, so the two halves of one session meet.
func SDWANStateChangeEvents(spec ConnectorSpec, tenant, integrationID string, changes []StateChange) []ControllerEvent {
	var out []ControllerEvent
	for _, ch := range changes {
		typ, ok := sdwanStateEventType[ch.Record.StateKind]
		if !ok || ch.From == ch.To {
			continue
		}
		severity, role, transition := "info", RoleSupporting, "recovery"
		switch {
		case sdwanBad(ch.To):
			severity, role, transition = "high", RoleDiscriminating, "fault" // canonical (model.go); "major" read as WARN and never opened
		case ch.To == "yellow" || ch.To == "warning":
			severity, role, transition = "warn", RoleDiscriminating, "degraded"
		}
		if transition == "recovery" {
			typ += "_clear"
		}
		hints := map[string]string{
			"state_kind": ch.Record.StateKind, "entity": ch.Record.EntityKey,
			"from": ch.From, "to": ch.To, "transition": transition,
		}
		if ch.Record.TunnelID != "" {
			hints["tunnel_scheme"] = "tloc_pair"
		}
		ev := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: spec.SourceSystem,
			Vendor: spec.Maker, Product: spec.Product,
			// Deterministic id: one event per (entity, transition, time) even if
			// the cycle re-runs.
			EventID:             fmt.Sprintf("%s|%s|%s->%s|%d", ch.Record.EntityKey, ch.Record.StateKind, ch.From, ch.To, ch.Record.LastSeen.UnixMilli()),
			EventTime:           ch.Record.LastSeen,
			IngestTime:          time.Now().UTC(),
			EventType:           ch.Record.StateKind + "_transition",
			NormalizedEventType: typ,
			Severity:            severity,
			Category:            "sdwan_state",
			DeviceID:            ch.Record.DeviceID,
			SiteID:              ch.Record.SiteID,
			TunnelID:            ch.Record.TunnelID,
			PeerID:              ch.Record.PeerID,
			Message:             fmt.Sprintf("%s %s → %s (flap count %d)", ch.Record.StateKind, ch.From, ch.To, ch.Record.FlapCount),
			EvidenceRole:        role,
			CorrelationHints:    hints,
		}
		ev.DedupeKey = DedupeKey(ev)
		out = append(out, ev)
	}
	return out
}
