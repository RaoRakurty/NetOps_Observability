// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"fmt"
	"time"
)

// wireless_events.go — wireless state-change → controller-event synthesis
// (tracker #128 Phase 3).
//
// The scheduler persists States and produces Events; StateChanges were
// display-only until now. Wireless join/radio transitions are exactly the
// evidence the correlation engine needs (wireless_ap_down grounds the
// ap-down-power vs ap-software-fault pair), so the wireless state kinds — and
// ONLY the wireless state kinds; other connectors' state semantics are
// unchanged — synthesize events onto the existing netops.controller_events
// lane. Same lane, same consumer, no parallel wireless pipeline (spec §1).
//
// Flap escalation: the StateTracker counts transitions; at ≥flapThreshold
// transitions the synthesized event escalates to wireless_ap_join_flap — the
// evidence the capwap-instability signature requires. The correlation engine's
// own episode machinery handles windows; here a simple monotonic count is
// enough because FlapCount resets with process lifetime, not wall-clock (an
// AP that transitioned 6 times since boot IS unstable).

const wirelessFlapThreshold = 6 // transitions before a join flap escalates

// wirelessStateKinds are the state kinds this synthesis owns.
var wirelessStateKinds = map[string]bool{"ap_join": true, "radio_oper": true}

// WirelessStateChangeEvents converts wireless state transitions into
// normalized controller events. Non-wireless kinds pass through untouched
// (returned slice contains only the synthesized wireless events). Pure.
func WirelessStateChangeEvents(tenant, integrationID, sourceSystem string, changes []StateChange) []ControllerEvent {
	var out []ControllerEvent
	for _, ch := range changes {
		if !wirelessStateKinds[ch.Record.StateKind] {
			continue
		}
		kind, severity := wirelessEventKind(ch)
		if kind == "" {
			continue
		}
		ev := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: sourceSystem,
			Vendor: "cisco", Product: "Catalyst 9800",
			// Deterministic id: one event per (entity, transition, time) even
			// if the cycle re-runs.
			EventID:             fmt.Sprintf("%s|%s|%s->%s|%d", ch.Record.EntityKey, ch.Record.StateKind, ch.From, ch.To, ch.Record.LastSeen.UnixMilli()),
			EventTime:           ch.Record.LastSeen,
			IngestTime:          time.Now().UTC(),
			EventType:           ch.Record.StateKind + "_transition",
			NormalizedEventType: kind,
			Severity:            severity,
			Category:            "wireless_state",
			// DeviceID carries the CANONICAL wireless entity id (ap-<id> /
			// ap-<id>:radioN) — the correlation consumer binds to it directly,
			// which is what makes the rank-1 grounding work (report §7.3).
			DeviceID:   ch.Record.EntityKey,
			DeviceName: ch.Record.DeviceID,
			SiteID:     ch.Record.SiteID,
			Message:    fmt.Sprintf("%s %s → %s (flap count %d)", ch.Record.StateKind, ch.From, ch.To, ch.Record.FlapCount),
			EvidenceRole: func() EvidenceRole {
				if severity == "info" {
					return RoleSupporting // a recovery supports; it is not a fault
				}
				return RoleDiscriminating
			}(),
			CorrelationHints: map[string]string{
				"state_kind": ch.Record.StateKind,
				"from":       ch.From, "to": ch.To,
			},
		}
		ev.DedupeKey = DedupeKey(ev)
		out = append(out, ev)
	}
	return out
}

// wirelessEventKind maps one transition to its normalized event kind +
// severity. Returns "" to emit nothing (unknown target states stay silent —
// an unmappable transition must not fabricate a fault).
func wirelessEventKind(ch StateChange) (kind, severity string) {
	switch ch.Record.StateKind {
	case "ap_join":
		if ch.To == "down" {
			if ch.Record.FlapCount >= wirelessFlapThreshold {
				return "wireless_ap_join_flap", "high"
			}
			return "wireless_ap_down", "high"
		}
		if ch.To == "up" {
			if ch.Record.FlapCount >= wirelessFlapThreshold {
				// Recovery during a flap storm is part of the flap, not a clear.
				return "wireless_ap_join_flap", "warn"
			}
			return "wireless_ap_up", "info"
		}
	case "radio_oper":
		if ch.To == "down" {
			return "wireless_radio_down", "warn"
		}
		if ch.To == "up" {
			return "wireless_radio_up", "info"
		}
	}
	return "", ""
}
