// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"encoding/json"
	"strings"
	"time"
)

// vmanage.go — Cisco Catalyst SD-WAN Manager (vManage) transformer. Poll
// archetype. A vManage alarm carries BOTH a discrete alarm (event) AND an
// operational state (BFD/tunnel/control-connection up/down) — so it emits into
// TWO classes (§3.2 + §3.3), the canonical example of "not everything is an
// event."

// VManageTransformer normalizes a vManage /dataservice/alarms response.
type VManageTransformer struct{}

func (VManageTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Data []struct {
			UUID      string           `json:"uuid"`
			EventName string           `json:"eventname"`
			Type      string           `json:"type"`
			RuleDisp  string           `json:"rule_name_display"`
			Component string           `json:"component"`
			Severity  string           `json:"severity"`
			EntryTime int64            `json:"entry_time"`
			SystemIP  string           `json:"system_ip"`
			HostName  string           `json:"host_name"`
			SiteID    string           `json:"site_id"`
			Active    bool             `json:"active"`
			Values    []map[string]any `json:"values"`
			// The device a real alarm concerns: 20.6 sends it here
			// (devices[].system-ip), not in a top-level system_ip — recorded
			// in testdata/vmanage_20.6/alarms.json. Read both.
			Devices []map[string]any `json:"devices"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, a := range resp.Data {
		// Canonical kind from the stable rule key (vmanage_kinds.go); the
		// substring guess remains only for a rule the table does not know.
		net, stateKind := vmanageNormType(a.Type, a.Component, a.EventName)
		recovery := !a.Active
		if k, ok := vmanageAlarmKind(a.RuleDisp); ok {
			net, stateKind = k.Kind, k.StateKind
			if k.Recovery {
				recovery = true
			}
			if net == "link_state_change" {
				if st := strings.ToLower(vmValue(a.Values, "new-state", "if-oper-status", "if-admin-status")); st == "up" {
					recovery = true
				}
			}
		}
		systemIP := firstNonEmpty(a.SystemIP, vmValue(a.Devices, "system-ip"))
		hostName := firstNonEmpty(a.HostName, vmValue(a.Values, "host-name"))
		siteID := firstNonEmpty(a.SiteID, vmValue(a.Values, "site-id"))
		et := msToTime(a.EntryTime)
		e := ControllerEvent{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			Vendor: "cisco", Product: "Catalyst SD-WAN Manager",
			EventID:             a.UUID,
			EventTime:           et,
			IngestTime:          time.Now().UTC(),
			EventType:           firstNonEmpty(a.Type, a.EventName),
			NormalizedEventType: net,
			Severity:            normSeverity(a.Severity),
			Category:            strings.ToLower(a.Component),
			DeviceID:            systemIP,
			DeviceName:          hostName,
			SiteID:              siteID,
			InterfaceName:       vmValue(a.Values, "if-name", "ifname", "interface-name", "interface"),
			PeerID:              vmValue(a.Values, "peer", "peer-addr", "neighbor", "neighbor-address"),
			Message:             firstNonEmpty(a.RuleDisp, a.EventName),
			RawPayload:          mustJSON(a),
			EvidenceRole:        roleForEventType(net),
			CorrelationHints:    map[string]string{"component": a.Component, "system_ip": systemIP, "rule": a.RuleDisp},
		}
		if recovery {
			// A cleared alarm is a RECOVERY, not a fault: before 2026-10-25 it
			// was emitted under the fault kind with the vendor's original
			// severity, so a cleared Critical arrived as crit evidence. It now
			// takes the engine's clear convention and its own dedupe identity
			// (vManage may reuse the alarm uuid when the alarm clears).
			e.NormalizedEventType += "_clear"
			e.Severity = "info"
			e.EvidenceRole = RoleSupporting
			e.CorrelationHints["transition"] = "recovery"
			if e.EventID != "" {
				e.EventID += ":clear"
			}
		}
		e.DedupeKey = DedupeKey(e)
		b.Events = append(b.Events, e)

		// The same alarm is also a STATE fact when it's up/down-shaped.
		if stateKind != "" {
			cur := "down"
			if recovery { // a cleared alarm, an *_Up rule or an interface back up
				cur = "up"
			}
			b.States = append(b.States, ControllerState{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
				EntityKey: firstNonEmpty(systemIP, hostName), StateKind: stateKind,
				CurrentState: cur, DeviceID: systemIP, SiteID: siteID, Time: et,
				Data: map[string]any{"component": a.Component},
			})
		}
	}
	return b, nil
}

// vmanageNormType returns (normalized_event_type, stateKind). stateKind is ""
// when the alarm is not an operational up/down state.
func vmanageNormType(typ, component, eventName string) (string, string) {
	t := strings.ToLower(typ + " " + component + " " + eventName)
	switch {
	case strings.Contains(t, "bfd"):
		return "controller_bfd_down", "bfd"
	case strings.Contains(t, "control") && strings.Contains(t, "conn"):
		return "controller_control_connection_loss", "control_conn"
	case strings.Contains(t, "omp"):
		// OMP is SD-WAN's overlay control-plane routing — its own state kind.
		return "controller_control_connection_loss", "omp"
	case strings.Contains(t, "tunnel") || strings.Contains(t, "tloc"):
		return "controller_tunnel_state", "tunnel"
	case strings.Contains(t, "bgp"):
		return "controller_alarm", "bgp"
	case strings.Contains(t, "reachab") || strings.Contains(t, "unreach"):
		return "controller_device_unreachable", "reachability"
	case strings.Contains(t, "policy") || strings.Contains(t, "template"):
		return "controller_policy_change", ""
	default:
		return "controller_alarm", ""
	}
}
